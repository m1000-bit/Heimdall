//! Encrypted, tamper-evident audit log.
//!
//! The in-memory log dies with the process; this makes it durable. Entries are
//! sealed with ChaCha20-Poly1305 under a passphrase-derived key, hash-chained
//! with SHA3-256, and each record's AAD binds it to its sequence and position
//! so moving a record breaks authentication.
//!
//! # Record format
//!
//! ```text
//! "HDVA" | version | seq (u64) | prev chain hash (32) | nonce (12) | plain length (u32) | ciphertext || tag
//! ```
//!
//! The length field is what makes the log seekable: a reader knows where one
//! entry ends without having to decrypt it first, and a truncated tail is
//! detected as a short record rather than as a decryption failure.
//!
//! # Limitations (by design)
//! Truncating the last record(s) is not detectable by the chain: there is no
//! external anchor for the head. A `head_hash()` that the operator records
//! elsewhere, or a periodic seal of the head into a separate file, is what
//! closes that gap.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use sha3::Sha3_256;

use crate::error::{Error, Result};
use crate::gate::{AuditEntry, AuditEvent};

/// The HKDF label that separates the audit-log key from every other key.
pub const AUDIT_KEY_LABEL: &[u8] = b"heimdall/audit-log/v1";

const MAGIC: &[u8; 4] = b"HDVA";
const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const PREV_HASH_LEN: usize = 32;
const SEQ_LEN: usize = 8;
const PLAIN_LEN_LEN: usize = 4;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SEQ_LEN + PREV_HASH_LEN + NONCE_LEN + PLAIN_LEN_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEntry {
    at_secs: u64,
    at_nanos: u32,
    proposal_id: u64,
    event: u8,
    actor: String,
    note: String,
}

fn event_to_u8(e: AuditEvent) -> u8 {
    match e {
        AuditEvent::Submitted => 0,
        AuditEvent::Approved => 1,
        AuditEvent::Rejected => 2,
        AuditEvent::Superseded => 3,
        AuditEvent::Expired => 4,
        AuditEvent::Applied => 5,
        AuditEvent::ApplicationFailed => 6,
    }
}

fn event_from_u8(v: u8) -> Result<AuditEvent> {
    match v {
        0 => Ok(AuditEvent::Submitted),
        1 => Ok(AuditEvent::Approved),
        2 => Ok(AuditEvent::Rejected),
        3 => Ok(AuditEvent::Superseded),
        4 => Ok(AuditEvent::Expired),
        5 => Ok(AuditEvent::Applied),
        6 => Ok(AuditEvent::ApplicationFailed),
        other => Err(Error::Crypto(heimdall_crypto::Error::Protocol(format!(
            "unknown audit event discriminant {other}"
        )))),
    }
}

fn entry_to_wire(e: &AuditEntry) -> WireEntry {
    let elapsed = e.at.duration_since(UNIX_EPOCH).unwrap_or_default();
    WireEntry {
        at_secs: elapsed.as_secs(),
        at_nanos: elapsed.subsec_nanos(),
        proposal_id: e.proposal_id,
        event: event_to_u8(e.event),
        actor: e.actor.clone(),
        note: e.note.clone(),
    }
}

fn wire_to_entry(w: WireEntry) -> AuditEntry {
    let at = UNIX_EPOCH + Duration::new(w.at_secs, w.at_nanos);
    AuditEntry {
        at,
        proposal_id: w.proposal_id,
        event: match event_from_u8(w.event) {
            Ok(e) => e,
            Err(_) => AuditEvent::Submitted, // Should not happen if verified
        },
        actor: w.actor,
        note: w.note,
    }
}

#[derive(Debug)]
struct ParsedRecord {
    seq: u64,
    prev_header: [u8; PREV_HASH_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// A durable, encrypted, hash-chained audit log.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    key: heimdall_crypto::aead::CipherKey,
    entries: Vec<AuditEntry>,
    head_hash: [u8; PREV_HASH_LEN],
    file: File,
}

impl AuditLog {
    /// Opens the log at `path`, creating it (and its key material) if needed.
    pub fn open(
        path: impl Into<PathBuf>,
        passphrase: &heimdall_crypto::Passphrase,
    ) -> Result<Self> {
        let path = path.into();
        let salt_path = salt_sidecar_path(&path);
        let salt = load_or_create_salt(&salt_path)?;

        let master = heimdall_crypto::kdf::derive_from_passphrase(passphrase.as_bytes(), &salt)?;
        let key = heimdall_crypto::aead::derive_key(
            heimdall_crypto::aead::Suite::ChaCha20Poly1305,
            &master,
            AUDIT_KEY_LABEL,
        )?;

        // Open/create the log file
        let mut file_opts = OpenOptions::new();
        file_opts.read(true).write(true).create(true);
        let mut file = file_opts.open(&path).map_err(Error::Io)?;

        // Read all existing records
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(Error::Io)?;

        let mut entries = Vec::new();
        let mut head_hash = [0u8; PREV_HASH_LEN];
        if !buf.is_empty() {
            let mut cursor = &buf[..];
            let mut expected_seq: u64 = 0;
            let mut prev_chain: [u8; PREV_HASH_LEN] = [0u8; PREV_HASH_LEN];
            while !cursor.is_empty() {
                let rec = parse_record(&mut cursor)?;
                if rec.seq != expected_seq {
                    return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                        "audit log sequence mismatch".into(),
                    )));
                }
                if rec.prev_header != prev_chain {
                    return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                        "audit log chain prev mismatch".into(),
                    )));
                }

                let aad = make_aad(rec.seq, &rec.prev_header);
                let sealed = heimdall_crypto::aead::Sealed {
                    nonce: rec.nonce,
                    ciphertext: rec.ciphertext.clone(),
                };
                let plaintext = heimdall_crypto::aead::open_with(&key, &sealed, &aad)
                    .map_err(|_| Error::Crypto(heimdall_crypto::Error::Decrypt))?;

                // Plaintext = JSON(entry) || prev_chain_hash (32 bytes)
                if plaintext.len() < PREV_HASH_LEN {
                    return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                        "truncated audit record plaintext".into(),
                    )));
                }
                let (json_bytes, stored_prev) = plaintext.split_at(plaintext.len() - PREV_HASH_LEN);
                if stored_prev != prev_chain {
                    return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                        "audit log plaintext prev mismatch".into(),
                    )));
                }

                let wire: WireEntry = serde_json::from_slice(json_bytes)
                    .map_err(|e| Error::Crypto(heimdall_crypto::Error::Protocol(e.to_string())))?;
                let entry = wire_to_entry(wire);
                entries.push(entry);

                // Compute chain hash for this record
                let mut hasher = Sha3_256::new();
                hasher.update(prev_chain);
                hasher.update(&plaintext);
                let chain_hash: [u8; PREV_HASH_LEN] = hasher.finalize().into();

                prev_chain = chain_hash;
                expected_seq += 1;
            }
            head_hash = prev_chain;
        }

        // Seek to end for appending
        file.seek(std::io::SeekFrom::End(0)).map_err(Error::Io)?;

        Ok(Self {
            path,
            key,
            entries,
            head_hash,
            file,
        })
    }

    /// Appends one entry: seals it, chains it onto the previous entry, and fsyncs.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<()> {
        let seq = self.entries.len() as u64;
        let prev_chain = self.head_hash;

        let wire = entry_to_wire(entry);
        let mut json_bytes = serde_json::to_vec(&wire)
            .map_err(|e| Error::Crypto(heimdall_crypto::Error::Protocol(e.to_string())))?;
        // Append prev chain hash to plaintext
        json_bytes.extend_from_slice(&prev_chain);

        let aad = make_aad(seq, &prev_chain);
        let sealed = heimdall_crypto::aead::seal_with(&self.key, &json_bytes, &aad)?;

        // Build record
        let plain_len = u32::try_from(json_bytes.len()).map_err(|_| {
            Error::Crypto(heimdall_crypto::Error::Protocol(
                "audit entry too long".into(),
            ))
        })?;
        let mut record = Vec::with_capacity(HEADER_LEN + sealed.ciphertext.len());
        record.extend_from_slice(MAGIC);
        record.push(VERSION);
        record.extend_from_slice(&seq.to_be_bytes());
        record.extend_from_slice(&prev_chain);
        record.extend_from_slice(&sealed.nonce);
        record.extend_from_slice(&plain_len.to_be_bytes());
        record.extend_from_slice(&sealed.ciphertext);

        self.file.write_all(&record).map_err(Error::Io)?;
        self.file.flush().map_err(Error::Io)?;
        self.file.sync_all().map_err(Error::Io)?;

        // Compute chain hash
        let mut hasher = Sha3_256::new();
        hasher.update(prev_chain);
        hasher.update(&json_bytes);
        let chain_hash: [u8; PREV_HASH_LEN] = hasher.finalize().into();
        self.head_hash = chain_hash;

        self.entries.push(entry.clone());
        Ok(())
    }

    /// The entries read or written so far, oldest first.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Where the log lives on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The hash of the last entry; the head of the chain.
    pub fn head_hash(&self) -> [u8; PREV_HASH_LEN] {
        self.head_hash
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reads the log from disk and verifies the whole chain.
    /// Fails if the file is malformed, the passphrase is wrong, any record
    /// fails authentication, or the hash chain does not link up.
    pub fn verify(
        path: impl Into<PathBuf>,
        passphrase: &heimdall_crypto::Passphrase,
    ) -> Result<()> {
        let path = path.into();
        let salt_path = salt_sidecar_path(&path);
        if !salt_path.exists() && !path.exists() {
            return Ok(());
        }
        let salt = load_or_create_salt(&salt_path)?;
        let master = heimdall_crypto::kdf::derive_from_passphrase(passphrase.as_bytes(), &salt)?;
        let key = heimdall_crypto::aead::derive_key(
            heimdall_crypto::aead::Suite::ChaCha20Poly1305,
            &master,
            AUDIT_KEY_LABEL,
        )?;

        let mut file = File::open(&path).map_err(Error::Io)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(Error::Io)?;

        if buf.is_empty() {
            return Ok(());
        }

        let mut cursor = &buf[..];
        let mut expected_seq: u64 = 0;
        let mut prev_chain: [u8; PREV_HASH_LEN] = [0u8; PREV_HASH_LEN];
        while !cursor.is_empty() {
            let rec = parse_record(&mut cursor)?;
            if rec.seq != expected_seq {
                return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                    "audit log sequence mismatch".into(),
                )));
            }
            if rec.prev_header != prev_chain {
                return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                    "audit log chain prev mismatch".into(),
                )));
            }

            let aad = make_aad(rec.seq, &rec.prev_header);
            let sealed = heimdall_crypto::aead::Sealed {
                nonce: rec.nonce,
                ciphertext: rec.ciphertext.clone(),
            };
            let plaintext = heimdall_crypto::aead::open_with(&key, &sealed, &aad)
                .map_err(|_| Error::Crypto(heimdall_crypto::Error::Decrypt))?;

            if plaintext.len() < PREV_HASH_LEN {
                return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                    "truncated audit record plaintext".into(),
                )));
            }
            let (_json_bytes, stored_prev) = plaintext.split_at(plaintext.len() - PREV_HASH_LEN);
            if stored_prev != prev_chain {
                return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
                    "audit log plaintext prev mismatch".into(),
                )));
            }

            // Verify chain hash
            let mut hasher = Sha3_256::new();
            hasher.update(prev_chain);
            hasher.update(&plaintext);
            let chain_hash: [u8; PREV_HASH_LEN] = hasher.finalize().into();
            prev_chain = chain_hash;
            expected_seq += 1;
        }
        Ok(())
    }
}

fn salt_sidecar_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".salt");
    PathBuf::from(p)
}

fn load_or_create_salt(salt_path: &Path) -> Result<[u8; 16]> {
    if salt_path.exists() {
        let mut f = File::open(salt_path).map_err(Error::Io)?;
        let mut buf = [0u8; 16];
        f.read_exact(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Crypto(heimdall_crypto::Error::Protocol("wrong-length salt".into()))
            } else {
                Error::Io(e)
            }
        })?;
        Ok(buf)
    } else {
        if let Some(parent) = salt_path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        let salt = heimdall_crypto::random_bytes::<16>();
        let salt_bytes = *salt.as_bytes();
        // Atomic write via temp file + rename
        let mut tmp_path = salt_path.to_path_buf();
        let mut tmp_name = salt_path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        let mut f = File::create(&tmp_path).map_err(Error::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = f.metadata().map_err(Error::Io)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&tmp_path, perms).map_err(Error::Io)?;
        }
        f.write_all(&salt_bytes).map_err(Error::Io)?;
        f.flush().map_err(Error::Io)?;
        f.sync_all().map_err(Error::Io)?;
        fs::rename(&tmp_path, salt_path).map_err(Error::Io)?;
        Ok(salt_bytes)
    }
}

fn make_aad(seq: u64, prev: &[u8; PREV_HASH_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AUDIT_KEY_LABEL.len() + SEQ_LEN + PREV_HASH_LEN);
    aad.extend_from_slice(AUDIT_KEY_LABEL);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(prev);
    aad
}

fn parse_record(cursor: &mut &[u8]) -> Result<ParsedRecord> {
    if cursor.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
            "truncated tail record".into(),
        )));
    }
    if &cursor[..4] != MAGIC {
        return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
            "bad audit log magic".into(),
        )));
    }
    let mut pos = 4;
    if cursor[pos] != VERSION {
        return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
            "bad audit log version".into(),
        )));
    }
    pos += 1;
    let mut seq_bytes = [0u8; SEQ_LEN];
    seq_bytes.copy_from_slice(&cursor[pos..pos + SEQ_LEN]);
    let seq = u64::from_be_bytes(seq_bytes);
    pos += SEQ_LEN;
    let mut prev_header = [0u8; PREV_HASH_LEN];
    prev_header.copy_from_slice(&cursor[pos..pos + PREV_HASH_LEN]);
    pos += PREV_HASH_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&cursor[pos..pos + NONCE_LEN]);
    pos += NONCE_LEN;
    let mut plain_len_bytes = [0u8; PLAIN_LEN_LEN];
    plain_len_bytes.copy_from_slice(&cursor[pos..pos + PLAIN_LEN_LEN]);
    pos += PLAIN_LEN_LEN;

    // The length is what makes a record a record: without it the reader
    // cannot tell where one entry ends and the next begins.
    let plain_len = u32::from_be_bytes(plain_len_bytes) as usize;
    let body_len = plain_len.checked_add(TAG_LEN).ok_or_else(|| {
        Error::Crypto(heimdall_crypto::Error::Protocol(
            "audit record too long".into(),
        ))
    })?;
    if cursor.len() < pos + body_len {
        return Err(Error::Crypto(heimdall_crypto::Error::Protocol(
            "truncated tail record".into(),
        )));
    }
    let ciphertext = cursor[pos..pos + body_len].to_vec();
    *cursor = &cursor[pos + body_len..];
    Ok(ParsedRecord {
        seq,
        prev_header,
        nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{AuditEntry, AuditEvent};
    use heimdall_crypto::Passphrase;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_pass() -> Passphrase {
        Passphrase::from_utf8(b"correct horse battery staple")
    }

    fn unique_tmp() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut p = std::env::temp_dir();
        p.push(format!("heimdall-audit-{nanos}-{}", "test"));
        p
    }

    #[test]
    fn append_then_read_roundtrip() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();

        let e1 = AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1000),
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "model-a".to_string(),
            note: "awaiting explicit user authorisation".to_string(),
        };
        let e2 = AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1001),
            proposal_id: 1,
            event: AuditEvent::Approved,
            actor: "alice".to_string(),
            note: "user authorised the change".to_string(),
        };
        let e3 = AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1002),
            proposal_id: 1,
            event: AuditEvent::Applied,
            actor: "alice".to_string(),
            note: "written to the working tree".to_string(),
        };
        log.append(&e1).unwrap();
        log.append(&e2).unwrap();
        log.append(&e3).unwrap();

        assert_eq!(log.entries().len(), 3);
        assert_eq!(log.entries()[0], e1);
        assert_eq!(log.entries()[1], e2);
        assert_eq!(log.entries()[2], e3);

        // reopen
        let log2 = AuditLog::open(&log_path, &pass).unwrap();
        assert_eq!(log2.entries().len(), 3);
        assert_eq!(log2.entries()[0], e1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_not_plaintext() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        let e1 = AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1000),
            proposal_id: 42,
            event: AuditEvent::Submitted,
            actor: "secret-actor-xyz".to_string(),
            note: "top-secret-note-abc".to_string(),
        };
        log.append(&e1).unwrap();
        let bytes = fs::read(&log_path).unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(!s.contains("secret-actor-xyz"));
        assert!(!s.contains("top-secret-note-abc"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails_verify() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH,
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "a".into(),
            note: "n".into(),
        })
        .unwrap();
        drop(log);
        let bad = Passphrase::from_utf8(b"wrong wrong wrong wrong");
        assert!(AuditLog::verify(&log_path, &bad).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flip_byte_fails() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH,
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "a".into(),
            note: "n".into(),
        })
        .unwrap();
        drop(log);
        let mut bytes = fs::read(&log_path).unwrap();
        if !bytes.is_empty() {
            let idx = bytes.len() / 2;
            bytes[idx] ^= 0x01;
            fs::write(&log_path, bytes).unwrap();
        }
        assert!(AuditLog::verify(&log_path, &pass).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_middle_fails() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1),
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "a".into(),
            note: "n1".into(),
        })
        .unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(2),
            proposal_id: 1,
            event: AuditEvent::Approved,
            actor: "b".into(),
            note: "n2".into(),
        })
        .unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(3),
            proposal_id: 1,
            event: AuditEvent::Applied,
            actor: "b".into(),
            note: "n3".into(),
        })
        .unwrap();
        drop(log);
        let bytes = fs::read(&log_path).unwrap();
        // Try to delete from middle - rough cut
        if bytes.len() > 100 {
            let mut new_bytes = bytes[..50].to_vec();
            new_bytes.extend_from_slice(&bytes[120..]);
            fs::write(&log_path, new_bytes).unwrap();
        }
        assert!(AuditLog::verify(&log_path, &pass).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_mid_record_fails() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        log.append(&AuditEntry {
            at: UNIX_EPOCH,
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "a".into(),
            note: "n".into(),
        })
        .unwrap();
        drop(log);
        let bytes = fs::read(&log_path).unwrap();
        if bytes.len() > 10 {
            fs::write(&log_path, &bytes[..bytes.len() - 5]).unwrap();
        }
        assert!(AuditLog::verify(&log_path, &pass).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_hash_changes_and_matches() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let mut log = AuditLog::open(&log_path, &pass).unwrap();
        let h0 = log.head_hash();
        log.append(&AuditEntry {
            at: UNIX_EPOCH,
            proposal_id: 1,
            event: AuditEvent::Submitted,
            actor: "a".into(),
            note: "n".into(),
        })
        .unwrap();
        let h1 = log.head_hash();
        assert_ne!(h0, h1);
        log.append(&AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(1),
            proposal_id: 1,
            event: AuditEvent::Approved,
            actor: "b".into(),
            note: "n2".into(),
        })
        .unwrap();
        let h2 = log.head_hash();
        assert_ne!(h1, h2);
        AuditLog::verify(&log_path, &pass).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_creates_salt_sidecar() {
        let dir = unique_tmp();
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.log");
        let pass = make_pass();
        let log = AuditLog::open(&log_path, &pass).unwrap();
        assert!(log.is_empty());
        assert!(salt_sidecar_path(&log_path).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
