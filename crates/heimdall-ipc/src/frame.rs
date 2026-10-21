//! Wire framing.
//!
//! Every frame is length-prefixed and then sealed, so a peer cannot desync a
//! parser by feeding a length the AEAD will reject later. The length is capped
//! before allocation so a single malformed header cannot make the process
//! reserve gigabytes.
//!
//! ```text
//! | magic(4) | version(1) | type(1) | seq(8) | ciphertext_len(4) | ct+tag |
//! ```
//!
//! The header is fed to the AEAD as associated data, which means the type and
//! sequence numbers are covered by the authentication tag. Without that, an
//! attacker could replay a `Close` frame in the middle of a stream or relabel a
//! payload as a different message type.

use heimdall_crypto::{aead::CipherKey, aead::Sealed, aead::open, aead::seal};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"HDV3";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 4;

/// Upper bound on a single plaintext. Large enough for a batch of threat events
/// or a patch manifest, small enough that a bad length cannot exhaust memory.
pub const MAX_PLAINTEXT_LEN: usize = 8 * 1024 * 1024;

/// The largest wire frame: the largest plaintext plus the nonce and the tag.
///
/// Every length that arrives from the wire is checked against this before it
/// is used to allocate. A header is eighteen bytes and can claim a length of
/// four gigabytes, so a reader that trusts it will try to allocate four
/// gigabytes on the say-so of a peer it has not authenticated yet.
pub const MAX_FRAME_LEN: usize = MAX_PLAINTEXT_LEN + 12 + 16;

/// Handshake flights are sent before any session key exists, so they travel
/// cleartext with their own signature. Nothing but public keys, nonces and
/// signatures goes in them.
///
/// Exact size: `version(1) | suite(1) | identity(32) | ephemeral(32) |
/// transcript_hash(32) | signature(64)`.
pub const HELLO_LEN: usize = 1 + 1 + 3 * 32 + 64;

/// A decoded, still-encrypted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub seq: u64,
    pub sealed: Sealed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Unencrypted handshake flight.
    Hello = 0,
    /// Encrypted application record, Core -> Sentinel.
    CoreToSentinel = 1,
    /// Encrypted application record, Sentinel -> Core.
    SentinelToCore = 2,
    /// In-band session teardown, still encrypted.
    Close = 3,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Hello),
            1 => Ok(Self::CoreToSentinel),
            2 => Ok(Self::SentinelToCore),
            3 => Ok(Self::Close),
            other => Err(Error::Protocol(format!("unknown frame type {other}"))),
        }
    }
}

/// The 18 bytes that precede the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: FrameKind,
    pub seq: u64,
    pub ciphertext_len: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        out[6..14].copy_from_slice(&self.seq.to_be_bytes());
        out[14..18].copy_from_slice(&self.ciphertext_len.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        // Callers pass the whole frame; only the leading `HEADER_LEN` bytes are
        // meaningful here.
        if buf.len() < HEADER_LEN {
            return Err(Error::Protocol("short frame header".into()));
        }
        if buf[..4] != MAGIC {
            return Err(Error::Protocol("bad frame magic".into()));
        }
        if buf[4] != VERSION {
            return Err(Error::Protocol(format!(
                "unsupported frame version {}",
                buf[4]
            )));
        }
        let kind = FrameKind::from_u8(buf[5])?;
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[6..14]);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buf[14..18]);
        let ciphertext_len = u32::from_be_bytes(len_bytes);
        // The length is checked here, not by the callers, because this is the
        // one place every frame passes through on its way in. A caller that
        // allocates from the decoded length is then allocating from a length
        // that has already been refused if it was not believable.
        if ciphertext_len as usize > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge {
                max: MAX_FRAME_LEN,
                actual: ciphertext_len as usize,
            });
        }
        Ok(Self {
            kind,
            seq: u64::from_be_bytes(seq_bytes),
            ciphertext_len,
        })
    }
}

/// Encrypts `plaintext` into a complete wire frame.
pub fn seal_frame(kind: FrameKind, seq: u64, key: &CipherKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Error::FrameTooLarge {
            max: MAX_PLAINTEXT_LEN,
            actual: plaintext.len(),
        });
    }
    let header_len = u32::try_from(HEADER_LEN).expect("header length is a constant");
    let mut aad = Vec::with_capacity(HEADER_LEN);
    aad.extend_from_slice(&header_len.to_be_bytes());
    aad.extend_from_slice(&(kind as u8).to_be_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());

    let sealed = seal(key.suite(), key.key(), plaintext, &aad)?;
    // `Sealed::len` reports the AEAD output only; the wire form prefixes the
    // nonce, so the length field must cover both.
    let wire = sealed.to_bytes();
    let header = Header {
        kind,
        seq,
        ciphertext_len: u32::try_from(wire.len())
            .map_err(|_| Error::Protocol("frame too large".into()))?,
    };

    let mut out = Vec::with_capacity(HEADER_LEN + wire.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&wire);
    Ok(out)
}

/// Wraps an already-encoded handshake flight. The length is still validated so
/// the reader never allocates from an attacker-controlled field.
pub fn hello_frame(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > HELLO_LEN {
        return Err(Error::FrameTooLarge {
            max: HELLO_LEN,
            actual: bytes.len(),
        });
    }
    let header = Header {
        kind: FrameKind::Hello,
        seq: 0,
        ciphertext_len: u32::try_from(bytes.len())
            .map_err(|_| Error::Protocol("hello too large".into()))?,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + bytes.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Reads the header from a buffer and returns it with the remaining bytes.
pub fn split_frame_header(buf: &[u8]) -> Result<(Header, &[u8])> {
    let header = Header::decode(buf)?;
    let advertised = header.ciphertext_len as usize;
    if advertised < 12 + 16 {
        return Err(Error::Protocol("frame shorter than nonce + tag".into()));
    }
    if advertised > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge {
            max: MAX_FRAME_LEN,
            actual: advertised,
        });
    }
    let body = &buf[HEADER_LEN..];
    if body.len() < advertised {
        return Err(Error::Protocol("truncated frame body".into()));
    }
    Ok((header, &body[..advertised]))
}

/// Authenticates and decrypts an encrypted frame.
pub fn open_frame(header: Header, body: &[u8], key: &CipherKey) -> Result<Vec<u8>> {
    let sealed = Sealed::from_bytes(body)?;
    let header_len = u32::try_from(HEADER_LEN).expect("header length is a constant");
    let mut aad = Vec::with_capacity(HEADER_LEN);
    aad.extend_from_slice(&header_len.to_be_bytes());
    aad.extend_from_slice(&(header.kind as u8).to_be_bytes());
    aad.extend_from_slice(&header.seq.to_be_bytes());
    open(key.suite(), key.key(), &sealed, &aad).map_err(Error::from)
}

/// Scrubs a plaintext buffer that has already been dispatched.
pub fn scrub(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_crypto::aead::Suite;

    fn key() -> CipherKey {
        CipherKey::generate(Suite::ChaCha20Poly1305)
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            kind: FrameKind::SentinelToCore,
            seq: u64::MAX,
            ciphertext_len: 1234,
        };
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn header_rejects_bad_magic_and_version() {
        let mut bytes = Header {
            kind: FrameKind::Hello,
            seq: 1,
            ciphertext_len: 1,
        }
        .encode();
        bytes[0] = b'X';
        assert!(Header::decode(&bytes).is_err());

        let mut bytes = Header {
            kind: FrameKind::Hello,
            seq: 1,
            ciphertext_len: 1,
        }
        .encode();
        bytes[4] = 99;
        assert!(Header::decode(&bytes).is_err());

        assert!(Header::decode(&bytes[..4]).is_err());
    }

    #[test]
    fn a_length_beyond_the_cap_is_refused_by_the_header_itself() {
        // The header is where every incoming frame passes through, so the
        // cap is enforced there. A reader that allocates from a decoded
        // length is then allocating from a length that has already been
        // refused.
        let bytes = Header {
            kind: FrameKind::CoreToSentinel,
            seq: 1,
            ciphertext_len: u32::MAX,
        }
        .encode();
        let err = Header::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }), "{err:?}");

        // Just over the cap is refused as well.
        let bytes = Header {
            kind: FrameKind::CoreToSentinel,
            seq: 1,
            ciphertext_len: u32::try_from(MAX_FRAME_LEN + 1).unwrap(),
        }
        .encode();
        assert!(Header::decode(&bytes).is_err());

        // Exactly at the cap is allowed: the cap is a ceiling, not a
        // narrower limit.
        let bytes = Header {
            kind: FrameKind::CoreToSentinel,
            seq: 1,
            ciphertext_len: u32::try_from(MAX_FRAME_LEN).unwrap(),
        }
        .encode();
        assert!(Header::decode(&bytes).is_ok());
    }

    #[test]
    fn sealed_frame_roundtrip() {
        let k = key();
        let frame = seal_frame(FrameKind::CoreToSentinel, 42, &k, b"threat report").unwrap();
        let (header, body) = split_frame_header(&frame).unwrap();
        assert_eq!(header.kind, FrameKind::CoreToSentinel);
        assert_eq!(header.seq, 42);
        assert_eq!(open_frame(header, body, &k).unwrap(), b"threat report");
    }

    #[test]
    fn wrong_key_fails() {
        let frame = seal_frame(FrameKind::CoreToSentinel, 1, &key(), b"x").unwrap();
        let (header, body) = split_frame_header(&frame).unwrap();
        assert!(open_frame(header, body, &key()).is_err());
    }

    #[test]
    fn type_is_covered_by_the_tag() {
        // Relabelling a Core->Sentinel frame as Sentinel->Core must fail: the
        // frame type is part of the associated data.
        let k = key();
        let frame = seal_frame(FrameKind::CoreToSentinel, 7, &k, b"x").unwrap();
        let mut tampered = frame.clone();
        tampered[5] = FrameKind::SentinelToCore as u8;
        let (header, body) = split_frame_header(&tampered).unwrap();
        assert!(open_frame(header, body, &k).is_err());
    }

    #[test]
    fn sequence_is_covered_by_the_tag() {
        let k = key();
        let frame = seal_frame(FrameKind::CoreToSentinel, 7, &k, b"x").unwrap();
        let mut tampered = frame.clone();
        tampered[6] ^= 0x01;
        let (header, body) = split_frame_header(&tampered).unwrap();
        assert!(open_frame(header, body, &k).is_err());
    }

    #[test]
    fn plaintext_is_not_visible_on_the_wire() {
        let k = key();
        let secret = b"ATTACKER-WAS-HERE".as_slice();
        let frame = seal_frame(FrameKind::CoreToSentinel, 1, &k, secret).unwrap();
        assert!(
            !frame.windows(secret.len()).any(|w| w == secret),
            "plaintext leaked into the cleartext frame"
        );
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = Header {
            kind: FrameKind::CoreToSentinel,
            seq: 0,
            ciphertext_len: u32::MAX,
        }
        .encode()
        .to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let err = split_frame_header(&buf).unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }), "{err:?}");
    }

    #[test]
    fn tiny_length_is_rejected() {
        let mut buf = Header {
            kind: FrameKind::CoreToSentinel,
            seq: 0,
            ciphertext_len: 4,
        }
        .encode()
        .to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        assert!(split_frame_header(&buf).is_err());
    }

    #[test]
    fn hello_frame_is_length_capped() {
        assert!(hello_frame(&[0u8; HELLO_LEN]).is_ok());
        assert!(hello_frame(&[0u8; HELLO_LEN + 1]).is_err());
    }
}
