//! Small non-cryptographic helpers kept deliberately dependency-free.

use crate::error::{Error, Result};

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    if !s.is_ascii() || s.len() % 2 != 0 {
        return Err("expected an even-length ASCII hex string");
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: u8) -> std::result::Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex digit"),
    }
}

/// Compares two byte strings without an early exit. Used for MAC/tag checks in
/// code that has not yet been converted to the AEAD layer.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Length-prefixed write, so that concatenated fields are unambiguous.
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::Protocol("field too long".into()));
    match len {
        Ok(len) => out.extend_from_slice(&len.to_be_bytes()),
        Err(_) => return,
    }
    out.extend_from_slice(bytes);
}

/// Inverse of [`put_bytes`].
pub fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    if input.len() < 4 {
        return Err(Error::Protocol("truncated length prefix".into()));
    }
    let (prefix, rest) = input.split_at(4);
    let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    if rest.len() < len {
        return Err(Error::Protocol("truncated field".into()));
    }
    let (field, tail) = rest.split_at(len);
    *input = tail;
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x0f, 0xff, 0xa5];
        assert_eq!(to_hex(&data), "000fffa5");
        assert_eq!(from_hex("000fffa5").unwrap(), data);
        assert_eq!(from_hex("000FFFA5").unwrap(), data);
    }

    #[test]
    fn hex_rejects_malformed() {
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert!(from_hex("0 0").is_err());
    }

    #[test]
    fn length_prefixed_fields_are_unambiguous() {
        let mut buf = Vec::new();
        put_bytes(&mut buf, b"ab");
        put_bytes(&mut buf, b"c");
        assert_eq!(&buf[4..6], b"ab");
        assert_eq!(&buf[10..], b"c");

        let mut cursor = &buf[..];
        assert_eq!(take_bytes(&mut cursor).unwrap(), b"ab");
        assert_eq!(take_bytes(&mut cursor).unwrap(), b"c");
        assert!(cursor.is_empty());
        assert!(take_bytes(&mut cursor).is_err());
    }

    #[test]
    fn truncated_length_prefix_is_rejected() {
        let mut cursor: &[u8] = &[0x00, 0x00];
        assert!(take_bytes(&mut cursor).is_err());
        let mut cursor: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x01];
        assert!(take_bytes(&mut cursor).is_err());
    }
}
