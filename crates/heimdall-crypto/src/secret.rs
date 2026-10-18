use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// A fixed-size secret byte array whose memory is scrubbed on drop.
///
/// Hardening applied for section 5 "Memory Protection" of the design document:
///
/// 1. `Drop` overwrites the buffer before releasing it, so a freed page is not a
///    readable copy of key material (defeats `core(1)`/`/proc/kcore` dumps).
///    `zeroize` writes through volatile operations internally, so the compiler
///    may not elide the scrub as a dead store.
/// 2. The buffer is boxed, keeping it in a separate allocation from any other
///    secret so scrubbing one cannot corrupt another.
/// 3. `Debug` renders a fixed redaction string, so secrets cannot leak into
///    logs, `panic!` payloads, or `tracing` field values.
pub struct Secret<const N: usize> {
    inner: Box<[u8; N]>,
}

impl<const N: usize> Secret<N> {
    /// Wraps raw key material.
    ///
    /// # Panics
    /// Panics if `bytes.len() != N`. A silently truncated or padded key is a
    /// catastrophic failure mode, so this is a hard stop rather than a `Result`.
    pub fn new(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            N,
            "secret must be exactly {N} bytes, got {}",
            bytes.len()
        );
        let mut buf = Box::new([0u8; N]);
        buf.copy_from_slice(bytes);
        Self { inner: buf }
    }

    /// Copies `bytes` into a secret and then scrubs the caller's buffer. Used
    /// when the caller owns scratch space (e.g. a stack passphrase array).
    pub fn new_wiping(bytes: &mut [u8]) -> Self {
        let secret = Self::new(bytes);
        bytes.zeroize();
        secret
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.inner
    }

    /// Copies out into a zeroizing buffer, for handing to APIs that insist on a
    /// slice.
    pub fn to_vec(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.as_bytes().to_vec())
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Constant-time equality. `==` would leak the length of the matching
    /// prefix through timing.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.as_bytes()
            .as_slice()
            .ct_eq(other.as_bytes().as_slice())
            .into()
    }
}

impl<const N: usize> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        Self::new(self.as_bytes())
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> Eq for Secret<N> {}

pub type Key32 = Secret<32>;

impl Key32 {
    /// Rejects an all-zero key. Such a key signals uninitialised memory that
    /// would otherwise be silently used as key material.
    pub fn is_usable(&self) -> bool {
        !bool::from(self.as_bytes().as_slice().ct_eq([0u8; 32].as_slice()))
    }
}

/// Cryptographically secure random bytes.
///
/// `OsRng` is the only source: there is no acceptable-seed fallback for key
/// generation, and a deterministic PRNG here would compromise every key derived
/// from it.
pub fn random_bytes<const N: usize>() -> Secret<N> {
    use rand::RngCore as _;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Secret::new_wiping(&mut buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_value_semantics() {
        let a = Secret::<8>::new(b"abcdefgh");
        let b = Secret::<8>::new(b"abcdefgh");
        let c = Secret::<8>::new(b"abcdefgi");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_eq!(a, b);
    }

    #[test]
    #[should_panic(expected = "secret must be exactly 32 bytes")]
    fn wrong_length_panics() {
        let _ = Secret::<32>::new(b"too short");
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let s = Key32::new(&[b'k'; 32]);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("kkkk"), "{rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn new_wiping_clears_the_source_buffer() {
        let mut buf = *b"scratch-key-material-32-bytes!!!";
        let s = Secret::new_wiping(&mut buf);
        assert_eq!(s.as_bytes(), b"scratch-key-material-32-bytes!!!");
        assert!(buf.iter().all(|&b| b == 0), "source buffer was not wiped");
    }

    #[test]
    fn is_usable_rejects_all_zero() {
        assert!(!Key32::new(&[0u8; 32]).is_usable());
        let mut k = [0u8; 32];
        k[17] = 1;
        assert!(Key32::new(&k).is_usable());
    }

    #[test]
    fn random_bytes_are_not_all_zero() {
        assert!(random_bytes::<32>().is_usable());
    }
}
