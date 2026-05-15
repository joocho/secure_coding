//! Tokens.
//!
//! Tokens are 128-bit random values handed out to students. Only their SHA-256
//! digest is stored on the server. The raw token is the bearer secret — anyone
//! holding it can post exactly once.
//!
//! Threat model assumptions:
//!   * 128 bits is far beyond brute-force feasibility (2^128).
//!   * SHA-256 is preimage-resistant, so the stored digest does not leak the
//!     raw token even if the entire DB is dumped.
//!   * Tokens are typed once by humans, so we choose base32 (RFC 4648
//!     alphabet, no padding) for case-insensitive, easy-to-read entry.

use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 16 bytes = 128 bits of entropy.
pub const TOKEN_BYTES: usize = 16;
pub const TOKEN_HASH_BYTES: usize = 32;

/// A raw token. Never persist, never log.
///
/// `ZeroizeOnDrop` ensures the bytes are wiped from memory when the value
/// leaves scope, reducing the window in which a heap dump / core file could
/// reveal an unused token.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RawToken([u8; TOKEN_BYTES]);

/// SHA-256(raw_token). Safe to persist.
///
/// Equality on `TokenHash` uses the default `PartialEq` because the hash itself
/// is non-secret in the DB query path — what we must protect is the raw token,
/// and that is what we compare *against* only via hash lookup, never directly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; TOKEN_HASH_BYTES]);

impl RawToken {
    /// Generate a fresh token using the OS CSPRNG.
    ///
    /// `OsRng` reads from `/dev/urandom` / `getrandom(2)` / equivalent. We
    /// deliberately avoid `rand::thread_rng()` because (a) it may not be
    /// reseeded as often as we'd like, and (b) `OsRng` is the documented
    /// choice for cryptographic key material.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Render as 26 uppercase base32 characters with no padding.
    /// Example: `K4P7M9N2QXJZBVW3HFLC5DST8R`.
    ///
    /// We do NOT add formatting dashes here; rendering is the caller's
    /// concern. The `decode` function is tolerant of dashes/spaces on input.
    pub fn encode(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// Parse a token from human input. Returns `None` on any malformed
    /// input. Tolerant of mixed case, whitespace, and dashes.
    pub fn decode(s: &str) -> Option<Self> {
        let normalized: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .flat_map(|c| c.to_uppercase())
            .collect();
        if normalized.len() != 26 {
            return None;
        }
        let bytes = BASE32_NOPAD.decode(normalized.as_bytes()).ok()?;
        let arr: [u8; TOKEN_BYTES] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    /// SHA-256 of the raw bytes.
    pub fn hash(&self) -> TokenHash {
        let digest = Sha256::digest(self.0);
        let mut out = [0u8; TOKEN_HASH_BYTES];
        out.copy_from_slice(&digest);
        TokenHash(out)
    }
}

/// Custom Debug to prevent accidental leakage through `{:?}` formatting,
/// panic backtraces, or `tracing::debug!` calls.
impl std::fmt::Debug for RawToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawToken(***redacted***)")
    }
}

impl TokenHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encode_decode() {
        for _ in 0..100 {
            let t = RawToken::generate();
            let s = t.encode();
            assert_eq!(s.len(), 26);
            let t2 = RawToken::decode(&s).expect("must decode");
            assert_eq!(t.0, t2.0);
        }
    }

    #[test]
    fn decode_tolerates_formatting() {
        let t = RawToken::generate();
        let s = t.encode();
        let formatted = format!(
            "  {}-{}-{} ",
            &s[0..8],
            &s[8..16],
            &s[16..26]
        );
        let t2 = RawToken::decode(&formatted).expect("must decode");
        assert_eq!(t.0, t2.0);
    }

    #[test]
    fn decode_lowercase() {
        let t = RawToken::generate();
        let s = t.encode().to_lowercase();
        let t2 = RawToken::decode(&s).expect("must decode lowercase");
        assert_eq!(t.0, t2.0);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(RawToken::decode("ABCD").is_none());
        assert!(RawToken::decode(&"A".repeat(100)).is_none());
        assert!(RawToken::decode("").is_none());
    }

    #[test]
    fn decode_rejects_invalid_chars() {
        // base32 has no '0' '1' '8' '9' in the alphabet (RFC4648).
        assert!(RawToken::decode("00000000000000000000000000").is_none());
    }

    #[test]
    fn hash_is_deterministic_and_distinct() {
        let t = RawToken::generate();
        assert_eq!(t.hash(), t.hash());
        let t2 = RawToken::generate();
        assert_ne!(t.hash(), t2.hash());
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let t = RawToken::generate();
        let s = format!("{:?}", t);
        assert!(!s.contains(&t.encode()));
        assert!(s.contains("redacted"));
    }
}
