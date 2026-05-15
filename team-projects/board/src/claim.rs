//! Claim codes.
//!
//! A claim code is a short, human-typeable string that the instructor
//! displays during class. Students enter it on `/claim` and receive
//! N fresh access tokens. The number of claims per code is capped so
//! that one student cannot exhaust the supply.
//!
//! Compared to access tokens (in `token.rs`), claim codes are:
//!   * Multi-use (up to `max_claims`).
//!   * Lower entropy in the typical case (admin may pick a memorable
//!     code like `MATH2026A7`); the brute-force defense relies on
//!     short expiry and a low `max_claims` cap.
//!   * Less sensitive: capturing a claim code grants posting power
//!     equal to `tokens_per_claim` posts only, and only while the
//!     claim hasn't reached its cap.
//!
//! Storage: only `SHA-256(normalized_code)` is persisted. The raw code
//! is never written to the DB.

use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const MIN_CODE_LEN: usize = 4;
const MAX_CODE_LEN: usize = 64;

/// A normalized claim code: uppercase ASCII alphanumeric, no separators.
///
/// We deliberately do NOT use `ZeroizeOnDrop` here — claim codes are
/// publicly displayed during class. Tokens issued by a claim ARE
/// zeroized via `RawToken`.
#[derive(Clone)]
pub struct ClaimCode(String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClaimCodeHash([u8; 32]);

impl ClaimCode {
    /// Parse user-typed input. Tolerant of case, whitespace, dashes,
    /// and underscores. Rejects empty / overly long / non-alphanumeric.
    pub fn from_user_input(s: &str) -> Option<Self> {
        let normalized: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .flat_map(|c| c.to_uppercase())
            .collect();
        if normalized.len() < MIN_CODE_LEN || normalized.len() > MAX_CODE_LEN {
            return None;
        }
        if !normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        Some(Self(normalized))
    }

    /// Generate a random claim code (12 base32 chars = 60 bits entropy,
    /// displayed with dashes every 4 chars for readability).
    ///
    /// Even though brute force is the proxy's concern (rate limiting),
    /// 60 bits is comfortably beyond casual guessing.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 8]; // 64 bits → 13 chars; we'll trim to 12
        OsRng.fill_bytes(&mut bytes);
        let raw = BASE32_NOPAD.encode(&bytes);
        // Take first 12 chars for a stable length.
        let normalized: String = raw.chars().take(12).collect();
        debug_assert_eq!(normalized.len(), 12);
        Self(normalized)
    }

    /// Render for display: insert a dash every 4 characters.
    /// e.g. `MATH2026A7B2` → `MATH-2026-A7B2`
    pub fn display(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + self.0.len() / 4);
        for (i, c) in self.0.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// SHA-256 of the normalized form. Use this for DB lookup.
    pub fn hash(&self) -> ClaimCodeHash {
        let digest = Sha256::digest(self.0.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        ClaimCodeHash(out)
    }
}

/// Redact in `{:?}` to prevent accidental log/panic leakage.
impl std::fmt::Debug for ClaimCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimCode(***redacted***)")
    }
}

impl ClaimCodeHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Short hex prefix (16 chars) suitable for use in a cookie name
    /// for per-claim browser deduplication.
    pub fn short_hex(&self) -> String {
        self.0[..8].iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_user_input_normalizes() {
        let a = ClaimCode::from_user_input("math-2026-a7").unwrap();
        let b = ClaimCode::from_user_input("MATH2026A7").unwrap();
        let c = ClaimCode::from_user_input("  Math 2026 A7  ").unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.hash(), c.hash());
    }

    #[test]
    fn rejects_too_short() {
        assert!(ClaimCode::from_user_input("ABC").is_none());
        assert!(ClaimCode::from_user_input("").is_none());
        assert!(ClaimCode::from_user_input("---").is_none());
    }

    #[test]
    fn rejects_too_long() {
        let long = "A".repeat(100);
        assert!(ClaimCode::from_user_input(&long).is_none());
    }

    #[test]
    fn rejects_special_chars() {
        assert!(ClaimCode::from_user_input("ABC.123").is_none());
        assert!(ClaimCode::from_user_input("ABC$123").is_none());
        // Dashes and underscores are allowed as separators.
        assert!(ClaimCode::from_user_input("ABC-123").is_some());
        assert!(ClaimCode::from_user_input("ABC_123").is_some());
    }

    #[test]
    fn generate_yields_valid_code() {
        for _ in 0..50 {
            let c = ClaimCode::generate();
            assert_eq!(c.0.len(), 12);
            let parsed = ClaimCode::from_user_input(&c.display()).unwrap();
            assert_eq!(c.hash(), parsed.hash());
        }
    }

    #[test]
    fn display_has_dashes() {
        let c = ClaimCode::from_user_input("MATH2026A7B2C9").unwrap();
        let d = c.display();
        // Should have at least one dash for codes > 4 chars
        assert!(d.contains('-'));
    }

    #[test]
    fn debug_does_not_leak() {
        let c = ClaimCode::from_user_input("MATH2026A7").unwrap();
        let s = format!("{:?}", c);
        assert!(!s.contains("MATH"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn short_hex_is_deterministic() {
        let c = ClaimCode::from_user_input("MATH2026A7").unwrap();
        let h1 = c.hash().short_hex();
        let h2 = c.hash().short_hex();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }
}
