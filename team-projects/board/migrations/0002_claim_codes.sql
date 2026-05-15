-- Claim codes — short human-readable strings that issue N fresh tokens
-- when redeemed, up to a max number of total claims. Used as a one-step
-- distribution mechanism (display on a screen during class) without
-- requiring per-student authentication.
--
-- Security notes:
--   * Only SHA-256(claim_code) is stored. The raw code lives only on the
--     instructor's screen + students' phones.
--   * `claims_used` is incremented atomically by the UPDATE in
--     `redeem_claim` (see storage.rs) so concurrent claims cannot
--     exceed `max_claims`.
--   * No record of WHICH tokens were issued to WHICH claim event is
--     kept. The token rows in `tokens` and the counter in
--     `claim_codes` are deliberately unlinked — this is what makes
--     the system unable to deanonymize even on full DB dump.

CREATE TABLE claim_codes (
    code_hash BLOB PRIMARY KEY NOT NULL,
    tokens_per_claim INTEGER NOT NULL
        CHECK (tokens_per_claim > 0 AND tokens_per_claim <= 20),
    max_claims INTEGER NOT NULL
        CHECK (max_claims > 0 AND max_claims <= 1000),
    claims_used INTEGER NOT NULL DEFAULT 0
        CHECK (claims_used >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER  -- Unix seconds; NULL = never expires
);

CREATE INDEX idx_claim_codes_expires ON claim_codes(expires_at)
    WHERE expires_at IS NOT NULL;
