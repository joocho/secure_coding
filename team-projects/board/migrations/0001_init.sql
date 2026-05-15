-- Anonymous Q&A board schema.
--
-- Design notes:
--   * We never store raw tokens. Only SHA-256(token) is stored, so a DB
--     leak does NOT yield usable unused tokens to an attacker (preimage
--     resistance of SHA-256 ≈ 2^256 work to invert).
--   * Token state machine: row exists with used=0 → used=1 (single-use).
--     Row is never deleted, so a used token cannot be silently re-issued.
--   * We deliberately do NOT store any per-token metadata (student id,
--     batch tag, etc). The DB schema itself is the privacy boundary —
--     even a full DB read does not reveal who posted what.
--   * Questions have no foreign key to tokens. The two tables are
--     unlinked by design; the only correlation is the timestamp.

CREATE TABLE tokens (
    token_hash BLOB PRIMARY KEY NOT NULL,
    used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
    created_at INTEGER NOT NULL,
    used_at INTEGER
);

-- Partial index speeds up the "find unused token" lookup at submission time.
CREATE INDEX idx_tokens_unused ON tokens(token_hash) WHERE used = 0;

CREATE TABLE questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_questions_created ON questions(created_at DESC);
