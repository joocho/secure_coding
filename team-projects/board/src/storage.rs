//! Persistence layer.
//!
//! Security-relevant properties enforced here:
//!
//! 1. **Atomic redeem**: `submit_question` consumes a token and inserts a
//!    question in a single transaction. The token UPDATE has both
//!    `token_hash = ?` AND `used = 0` in its WHERE clause; if the UPDATE
//!    affects 0 rows, the token is unknown or already used and we fail.
//!    This collapses two error cases into one to avoid leaking which.
//!
//! 2. **No PII**: We do not store IPs, user-agents, browser fingerprints,
//!    or any per-token metadata. Tokens and questions live in separate
//!    tables with no foreign-key linkage.
//!
//! 3. **Prepared statements**: All queries use sqlx parameter binding,
//!    eliminating SQL injection.
//!
//! 4. **Generic errors**: We return `StorageError::InvalidToken` for
//!    both "doesn't exist" and "already used" cases.

use crate::claim::ClaimCodeHash;
use crate::token::{RawToken, TokenHash};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Token is unknown OR was already used. The two cases are deliberately
    /// merged to deny an attacker an oracle for token existence.
    #[error("invalid or already-used token")]
    InvalidToken,

    /// Claim code is unknown, exhausted, or expired. Merged to avoid leaking
    /// which condition applies.
    #[error("invalid, exhausted, or expired claim code")]
    InvalidClaim,

    #[error("database error")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct ClaimCodeInfo {
    #[allow(dead_code)]
    pub tokens_per_claim: i64,
    pub max_claims: i64,
    pub claims_used: i64,
    #[allow(dead_code)]
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug)]
pub struct Question {
    pub id: i64,
    pub content: String,
    // Deliberately fetched but not displayed publicly: showing exact
    // timestamps would let an observer correlate post times with
    // student behavior. Kept for moderation / future admin views.
    #[allow(dead_code)]
    pub created_at: i64,
}

impl Storage {
    /// Open or create the SQLite database at `path` and run migrations.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        // `create_if_missing(true)` lets the admin bootstrap a fresh DB
        // by simply running `generate`. WAL mode is enabled for better
        // concurrent reads.
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        // Restrict the DB (and its WAL/SHM siblings) to owner-only access.
        // Question content lives here in plaintext, and a leak should not
        // be casually readable by other local accounts.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let p = path.with_extension(format!(
                    "{}{}",
                    path.extension().and_then(|s| s.to_str()).unwrap_or(""),
                    suffix
                ));
                if p.exists() {
                    let _ = std::fs::set_permissions(
                        &p,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
            }
            // Also handle the plain path itself, regardless of extension.
            if path.exists() {
                let _ = std::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
        }

        Ok(Self { pool })
    }

    /// Insert hashed tokens. Idempotent on `token_hash` thanks to `INSERT OR IGNORE`.
    /// Returns the number of rows actually inserted (excluding any duplicates).
    pub async fn insert_token_hashes(
        &self,
        hashes: &[TokenHash],
    ) -> anyhow::Result<usize> {
        let now = unix_now();
        let mut tx = self.pool.begin().await?;
        let mut inserted = 0usize;
        for hash in hashes {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO tokens (token_hash, used, created_at) VALUES (?, 0, ?)",
            )
            .bind(hash.as_bytes())
            .bind(now)
            .execute(&mut *tx)
            .await?;
            inserted += result.rows_affected() as usize;
        }
        tx.commit().await?;
        Ok(inserted)
    }

    /// Atomically redeem a token and insert a question.
    ///
    /// Returns `Ok(question_id)` on success.
    /// Returns `Err(InvalidToken)` if the token is unknown OR already used.
    pub async fn submit_question(
        &self,
        token_hash: &TokenHash,
        content: &str,
    ) -> Result<i64, StorageError> {
        let now = unix_now();
        let mut tx = self.pool.begin().await?;

        // Conditional UPDATE: only proceeds if the row exists AND used=0.
        // SQLite makes this single-statement update atomic. The outer
        // transaction additionally guarantees that the inserted question
        // either both commits with the token consumption or neither does.
        let upd = sqlx::query(
            "UPDATE tokens SET used = 1, used_at = ? WHERE token_hash = ? AND used = 0",
        )
        .bind(now)
        .bind(token_hash.as_bytes())
        .execute(&mut *tx)
        .await?;

        if upd.rows_affected() == 0 {
            // Roll back the (empty) transaction. We do NOT log the hash
            // here — repeated invalid attempts could otherwise reveal the
            // hash of a token someone is trying to brute-force.
            tx.rollback().await?;
            return Err(StorageError::InvalidToken);
        }

        let row = sqlx::query(
            "INSERT INTO questions (content, created_at) VALUES (?, ?) RETURNING id",
        )
        .bind(content)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        let id: i64 = row.get(0);

        tx.commit().await?;
        Ok(id)
    }

    /// List the most-recent `limit` questions.
    pub async fn list_questions(&self, limit: i64) -> anyhow::Result<Vec<Question>> {
        let rows = sqlx::query(
            "SELECT id, content, created_at FROM questions ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| Question {
                id: row.get(0),
                content: row.get(1),
                created_at: row.get(2),
            })
            .collect())
    }

    pub async fn delete_question(&self, id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM questions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn token_stats(&self) -> anyhow::Result<(i64, i64)> {
        let row = sqlx::query(
            "SELECT
                SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) AS unused,
                SUM(CASE WHEN used = 1 THEN 1 ELSE 0 END) AS used
             FROM tokens",
        )
        .fetch_one(&self.pool)
        .await?;
        let unused: Option<i64> = row.get(0);
        let used: Option<i64> = row.get(1);
        Ok((unused.unwrap_or(0), used.unwrap_or(0)))
    }

    // -------------------- claim codes --------------------

    /// Insert a new claim code. Errors if a code with the same hash exists.
    pub async fn insert_claim_code(
        &self,
        code_hash: &ClaimCodeHash,
        tokens_per_claim: i64,
        max_claims: i64,
        expires_at: Option<i64>,
    ) -> anyhow::Result<()> {
        let now = unix_now();
        sqlx::query(
            "INSERT INTO claim_codes
                (code_hash, tokens_per_claim, max_claims, claims_used, created_at, expires_at)
             VALUES (?, ?, ?, 0, ?, ?)",
        )
        .bind(code_hash.as_bytes())
        .bind(tokens_per_claim)
        .bind(max_claims)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically redeem one claim slot and issue fresh tokens.
    ///
    /// Returns the raw tokens. Their SHA-256 hashes are persisted in the
    /// `tokens` table; the raw values are returned to the caller and
    /// MUST NOT be otherwise persisted by the server.
    ///
    /// Error semantics: returns `InvalidClaim` for *any* of:
    ///   - code unknown
    ///   - code exhausted (claims_used >= max_claims)
    ///   - code expired (expires_at <= now)
    /// merged to avoid leaking which condition applies.
    pub async fn redeem_claim(
        &self,
        code_hash: &ClaimCodeHash,
    ) -> Result<Vec<RawToken>, StorageError> {
        let now = unix_now();
        let mut tx = self.pool.begin().await?;

        // Atomically increment claims_used. SQLite serializes writes, so
        // the WHERE clause + the +1 update is race-free. If the row is
        // already at max_claims, expired, or absent, rows_affected = 0.
        let upd = sqlx::query(
            "UPDATE claim_codes
             SET claims_used = claims_used + 1
             WHERE code_hash = ?
               AND claims_used < max_claims
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(code_hash.as_bytes())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        if upd.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(StorageError::InvalidClaim);
        }

        // Read how many tokens to issue for this code.
        let tpc: i64 = sqlx::query_scalar(
            "SELECT tokens_per_claim FROM claim_codes WHERE code_hash = ?",
        )
        .bind(code_hash.as_bytes())
        .fetch_one(&mut *tx)
        .await?;

        // Generate fresh tokens and persist their hashes. If by astronomical
        // accident a hash already exists, the PK constraint aborts and the
        // entire transaction (including the claim counter increment) rolls
        // back — this is the safe direction.
        let raw_tokens: Vec<RawToken> =
            (0..tpc).map(|_| RawToken::generate()).collect();
        for t in &raw_tokens {
            let h: TokenHash = t.hash();
            sqlx::query(
                "INSERT INTO tokens (token_hash, used, created_at) VALUES (?, 0, ?)",
            )
            .bind(h.as_bytes())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(raw_tokens)
    }

    /// Read claim-code metadata WITHOUT incrementing the counter.
    /// Used by the admin `list-claims` command.
    pub async fn list_claim_codes(&self) -> anyhow::Result<Vec<ClaimCodeInfo>> {
        let rows = sqlx::query(
            "SELECT tokens_per_claim, max_claims, claims_used, created_at, expires_at
             FROM claim_codes
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| ClaimCodeInfo {
                tokens_per_claim: row.get(0),
                max_claims: row.get(1),
                claims_used: row.get(2),
                created_at: row.get(3),
                expires_at: row.get(4),
            })
            .collect())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
