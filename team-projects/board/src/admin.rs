//! Admin operations.
//!
//! Token generation writes the raw tokens to disk with mode 0600 so that
//! a co-tenant or service account on the same host cannot read them via
//! the filesystem. The admin's responsibility is then to distribute them
//! and shred the file.

use crate::claim::ClaimCode;
use crate::storage::Storage;
use crate::token::RawToken;
use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate `count` tokens. Stores SHA-256 digests in the DB and writes the
/// raw tokens to `output` (one per line) for distribution.
pub async fn generate_tokens(
    storage: &Storage,
    count: usize,
    output: &Path,
) -> Result<()> {
    if count == 0 {
        bail!("count must be > 0");
    }
    if count > 100_000 {
        bail!("refusing to generate >100k tokens at once");
    }

    let raw_tokens: Vec<RawToken> = (0..count).map(|_| RawToken::generate()).collect();
    let hashes: Vec<_> = raw_tokens.iter().map(|t| t.hash()).collect();

    let inserted = storage.insert_token_hashes(&hashes).await?;
    if inserted != count {
        // Astronomically unlikely with 128-bit tokens, but guard anyway.
        bail!(
            "expected to insert {} tokens but only {} stuck — possible hash collision",
            count,
            inserted
        );
    }

    // Write tokens to a fresh file with restrictive permissions.
    //   * `create_new` refuses to overwrite an existing file (avoid
    //     clobbering a previous distribution by accident).
    //   * mode 0600 — owner read/write only.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(output)
        .with_context(|| format!("creating {}", output.display()))?;

    writeln!(file, "# Q&A board access tokens — {} total", count)?;
    writeln!(file, "# Each line is a single-use token. Distribute one per student.")?;
    writeln!(file, "# Treat this file as sensitive: anyone who reads it can post.")?;
    writeln!(file, "# Shred after distribution: `shred -u {}`", output.display())?;
    writeln!(file)?;
    for t in &raw_tokens {
        writeln!(file, "{}", t.encode())?;
    }
    file.sync_all()?;

    // raw_tokens drop here, zeroizing their bytes.
    drop(raw_tokens);

    eprintln!(
        "Generated {} tokens. Raw values written to {} (mode 0600).",
        count,
        output.display()
    );
    Ok(())
}

pub async fn print_stats(storage: &Storage) -> Result<()> {
    let (unused, used) = storage.token_stats().await?;
    println!("tokens.unused = {}", unused);
    println!("tokens.used   = {}", used);
    println!("tokens.total  = {}", unused + used);
    Ok(())
}

pub async fn delete_question(storage: &Storage, id: i64) -> Result<()> {
    let deleted = storage.delete_question(id).await?;
    if deleted {
        println!("deleted question {}", id);
    } else {
        println!("no such question: {}", id);
    }
    Ok(())
}

/// Create a new claim code.
///
/// If `code_str` is `None`, a random 12-char base32 code is generated.
/// If provided by the admin, it is normalized (uppercase, alphanumeric only).
///
/// Note: passing a code on the command line records it in shell history.
/// For sensitive deployments, prefer auto-generation.
pub async fn create_claim_code(
    storage: &Storage,
    code_str: Option<String>,
    tokens_per_claim: i64,
    max_claims: i64,
    expires_in_secs: Option<u64>,
) -> Result<()> {
    if !(1..=20).contains(&tokens_per_claim) {
        bail!("tokens-per-claim must be in 1..=20");
    }
    if !(1..=1000).contains(&max_claims) {
        bail!("max-claims must be in 1..=1000");
    }

    let claim = match code_str {
        Some(s) => ClaimCode::from_user_input(&s).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid claim code: must be 4..=64 alphanumeric chars \
                 (dashes/underscores allowed as separators)"
            )
        })?,
        None => ClaimCode::generate(),
    };

    let expires_at = expires_in_secs.map(|secs| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (now + secs) as i64
    });

    storage
        .insert_claim_code(&claim.hash(), tokens_per_claim, max_claims, expires_at)
        .await
        .with_context(|| "inserting claim code (does the code already exist?)")?;

    // Print to stdout so the instructor can pipe it / copy it.
    // We use eprintln for narrative output and println for the actual code
    // so `qa-board create-claim --output=- | head -1` gives just the code.
    eprintln!("Claim code created.");
    eprintln!("  tokens per claim: {}", tokens_per_claim);
    eprintln!("  max claims:       {}", max_claims);
    if let Some(exp) = expires_at {
        eprintln!("  expires at:       {} (unix)", exp);
    } else {
        eprintln!("  expires at:       never");
    }
    eprintln!();
    eprintln!("Display this code in class. Students enter it at /claim:");
    eprintln!();
    println!("{}", claim.display());
    Ok(())
}

pub async fn list_claim_codes(storage: &Storage) -> Result<()> {
    let rows = storage.list_claim_codes().await?;
    if rows.is_empty() {
        println!("no claim codes");
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    println!("{:>4} {:>10} {:>11} {:>12}", "TPC", "USED/MAX", "EXPIRES_IN", "STATE");
    for r in rows {
        let state = match r.expires_at {
            _ if r.claims_used >= r.max_claims => "EXHAUSTED",
            Some(exp) if exp <= now => "EXPIRED",
            _ => "active",
        };
        let exp_str = match r.expires_at {
            None => "never".to_string(),
            Some(exp) if exp <= now => "—".to_string(),
            Some(exp) => format!("{}s", exp - now),
        };
        println!(
            "{:>4} {:>10} {:>11} {:>12}",
            r.tokens_per_claim,
            format!("{}/{}", r.claims_used, r.max_claims),
            exp_str,
            state,
        );
    }
    Ok(())
}
