//! Anonymous classroom Q&A board.
//!
//! Subcommands:
//!   generate   create tokens for distribution
//!   serve      run the web server
//!   stats      report token usage
//!   delete     remove a question by id (moderation)

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod admin;
mod claim;
mod server;
mod storage;
mod token;

#[derive(Parser)]
#[command(
    name = "qa-board",
    about = "Anonymous classroom Q&A board with one-time tokens",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate single-use tokens and write them to a file for distribution.
    Generate {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
        /// How many tokens to generate (e.g. students * tokens_per_student).
        #[arg(long)]
        count: usize,
        /// Output file (will refuse to overwrite an existing file).
        #[arg(long)]
        output: PathBuf,
    },
    /// Run the web server.
    Serve {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
        /// Bind address. Keep on 127.0.0.1 and put a TLS reverse proxy in front.
        #[arg(long, default_value = "127.0.0.1:3000")]
        bind: String,
    },
    /// Show token usage statistics.
    Stats {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
    },
    /// Delete a question by id (moderation).
    Delete {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
        id: i64,
    },
    /// Create a claim code (for screen-based distribution during class).
    ///
    /// Students go to /claim, enter the code, and receive
    /// `tokens_per_claim` fresh tokens. Up to `max_claims` total students
    /// can use the same code.
    CreateClaim {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
        /// Optional custom code (e.g. "MATH2026-A7"). If omitted, a random
        /// code is generated. WARNING: passing --code records the code in
        /// shell history. Prefer auto-generation.
        #[arg(long)]
        code: Option<String>,
        /// Tokens issued per successful claim.
        #[arg(long, default_value_t = 3)]
        tokens_per_claim: i64,
        /// Maximum number of times this code can be claimed in total.
        #[arg(long, default_value_t = 50)]
        max_claims: i64,
        /// Expiry as a human duration: e.g. `4h`, `90m`, `1d`, `3600s`.
        #[arg(long, value_parser = parse_duration_secs)]
        expires_in: Option<u64>,
    },
    /// List all claim codes with their usage and state.
    ListClaims {
        #[arg(long, default_value = "board.db")]
        db: PathBuf,
    },
}

fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let split = s
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    let (n_part, unit) = s.split_at(split);
    let n: u64 = n_part
        .parse()
        .map_err(|_| format!("invalid number: {:?}", n_part))?;
    let mul: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        other => {
            return Err(format!(
                "unknown unit {:?}: use s, m, h, or d",
                other
            ))
        }
    };
    n.checked_mul(mul).ok_or_else(|| "duration overflow".into())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Conservative logging: no request body / header capture. We rely on
    // explicit `tracing::error!` calls in handlers for visibility.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qa_board=info,axum=warn,sqlx=warn".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Generate { db, count, output } => {
            let storage = storage::Storage::open(&db).await?;
            admin::generate_tokens(&storage, count, &output).await?;
        }
        Command::Serve { db, bind } => {
            let storage = storage::Storage::open(&db).await?;
            server::run(storage, &bind).await?;
        }
        Command::Stats { db } => {
            let storage = storage::Storage::open(&db).await?;
            admin::print_stats(&storage).await?;
        }
        Command::Delete { db, id } => {
            let storage = storage::Storage::open(&db).await?;
            admin::delete_question(&storage, id).await?;
        }
        Command::CreateClaim {
            db,
            code,
            tokens_per_claim,
            max_claims,
            expires_in,
        } => {
            let storage = storage::Storage::open(&db).await?;
            admin::create_claim_code(
                &storage,
                code,
                tokens_per_claim,
                max_claims,
                expires_in,
            )
            .await?;
        }
        Command::ListClaims { db } => {
            let storage = storage::Storage::open(&db).await?;
            admin::list_claim_codes(&storage).await?;
        }
    }
    Ok(())
}
