# qa-board

Anonymous classroom Q&A board with one-time access tokens.

The instructor either hands out single-use tokens on paper / via the
`generate` CLI, **or** displays a short *claim code* on a classroom screen
and lets students self-serve N tokens at `/claim`. Each token then lets
the student post exactly one anonymous question. There is no account,
no session, no IP logging, and no link between a student and the
questions they submit.

## Two distribution modes

### A. Pre-printed slips (CLI `generate`)
```
generate ─▶ tokens.txt (hashed in DB, raw on paper)
   ↓
print, cut, hand out at random
   ↓
student types token at /ask
```

### B. Claim code (CLI `create-claim` + web `/claim`)
```
create-claim ─▶ "MATH-2026-A7B2"  (only its hash is stored)
   ↓
displayed on classroom screen
   ↓
student opens /claim, types code, gets N tokens shown once
   ↓
student types one token at /ask
```

Both modes feed the same `tokens` table. `/ask` doesn't care how a token
got there. You can mix the two within one deployment.

## How it works (cryptographic core)

```
Instructor                Server                  Student
-----------               ------                  -------
generate tokens   ──hash──▶  tokens DB
                              (only SHA-256(token)
                               is stored)
print/distribute  ───────────────────────▶  receives slip
                                            with raw token

                          ◀──── POST /ask ──────  enters token
                          UPDATE tokens
                          SET used=1
                          WHERE hash=? AND used=0
                            (atomic redeem)
                          INSERT question
```

Tokens are 128-bit random values rendered as 26 base32 characters
(e.g. `K4P7M9N2QXJZBVW3HFLC5DST8R`). The server only ever stores the
SHA-256 digest, so a database leak does not expose unused tokens.

Claim codes (mode B) are a thin layer on top: they're stored as their
SHA-256 too, have a `max_claims` counter that's incremented atomically
on each successful `/claim`, and each successful claim generates N fresh
tokens whose hashes go into the same `tokens` table. The server never
records *which* tokens went to which claim event — so even an admin
with the full DB cannot tell which question came from which claim.

## Build

Requires Rust 1.85+ (because of edition2024 transitive deps).

```bash
cargo build --release
```

## Use

### Option A — pre-printed slips
```bash
# 1. Generate tokens for the class (writes raw tokens to tokens.txt with mode 0600).
./target/release/qa-board generate --db board.db --count 90 --output tokens.txt

# 2. Print and cut into slips. After distribution:
shred -u tokens.txt   # NB: shred is unreliable on SSDs / journaling FS
                      # consider writing to /dev/shm/tokens.txt instead

# 3. Run the server (behind a TLS reverse proxy in production).
./target/release/qa-board serve --db board.db --bind 127.0.0.1:3000
```

### Option B — claim code (recommended for live class)
```bash
# 1. Run the server.
./target/release/qa-board serve --db board.db --bind 127.0.0.1:3000

# 2. Create a claim code at the start of class. Auto-generated form:
./target/release/qa-board create-claim --db board.db \
    --tokens-per-claim 3 --max-claims 30 --expires-in 4h
# → prints something like  MATH-A7B2-9KQR

# 3. Display the code on the classroom screen.
#    Students go to https://<your-host>/claim, enter the code,
#    receive 3 tokens shown ONCE, and use them at /ask.

# 4. Watch live usage.
./target/release/qa-board list-claims --db board.db
```

### Stats and moderation
```bash
./target/release/qa-board stats --db board.db
./target/release/qa-board delete --db board.db 42   # delete question by id
```

## Security properties

| Property | How |
|---|---|
| 128-bit token entropy | `OsRng` → 16 bytes |
| Tokens cannot be recovered from DB | SHA-256 stored, raw token never persisted |
| Token redemption is atomic | Single SQL UPDATE with `WHERE used = 0` |
| No oracle for "exists vs used" | Both cases return the same error |
| Tokens zeroized in memory after use | `zeroize::ZeroizeOnDrop` on `RawToken` |
| Token never appears in logs / panics | Custom `Debug` redacts; no body logging |
| Stored XSS prevented | askama auto-escaping on all template output |
| CSRF prevented | `SameSite=Strict` cookie + form field, constant-time compare |
| Clickjacking prevented | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| MIME sniffing prevented | `X-Content-Type-Options: nosniff` |
| Referrer leakage prevented | `Referrer-Policy: no-referrer` |
| HSTS preload-ready | `Strict-Transport-Security: max-age=31536000` |
| Body-size DoS prevented | `RequestBodyLimitLayer` at 16 KiB |
| Question length capped | 2000 Unicode scalars |
| SQL injection prevented | sqlx parameter binding throughout |
| Tokens / DB readable only by owner | `chmod 0600` on file creation |
| Time-correlation leakage limited | `created_at` stored but never displayed |
| Question ↔ token correlation prevented | Tables share no foreign key |
| **Claim code stored only as hash** | SHA-256 of normalized form |
| **Claim race-free under max_claims** | Atomic UPDATE with `WHERE claims_used < max_claims` |
| **Claim-to-token mapping never recorded** | Tokens issued under a claim are indistinguishable from any other token |
| **Same-browser re-claim blocked** | Per-claim `qa_claimed_<hash>` cookie |
| **Claim success page is non-cacheable** | `Cache-Control: no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` |
| **Claim error messages are generic** | Unknown / exhausted / expired → same string |

## Threat model and limits

**In scope** — the instructor wants to enable honest questions and limit
spam, without learning which student wrote which question. Students are
not adversarial cryptographers but may try the basics (token reuse,
fake tokens, XSS, oversized bodies, claim-code brute force).

**Out of scope:**
- A *malicious server operator* who modifies the binary can deanonymize
  by logging incoming POST bodies. The instructor's discipline is part
  of the trust model.
- A *malicious network observer* with no TLS in between can see questions
  in transit. Always deploy behind HTTPS.
- *Token sharing* — a student who gives their token to a friend transfers
  posting capability. No cryptographic defense; treat tokens like physical
  tickets.
- *Style attribution* — analyzing question prose can sometimes identify a
  writer. Out of band for this system.
- *Claim-code hoarding* — `qa_claimed_*` cookies are best-effort. A student
  who opens incognito or clears cookies can claim more than once.
  Defense-in-depth: keep `max_claims` close to the actual class size and
  let the cap catch egregious cases.
- *Claim-code brute-force over the wire* — for short codes, rate-limit
  `/claim` at the reverse proxy (e.g. nginx `limit_req zone=claim`).

## Deployment checklist

1. Run behind a TLS reverse proxy (nginx, Caddy, traefik). Bind on
   `127.0.0.1` so only the proxy can reach the app.
2. Configure the proxy to **strip / refuse to log** `X-Forwarded-For`,
   `User-Agent`, and `Referer` for `/ask` POSTs.
3. Set a per-IP rate limit on the proxy (e.g. 20 req/min) to slow down
   anyone who tries to brute-force the token namespace (futile against
   128 bits but cheap to add).
4. Set the SQLite database file's parent directory to mode 0700.
5. After the class ends, archive `board.db` somewhere safe and delete the
   live file. Question content remains in plaintext in the DB.
6. Run `shred -u tokens.txt` immediately after distributing slips.

## File layout

```
qa-board/
├── Cargo.toml
├── migrations/
│   ├── 0001_init.sql
│   └── 0002_claim_codes.sql
├── src/
│   ├── main.rs       # CLI entry + clap subcommands
│   ├── token.rs      # RawToken / TokenHash + tests
│   ├── claim.rs      # ClaimCode / ClaimCodeHash + tests
│   ├── storage.rs    # SQLite operations, atomic redeem (tokens + claims)
│   ├── admin.rs      # Token generation, claim creation, moderation
│   └── server.rs     # axum routes, CSRF, security headers
└── templates/
    ├── list.html
    ├── ask.html
    ├── submitted.html
    ├── claim.html
    └── claim_success.html
```

## Tests

```bash
cargo test                  # 15 unit tests (token + claim)
bash tests/e2e.sh           # 42 end-to-end tests across both flows
```
