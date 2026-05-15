//! HTTP server.
//!
//! Security choices:
//!
//! 1. **Body size limit** at the tower layer prevents memory-exhaustion DoS.
//! 2. **Question length limit** rejects pathologically long inputs before DB.
//! 3. **CSRF protection**: GET /ask issues a random `csrf` cookie with
//!    `SameSite=Strict; HttpOnly` plus the same value in a hidden form
//!    field. POST /ask requires both and compares them in constant time.
//! 4. **No referrer**: `Referrer-Policy: no-referrer` and a meta tag prevent
//!    leaking the token (if it ever ends up in a URL fragment).
//! 5. **Security headers** on every response: HSTS, X-Content-Type-Options,
//!    X-Frame-Options, restrictive CSP.
//! 6. **Auto-escaping templates** (askama) defang stored XSS in question bodies.
//! 7. **No IP / User-Agent logging**: the tracing setup includes no request
//!    middleware that would log these. Deployment behind a reverse proxy
//!    should similarly anonymize.
//! 8. **Constant-time CSRF comparison** via `subtle::ConstantTimeEq`.
//!
//! Not implemented in code (deployment concerns):
//!   * TLS termination (use a fronting reverse proxy / load balancer).
//!   * Per-IP rate limiting (use the reverse proxy).
//!   * Database file permissions (chmod 0600 the SQLite file).

use crate::claim::ClaimCode;
use crate::storage::{Question, Storage, StorageError};
use crate::token::RawToken;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Form, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;

const MAX_QUESTION_CHARS: usize = 2_000;
const MAX_BODY_BYTES: usize = 16 * 1024;
const CSRF_COOKIE: &str = "qa_csrf";
const CSRF_BYTES: usize = 32;

#[derive(Template)]
#[template(path = "list.html")]
struct ListTemplate {
    questions: Vec<Question>,
}

#[derive(Template)]
#[template(path = "ask.html")]
struct AskTemplate {
    csrf: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "submitted.html")]
struct SubmittedTemplate;

#[derive(Template)]
#[template(path = "claim.html")]
struct ClaimTemplate {
    csrf: String,
    prefill_code: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "claim_success.html")]
struct ClaimSuccessTemplate {
    tokens: Vec<String>, // base32-encoded tokens, one per line
}

#[derive(Deserialize)]
struct AskForm {
    csrf: String,
    token: String,
    content: String,
}

#[derive(Deserialize)]
struct ClaimForm {
    csrf: String,
    code: String,
}

#[derive(Deserialize, Default)]
struct ClaimQuery {
    /// Optional pre-fill from a QR/link the instructor shares.
    code: Option<String>,
}

// We deliberately do NOT derive `Debug` on any *Form struct: their
// fields hold bearer credentials (tokens, claim codes) that must not
// flow into panic messages or logs.

pub async fn run(storage: Storage, addr: &str) -> anyhow::Result<()> {
    let state = Arc::new(storage);

    let app = Router::new()
        .route("/", get(list_handler))
        .route("/ask", get(ask_form_handler).post(ask_submit_handler))
        .route("/claim", get(claim_form_handler).post(claim_submit_handler))
        .route("/health", get(|| async { "ok" }))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Attaches conservative security headers on every response.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    static_header(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    static_header(headers, header::X_FRAME_OPTIONS, "DENY");
    static_header(headers, header::REFERRER_POLICY, "no-referrer");
    // CSP: allow only inline styles (we use a small <style> block) and no
    // scripts. Tightening to no-inline would require external CSS.
    static_header(
        headers,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    // HSTS only makes sense over HTTPS. Harmless over plain HTTP but the
    // browser will simply ignore it. Set this aggressively for production.
    static_header(
        headers,
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000",
    );
    response
}

fn static_header(map: &mut HeaderMap, name: header::HeaderName, value: &'static str) {
    map.insert(name, HeaderValue::from_static(value));
}

async fn list_handler(State(storage): State<Arc<Storage>>) -> Response {
    match storage.list_questions(500).await {
        Ok(questions) => render(ListTemplate { questions }),
        Err(e) => internal_error(e),
    }
}

async fn ask_form_handler(jar: CookieJar) -> impl IntoResponse {
    // Generate a fresh CSRF token, set it as a Strict-SameSite, HttpOnly
    // cookie, and embed the same value in the form.
    let csrf = random_hex(CSRF_BYTES);
    let cookie = csrf_cookie(&csrf);

    let html = AskTemplate { csrf, error: None }
        .render()
        .unwrap_or_default();
    (jar.add(cookie), Html(html)).into_response()
}

async fn ask_submit_handler(
    State(storage): State<Arc<Storage>>,
    jar: CookieJar,
    Form(form): Form<AskForm>,
) -> Response {
    // 1. CSRF check: cookie must exist and equal the form field (constant-time).
    let cookie_csrf = match jar.get(CSRF_COOKIE) {
        Some(c) => c.value().to_owned(),
        None => return render_ask_error("Session expired. Refresh the page and try again."),
    };
    if !ct_eq_str(&cookie_csrf, &form.csrf) {
        return render_ask_error("Session expired. Refresh the page and try again.");
    }

    // 2. Validate content. We use char count (not byte len) so a Korean
    //    user gets the same effective limit as an English user.
    let content = form.content.trim();
    if content.is_empty() {
        return render_ask_error("질문 내용을 입력해 주세요.");
    }
    if content.chars().count() > MAX_QUESTION_CHARS {
        return render_ask_error("질문이 너무 깁니다 (최대 2000자).");
    }

    // 3. Parse the token. We do not distinguish "malformed" from
    //    "invalid" in the user-visible error.
    let raw_token = match RawToken::decode(&form.token) {
        Some(t) => t,
        None => return render_ask_error("Invalid or already-used token."),
    };
    let hash = raw_token.hash();
    drop(raw_token); // explicit zeroize via Drop

    // 4. Atomically redeem and post.
    match storage.submit_question(&hash, content).await {
        Ok(_) => render(SubmittedTemplate),
        Err(StorageError::InvalidToken) => render_ask_error("Invalid or already-used token."),
        Err(e) => {
            tracing::error!(error = %e, "submit_question failed");
            render_ask_error("Internal error. Please try again later.")
        }
    }
}

// -------------------- /claim handlers --------------------

const CLAIMED_COOKIE_PREFIX: &str = "qa_claimed_";

async fn claim_form_handler(
    jar: CookieJar,
    Query(q): Query<ClaimQuery>,
) -> impl IntoResponse {
    let csrf = random_hex(CSRF_BYTES);
    let cookie = csrf_cookie(&csrf);

    // Pre-fill is taken from the URL query string (e.g. from a QR code).
    // We DO NOT trust this as authentication — the user still has to
    // submit and pass CSRF + dedup checks.
    let prefill = q.code.unwrap_or_default();
    // Cap pre-fill length to defang stuffing of giant strings into the form.
    let prefill_code: String = prefill.chars().take(128).collect();

    let html = ClaimTemplate {
        csrf,
        prefill_code,
        error: None,
    }
    .render()
    .unwrap_or_default();
    (jar.add(cookie), Html(html)).into_response()
}

async fn claim_submit_handler(
    State(storage): State<Arc<Storage>>,
    jar: CookieJar,
    Form(form): Form<ClaimForm>,
) -> Response {
    // 1. CSRF check.
    let cookie_csrf = match jar.get(CSRF_COOKIE) {
        Some(c) => c.value().to_owned(),
        None => return render_claim_error("Session expired. Refresh the page and try again."),
    };
    if !ct_eq_str(&cookie_csrf, &form.csrf) {
        return render_claim_error("Session expired. Refresh the page and try again.");
    }

    // 2. Parse the claim code. We don't distinguish "malformed" from
    //    "unknown" in the user-visible error to avoid a probing oracle.
    let code = match ClaimCode::from_user_input(&form.code) {
        Some(c) => c,
        None => return render_claim_error("Invalid, exhausted, or expired claim code."),
    };
    let code_hash = code.hash();

    // 3. Browser dedup: if a cookie indicates this browser already claimed
    //    against this code, refuse. The cookie is bound to the code hash
    //    so multiple codes can coexist in one browser.
    //
    //    This is best-effort: clearing cookies / opening incognito bypasses
    //    it. Anti-greed defense, not anti-attacker.
    let dedup_name = format!("{}{}", CLAIMED_COOKIE_PREFIX, code_hash.short_hex());
    if jar.get(&dedup_name).is_some() {
        return render_claim_error("This browser has already redeemed this claim code.");
    }

    // 4. Atomically redeem and issue tokens.
    let raw_tokens = match storage.redeem_claim(&code_hash).await {
        Ok(ts) => ts,
        Err(StorageError::InvalidClaim) => {
            return render_claim_error("Invalid, exhausted, or expired claim code.");
        }
        Err(e) => {
            tracing::error!(error = %e, "redeem_claim failed");
            return render_claim_error("Internal error. Please try again later.");
        }
    };

    // 5. Encode tokens for one-time display.
    let encoded: Vec<String> = raw_tokens.iter().map(|t| t.encode()).collect();
    // raw_tokens drops here, zeroizing the in-memory bytes. The encoded
    // strings still hold the token characters until the response is sent.
    drop(raw_tokens);

    // 6. Render the success page with strict no-cache headers, and set
    //    the dedup cookie so the next visit to /claim with the same code
    //    fails immediately.
    let html = ClaimSuccessTemplate { tokens: encoded }
        .render()
        .unwrap_or_default();

    let claimed_cookie = Cookie::build((dedup_name, "1"))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .path("/")
        // No `max_age`: a session cookie is sufficient. Students who
        // close the browser between class sessions get a fresh start,
        // which is the right UX for short-lived claim codes.
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    (jar.add(claimed_cookie), headers, Html(html)).into_response()
}

fn render_claim_error(msg: &'static str) -> Response {
    let csrf = random_hex(CSRF_BYTES);
    let cookie = csrf_cookie(&csrf);
    let html = ClaimTemplate {
        csrf,
        prefill_code: String::new(),
        error: Some(msg),
    }
    .render()
    .unwrap_or_default();
    (
        StatusCode::BAD_REQUEST,
        CookieJar::new().add(cookie),
        Html(html),
    )
        .into_response()
}

/// Shared helper for building the CSRF cookie.
fn csrf_cookie(value: &str) -> Cookie<'static> {
    Cookie::build((CSRF_COOKIE, value.to_owned()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .path("/")
        .build()
}

// -------------------- /ask handlers (existing, lightly refactored to share csrf_cookie) --------------------

fn render_ask_error(msg: &'static str) -> Response {
    // Re-issue a CSRF token on the error page so the user can retry.
    let csrf = random_hex(CSRF_BYTES);
    let cookie = csrf_cookie(&csrf);
    let html = AskTemplate {
        csrf,
        error: Some(msg),
    }
    .render()
    .unwrap_or_default();
    (
        StatusCode::BAD_REQUEST,
        CookieJar::new().add(cookie),
        Html(html),
    )
        .into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => internal_error(e),
    }
}

fn internal_error<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
}

/// Constant-time string equality.
fn ct_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    // Differing-length strings can short-circuit; the lengths themselves
    // are not secret.
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Hex-encoded random string. Used for CSRF tokens. Length-explicit rather
/// than fitting all into a base64'd buffer because the URL/cookie space
/// for a 32-byte CSRF nonce is tiny either way.
fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}
