//! lib.rs — Streaming Worker (workers-rs 0.8.7)
//!
//! دو بخش اصلی:
//!   1. SlidingWindowRateLimiter — Durable Object با SQLite
//!   2. main Worker handler — routing + HMAC verify + stream pipe
//!
//! ── یادداشت مهاجرت به worker 0.8.7 ──────────────────────────────
//! تغییرات API نسبت به 0.5 که در این فایل اعمال شده‌اند:
//!   • `#[durable_object]` فقط روی **struct** می‌آید، نه روی impl block
//!     (در 0.8.7 گذاشتن آن روی impl یک خطای کامپایل صریح است).
//!   • امضای trait: `async fn fetch(&self, req: Request)` (قبلاً `&mut self`).
//!   • SQLite: `sql.exec(query, bindings)` جای `exec()`/`exec_with()` را گرفته و
//!     bindings از نوع `Vec<SqlStorageValue>` است (نه `&[JsValue]`).
//!   • نتایج کوئری با `SqlCursor::to_array::<T>()` دیکد می‌شوند (typed).

use serde::{Deserialize, Serialize};
use worker::*;

// ══════════════════════════════════════════════════════════════
//  Durable Object: SlidingWindowRateLimiter
//  الهام گرفته از Valkey/Redis Sliding Window با INCR + EXPIRE
//  تفاوت کلیدی:
//    — KV: Eventually Consistent → می‌تواند از limit عبور کند
//    — Durable Object + SQLite: Strongly Consistent + Atomic
//    — هر IP یک instance مستقل دارد (sharding خودکار)
// ══════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct RateLimitResponse {
    allowed: bool,
    remaining: i64,
    limit: i64,
    window_ms: i64,
    retry_after_ms: Option<i64>,
}

/// ردیف نتیجهٔ `SELECT COUNT(*) AS cnt`
#[derive(Deserialize)]
struct CountRow {
    cnt: i64,
}

/// ردیف نتیجهٔ `SELECT MIN(ts) AS oldest`
#[derive(Deserialize)]
struct OldestRow {
    oldest: Option<i64>,
}

// در workers-rs 0.8.7 این attribute فقط روی struct قرار می‌گیرد.
// قرار دادن آن روی `impl DurableObject for ...` خطای کامپایل می‌دهد:
// "The #[durable_object] macro is no longer required for `impl` blocks"
#[durable_object]
pub struct SlidingWindowRateLimiter {
    state: State,
    _env: Env,
}

impl DurableObject for SlidingWindowRateLimiter {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    // 0.8.7: `&self` (نه `&mut self`)
    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let limit: i64 = params
            .get("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);

        let window_ms: i64 = params
            .get("window_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60_000);

        // ── SQLite در Durable Object ───────────────────────────
        // هر Durable Object instance یک SQLite database مستقل دارد
        let sql = self.state.storage().sql();

        // جدول یک بار ساخته می‌شود — idempotent
        // 0.8.7: exec(query, bindings) — پارامتر دوم اجباری است (None = بدون binding)
        sql.exec(
            "CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL
            )",
            None,
        )?;

        // Timestamp فعلی — UTC milliseconds
        let now_ms = Date::now().as_millis() as i64;
        let cutoff = now_ms - window_ms;

        // ── Atomic Sliding Window ──────────────────────────────
        // هیچ race condition امکان‌پذیر نیست چون Durable Object single-threaded است

        // ۱. پاکسازی hits قدیمی خارج از window
        sql.exec(
            "DELETE FROM hits WHERE ts < ?1",
            vec![SqlStorageValue::Integer(cutoff)],
        )?;

        // ۲. شمارش hits فعال در window فعلی
        let count: i64 = sql
            .exec("SELECT COUNT(*) as cnt FROM hits", None)?
            .to_array::<CountRow>()
            .ok()
            .and_then(|rows| rows.first().map(|r| r.cnt))
            .unwrap_or(0);

        if count >= limit {
            // Rate limit exceeded
            // محاسبه زمان باقی‌مانده تا پاکسازی قدیمی‌ترین hit
            let oldest_ts: i64 = sql
                .exec("SELECT MIN(ts) as oldest FROM hits", None)?
                .to_array::<OldestRow>()
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.oldest))
                .unwrap_or(now_ms - window_ms);

            let retry_after_ms = (oldest_ts + window_ms) - now_ms;
            let retry_after_ms = retry_after_ms.max(1000); // حداقل ۱ ثانیه

            let resp_body = serde_json::to_string(&RateLimitResponse {
                allowed: false,
                remaining: 0,
                limit,
                window_ms,
                retry_after_ms: Some(retry_after_ms),
            })
            .unwrap_or_default();

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("X-RateLimit-Limit", &limit.to_string())?;
            headers.set("X-RateLimit-Remaining", "0")?;
            headers.set("Retry-After", &(retry_after_ms / 1000).to_string())?;

            return Response::error(resp_body, 429).map(|r| r.with_headers(headers));
        }

        // ۳. ثبت hit جدید
        sql.exec(
            "INSERT INTO hits (ts) VALUES (?1)",
            vec![SqlStorageValue::Integer(now_ms)],
        )?;

        let remaining = limit - count - 1;

        let resp_body = serde_json::to_string(&RateLimitResponse {
            allowed: true,
            remaining,
            limit,
            window_ms,
            retry_after_ms: None,
        })
        .unwrap_or_default();

        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        headers.set("X-RateLimit-Limit", &limit.to_string())?;
        headers.set("X-RateLimit-Remaining", &remaining.to_string())?;

        Response::ok(resp_body).map(|r| r.with_headers(headers))
    }
}

// ══════════════════════════════════════════════════════════════
//  Main Worker Handler
// ══════════════════════════════════════════════════════════════

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();
    router
        .get_async("/stream", handle_stream)
        .get("/health", |_req, ctx| {
            let version = ctx
                .var("WORKER_VERSION")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            Response::ok(format!(
                r#"{{"status":"ok","worker":"ghost-streaming","version":"{}","runtime":"rust"}}"#,
                version
            ))
        })
        .run(req, env)
        .await
}

async fn handle_stream(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // ── ۱. استخراج IP client ────────────────────────────────
    let client_ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".to_string());

    // ── ۲. بررسی Rate Limit از Durable Object ───────────────
    // یک instance به‌ازای هر IP = Sharding خودکار بر اساس IP
    let rate_limit = ctx
        .var("RATE_LIMIT_RPM")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "500".to_string());
    let window_ms = ctx
        .var("RATE_WINDOW_MS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "60000".to_string());

    let limiter_namespace = ctx.durable_object("RATE_LIMITER")?;
    let limiter_id = limiter_namespace.id_from_name(&format!("stream:{}", client_ip))?;
    let limiter_stub = limiter_id.get_stub()?;

    let check_url = format!(
        "http://internal/check?limit={}&window_ms={}",
        rate_limit, window_ms
    );
    let limit_req = Request::new(&check_url, Method::Get)?;
    let limit_resp = limiter_stub.fetch_with_request(limit_req).await?;

    if limit_resp.status_code() == 429 {
        // Rate limit — headers را از DO منتقل می‌کنیم
        return Ok(limit_resp);
    }

    // ── ۳. خواندن و validate کردن query params ──────────────
    let url = req.url()?;
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let target_url = params
        .get("target")
        .ok_or_else(|| Error::RustError("Missing 'target' query parameter".into()))?
        .clone();

    let sig = params
        .get("sig")
        .ok_or_else(|| Error::RustError("Missing 'sig' query parameter".into()))?
        .clone();

    let seq = params
        .get("seq")
        .ok_or_else(|| Error::RustError("Missing 'seq' query parameter".into()))?
        .clone();

    // ── ۴. HMAC Verification ────────────────────────────────
    let secret = ctx.secret("HMAC_SECRET")?.to_string();
    let message = format!("{}:{}", target_url, seq);

    if !verify_hmac_signature(&message, &sig, &secret) {
        return Response::error("Forbidden: Invalid HMAC signature", 403);
    }

    // ── ۵. اعتبارسنجی URL مقصد — جلوگیری از SSRF ────────────
    if !is_allowed_target(&target_url) {
        return Response::error("Forbidden: Target URL not allowed", 403);
    }

    // ── ۶. Streaming Pipe — صفر بایت Buffer در Worker ────────
    let mut init = RequestInit::new();
    init.with_method(Method::Get);

    // انتقال Range header برای DASH segment support
    let mut upstream_headers = Headers::new();
    if let Ok(Some(range)) = req.headers().get("Range") {
        upstream_headers.set("Range", &range)?;
    }
    upstream_headers.set("User-Agent", "Mozilla/5.0 (compatible; GhostProxy/5.0)")?;
    init.with_headers(upstream_headers);

    let upstream_req = Request::new_with_init(&target_url, &init)?;
    let upstream_resp = Fetch::Request(upstream_req).send().await?;

    let upstream_headers_ref = upstream_resp.headers();

    // ساخت response headers
    let mut resp_headers = Headers::new();
    resp_headers.set("Access-Control-Allow-Origin", "*")?;
    resp_headers.set("X-Ghost-Worker", "streaming")?;

    // انتقال Content-Type از upstream
    if let Ok(Some(ct)) = upstream_headers_ref.get("Content-Type") {
        resp_headers.set("Content-Type", &ct)?;
    }
    // انتقال Content-Range برای DASH
    if let Ok(Some(cr)) = upstream_headers_ref.get("Content-Range") {
        resp_headers.set("Content-Range", &cr)?;
    }

    // بازگرداندن ReadableStream بدون buffer کردن
    Ok(upstream_resp.with_headers(resp_headers))
}

/// HMAC-SHA256 Verification — constant-time برای جلوگیری از timing attack
fn verify_hmac_signature(message: &str, provided_sig: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(message.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    if expected.len() != provided_sig.len() {
        return false;
    }
    expected
        .bytes()
        .zip(provided_sig.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Allowlist برای target URL — جلوگیری از SSRF
fn is_allowed_target(url: &str) -> bool {
    // فقط googlevideo.com و YouTube CDN مجاز
    let allowed_hosts = [
        "googlevideo.com",
        "youtube.com",
        "ytimg.com",
        "ggpht.com",
        "googleapis.com",
    ];

    // URL باید با https شروع شود
    if !url.starts_with("https://") {
        return false;
    }

    let url_lower = url.to_lowercase();
    allowed_hosts
        .iter()
        .any(|host| url_lower.contains(host))
}
