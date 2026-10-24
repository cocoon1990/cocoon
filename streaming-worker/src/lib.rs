//! lib.rs — Streaming Worker (workers-rs 0.8.7)
//!
//! Endpoints:
//!   GET /stream  → HMAC-verified streaming pipe (allowlist مقصد)
//!   GET /sub     → اشتراک VLESS به صورت Base64 (fail-closed)
//!   GET /health  → وضعیت worker
//!
//! دو بخش اصلی:
//!   1. SlidingWindowRateLimiter — Durable Object با SQLite
//!   2. main Worker handler — routing + HMAC verify + stream pipe
//!
//! ── نکتهٔ امنیتی مهم دربارهٔ /sub ────────────────────────────────
//! این worker خودش یک سرور VLESS **نیست**. `/sub` فقط یک لینک
//! استاندارد می‌سازد که به یک سرور VLESS واقعی (Xray/sing-box)
//! اشاره می‌کند؛ مقصد از `VLESS_HOST` خوانده می‌شود و هرگز به
//! خودِ این worker برنمی‌گردد. اگر پارامترها تنظیم نشده باشند،
//! endpoint عمداً 503 می‌دهد تا کلاینتی لینک مرده نگیرد.
//!
//! ── یادداشت مهاجرت به worker 0.8.7 ──────────────────────────────
//! تغییرات API نسبت به 0.5 که در این فایل اعمال شده‌اند:
//!   • `#[durable_object]` فقط روی **struct** می‌آید، نه روی impl block
//!     (در 0.8.7 گذاشتن آن روی impl یک خطای کامپایل صریح است).
//!   • امضای trait: `async fn fetch(&self, req: Request)` (قبلاً `&mut self`).
//!   • SQLite: `sql.exec(query, bindings)` جای `exec()`/`exec_with()` را گرفته و
//!     bindings از نوع `Vec<SqlStorageValue>` است (نه `&[JsValue]`).
//!   • نتایج کوئری با `SqlCursor::to_array::<T>()` دیکد می‌شوند (typed).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
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

        // ایندکس روی ts — بدون آن، هر DELETE/COUNT/MIN یک full scan است.
        // هزینه‌اش یک‌بار در هر instance است و هر درخواست بعدی را ارزان می‌کند.
        sql.exec("CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)", None)?;

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

// ══════════════════════════════════════════════════════════════
//  CORS — باید روی *همهٔ* پاسخ‌های /stream باشد
//
//  چرا این حیاتی است: Service Worker صفحه را روی origin دیگری
//  (github.io) اجرا می‌کند و درخواست به workers.dev یک درخواست
//  cross-origin است. اگر پاسخ هدر ACAO نداشته باشد، مرورگر بدنه و
//  status را به SW نمی‌دهد و fetch با TypeError: Failed to fetch
//  reject می‌شود — دقیقاً همان خطای «خطای شبکه/CORS».
//
//  قبلاً فقط مسیر موفق ACAO داشت؛ پس هر 400/403/429 به‌صورت خطای
//  شبکه‌ای مبهم دیده می‌شد و علت واقعی هرگز به UI نمی‌رسید.
// ══════════════════════════════════════════════════════════════

const CORS_EXPOSE: &str =
    "X-Ghost-Worker, X-Ghost-Sub, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining";

/// افزودن هدرهای CORS به یک پاسخ موجود (بدون دست‌زدن به بدنه)
fn with_cors(res: Response) -> Response {
    let headers = res.headers_mut();
    let _ = headers.set("Access-Control-Allow-Origin", "*");
    let _ = headers.set("Vary", "Origin");
    let _ = headers.set("Access-Control-Expose-Headers", CORS_EXPOSE);
    res
}

/// پاسخ خطای متنی + CORS — تا SW هرگز «Failed to fetch» نبیند
fn cors_error(message: &str, status: u16) -> Result<Response> {
    Ok(with_cors(Response::error(message, status)?))
}

/// preflight برای OPTIONS (Router خودش 405 می‌دهد، پس قبل از آن پاسخ می‌دهیم)
fn cors_preflight() -> Result<Response> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Vary", "Origin")?;
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Range, Content-Type, Authorization")?;
    headers.set("Access-Control-Expose-Headers", CORS_EXPOSE)?;
    headers.set("Access-Control-Max-Age", "86400")?;
    Ok(Response::empty()?.with_headers(headers).with_status(204))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // preflight سراسری — قبل از Router
    if req.method() == Method::Options {
        return cors_preflight();
    }

    let router = Router::new();
    router
        .get_async("/stream", handle_stream)
        .get_async("/sub", handle_subscription)
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

/// بررسی rate limit. خروجی `Some(resp)` فقط وقتی است که محدود شده‌ایم (429).
/// هر خطای زیرساختی → `None` (fail-open) با لاگ، نه 500 بدون CORS.
async fn check_rate_limit(ctx: &RouteContext<()>, client_ip: &str) -> Option<Response> {
    let rate_limit = ctx
        .var("RATE_LIMIT_RPM")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "500".to_string());
    let window_ms = ctx
        .var("RATE_WINDOW_MS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "60000".to_string());

    let namespace = match ctx.durable_object("RATE_LIMITER") {
        Ok(namespace) => namespace,
        Err(err) => {
            console_log!("[Ghost Streaming] RATE_LIMITER unavailable (fail-open): {:?}", err);
            return None;
        }
    };

    let id = match namespace.id_from_name(&format!("stream:{}", client_ip)) {
        Ok(id) => id,
        Err(err) => {
            console_log!("[Ghost Streaming] limiter id failed (fail-open): {:?}", err);
            return None;
        }
    };

    let stub = match id.get_stub() {
        Ok(stub) => stub,
        Err(err) => {
            console_log!("[Ghost Streaming] limiter stub failed (fail-open): {:?}", err);
            return None;
        }
    };

    let check_url = format!(
        "http://internal/check?limit={}&window_ms={}",
        rate_limit, window_ms
    );
    let request = match Request::new(&check_url, Method::Get) {
        Ok(request) => request,
        Err(err) => {
            console_log!("[Ghost Streaming] limiter request failed (fail-open): {:?}", err);
            return None;
        }
    };

    match stub.fetch_with_request(request).await {
        Ok(resp) if resp.status_code() == 429 => Some(resp),
        Ok(_) => None,
        Err(err) => {
            console_log!("[Ghost Streaming] limiter fetch failed (fail-open): {:?}", err);
            None
        }
    }
}

async fn handle_stream(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // ── ۱. استخراج IP client ────────────────────────────────
    let client_ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".to_string());

    // ── ۲. بررسی Rate Limit از Durable Object ───────────────
    // خطای DO نباید کل streaming را از کار بیندازد (fail-open) ولی
    // نباید بی‌صدا هم باشد. گیت HMAC همچنان پابرجاست.
    if let Some(resp) = check_rate_limit(&ctx, &client_ip).await {
        // 429 — هدرهای DO حفظ می‌شوند و CORS هم اضافه می‌شود
        return Ok(with_cors(resp));
    }

    // ── ۳. خواندن و validate کردن query params ──────────────
    let url = match req.url() {
        Ok(url) => url,
        Err(_) => return cors_error("Bad Request: malformed request URL", 400),
    };
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // پارامترهای ناقص باید 400 بدهند، نه 500.
    // (قبلاً Error::RustError برمی‌گشت و کلاینتی که query را اشتباه می‌ساخت
    //  پیام «internal error» می‌گرفت — دیباگ را غیرممکن می‌کرد.)
    let target_url = params.get("target").cloned();
    let sig = params.get("sig").cloned();
    let seq = params.get("seq").cloned();

    let (Some(target_url), Some(sig), Some(seq)) = (target_url, sig, seq) else {
        return cors_error(
            "Bad Request: 'target', 'sig' and 'seq' query parameters are required",
            400,
        );
    };

    // اعتبارسنجی شکل ورودی قبل از هر کار رمزنگاری
    if seq.parse::<u64>().is_err() {
        return cors_error("Bad Request: 'seq' must be an unsigned integer", 400);
    }
    if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return cors_error(
            "Bad Request: 'sig' must be a 64-character hex HMAC-SHA256 digest",
            400,
        );
    }

    // ── ۴. HMAC Verification ────────────────────────────────
    let secret = match ctx.secret("HMAC_SECRET") {
        Ok(secret) => secret.to_string(),
        Err(_) => {
            console_log!("[Ghost Streaming] HMAC_SECRET is not configured");
            return cors_error("Server Error: HMAC_SECRET is not configured", 500);
        }
    };
    let message = format!("{}:{}", target_url, seq);

    if !verify_hmac_signature(&message, &sig, &secret) {
        return cors_error("Forbidden: Invalid HMAC signature", 403);
    }

    // ── ۵. اعتبارسنجی URL مقصد — جلوگیری از SSRF ────────────
    if !is_allowed_target(&target_url) {
        return cors_error(
            "Forbidden: Target URL not allowed. /stream only proxies allowlisted hosts (YouTube/Google CDN).",
            403,
        );
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

    let upstream_req = match Request::new_with_init(&target_url, &init) {
        Ok(request) => request,
        Err(err) => {
            console_log!("[Ghost Streaming] upstream request build failed: {:?}", err);
            return cors_error("Bad Gateway: upstream request could not be constructed", 502);
        }
    };
    let upstream_resp = match Fetch::Request(upstream_req).send().await {
        Ok(response) => response,
        Err(err) => {
            console_log!("[Ghost Streaming] upstream fetch failed: {:?}", err);
            return cors_error("Bad Gateway: upstream fetch failed", 502);
        }
    };

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
    // Content-Encoding/Content-Length هم باید منتقل شوند، وگرنه بدنهٔ
    // gzip بدون هدر می‌رسد و کلاینت آن را خراب می‌بیند.
    if let Ok(Some(ce)) = upstream_headers_ref.get("Content-Encoding") {
        resp_headers.set("Content-Encoding", &ce)?;
    }
    if let Ok(Some(cl)) = upstream_headers_ref.get("Content-Length") {
        resp_headers.set("Content-Length", &cl)?;
    }

    // بازگرداندن ReadableStream بدون buffer کردن (+ CORS)
    Ok(with_cors(upstream_resp.with_headers(resp_headers)))
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

// ══════════════════════════════════════════════════════════════
//  Allowlist مقصد — جلوگیری از SSRF
//
//  ⚠️ باگ امنیتی نسخهٔ قبل: مقایسه با `contains()` روی *کل URL*
//  انجام می‌شد، پس هر آدرسی که نام یک دامنهٔ مجاز را «جایی» داشت
//  قبول می‌شد:
//      https://attacker.example/?x=googlevideo.com   ← قبول (باگ)
//      https://googlevideo.com.attacker.example/     ← قبول (باگ)
//  یعنی با یک امضای معتبر (که هر کلاینتی از /session-init می‌گیرد)
//  می‌شد این worker را به یک fetch-open-proxy برای هر مقصدی تبدیل
//  کرد. حالا host واقعی استخراج و به‌صورت anchored مقایسه می‌شود.
// ══════════════════════════════════════════════════════════════

const ALLOWED_TARGET_DOMAINS: [&str; 5] = [
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    "googleapis.com",
];

/// آیا `host` دقیقاً `domain` است یا زیردامنهٔ آن؟
/// `evilyoutube.com` و `youtube.com.evil.example` هر دو رد می‌شوند.
fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .map(|prefix| prefix.ends_with('.'))
            .unwrap_or(false)
}

/// Allowlist برای target URL — مقایسهٔ anchored روی host واقعی
fn is_allowed_target(raw_url: &str) -> bool {
    // ۰) کاراکتر کنترلی/فاصله در URL ممنوع (جلوگیری از request smuggling)
    if raw_url
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ')
    {
        return false;
    }

    // ۱) فقط https — با نرمال‌سازی scheme (طول بایت‌ها تغییر نمی‌کند)
    let lower = raw_url.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }

    // ۲) authority تا اولین '/', '?' یا '#' — همان مرزی که URL parser می‌بیند
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        // userinfo می‌تواند host واقعی را پنهان کند → رد
        return false;
    }

    // ۳) پورت: فقط 443 یا بدون پورت
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port == "443" => host,
        Some(_) => return false,
        None => authority,
    };

    // ۴) نرمال‌سازی و اعتبارسنجی host
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains("..")
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return false;
    }

    // ۵) مقایسهٔ anchored — نه substring
    ALLOWED_TARGET_DOMAINS
        .iter()
        .any(|domain| host_matches_domain(&host, domain))
}

// ══════════════════════════════════════════════════════════════
//  /sub — اشتراک VLESS (Base64)
//
//  این worker سرور VLESS نیست. این endpoint فقط یک URI استاندارد
//  می‌سازد که به سرور واقعی (VLESS_HOST) اشاره می‌کند.
//
//  فیلدها:
//    Secret  SUB_TOKEN    توکن اجباری (>= 24 کاراکتر) — بدون آن endpoint خاموش است
//    Secret  VLESS_UUID   UUID کلاینت روی سرور VLESS
//    Var     VLESS_HOST   دامنهٔ سرور VLESS (بدون scheme)
//    Var     VLESS_PATH   مسیر WebSocket (پیش‌فرض /vless)
//    Var     VLESS_SNI    پیش‌فرض = VLESS_HOST
//    Var     VLESS_REMARK نام نمایشی نود (پیش‌فرض SCP-GHOST)
//
//  چرا fail-closed: لینک VLESS به یک سرور غیر-VLESS = تونل مرده.
//  بهتر است endpoint 503 بدهد تا کلاینت لینک بی‌مصرف import نکند.
// ══════════════════════════════════════════════════════════════

const SUB_TOKEN_MIN_LEN: usize = 24;
const SUB_HEADER: &str = "X-Ghost-Sub";

/// مقایسهٔ constant-time برای توکن
fn ct_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// percent-encode مطابق RFC 3986 (unreserved + '/' دست‌نخورده)
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/');
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn is_valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, byte) in bytes.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.contains("..") {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return false;
    }
    if !host.contains('.') || !host.bytes().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    host.split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

fn is_valid_sub_path(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > 256 {
        return false;
    }
    path.bytes().all(|b| {
        b.is_ascii_graphic() && b != b'?' && b != b'#' && b != b'"' && b != b'\'' && b != b'\\'
    })
}

/// خواندن یک تنظیم از secret یا var (secret اولویت دارد).
/// مقدار trim‌شده برمی‌گردد؛ اگر هیچ‌کدام نبود، رشتهٔ خالی.
fn read_setting(ctx: &RouteContext<()>, name: &str) -> String {
    // توجه: `Env::secret()` نوع `Secret` برمی‌گرداند و `Env::var()` نوع
    // `String`. هر دو Display هستند، پس اول به String نرمال می‌شوند تا
    // این دو Option هم‌نوع باشند.
    let from_secret = ctx.secret(name).ok().map(|value| value.to_string());
    let from_var = ctx.var(name).ok().map(|value| value.to_string());

    from_secret
        .or(from_var)
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

struct VlessNode<'a> {
    uuid: &'a str,
    host: &'a str,
    sni: &'a str,
    path: &'a str,
    remark: &'a str,
}

/// ساخت URI استاندارد VLESS over WebSocket + TLS
fn build_vless_uri(node: &VlessNode<'_>) -> String {
    format!(
        "vless://{}@{}:443?encryption=none&security=tls&sni={}&fp=chrome&type=ws&host={}&path={}#{}",
        node.uuid,
        node.host,
        node.sni,
        node.host,
        percent_encode(node.path),
        percent_encode(node.remark),
    )
}

fn sub_response(status: u16, gate: &str, content_type: &str, body: String) -> Result<Response> {
    let headers = Headers::new();
    headers.set(SUB_HEADER, gate)?;
    headers.set("Content-Type", content_type)?;
    headers.set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    )?;
    headers.set("Pragma", "no-cache")?;
    headers.set("X-Content-Type-Options", "nosniff")?;

    let response = if status == 200 {
        Response::ok(body)?
    } else {
        Response::error(body, status)?
    };

    Ok(response.with_headers(headers))
}

async fn handle_subscription(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // ── ۱. توکن ──────────────────────────────────────────────
    let token = ctx
        .secret("SUB_TOKEN")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let token = token.trim().to_string();

    // بدون توکن قوی، endpoint هیچ چیزی سرو نمی‌کند.
    if token.len() < SUB_TOKEN_MIN_LEN {
        console_log!(
            "[Ghost Streaming] /sub is unconfigured: SUB_TOKEN missing or shorter than {} chars",
            SUB_TOKEN_MIN_LEN
        );
        let body = serde_json::json!({
            "error": "subscription_not_configured",
            "message": "Subscription endpoint is disabled. Set SUB_TOKEN (>= 24 chars), VLESS_UUID and VLESS_HOST, then retry.",
            "missing": ["SUB_TOKEN", "VLESS_UUID", "VLESS_HOST"],
        })
        .to_string();
        return sub_response(503, "unconfigured", "application/json; charset=utf-8", body);
    }

    // ── ۲. احراز هویت: ?token= یا Authorization: Bearer ────
    let query_params: std::collections::HashMap<String, String> = match req.url() {
        Ok(url) => url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        Err(_) => std::collections::HashMap::new(),
    };
    let provided = query_params.get("token").cloned().unwrap_or_default();
    let provided = if provided.is_empty() {
        req.headers()
            .get("Authorization")
            .ok()
            .flatten()
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .map(|token| token.trim().to_string())
            })
            .unwrap_or_default()
    } else {
        provided
    };

    if !ct_eq_str(provided.trim(), &token) {
        let body = serde_json::json!({
            "error": "invalid_subscription_token",
            "message": "Provide the subscription token via ?token=... or the Authorization: Bearer header.",
        })
        .to_string();
        return sub_response(403, "token-required", "application/json; charset=utf-8", body);
    }

    // ── ۳. پیکربندی نود ─────────────────────────────────────
    // هر مقدار می‌تواند secret باشد یا var — ترتیب: secret، بعد var.
    // (کاربر نباید درگیر این شود که کدام را کجا گذاشته است.)
    let uuid = read_setting(&ctx, "VLESS_UUID");
    let host = read_setting(&ctx, "VLESS_HOST");

    let path = {
        let value = read_setting(&ctx, "VLESS_PATH");
        if value.is_empty() {
            "/vless".to_string()
        } else {
            value
        }
    };

    let remark = {
        let value = read_setting(&ctx, "VLESS_REMARK");
        if value.is_empty() {
            "SCP-GHOST".to_string()
        } else {
            value
        }
    };

    let sni = {
        let value = read_setting(&ctx, "VLESS_SNI");
        if value.is_empty() {
            host.clone()
        } else {
            value
        }
    };

    let mut missing: Vec<&str> = Vec::new();
    if !is_valid_uuid(&uuid) {
        missing.push("VLESS_UUID");
    }
    if !is_valid_hostname(&host) {
        missing.push("VLESS_HOST");
    }
    if !is_valid_sub_path(&path) {
        missing.push("VLESS_PATH");
    }
    if !is_valid_hostname(&sni) {
        missing.push("VLESS_SNI");
    }

    if !missing.is_empty() {
        console_log!("[Ghost Streaming] /sub is unconfigured: {:?}", missing);
        let body = serde_json::json!({
            "error": "subscription_not_configured",
            "message": "VLESS parameters are missing or invalid. Set them with `wrangler secret put` / `[vars]`, then retry.",
            "missing": missing,
        })
        .to_string();
        return sub_response(503, "unconfigured", "application/json; charset=utf-8", body);
    }

    // ── ۴. ساخت و Base64 ────────────────────────────────────
    let node = VlessNode {
        uuid: &uuid,
        host: &host,
        sni: &sni,
        path: &path,
        remark: &remark,
    };
    let encoded = B64.encode(build_vless_uri(&node).as_bytes());

    console_log!("[Ghost Streaming] /sub served 1 node ({})", host);
    sub_response(200, "ok", "text/plain; charset=utf-8", encoded)
}
