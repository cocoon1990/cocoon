//! lib.rs — Signaling Worker (workers-rs 0.8.7)
//!
//! Endpoints:
//!   GET     /health               → وضعیت worker
//!   GET     /config               → خواندن routing_config از Cloudflare KV
//!   POST    /session-init         → تبادل کلید X25519 (بدون ارسال secret خام)
//!   POST    /admin/reload-config  → تأیید دریافت SIGNAL از GitHub Actions
//!
//! ══════════════════════════════════════════════════════════════
//!  پروتکل تبادل کلید — `x25519-hkdf-sha256-aesgcm-v1`
//! ══════════════════════════════════════════════════════════════
//! نسخهٔ قبلی `hmac_key_hex` و یک `aes_key_hex` هاردکد را به هر
//! کلاینتی برمی‌گرداند. حالا هیچ secret خامی از سرور خارج نمی‌شود:
//!
//!   1. کلاینت یک keypair موقت X25519 می‌سازد (کلید خصوصی هرگز
//!      از دستگاه خارج نمی‌شود) و فقط public key را می‌فرستد:
//!         POST /session-init {"client_pubkey": base64(32 bytes)}
//!   2. worker هم یک keypair موقت می‌سازد، X25519 انجام می‌دهد و
//!      از shared secret یک KEK می‌سازد:
//!         KEK = HKDF-SHA256(ikm = shared, salt = salt, info = "ghost/session-kek/v1")
//!   3. worker کلیدهای اصلی (`HMAC_SECRET` و `AES_KEY`) را با
//!      AES-256-GCM زیر KEK رمز می‌کند و برمی‌گرداند:
//!         wrapped = nonce(12) || ciphertext+tag
//!         AAD     = "ghost/session/v1" || client_pub || server_pub
//!   4. کلاینت همان KEK را محاسبه و payload را باز می‌کند.
//!
//! چرا کلیدها «رمز شده» فرستاده می‌شوند و نه «مشتق‌شده»؟
//! چون `streaming-worker` امضای درخواست‌ها را با `HMAC_SECRET` ثابت
//! verify می‌کند. اگر کلاینت کلید مشتق‌شدهٔ دیگری می‌گرفت، امضاها
//! معتبر نبودند. پس کلید باید همان کلید اصلی باشد — ولی حالا فقط
//! کلاینتی که واقعاً کلید خصوصی X25519 خودش را دارد می‌تواند آن را
//! بخواند. (راه‌حل بلندمدت: مشتق‌کردن per-session key در هر دو
//! worker بر اساس session_id — نیازمند تغییر streaming-worker.)
//!
//! ⚠️ محدودیت‌ها: X25519 در اینجا **احراز هویت** نیست (کلاینت
//! ناشناس است)؛ فقط محرمانگی روی سیم + جلوگیری از خواندن کلید توسط
//! ناظر شبکه/سایت‌های دیگر را تضمین می‌کند. برای احراز هویت واقعی
//! باید توکن یا mTLS اضافه شود. Rate limit هم جلوی سوءاستفاده
//! تدریجی را می‌گیرد، نه حملهٔ توزیع‌شده.
//!
//! ══════════════════════════════════════════════════════════════
//!  CORS — allowlist (نه `*`)
//! ══════════════════════════════════════════════════════════════
//!   • منبع: var به نام `ALLOWED_ORIGIN` (چند مقدار با کاما)
//!   • origin درخواست echo می‌شود + هدر `Vary: Origin`
//!   • preflight سراسری: هر OPTIONS — روی هر مسیری — قبل از Router در
//!     `main()` پاسخ می‌گیرد (204)، پس هرگز 405 نمی‌شود
//!   • `finalize()` هدر CORS را روی *همهٔ* پاسخ‌ها تضمین می‌کند
//!     و بدنهٔ 404/405 را به JSON گویا تبدیل می‌کند
//!   • origin غیرمجاز → preflight با 403 و بدون هیچ هدر CORS
//!   • درخواست بدون Origin (curl / health check) → origin اصلی
//!
//! ── یادداشت سازگاری با worker 0.8.7 ────────────────────────────
//!   • `RouteContext` فیلد عمومی `env: Env` دارد.
//!   • `Headers::get(name) -> Result<Option<String>>`
//!   • `Headers::set(&self, ...)` → نیازی به `mut` نیست.
//!   • `#[durable_object]` فقط روی struct؛ `fetch(&self, Request)`.
//!   • `sql.exec(q, Option<Vec<SqlStorageValue>>)` — بدون `exec_with`.
//!   • `Request::json()` نیاز به `&mut self` دارد.
//!   • `Response::ok/empty/error` + `with_headers` (جایگزین می‌کند).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use worker::*;
use x25519_dalek::{PublicKey, StaticSecret};

// ══════════════════════════════════════════════════════════════
//  ثابت‌های پروتکل — باید دقیقاً با کلاینت (browser-wasm) یکی باشد
// ══════════════════════════════════════════════════════════════

/// شناسهٔ پروتکل که در پاسخ برگردانده می‌شود
const PROTOCOL: &str = "x25519-hkdf-sha256-aesgcm-v1";

/// info در HKDF برای ساخت KEK
const HKDF_INFO_KEK: &[u8] = b"ghost/session-kek/v1";

/// پیشوند AAD برای AES-GCM (بایند کردن پیام به هر دو public key)
const AAD_PREFIX: &[u8] = b"ghost/session/v1";

/// origin(pre) پیش‌فرض مجاز — اگر `ALLOWED_ORIGIN` ست نشده باشد
const DEFAULT_ALLOWED_ORIGIN: &str = "https://cocoon1990.github.io,tauri://localhost";

// ══════════════════════════════════════════════════════════════
//  CORS
// ══════════════════════════════════════════════════════════════

/// خواندن allowlist از var به نام `ALLOWED_ORIGIN`.
/// چند origin با کاما جدا می‌شوند؛ فاصله و اسلش انتهایی حذف می‌شود.
fn allowed_origins(env: &Env) -> Vec<String> {
    let raw = env
        .var("ALLOWED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| DEFAULT_ALLOWED_ORIGIN.to_string());

    let mut list: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if list.is_empty() {
        list = DEFAULT_ALLOWED_ORIGIN
            .split(',')
            .map(|s| s.to_string())
            .collect();
    }

    list
}

/// اگر origin درخواست در allowlist باشد همان را برمی‌گرداند؛ وگرنه `None`.
/// درخواست بدون هدر Origin (curl / health check) → اولین عضو allowlist.
fn matching_origin(env: &Env, request_origin: Option<&str>) -> Option<String> {
    let allowed = allowed_origins(env);

    match request_origin {
        Some(origin) => {
            let clean = origin.trim().trim_end_matches('/');
            allowed
                .iter()
                .find(|a| a.eq_ignore_ascii_case(clean))
                .cloned()
        }
        None => allowed.into_iter().next(),
    }
}

/// هدرهای CORS برای پاسخ‌های عادی.
/// `Vary: Origin` اجباری است: بدون آن کش/Cloudflare ممکن است پاسخ یک
/// origin را به origin دیگری بدهد.
fn cors_headers(origin: Option<&str>) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("Vary", "Origin")?;
    if let Some(origin) = origin {
        headers.set("Access-Control-Allow-Origin", origin)?;
    }
    Ok(headers)
}

/// هدرهای JSON + CORS — برای پاسخ‌های بدنه‌دار
fn json_headers(origin: Option<&str>) -> Result<Headers> {
    let headers = cors_headers(origin)?;
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store, no-cache")?;
    Ok(headers)
}

/// پاسخ preflight برای OPTIONS.
/// origin غیرمجاز → 403 و **بدون** هیچ هدر CORSی.
fn cors_preflight(env: &Env, request_origin: Option<&str>) -> Result<Response> {
    let Some(origin) = matching_origin(env, request_origin) else {
        console_log!("CORS preflight rejected for origin: {:?}", request_origin);
        return Response::error("Origin not allowed", 403);
    };

    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", &origin)?;
    headers.set("Vary", "Origin")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    headers.set("Access-Control-Allow-Private-Network", "true")?;
    // نتیجهٔ preflight را ۲۴ ساعت کش کن
    headers.set("Access-Control-Max-Age", "86400")?;

    Ok(Response::empty()?.with_headers(headers).with_status(204))
}

/// خواندن هدر Origin از درخواست
fn request_origin(req: &Request) -> Option<String> {
    req.headers().get("Origin").ok().flatten()
}

// ══════════════════════════════════════════════════════════════
//  Durable Object: SignalingRateLimiter
//  Sliding window با SQLite — strongly consistent و atomic.
//  یک instance به‌ازای هر IP (sharding خودکار).
// ══════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
struct RateLimitResponse {
    allowed: bool,
    remaining: i64,
    limit: i64,
    window_ms: i64,
    retry_after_ms: Option<i64>,
}

#[derive(Deserialize)]
struct CountRow {
    cnt: i64,
}

#[derive(Deserialize)]
struct OldestRow {
    oldest: Option<i64>,
}

#[durable_object]
pub struct SignalingRateLimiter {
    state: State,
    _env: Env,
}

impl DurableObject for SignalingRateLimiter {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let limit: i64 = params
            .get("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);

        let window_ms: i64 = params
            .get("window_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60_000);

        let sql = self.state.storage().sql();

        sql.exec(
            "CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL
            )",
            None,
        )?;

        let now_ms = Date::now().as_millis() as i64;
        let cutoff = now_ms - window_ms;

        // ۱. پاکسازی hits قدیمی
        sql.exec(
            "DELETE FROM hits WHERE ts < ?1",
            vec![SqlStorageValue::Integer(cutoff)],
        )?;

        // ۲. شمارش window فعلی
        let count: i64 = sql
            .exec("SELECT COUNT(*) as cnt FROM hits", None)?
            .to_array::<CountRow>()
            .ok()
            .and_then(|rows| rows.first().map(|r| r.cnt))
            .unwrap_or(0);

        if count >= limit {
            let oldest_ts: i64 = sql
                .exec("SELECT MIN(ts) as oldest FROM hits", None)?
                .to_array::<OldestRow>()
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.oldest))
                .unwrap_or(now_ms - window_ms);

            let retry_after_ms = ((oldest_ts + window_ms) - now_ms).max(1000);

            let body = serde_json::to_string(&RateLimitResponse {
                allowed: false,
                remaining: 0,
                limit,
                window_ms,
                retry_after_ms: Some(retry_after_ms),
            })
            .unwrap_or_default();

            let headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("X-RateLimit-Limit", &limit.to_string())?;
            headers.set("X-RateLimit-Remaining", "0")?;
            headers.set("Retry-After", &(retry_after_ms / 1000).to_string())?;

            return Response::error(body, 429).map(|r| r.with_headers(headers));
        }

        // ۳. ثبت hit
        sql.exec(
            "INSERT INTO hits (ts) VALUES (?1)",
            vec![SqlStorageValue::Integer(now_ms)],
        )?;

        let remaining = limit - count - 1;
        let body = serde_json::to_string(&RateLimitResponse {
            allowed: true,
            remaining,
            limit,
            window_ms,
            retry_after_ms: None,
        })
        .unwrap_or_default();

        let headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        headers.set("X-RateLimit-Limit", &limit.to_string())?;
        headers.set("X-RateLimit-Remaining", &remaining.to_string())?;

        Response::ok(body).map(|r| r.with_headers(headers))
    }
}

/// بررسی rate limit برای یک IP.
/// خروجی: `Some(info)` یعنی محدود شده‌اید؛ `None` یعنی مجاز.
async fn check_rate_limit(
    ctx: &RouteContext<()>,
    client_ip: &str,
    scope: &str,
) -> Result<Option<RateLimitResponse>> {
    let limit = ctx
        .var("RATE_LIMIT_RPM")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "20".to_string());
    let window_ms = ctx
        .var("RATE_WINDOW_MS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "60000".to_string());

    let namespace = ctx.durable_object("RATE_LIMITER")?;
    let id = namespace.id_from_name(&format!("{}:{}", scope, client_ip))?;
    let stub = id.get_stub()?;

    let url = format!(
        "http://internal/check?limit={}&window_ms={}",
        limit, window_ms
    );
    let check_req = Request::new(&url, Method::Get)?;
    let mut resp = stub.fetch_with_request(check_req).await?;

    if resp.status_code() == 429 {
        let info: RateLimitResponse = resp.json().await?;
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

// ══════════════════════════════════════════════════════════════
//  رمزنگاری — X25519 + HKDF-SHA256 + AES-256-GCM
// ══════════════════════════════════════════════════════════════

/// ۳۲ بایت تصادفی امن (crypto.getRandomValues در workerd)
fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| Error::RustError(format!("RNG failure: {e}")))
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    B64.decode(input.trim()).ok()
}

/// ساخت KEK از shared secret
fn derive_kek(shared: &[u8; 32], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut kek = [0u8; 32];
    hk.expand(HKDF_INFO_KEK, &mut kek)
        .map_err(|_| Error::RustError("HKDF expand failed".into()))?;
    Ok(kek)
}

/// AAD = "ghost/session/v1" || client_pub || server_pub
fn build_aad(client_pub: &[u8], server_pub: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 64);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(client_pub);
    aad.extend_from_slice(server_pub);
    aad
}

/// رمزگذاری payload با AES-256-GCM؛ خروجی: nonce(12) || ciphertext
fn wrap_payload(kek: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));

    let mut nonce_bytes = [0u8; 12];
    random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::RustError("AES-GCM encryption failed".into()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// بدنهٔ درون wrapped — فقط کلیدها
#[derive(Serialize)]
struct SessionKeys {
    hmac_key_hex: String,
    aes_key_hex: String,
}

/// بدنهٔ درخواست کلاینت
#[derive(Deserialize)]
struct SessionInitRequest {
    client_pubkey: String,
    #[serde(default)]
    #[allow(dead_code)]
    client_version: Option<String>,
}

// ══════════════════════════════════════════════════════════════
//  Main
// ══════════════════════════════════════════════════════════════

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // ══════════════════════════════════════════════════════════
    //  MIDDLEWARE ۱ — preflight سراسری
    //
    //  هر درخواست OPTIONS، برای **هر مسیری** (حتی مسیرهایی که هنوز
    //  ساخته نشده‌اند)، همین‌جا و قبل از Router پاسخ می‌گیرد.
    //
    //  چرا این‌طور: در worker 0.8.7 تابع `Router::run` اگر برای متدِ
    //  درخواست هندلری پیدا نکند، قبل از هر fallback این را برمی‌گرداند:
    //      return Response::error("Method Not Allowed", 405);
    //  یعنی هندلرهای per-route و or_else هرگز به OPTIONS نمی‌رسند و
    //  هر مسیر جدید دوباره 405 می‌دهد. با interceptor سراسری، این کلاس
    //  از باگ‌ها برای همیشه بسته می‌شود.
    // ══════════════════════════════════════════════════════════
    let req_origin = request_origin(&req);

    if req.method() == Method::Options {
        return cors_preflight(&env, req_origin.as_deref());
    }

    let resolved_origin = matching_origin(&env, req_origin.as_deref());

    let router = Router::new();

    let response = router
        // ── GET /health ────────────────────────────────────────
        .get_async("/health", |req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let body = json!({
                "status": "ok",
                "worker": "ghost-signaling",
                "protocol": PROTOCOL,
                "version": ctx.var("WORKER_VERSION")?.to_string()
            })
            .to_string();

            Ok(Response::ok(body)?.with_headers(json_headers(origin.as_deref())?))
        })
        // ── GET /config ────────────────────────────────────────
        .get_async("/config", |req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let kv = ctx.kv("GHOST_CONFIG")?;
            let config = kv
                .get("routing_config")
                .text()
                .await?
                .unwrap_or_else(|| "{}".to_string());

            Ok(Response::ok(config)?.with_headers(json_headers(origin.as_deref())?))
        })
        // ── POST /session-init ─────────────────────────────────
        .post_async("/session-init", |mut req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let bad_request = |msg: &str| -> Result<Response> {
                Ok(Response::error(json!({"error": "bad_request", "message": msg}).to_string(), 400)?
                    .with_headers(json_headers(origin.as_deref())?))
            };

            // ۱. Rate limit (به‌ازای هر IP)
            let client_ip = req
                .headers()
                .get("CF-Connecting-IP")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".to_string());

            if let Some(info) = check_rate_limit(&ctx, &client_ip, "session-init").await? {
                let retry_secs = (info.retry_after_ms.unwrap_or(60_000) / 1000).max(1);
                let mut headers = json_headers(origin.as_deref())?;
                headers.set("Retry-After", &retry_secs.to_string())?;
                headers.set("X-RateLimit-Limit", &info.limit.to_string())?;
                headers.set("X-RateLimit-Remaining", "0")?;

                return Ok(Response::error(
                    json!({
                        "error": "rate_limited",
                        "message": "Too many session-init requests. Retry later.",
                        "retry_after_s": retry_secs
                    })
                    .to_string(),
                    429,
                )?
                .with_headers(headers));
            }

            // ۲. خواندن بدنه
            let payload: SessionInitRequest = match req.json().await {
                Ok(p) => p,
                Err(_) => {
                    return bad_request(
                        "Invalid JSON body. Expected {\"client_pubkey\": \"<base64 32 bytes>\"}.",
                    )
                }
            };

            let client_pub_vec = match b64_decode(&payload.client_pubkey) {
                Some(v) => v,
                None => return bad_request("client_pubkey is not valid base64."),
            };

            if client_pub_vec.len() != 32 {
                return bad_request("client_pubkey must decode to exactly 32 bytes.");
            }

            let mut client_pub_arr = [0u8; 32];
            client_pub_arr.copy_from_slice(&client_pub_vec);

            // ۳. کلیدهای اصلی — فقط از Secrets، هرگز از سورس
            let hmac_hex = match ctx.secret("HMAC_SECRET") {
                Ok(s) => s.to_string(),
                Err(_) => {
                    console_log!("HMAC_SECRET is not configured");
                    return server_error(origin.as_deref(), "Server key material unavailable.");
                }
            };
            let aes_hex = match ctx.secret("AES_KEY") {
                Ok(s) => s.to_string(),
                Err(_) => {
                    console_log!("AES_KEY is not configured");
                    return server_error(origin.as_deref(), "Server key material unavailable.");
                }
            };

            // اعتبارسنجی طول کلیدها
            let hmac_len = hmac_hex.trim().len();
            if hmac_len < 64 || hmac_len % 2 != 0 {
                console_log!("HMAC_SECRET has invalid length: {}", hmac_len);
                return server_error(origin.as_deref(), "Server key material invalid.");
            }
            if aes_hex.trim().len() != 64 {
                console_log!("AES_KEY must be 64 hex chars, got {}", aes_hex.trim().len());
                return server_error(origin.as_deref(), "Server key material invalid.");
            }
            if !matches!(hex::decode(aes_hex.trim()), Ok(v) if v.len() == 32) {
                console_log!("AES_KEY is not valid hex");
                return server_error(origin.as_deref(), "Server key material invalid.");
            }

            // ۴. X25519 — keypair موقت سمت سرور
            let mut seed = [0u8; 32];
            random_bytes(&mut seed)?;
            let server_secret = StaticSecret::from(seed);
            let server_public = PublicKey::from(&server_secret);
            let client_public = PublicKey::from(client_pub_arr);

            let shared = server_secret.diffie_hellman(&client_public);
            if !shared.was_contributory() {
                // نقطهٔ low-order → shared secret قابل پیش‌بینی است
                return bad_request("client_pubkey is not a valid X25519 public key.");
            }

            // ۵. KEK از shared secret
            let mut salt = [0u8; 32];
            random_bytes(&mut salt)?;

            let kek = derive_kek(shared.as_bytes(), &salt)?;
            let server_pub_bytes = server_public.as_bytes();
            let aad = build_aad(&client_pub_arr, server_pub_bytes);

            // ۶. رمزگذاری کلیدها زیر KEK
            let plaintext = serde_json::to_vec(&SessionKeys {
                hmac_key_hex: hmac_hex.trim().to_string(),
                aes_key_hex: aes_hex.trim().to_string(),
            })
            .map_err(|e| Error::RustError(format!("serialize failed: {e}")))?;

            let wrapped = wrap_payload(&kek, &plaintext, &aad)?;

            // ۷. پاسخ — هیچ secret خامی اینجا نیست
            let body = json!({
                "protocol": PROTOCOL,
                "server_pubkey": B64.encode(server_pub_bytes),
                "salt": B64.encode(salt),
                "wrapped": B64.encode(wrapped),
                "gas_endpoints": [],
                "config_version": "5.1.1"
            })
            .to_string();

            Ok(Response::ok(body)?.with_headers(json_headers(origin.as_deref())?))
        })
        // preflight — بدون این، مرورگر preflight را با 405 رد می‌کند
        // ── POST /admin/reload-config ──────────────────────────
        .post_async("/admin/reload-config", |mut req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let body: serde_json::Value = req.json().await.unwrap_or_default();
            console_log!("Config reload requested: {:?}", body);

            Ok(Response::ok(json!({"status": "acknowledged"}).to_string())?
                .with_headers(json_headers(origin.as_deref())?))
        })
        .run(req, env)
        .await?;

    // ══════════════════════════════════════════════════════════
    //  MIDDLEWARE ۲ — finalize
    //  هر پاسخی (موفق یا خطا، حتی 404/405) از اینجا رد می‌شود تا
    //  هدرهای CORS همیشه حاضر باشند و بدنهٔ خطاها JSON گویا باشد
    //  (نه صفحهٔ HTML پیش‌فرض که دیباگ را غیرممکن می‌کند).
    // ══════════════════════════════════════════════════════════
    finalize(response, resolved_origin.as_deref())
}

/// مسیرهای شناخته‌شده — برای پیام خطای گویا
const KNOWN_ENDPOINTS: [&str; 4] = [
    "GET /health",
    "GET /config",
    "POST /session-init",
    "POST /admin/reload-config",
];

/// آخرین مرحلهٔ هر پاسخ: CORS تضمینی + بدنهٔ JSON برای 404/405.
fn finalize(res: Response, origin: Option<&str>) -> Result<Response> {
    let status = res.status_code();

    // ── خطاهای مسیر/متد: بدنهٔ JSON قابل دیباگ ──────────────
    if status == 404 || status == 405 {
        let (error, message) = if status == 405 {
            (
                "method_not_allowed",
                "This method is not allowed for this path. \
                 Preflight (OPTIONS) is handled globally; \
                 this 405 is for the real request method.",
            )
        } else {
            (
                "not_found",
                "Unknown path. Check the URL — the endpoint list is in 'endpoints'.",
            )
        };

        let body = json!({
            "error": error,
            "message": message,
            "protocol": PROTOCOL,
            "endpoints": KNOWN_ENDPOINTS,
        })
        .to_string();

        return Ok(Response::error(body, status)?.with_headers(json_headers(origin)?));
    }

    // ── بقیهٔ پاسخ‌ها: CORS را اگر نبود اضافه کن ────────────
    let headers = res.headers_mut();
    if let Some(origin) = origin {
        let _ = headers.set("Access-Control-Allow-Origin", origin);
    }
    let _ = headers.set("Vary", "Origin");

    Ok(res)
}

/// پاسخ 500 با هدرهای CORS
fn server_error(origin: Option<&str>, msg: &str) -> Result<Response> {
    Ok(
        Response::error(json!({"error": "server_error", "message": msg}).to_string(), 500)?
            .with_headers(json_headers(origin)?),
    )
}
