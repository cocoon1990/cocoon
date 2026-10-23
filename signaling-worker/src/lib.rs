//! lib.rs — Signaling Worker (workers-rs 0.8.7)
//!
//! Endpoints:
//!   GET     /health               → وضعیت worker
//!   GET     /config               → خواندن routing_config از Cloudflare KV
//!   POST    /session-init         → توزیع کلیدهای session به Service Worker
//!   POST    /admin/reload-config  → تأیید دریافت SIGNAL از GitHub Actions
//!
//! ── CORS (نسخهٔ 5.0.3 — allowlist به‌جای `*`) ───────────────────
//! قبلاً `Access-Control-Allow-Origin: *` بود. چون `POST /session-init`
//! کلید HMAC را برمی‌گرداند، `*` یعنی هر سایتی که کاربر باز کند می‌تواند
//! آن را بخواند. حالا فقط origin‌های موجود در allowlist پاسخ می‌گیرند:
//!
//!   • منبع allowlist: var به نام `ALLOWED_ORIGIN` در wrangler.toml
//!     (چند مقدار با کاما مجاز است)
//!   • اگر var ست نشده باشد → `DEFAULT_ALLOWED_ORIGIN`
//!   • origin درخواست echo می‌شود (نه مقدار ثابت) + هدر `Vary: Origin`
//!   • origin غیرمجاز → preflight با 403 رد می‌شود و هیچ هدر CORSی
//!     در پاسخ‌های عادی گذاشته نمی‌شود
//!
//! ⚠️ محدودکردن CORS فقط جلوی **مرورگر** را می‌گیرد؛ `curl` همچنان
//! می‌تواند کلید را بگیرد. CORS احراز هویت نیست.
//!
//! ── یادداشت مهاجرت به worker 0.8.7 ──────────────────────────────
//!   • `Env::var` / `Env::secret` / `Env::kv` → هر سه در 0.8.7 همان امضا را دارند.
//!   • `RouteContext` فیلد عمومی `env: Env` دارد → هدرها را از همان می‌سازیم.
//!   • `Headers::get(name) -> Result<Option<String>>` (نه Option خالی).
//!   • `KvStore::get(key).text().await` → `Result<Option<String>, KvError>`.
//!   • `Request::json()` در 0.8.7 نیاز به `&mut self` دارد → پارامتر `mut req`.
//!   • `Response::ok/empty/error` + `with_headers` (جایگزین می‌کند، نه merge)
//!     + `with_status` در 0.8.7 موجودند.
//!   • `Router::options_async(pattern, handler)` در 0.8.7 موجود است.

use serde_json::json;
use worker::*;

// ══════════════════════════════════════════════════════════════
//  CORS — allowlist
// ══════════════════════════════════════════════════════════════

/// origin پیش‌فرض مجاز (اگر `ALLOWED_ORIGIN` در wrangler.toml ست نشده باشد).
const DEFAULT_ALLOWED_ORIGIN: &str = "https://cocoon1990.github.io";

/// خواندن allowlist از var به نام `ALLOWED_ORIGIN`.
/// چند origin با کاما جدا می‌شوند؛ اسلش انتهایی و فاصله‌ها حذف می‌شوند.
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
        list.push(DEFAULT_ALLOWED_ORIGIN.to_string());
    }

    list
}

/// اگر origin درخواست در allowlist باشد، همان را برمی‌گرداند؛ وگرنه `None`.
/// اگر درخواست هدر Origin نداشته باشد (curl / GitHub Actions) اولین عضو
/// allowlist استفاده می‌شود — این برای مرورگر بی‌خطر است، چون مرورگر
/// همیشه Origin می‌فرستد و مقدار نامطابق را رد می‌کند.
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
/// origin را به origin دیگری بدهد (با `*` این مشکل وجود نداشت).
fn cors_headers(origin: Option<&str>) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("Vary", "Origin")?;
    if let Some(origin) = origin {
        headers.set("Access-Control-Allow-Origin", origin)?;
    }
    Ok(headers)
}

/// هدرهای JSON + CORS — برای همهٔ پاسخ‌های بدنه‌دار
fn json_headers(origin: Option<&str>) -> Result<Headers> {
    let headers = cors_headers(origin)?;
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store, no-cache")?;
    Ok(headers)
}

/// پاسخ preflight برای درخواست‌های OPTIONS.
/// بدنه ندارد → 204 No Content (سریع‌ترین پاسخ معتبر برای preflight).
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
    // نتیجهٔ preflight را ۲۴ ساعت کش کن تا برای هر درخواست تکرار نشود
    headers.set("Access-Control-Max-Age", "86400")?;

    // توجه: with_headers هدرها را جایگزین می‌کند، پس همه را همین‌جا داده‌ایم
    Ok(Response::empty()?.with_headers(headers).with_status(204))
}

/// خواندن هدر Origin از درخواست (بدون خطا دادن روی هدر نامعتبر)
fn request_origin(req: &Request) -> Option<String> {
    req.headers().get("Origin").ok().flatten()
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // ── GET /health ────────────────────────────────────────
        .get_async("/health", |req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let body = json!({
                "status": "ok",
                "worker": "ghost-signaling",
                "version": ctx.var("WORKER_VERSION")?.to_string()
            })
            .to_string();

            Ok(Response::ok(body)?.with_headers(json_headers(origin.as_deref())?))
        })
        .options_async("/health", |req, ctx| async move {
            let req_origin = request_origin(&req);
            cors_preflight(&ctx.env, req_origin.as_deref())
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
        .options_async("/config", |req, ctx| async move {
            let req_origin = request_origin(&req);
            cors_preflight(&ctx.env, req_origin.as_deref())
        })
        // ── POST /session-init ─────────────────────────────────
        // فقط POST — درخواست متد دیگر به این مسیر 405 می‌گیرد، مگر
        // preflight که هندلر جداگانهٔ خودش را دارد.
        .post_async("/session-init", |req, ctx| async move {
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let hmac_secret = ctx.secret("HMAC_SECRET")?.to_string();
            let resp = json!({
                "hmac_key_hex": hmac_secret,
                "aes_key_hex": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "gas_endpoints": [],
                "config_version": "5.0.3"
            });

            Ok(Response::ok(resp.to_string())?.with_headers(json_headers(origin.as_deref())?))
        })
        // preflight — بدون این، مرورگر preflight را با 405 رد می‌کند
        .options_async("/session-init", |req, ctx| async move {
            let req_origin = request_origin(&req);
            cors_preflight(&ctx.env, req_origin.as_deref())
        })
        // ── POST /admin/reload-config ──────────────────────────
        .post_async("/admin/reload-config", |mut req, ctx| async move {
            // This endpoint is called by GitHub Actions to notify workers of config changes.
            // Since workers read config lazily from KV on each request, we just acknowledge.
            let req_origin = request_origin(&req);
            let origin = matching_origin(&ctx.env, req_origin.as_deref());

            let body: serde_json::Value = req.json().await.unwrap_or_default();
            console_log!("Config reload requested: {:?}", body);

            Ok(Response::ok(json!({"status": "acknowledged"}).to_string())?
                .with_headers(json_headers(origin.as_deref())?))
        })
        .options_async("/admin/reload-config", |req, ctx| async move {
            let req_origin = request_origin(&req);
            cors_preflight(&ctx.env, req_origin.as_deref())
        })
        .run(req, env)
        .await
}
