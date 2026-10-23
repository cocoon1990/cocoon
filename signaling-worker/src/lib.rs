//! lib.rs — Signaling Worker (workers-rs 0.8.7)
//!
//! Endpoints:
//!   GET     /health               → وضعیت worker
//!   GET     /config               → خواندن routing_config از Cloudflare KV
//!   POST    /session-init         → توزیع کلیدهای session به Service Worker
//!   POST    /admin/reload-config  → تأیید دریافت SIGNAL از GitHub Actions
//!
//! ── CORS (نسخهٔ 5.0.2) ──────────────────────────────────────────
//! UI روی `<user>.github.io` و worker روی `*.workers.dev` است، پس هر
//! فراخوانی cross-origin است. UI برای `/session-init` این را می‌فرستد:
//!
//!     fetch(`${SIGNALING_URL}/session-init`, {
//!       method: "POST",
//!       headers: { "Content-Type": "application/json" }, ...
//!     })
//!
//! چون `Content-Type: application/json` یک هدر «غیرساده» است، مرورگر
//! **قبل از** POST یک درخواست `OPTIONS` (preflight) می‌فرستد.
//!
//! باگ قبلی: هیچ route‌ای برای OPTIONS ثبت نشده بود. در `Router::run`
//! نسخهٔ 0.8.7، وقتی متدی برای درخواست پیدا نشود، روتر مسیرهای سایر
//! متدها را چک می‌کند و اگر path وجود داشته باشد `405 Method Not Allowed`
//! برمی‌گرداند — یعنی preflight با 405 رد می‌شد و POST هرگز فرستاده
//! نمی‌شد. حالا هر مسیر عمومی یک هندلر `options_async` دارد.
//!
//! ── یادداشت مهاجرت به worker 0.8.7 ──────────────────────────────
//!   • `Env::var` / `Env::secret` / `Env::kv` → هر سه در 0.8.7 همان امضا را دارند.
//!   • `RouteContext::var` / `secret` / `kv` → بدون تغییر.
//!   • `KvStore::get(key).text().await` → `Result<Option<String>, KvError>` و
//!     `From<KvError> for worker::Error` در 0.8.7 موجود است، پس `?` کار می‌کند.
//!   • `Request::json()` در 0.8.7 نیاز به `&mut self` دارد → پارامتر `mut req` حفظ شد.
//!   • `Response::ok(..)` / `empty()` / `with_headers(..)` / `with_status(..)`
//!     در 0.8.7 موجودند (headers را کامل جایگزین می‌کند، نه merge).
//!   • `Router::options_async(pattern, handler)` در 0.8.7 موجود است.

use serde_json::json;
use worker::*;

// ══════════════════════════════════════════════════════════════
//  CORS
//  هدرها را یک‌جا می‌سازیم تا هیچ endpointی بدون CORS نماند.
// ══════════════════════════════════════════════════════════════

/// هدرهای CORS برای پاسخ‌های عادی (غیر از preflight).
/// `*` استفاده می‌شود چون هیچ‌کدام از درخواست‌ها credentials ندارند
/// (اگر روزی `credentials: "include"` اضافه شد، باید origin دقیق
/// برگردانده شود، نه `*`).
fn cors_headers() -> Result<Headers> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    Ok(headers)
}

/// هدرهای JSON + CORS — برای همهٔ پاسخ‌های بدنه‌دار
fn json_headers() -> Result<Headers> {
    let headers = cors_headers()?;
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store, no-cache")?;
    Ok(headers)
}

/// پاسخ preflight برای درخواست‌های OPTIONS.
/// بدنه ندارد → 204 No Content (سریع‌ترین پاسخ معتبر برای preflight).
fn cors_preflight() -> Result<Response> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    // نتیجهٔ preflight را ۲۴ ساعت کش کن تا برای هر درخواست تکرار نشود
    headers.set("Access-Control-Max-Age", "86400")?;

    // توجه: with_headers هدرها را جایگزین می‌کند، پس همه را همین‌جا داده‌ایم
    Ok(Response::empty()?.with_headers(headers).with_status(204))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // ── GET /health ────────────────────────────────────────
        .get_async("/health", |_req, ctx| async move {
            let body = json!({
                "status": "ok",
                "worker": "ghost-signaling",
                "version": ctx.var("WORKER_VERSION")?.to_string()
            })
            .to_string();

            Ok(Response::ok(body)?.with_headers(json_headers()?))
        })
        .options_async("/health", |_req, _ctx| async move {
            cors_preflight()
        })
        // ── GET /config ────────────────────────────────────────
        .get_async("/config", |_req, ctx| async move {
            let kv = ctx.kv("GHOST_CONFIG")?;
            let config = kv
                .get("routing_config")
                .text()
                .await?
                .unwrap_or_else(|| "{}".to_string());

            Ok(Response::ok(config)?.with_headers(json_headers()?))
        })
        .options_async("/config", |_req, _ctx| async move {
            cors_preflight()
        })
        // ── POST /session-init ─────────────────────────────────
        // فقط POST — درخواست GET/OPTIONS به این مسیر با 405 پاسخ داده
        // می‌شود، مگر preflight که هندلر جداگانهٔ خودش را دارد.
        .post_async("/session-init", |_req, ctx| async move {
            let hmac_secret = ctx.secret("HMAC_SECRET")?.to_string();
            let resp = json!({
                "hmac_key_hex": hmac_secret,
                "aes_key_hex": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "gas_endpoints": [],
                "config_version": "5.0.2"
            });

            Ok(Response::ok(resp.to_string())?.with_headers(json_headers()?))
        })
        // preflight — بدون این، مرورگر preflight را با 405 رد می‌کند
        .options_async("/session-init", |_req, _ctx| async move {
            cors_preflight()
        })
        // ── POST /admin/reload-config ──────────────────────────
        .post_async("/admin/reload-config", |mut req, _ctx| async move {
            // This endpoint is called by GitHub Actions to notify workers of config changes.
            // Since workers read config lazily from KV on each request, we just acknowledge.
            let body: serde_json::Value = req.json().await.unwrap_or_default();
            console_log!("Config reload requested: {:?}", body);

            Ok(Response::ok(json!({"status": "acknowledged"}).to_string())?
                .with_headers(json_headers()?))
        })
        .options_async("/admin/reload-config", |_req, _ctx| async move {
            cors_preflight()
        })
        .run(req, env)
        .await
}
