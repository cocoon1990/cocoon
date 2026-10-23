//! lib.rs — Signaling Worker (workers-rs 0.8.7)
//!
//! Endpoints:
//!   GET  /health               → وضعیت worker
//!   GET  /config               → خواندن routing_config از Cloudflare KV
//!   POST /session-init         → توزیع کلیدهای session به Service Worker
//!   POST /admin/reload-config  → تأیید دریافت SIGNAL از GitHub Actions
//!
//! ── یادداشت مهاجرت به worker 0.8.7 ──────────────────────────────
//! این فایل از ابتدا با API 0.8.7 سازگار بود؛ فقط موارد زیر بررسی/اصلاح شد:
//!   • `Env::var` / `Env::secret` / `Env::kv` → هر سه در 0.8.7 همان امضا را دارند.
//!   • `RouteContext::var` / `secret` / `kv` → بدون تغییر.
//!   • `KvStore::get(key).text().await` → `Result<Option<String>, KvError>` و
//!     `From<KvError> for worker::Error` در 0.8.7 موجود است، پس `?` کار می‌کند.
//!   • `Request::json()` در 0.8.7 نیاز به `&mut self` دارد → پارامتر `mut req` حفظ شد.
//!   • `Response::ok(..)` / `with_headers(..)` / `console_log!` بدون تغییر.

use serde_json::json;
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get_async("/health", |_req, ctx| async move {
            Response::ok(
                json!({
                    "status": "ok",
                    "worker": "ghost-signaling",
                    "version": ctx.var("WORKER_VERSION")?.to_string()
                })
                .to_string(),
            )
        })
        .get_async("/config", |_req, ctx| async move {
            let kv = ctx.kv("GHOST_CONFIG")?;
            let config = kv
                .get("routing_config")
                .text()
                .await?
                .unwrap_or_else(|| "{}".to_string());

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Cache-Control", "no-store, no-cache")?;

            Ok(Response::ok(config)?.with_headers(headers))
        })
        .post_async("/session-init", |_req, ctx| async move {
            let hmac_secret = ctx.secret("HMAC_SECRET")?.to_string();
            let resp = json!({
                "hmac_key_hex": hmac_secret,
                "aes_key_hex": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "gas_endpoints": [],
                "config_version": "5.0.1"
            });
            Response::ok(resp.to_string())
        })
        .post_async("/admin/reload-config", |mut req, _ctx| async move {
            // This endpoint is called by GitHub Actions to notify workers of config changes.
            // Since workers read config lazily from KV on each request, we just acknowledge.
            let body: serde_json::Value = req.json().await.unwrap_or_default();
            console_log!("Config reload requested: {:?}", body);

            Response::ok(json!({"status": "acknowledged"}).to_string())
        })
        .run(req, env)
        .await
}
