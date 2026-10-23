use worker::*;
use serde_json::json;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get_async("/health", |_req, ctx| async move {
            Response::ok(json!({
                "status": "ok",
                "worker": "ghost-signaling",
                "version": ctx.var("WORKER_VERSION")?.to_string()
            }).to_string())
        })
        .get_async("/config", |_req, ctx| async move {
            let kv = ctx.kv("GHOST_CONFIG")?;
            let config = kv.get("routing_config").text().await?.unwrap_or_else(|| "{}".to_string());
            
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Cache-Control", "no-store, no-cache")?;
            
            Ok(Response::ok(config)?.with_headers(headers))
        })
        .post_async("/session-init", |mut _req, ctx| async move {
            let hmac_secret = ctx.secret("HMAC_SECRET")?.to_string();
            let resp = serde_json::json!({
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
