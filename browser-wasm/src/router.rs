//! router.rs — Nginx-Inspired Declarative Router
//!
//! این ماژول داخل Browser Service Worker به صورت Wasm اجرا می‌شود.
//! هیچ hardcode routing logic وجود ندارد —
//! تمام تصمیمات از JSON Config که از Cloudflare KV لود می‌شود می‌آید.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ══════════════════════════════════════════════════════════════
//  Data Structures — سازگار با ghost-routing-config.json
// ══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    CloudflareStreamWorker,
    CloudflareSignalingWorker,
    GoogleAppsScriptPool,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MatchRule {
    pub url_patterns: Vec<String>,
    #[serde(default)]
    pub min_size_bytes: Option<u64>,
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    #[serde(default)]
    pub content_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Action {
    pub backend: BackendType,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub pipe_mode: Option<String>,
    #[serde(default)]
    pub hmac_required: bool,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub endpoints: Option<Vec<String>>,
    #[serde(default)]
    pub failover: Option<String>,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingRule {
    pub name: String,
    pub priority: u8,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(rename = "match")]
    pub match_rule: MatchRule,
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimits {
    pub streaming_rpm: u32,
    pub buffered_rpm: u32,
    pub window_seconds: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhostConfig {
    pub version: String,
    pub routing_rules: Vec<RoutingRule>,
    pub rate_limits: RateLimits,
}

// ══════════════════════════════════════════════════════════════
//  RouteDecision — نتیجه‌ای که به JavaScript برگردانده می‌شود
// ══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct RouteDecision {
    /// نام rule که match شد
    pub matched_rule: String,
    /// backend تصمیم‌گیری شده
    pub backend: String,
    /// endpoint مقصد (اگر وجود داشته باشد)
    pub endpoint: Option<String>,
    /// آیا HMAC لازم است؟
    pub hmac_required: bool,
    /// pipe_mode (ReadableStream / WebSocket / null)
    pub pipe_mode: Option<String>,
    /// timeout بر حسب میلی‌ثانیه
    pub timeout_ms: u64,
    /// برای Apps Script Pool: endpoint انتخاب شده بر اساس round_robin
    pub selected_gas_endpoint: Option<String>,
    /// آیا این درخواست باید رد شود؟
    pub is_denied: bool,
    /// پیام خطا اگر denied بود
    pub deny_message: Option<String>,
}

// ══════════════════════════════════════════════════════════════
//  DeclarativeRouter — موتور اصلی Routing
// ══════════════════════════════════════════════════════════════

pub struct DeclarativeRouter {
    rules: Vec<RoutingRule>,
    gas_round_robin_counter: std::cell::Cell<usize>,
}

impl DeclarativeRouter {
    /// ساخت Router از JSON Config
    /// Config از Cloudflare KV خوانده شده و به عنوان string پاس داده می‌شود.
    /// هیچ hardcode‌ای وجود ندارد.
    pub fn from_config_json(json: &str) -> Result<Self, String> {
        let mut config: GhostConfig =
            serde_json::from_str(json).map_err(|e| format!("Config parse error: {e}"))?;

        // مرتب‌سازی بر اساس priority — دقیقاً مثل Nginx
        // location با دقت بیشتر (priority کمتر) اول اجرا می‌شود
        config.routing_rules.sort_by_key(|r| r.priority);

        // اطمینان از وجود default_deny
        let has_deny = config
            .routing_rules
            .iter()
            .any(|r| r.action.backend == BackendType::Deny);

        if !has_deny {
            return Err("Config must contain a 'deny' backend rule (default_deny).".to_string());
        }

        Ok(Self {
            rules: config.routing_rules,
            gas_round_robin_counter: std::cell::Cell::new(0),
        })
    }

    /// تصمیم‌گیری routing برای یک درخواست
    /// url: URL کامل درخواست
    /// content_type: اختیاری — از HTTP header
    /// size_hint: اختیاری — اندازه تخمینی از Content-Length
    pub fn route(
        &self,
        url: &str,
        content_type: Option<&str>,
        size_hint: Option<u64>,
    ) -> RouteDecision {
        for rule in &self.rules {
            if self.rule_matches(&rule.match_rule, url, content_type, size_hint) {
                return self.build_decision(rule);
            }
        }
        // این خط هرگز نباید اجرا شود — default_deny همیشه match می‌کند
        RouteDecision {
            matched_rule: "fallback_deny".to_string(),
            backend: "deny".to_string(),
            endpoint: None,
            hmac_required: false,
            pipe_mode: None,
            timeout_ms: 0,
            selected_gas_endpoint: None,
            is_denied: true,
            deny_message: Some("Internal: No rule matched.".to_string()),
        }
    }

    fn rule_matches(
        &self,
        rule: &MatchRule,
        url: &str,
        content_type: Option<&str>,
        size_hint: Option<u64>,
    ) -> bool {
        // URL Pattern check
        let url_lower = url.to_lowercase();
        let pattern_ok = rule
            .url_patterns
            .iter()
            .any(|p| self.glob_match(&p.to_lowercase(), &url_lower));

        if !pattern_ok {
            return false;
        }

        // min_size check
        if let Some(min) = rule.min_size_bytes {
            match size_hint {
                Some(sz) if sz >= min => {}
                Some(_) => return false,
                // اگر size_hint نداریم و min_size تعریف شده،
                // از content_type برای تشخیص ویدیو استفاده می‌کنیم
                None => {
                    if let Some(ct) = content_type {
                        if !ct.starts_with("video/") && !ct.starts_with("application/octet") {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }

        // max_size check
        if let Some(max) = rule.max_size_bytes {
            if size_hint.unwrap_or(0) > max {
                return false;
            }
        }

        // content_type check
        if let Some(allowed_types) = &rule.content_types {
            if let Some(ct) = content_type {
                let ct_lower = ct.to_lowercase();
                let type_ok = allowed_types
                    .iter()
                    .any(|allowed| ct_lower.starts_with(allowed.as_str()));
                if !type_ok {
                    return false;
                }
            }
            // اگر content_type نداریم اما rule آن را نیاز دارد،
            // فقط بر اساس URL pattern تصمیم می‌گیریم (permissive)
        }

        true
    }

    fn build_decision(&self, rule: &RoutingRule) -> RouteDecision {
        let is_denied = rule.action.backend == BackendType::Deny;

        // برای Apps Script Pool: Round-Robin انتخاب endpoint
        let selected_gas_endpoint = if rule.action.backend == BackendType::GoogleAppsScriptPool {
            rule.action.endpoints.as_ref().and_then(|eps| {
                if eps.is_empty() {
                    return None;
                }
                // Atomic round-robin بدون race condition — single-threaded Wasm
                let idx = self.gas_round_robin_counter.get();
                let selected = eps[idx % eps.len()].clone();
                self.gas_round_robin_counter.set(idx.wrapping_add(1));
                Some(selected)
            })
        } else {
            None
        };

        RouteDecision {
            matched_rule: rule.name.clone(),
            backend: format!("{:?}", rule.action.backend)
                .to_lowercase()
                .replace("_", "-"),
            endpoint: rule.action.endpoint.clone(),
            hmac_required: rule.action.hmac_required,
            pipe_mode: rule.action.pipe_mode.clone(),
            timeout_ms: rule.action.timeout_ms,
            selected_gas_endpoint,
            is_denied,
            deny_message: if is_denied {
                rule.action.message.clone()
            } else {
                None
            },
        }
    }

    /// Glob Matching — * هر substring را match می‌کند
    /// پشتیبانی از: *.domain.com/*, */path/*, *extension
    fn glob_match(&self, pattern: &str, text: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        // بهینه‌سازی: اگر wildcard ندارد، مقایسه مستقیم
        if !pattern.contains('*') {
            return text == pattern || text.contains(pattern);
        }

        let parts: Vec<&str> = pattern.split('*').collect();
        let mut remaining = text;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 {
                // اول pattern باید با شروع text match کند
                if !remaining.starts_with(part) {
                    return false;
                }
                remaining = &remaining[part.len()..];
            } else if i == parts.len() - 1 {
                // آخرین part باید با انتها match کند
                if !remaining.ends_with(part) {
                    return false;
                }
                return true;
            } else {
                // وسط — پیدا کردن اولین وقوع
                match remaining.find(part) {
                    Some(idx) => remaining = &remaining[idx + part.len()..],
                    None => return false,
                }
            }
        }

        true
    }
}

// ══════════════════════════════════════════════════════════════
//  wasm-bindgen Public API — قابل فراخوانی از JavaScript
// ══════════════════════════════════════════════════════════════

/// نگه‌داری Router در static state — یک بار init، همیشه استفاده
static ROUTER: std::sync::OnceLock<DeclarativeRouter> = std::sync::OnceLock::new();

/// مقداردهی اولیه Router از JSON Config
/// باید یک بار در ابتدای Service Worker فراخوانی شود.
/// config_json: محتوای ghost-routing-config.json که از KV خوانده شده
#[wasm_bindgen]
pub fn init_router(config_json: &str) -> Result<(), JsValue> {
    match DeclarativeRouter::from_config_json(config_json) {
        Ok(router) => {
            ROUTER
                .set(router)
                .map_err(|_| JsValue::from_str("Router already initialized"))?;
            Ok(())
        }
        Err(e) => Err(JsValue::from_str(&e)),
    }
}

/// تصمیم‌گیری routing — فراخوانی از Service Worker fetch handler
/// بازگشت: JSON string حاوی RouteDecision
/// مثال فراخوانی در JS:
///   const decision = JSON.parse(route_request(url, contentType, sizeHint));
#[wasm_bindgen]
pub fn route_request(
    url: &str,
    content_type: &str,
    size_hint: i64, // i64 چون JS number می‌تواند منفی باشد (ناشناخته = -1)
) -> Result<String, JsValue> {
    let router = ROUTER
        .get()
        .ok_or_else(|| JsValue::from_str("Router not initialized. Call init_router() first."))?;

    let ct = if content_type.is_empty() {
        None
    } else {
        Some(content_type)
    };

    let sz = if size_hint < 0 {
        None
    } else {
        Some(size_hint as u64)
    };

    let decision = router.route(url, ct, sz);

    serde_json::to_string(&decision)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// بررسی اینکه Router مقداردهی اولیه شده است یا نه
#[wasm_bindgen]
pub fn is_router_initialized() -> bool {
    ROUTER.get().is_some()
}
