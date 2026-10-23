/**
 * sw.js — SCP-GHOST Service Worker
 *
 * این Service Worker:
 *   ۱. Wasm module را import و init می‌کند
 *   ۲. Config را از Signaling Worker می‌خواند و Router را init می‌کند
 *   ۳. هر fetch event را intercept می‌کند
 *   ۴. با route_request() تصمیم می‌گیرد (Streaming vs Deny)
 *   ۵. درخواست‌های Streaming را به CF Worker pipe می‌کند
 *   ۶. در beforeunload، PhantomSession را destroy می‌کند
 *
 * توجه: GAS (Google Apps Script) به طور کامل از معماری حذف شده است.
 * تمام ترافیک از مسیر Streaming می‌گذرد.
 *
 * این فایل یک ES Module Service Worker است.
 * ثبت آن در index.html با { type: 'module' } انجام می‌شود.
 */

// ──────────────────────────────────────────────────────────────
//  Endpoint URLs — توسط deploy-pages.yml در زمان build inject می‌شوند
// ──────────────────────────────────────────────────────────────
const STREAMING_WORKER_URL = "__CF_STREAMING_URL__";
const SIGNALING_WORKER_URL = "__CF_SIGNALING_URL__";

// ──────────────────────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────────────────────
const WASM_MODULE_PATH = "./wasm/ghost_wasm.js";
const CONFIG_CACHE_KEY  = "ghost-routing-config-v5";
const SW_VERSION        = "5.1.2";   // 5.1.2: رفع race شرط WASM_READY / INIT_SESSION

// ──────────────────────────────────────────────────────────────
//  State — module-level (در Worker thread زندگی می‌کند)
// ──────────────────────────────────────────────────────────────
let wasmModule    = null;   // exports از ghost_wasm.js
let session       = null;   // PhantomSession instance
let routerReady   = false;  // آیا init_router() صدا زده شده؟
let wasmReady     = false;  // آیا wasm import + ()default اجرا شده؟
let initPromise   = null;   // init در جریان — جلوگیری از اجرای موازی

// ──────────────────────────────────────────────────────────────
//  Lifecycle: install
// ──────────────────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  console.log(`[Ghost SW ${SW_VERSION}] Installing...`);
  // skipWaiting: فوری فعال شود بدون انتظار برای بسته شدن tab های قدیمی
  event.waitUntil(self.skipWaiting());
});

// ──────────────────────────────────────────────────────────────
//  Lifecycle: activate
// ──────────────────────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  console.log(`[Ghost SW ${SW_VERSION}] Activating...`);
  event.waitUntil(
    (async () => {
      // کنترل تمام client های باز را فوری بگیر
      await self.clients.claim();
      // Wasm را بارگذاری و Router را init کن
      await initializeGhostSystem();
    })()
  );
});

// ──────────────────────────────────────────────────────────────
//  Lifecycle: fetch — قلب Service Worker
// ──────────────────────────────────────────────────────────────
self.addEventListener("fetch", (event) => {
  const url = event.request.url;

  // درخواست‌های داخلی Service Worker را رد کن
  if (url.includes("/wasm/") || url === SIGNALING_WORKER_URL + "/config") {
    return; // به مرورگر اجازه می‌دهیم مستقیم fetch کند
  }

  // فقط درخواست‌هایی که باید proxy شوند را intercept کن
  if (!shouldProxy(url)) {
    return;
  }

  event.respondWith(handleFetch(event.request));
});

// ──────────────────────────────────────────────────────────────
//  Lifecycle: message — ارتباط با main thread
// ──────────────────────────────────────────────────────────────
self.addEventListener("message", (event) => {
  const { type, payload } = event.data || {};

  switch (type) {
    case "INIT_SESSION":
      // waitUntil: بدون آن، مرورگر می‌تواند SW را وسط init خاموش کند
      event.waitUntil(handleInitSession(payload, event));
      break;

    case "DESTROY":
      // beforeunload در main thread این را می‌فرستد
      destroySession();
      break;

    case "GET_STATUS":
      event.ports[0]?.postMessage(getStatus());
      break;

    case "PING":
      // بررسی فعال: main thread لازم نیست منتظر broadcast بماند.
      // اگر Wasm/Config هنوز آماده نیست، همین‌جا init می‌شود.
      event.waitUntil(
        (async () => {
          if (!wasmReady || !routerReady) {
            await initializeGhostSystem().catch((err) =>
              console.error("[Ghost SW] PING init failed:", err)
            );
          }
          event.ports[0]?.postMessage(getStatus());
        })()
      );
      break;

    case "RELOAD_CONFIG":
      // GitOps notify بعد از sync جدید
      event.waitUntil(initializeGhostSystem({ force: true }).catch(console.error));
      break;

    default:
      console.warn(`[Ghost SW] Unknown message type: ${type}`);
  }
});

// ──────────────────────────────────────────────────────────────
//  Core: مقداردهی اولیه سیستم Ghost
// ──────────────────────────────────────────────────────────────
async function initializeGhostSystem({ force } = {}) {
  try {
    // idempotent: اگر前に conclu شده، اجرا دوباره نکن
    if (!force && wasmModule && routerReady) {
      return;
    }

    console.log("[Ghost SW] Initializing Ghost system...");

    // ── Step 1: Import و Init Wasm Module ──────────────────
    if (!wasmModule) {
      const { default: init, ...exports } = await import(WASM_MODULE_PATH);
      await init(); // Wasm binary را لود می‌کند
      wasmModule = exports;
      wasmReady = true;
      console.log("[Ghost SW] ✅ Wasm module loaded");

      // broadcast WASM_READY به کل client هاست (UI Connect دکمه را فعال می‌کند)
      notifyClients({ type: "WASM_READY", version: SW_VERSION });
    }

    // ── Step 2: دریافت Config از Signaling Worker ──────────
    const configJson = await fetchRoutingConfig();
    if (!configJson) {
      console.error("[Ghost SW] ❌ Failed to fetch routing config");
      return;
    }

    // ── Step 3: Init Router با Config ─────────────────────
    if (!wasmModule.is_router_initialized()) {
      wasmModule.init_router(configJson);
      console.log("[Ghost SW] ✅ Declarative Router initialized");
    }

    routerReady = true;
    console.log("[Ghost SW] ✅ System ready — all traffic routed to streaming backend");

    // اطلاع به تمام client های باز
    notifyClients({ type: "GHOST_READY", version: SW_VERSION });

  } catch (err) {
    console.error("[Ghost SW] ❌ Initialization failed:", err);
    routerReady = false;
    wasmReady = false;
  }
}

// ──────────────────────────────────────────────────────────────
//  Core: دریافت Routing Config از Signaling Worker
// ──────────────────────────────────────────────────────────────
async function fetchRoutingConfig() {
  try {
    // ابتدا بررسی Cache
    const cache = await caches.open(CONFIG_CACHE_KEY);
    const cached = await cache.match("/routing-config");
    if (cached) {
      const age = cached.headers.get("x-ghost-cache-age");
      const now = Date.now();
      // Cache TTL: 5 دقیقه
      if (age && now - parseInt(age) < 5 * 60 * 1000) {
        console.log("[Ghost SW] Config loaded from cache");
        return cached.text();
      }
    }

    // درخواست از Signaling Worker
    const resp = await fetch(`${SIGNALING_WORKER_URL}/config`, {
      method: "GET",
      headers: { "Accept": "application/json" },
    });

    if (!resp.ok) {
      throw new Error(`Config fetch failed: HTTP ${resp.status}`);
    }

    const configJson = await resp.text();

    // ذخیره در Cache با timestamp
    const cachedResponse = new Response(configJson, {
      headers: {
        "Content-Type": "application/json",
        "x-ghost-cache-age": Date.now().toString(),
      },
    });
    await cache.put("/routing-config", cachedResponse);

    console.log("[Ghost SW] Config fetched from Signaling Worker and cached");
    return configJson;

  } catch (err) {
    console.error("[Ghost SW] Config fetch error:", err);
    return null;
  }
}

// ──────────────────────────────────────────────────────────────
//  Core: مدیریت Fetch — تصمیم‌گیری routing
// ──────────────────────────────────────────────────────────────
async function handleFetch(request) {
  // اگر سیستم آماده نیست، مستقیم pass-through کن
  if (!routerReady || !wasmModule) {
    console.warn("[Ghost SW] Router not ready — pass-through");
    return fetch(request);
  }

  // اگر Session وجود ندارد، نمی‌توانیم HMAC بسازیم
  if (!session) {
    console.warn("[Ghost SW] No active session — pass-through");
    return fetch(request);
  }

  const url = request.url;
  const contentType = request.headers.get("Content-Type") || "";
  const contentLength = parseInt(request.headers.get("Content-Length") || "-1", 10);

  try {
    // ── تصمیم‌گیری routing توسط Rust Router ───────────────
    const decisionJson = wasmModule.route_request(url, contentType, contentLength);
    const decision = JSON.parse(decisionJson);

    console.debug(`[Ghost SW] Route decision for ${url}:`, decision.matched_rule, "→", decision.backend);

    if (decision.is_denied) {
      return new Response(
        JSON.stringify({ error: decision.deny_message, url }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    switch (decision.backend) {
      case "cloudflare-stream-worker":
        return handleStreamingRequest(request, decision);

      case "cloudflare-signaling-worker":
        return fetch(request); // signaling را مستقیم می‌فرستیم

      default:
        console.warn("[Ghost SW] Unknown backend:", decision.backend);
        return fetch(request);
    }

  } catch (err) {
    console.error("[Ghost SW] Routing error:", err);
    // در صورت خطا، pass-through (graceful degradation)
    return fetch(request);
  }
}

// ──────────────────────────────────────────────────────────────
//  Streaming Path — ویدیو → Cloudflare Worker (ReadableStream)
// ──────────────────────────────────────────────────────────────
async function handleStreamingRequest(request, decision) {
  try {
    // ساخت HMAC-signed URL توسط PhantomSession در Wasm
    const signedUrl = session.build_stream_url(request.url);

    // انتقال Range header برای DASH segment support
    const headers = {};
    const rangeHeader = request.headers.get("Range");
    if (rangeHeader) {
      headers["Range"] = rangeHeader;
    }

    const streamResp = await fetch(signedUrl, {
      method: "GET",
      headers,
    });

    if (!streamResp.ok && streamResp.status !== 206) {
      throw new Error(`Streaming Worker returned HTTP ${streamResp.status}`);
    }

    // بازگرداندن ReadableStream مستقیم به مرورگر
    // هیچ buffer‌ای در Service Worker نگه داشته نمی‌شود
    return new Response(streamResp.body, {
      status: streamResp.status,
      headers: {
        "Content-Type": streamResp.headers.get("Content-Type") || "video/mp4",
        "Content-Range": streamResp.headers.get("Content-Range") || "",
        "Accept-Ranges": "bytes",
        "X-Ghost-Path": "streaming",
      },
    });

  } catch (err) {
    console.error("[Ghost SW] Streaming error:", err);
    return new Response("Streaming Error", { status: 502 });
  }
}

// ──────────────────────────────────────────────────────────────
//  Session Management
// ──────────────────────────────────────────────────────────────
async function handleInitSession(payload, event) {
  const MAX_RETRIES = 5;
  const RETRY_MS = 500;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      if (!wasmModule) {
        throw new Error("Wasm module not loaded. Call INIT_SESSION after SW is ready.");
      }

      const { hmacKeyHex, aesKeyHex, gasEndpointsJson } = payload;

      // ساخت PhantomSession — کلیدها در Rust/Wasm با ZeroizeOnDrop مدیریت می‌شوند
      session = new wasmModule.PhantomSession(
        hmacKeyHex,
        aesKeyHex,
        STREAMING_WORKER_URL,
        SIGNALING_WORKER_URL,
        gasEndpointsJson
      );

      console.log("[Ghost SW] ✅ PhantomSession created");
      event.ports[0]?.postMessage({ success: true });
      return;

    } catch (err) {
      console.error(`[Ghost SW] Session init error (attempt ${attempt}/${MAX_RETRIES}):`, err);

      // فقط در صورت loading되지 بودن wasm، تلاش مجدد کن
      const isLoadError =
        err.message && err.message.includes("Wasm module not loaded") && attempt < MAX_RETRIES;

      if (!isLoadError) {
        event.ports[0]?.postMessage({ success: false, error: err.message });
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, RETRY_MS));
    }
  }

  // هر ۵ تلاش هم شکست خورد
  event.ports[0]?.postMessage({
    success: false,
    error: "Wasm module still not loaded after retries — UI should wait for WASM_READY.",
  });
}

function destroySession() {
  if (session) {
    try {
      session.destroy(); // ZeroizeOnDrop — کلیدها از حافظه پاک می‌شوند
      session = null;
      console.log("[Ghost SW] ✅ PhantomSession destroyed — keys zeroized");
    } catch (err) {
      console.error("[Ghost SW] Session destroy error:", err);
    }
  }
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

/**
 * آیا این URL باید توسط Ghost proxy شود؟
 * URL های محلی (localhost، chrome-extension، etc.) را رد می‌کند.
 */
function shouldProxy(url) {
  // URL های داخلی خود سایت را proxy نکن
  if (url.startsWith(self.registration.scope)) {
    return false;
  }
  // URL های مرورگر داخلی را رد کن
  const internalSchemes = ["chrome-extension://", "moz-extension://", "about:", "blob:"];
  if (internalSchemes.some((s) => url.startsWith(s))) {
    return false;
  }
  // فقط http/https
  return url.startsWith("http://") || url.startsWith("https://");
}

function getStatus() {
  return {
    version: SW_VERSION,
    routerReady,
    hasSession: session !== null,
    wasmLoaded: wasmModule !== null,
    sessionStats: session ? session.stats() : null,
  };
}

async function notifyClients(message) {
  const clients = await self.clients.matchAll({ type: "window" });
  clients.forEach((client) => client.postMessage(message));
}
