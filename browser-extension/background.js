/**
 * background.js — MV3 Service Worker
 *
 * ══════════════════════════════════════════════════════════════
 *  چرا این فایل خودش X25519/HMAC را پیاده نمی‌کند؟
 * ══════════════════════════════════════════════════════════════
 *  همان Wasm کامپایل‌شدهٔ پروژه (browser-wasm) اینجا import می‌شود:
 *    • SessionHandshake → X25519 + HKDF + AES-GCM unwrap
 *    • PhantomSession   → HMAC-SHA256 + ساخت URL امضاشده
 *  این دقیقاً همان کدی است که در docs/index.html و docs/sw.js تست
 *  شده. بازنویسی آن در JS تنها منبع شناخته‌شدهٔ 403 (اختلاف کلید
 *  یا پیام) را دوباره باز می‌کرد.
 *
 *  ══════════════════════════════════════════════════════════════
 *  مشکل خوابیدن Service Worker در MV3
 *  ══════════════════════════════════════════════════════════════
 *  Chrome بعد از ~۳۰ ثانیه بی‌کاری SW را می‌کشد و کل حافظهٔ ماژول
 *  (از جمله PhantomSession و کلیدهای داخل آن) از بین می‌رود.
 *
 *  راه‌حل — دو لایه:
 *    ۱. پس از handshake، کلیدهای مشتق‌شده (hmac/aes hex) در
 *       chrome.storage.session ذخیره می‌شوند: حافظه‌ای، رمزنگاری‌نشده
 *       روی دیسک، و پس از بستن مرورگر پاک می‌شود.
 *    ۲. کلید خصوصی موقت X25519 هرگز ذخیره نمی‌شود (نباید بشود).
 *       در عوض هر بار که SW بیدار می‌شود، PhantomSession فقط از روی
 *       همان کلیدهای ذخیره‌شده بازسازی می‌شود — بدون شبکه.
 *
 *  نتیجه: هیچ alarm و هیچ keepalive هکی لازم نیست؛ خواب SW
 *  session را از بین نمی‌برد. (seq پس از بیداری از ۰ شروع می‌شود که
 *  بی‌خطر است — ورکر پنجرهٔ replay ندارد.)
 */

import initWasm, * as wasm from "./wasm/ghost_wasm.js?v=5.2.6";

const SIGNALING_URL = "https://ghost-signaling-worker.cocoon-de9.workers.dev";
const STREAMING_URL = "https://ghost-streaming-worker.cocoon-de9.workers.dev";
const VERSION = "5.2.6";

const STORAGE_KEY = "ghost_session";

// ── وضعیت درون‌حافظه‌ای (با خواب SW پاک می‌شود) ──────────────────
let session = null;

// ── Wasm: یک‌بار در هر عمر SW ───────────────────────────────────
let wasmReady = null;
function ensureWasm() {
  if (!wasmReady) {
    wasmReady = initWasm({
      module_or_path: new URL(`./wasm/ghost_wasm_bg.wasm?v=${VERSION}`, import.meta.url),
    }).then(() => wasm);
  }
  return wasmReady;
}

// ── ذخیره/بازیابی ───────────────────────────────────────────────
// storage.session: فقط در حافظه، مخصوص MV3؛ با بستن مرورگر پاک می‌شود.
async function saveSession(state) {
  await chrome.storage.session.set({ [STORAGE_KEY]: state });
}

async function loadSession() {
  const result = await chrome.storage.session.get(STORAGE_KEY);
  return result?.[STORAGE_KEY] || null;
}

async function clearSession() {
  await chrome.storage.session.remove(STORAGE_KEY);
}

/**
 * PhantomSession را از روی کلیدهای ذخیره‌شده بازسازی می‌کند.
 * اگر SW خوابیده باشد، اولین فراخوانی پس از بیداری همین‌جا انجام
 * می‌شود — بدون هیچ درخواست شبکه‌ای.
 */
async function rehydrate() {
  if (session) return session;

  const state = await loadSession();
  if (!state?.hmacKeyHex || !state?.aesKeyHex) return null;

  const mod = await ensureWasm();
  // امضای سازنده ۵ آرگومان است. شمارندهٔ seq پس از بیداری از ۰ شروع
  // می‌شود؛ این بی‌خطر است چون ورکر فقط امضای (target:seq) را بررسی
  // می‌کند و پنجرهٔ replay ندارد.
  session = new mod.PhantomSession(
    state.hmacKeyHex,
    state.aesKeyHex,
    STREAMING_URL,
    SIGNALING_URL,
    "[]"
  );
  return session;
}

// ── CONNECT: handshake واقعی + ذخیرهٔ کلیدها ────────────────────
async function connect() {
  const mod = await ensureWasm();

  // کلید خصوصی فقط در حافظهٔ Wasm می‌ماند و هرگز ذخیره نمی‌شود
  const handshake = new mod.SessionHandshake();

  let resp;
  try {
    resp = await fetch(`${SIGNALING_URL}/session-init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_pubkey: handshake.public_key_b64(),
        client_version: VERSION,
      }),
    });
  } catch (err) {
    handshake.free?.();
    throw new Error(`network/CORS: ${err.message}`);
  }

  if (!resp.ok) {
    const detail = (await resp.text()).slice(0, 200);
    handshake.free?.();
    throw new Error(`signaling HTTP ${resp.status}: ${detail}`);
  }

  const data = await resp.json();
  if (!data.server_pubkey || !data.salt || !data.wrapped) {
    handshake.free?.();
    throw new Error("incomplete handshake response");
  }

  let keys;
  try {
    keys = JSON.parse(
      handshake.complete(data.server_pubkey, data.salt, data.wrapped)
    );
  } finally {
    handshake.free?.();
  }

  session = new mod.PhantomSession(
    keys.hmac_key_hex,
    keys.aes_key_hex,
    STREAMING_URL,
    SIGNALING_URL,
    "[]"
  );

  await saveSession({
    hmacKeyHex: keys.hmac_key_hex,
    aesKeyHex: keys.aes_key_hex,
    seq: 0,
    connectedAt: Date.now(),
    configVersion: data.config_version || null,
  });

  return { configVersion: data.config_version || null };
}

async function disconnect() {
  try {
    session?.destroy?.();
  } catch (_) {
    /* zeroize best-effort */
  }
  session = null;
  try {
    await clearSession();
  } catch (_) {
    /* storage may be unavailable in a dying SW */
  }
}

// ── درخواست امضاشده ────────────────────────────────────────────
/**
 * target باید در allowlist ورکر باشد (YouTube / Google CDN).
 * امضا و URL دقیقاً توسط PhantomSession (همان Wasm وب) ساخته می‌شود.
 */
async function signedFetch(targetUrl) {
  const active = await rehydrate();
  if (!active) throw new Error("not connected");

  const signedUrl = active.build_stream_url(targetUrl);

  // seq را بعد از هر امضا ذخیره کن تا پس از خواب SW هم ادامه یابد
  const state = await loadSession();
  if (state) {
    const seq = Number(new URL(signedUrl).searchParams.get("seq"));
    if (Number.isFinite(seq)) await saveSession({ ...state, seq: seq + 1 });
  }

  const resp = await fetch(signedUrl, { method: "GET", cache: "no-store" });
  const body = await resp.text();

  return {
    status: resp.status,
    ok: resp.ok,
    path: resp.headers.get("X-Ghost-Path") || null,
    body: body.slice(0, 2000),
  };
}

// ── STATus برای popup ───────────────────────────────────────────
async function status() {
  const state = await loadSession();
  const active = await rehydrate().catch(() => null);

  return {
    connected: Boolean(state),
    // اگر SW خوابیده بود ولی کلیدها هستند، همین حالا بازسازی شده است
    hydrated: Boolean(active),
    configVersion: state?.configVersion || null,
    connectedAt: state?.connectedAt || null,
    seq: state?.seq ?? null,
    streamingUrl: STREAMING_URL,
    version: VERSION,
  };
}

// ── Router پیام‌ها ──────────────────────────────────────────────
const handlers = {
  CONNECT: connect,
  DISCONNECT: disconnect,
  STATUS: status,
  SIGNED_FETCH: (msg) => signedFetch(msg.target),
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) {
    sendResponse({ ok: false, error: `unknown message: ${msg?.type}` });
    return false;
  }

  Promise.resolve()
    .then(() => handler(msg))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));

  return true; // پاسخ async
});

// در دسترس بودن برای تست Node (بدون تأثیر در مرورگر)
export { connect, disconnect, status, signedFetch, handlers };
