/**
 * test_extension.mjs — تست خودکار افزونه بدون مرورگر
 *
 * چه چیزی واقعاً تست می‌شود:
 *   ۱. background.js واقعی import می‌شود (نه یک کپی).
 *   ۲. chrome.* با mock در حافظه جایگزین می‌شود.
 *   ۳. یک signaling-worker واقعی در Node پیاده می‌شود
 *      (X25519 + HKDF-SHA256 + AES-256-GCM) تا handshake کامل شود.
 *   ۴. URL ساخته‌شده توسط Wasm با «منطق دقیق ورکر» تأیید می‌شود —
 *      همان چیزی که 403 می‌داد.
 *   ۵. خوابیدن Service Worker شبیه‌سازی می‌شود تا ثابت شود
 *      chrome.storage.session کلیدها را حفظ می‌کند.
 *
 * اجرا: node scripts/test_extension.mjs
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const EXT = path.join(ROOT, "browser-extension");

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  ${detail}` : ""}`);
};

// ══════════════════════════════════════════════════════════════
//  ۱. Mock chrome.*
// ══════════════════════════════════════════════════════════════
const memorySession = {};
let storedAt;

globalThis.chrome = {
  storage: {
    session: {
      get: async (key) => (key in memorySession ? { [key]: structuredClone(memorySession[key]) } : {}),
      set: async (obj) => {
        Object.assign(memorySession, structuredClone(obj));
        storedAt = Date.now();
      },
      remove: async (key) => {
        delete memorySession[key];
      },
    },
  },
  runtime: {
    onMessage: { addListener: (fn) => (globalThis.__listener = fn) },
    lastError: null,
  },
  tabs: { query: async () => [], sendMessage: async () => {} },
  declarativeNetRequest: { updateDynamicRules: async () => {} },
  proxy: { settings: { set: async () => {}, clear: async () => {} } },
};

// ══════════════════════════════════════════════════════════════
//  ۲. signaling-worker واقعی (سمت سرور) در Node
// ══════════════════════════════════════════════════════════════
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex"); // Ed25519/X25519 SPKI
const rawPub = (pubKey) => pubKey.export({ type: "spki", format: "der" }).subarray(-32);
const importX25519 = (raw) =>
  crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });

const SERVER_HMAC_HEX = crypto.randomBytes(32).toString("hex");
const SERVER_AES_HEX = crypto.randomBytes(32).toString("hex");

const AAD_PREFIX = Buffer.from("ghost/session/v1");
const HKDF_INFO = Buffer.from("ghost/session-kek/v1");

function sessionInit(clientPubB64) {
  const clientRaw = Buffer.from(clientPubB64, "base64");
  if (clientRaw.length !== 32) return { status: 400, body: "client_pubkey must be 32 bytes" };

  const { publicKey: serverPub, privateKey: serverPriv } = crypto.generateKeyPairSync("x25519");
  const serverRaw = rawPub(serverPub);

  const shared = crypto.diffieHellman({ privateKey: serverPriv, publicKey: importX25519(clientRaw) });
  const salt = crypto.randomBytes(32);
  const kek = Buffer.from(crypto.hkdfSync("sha256", shared, salt, HKDF_INFO, 32));

  const aad = Buffer.concat([AAD_PREFIX, clientRaw, serverRaw]);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", kek, nonce);
  cipher.setAAD(aad);

  const plaintext = Buffer.from(
    JSON.stringify({ hmac_key_hex: SERVER_HMAC_HEX, aes_key_hex: SERVER_AES_HEX })
  );
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  return {
    status: 200,
    body: {
      protocol: "x25519-hkdf-sha256-aesgcm-v1",
      server_pubkey: serverRaw.toString("base64"),
      salt: salt.toString("base64"),
      wrapped: Buffer.concat([nonce, ct]).toString("base64"),
      gas_endpoints: [],
      config_version: "5.2.6",
    },
  };
}

// ══════════════════════════════════════════════════════════════
//  ۳. mock fetch: signaling + streaming-worker با verify واقعی
// ══════════════════════════════════════════════════════════════
const seen = { sessionInit: 0, stream: [] };

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);

  if (u.endsWith("/session-init")) {
    seen.sessionInit++;
    const payload = JSON.parse(init.body);
    const result = sessionInit(payload.client_pubkey);
    return new Response(
      typeof result.body === "string" ? result.body : JSON.stringify(result.body),
      { status: result.status, headers: { "Content-Type": "application/json" } }
    );
  }

  if (u.includes("/stream?")) {
    const parsed = new URL(u);
    const target = parsed.searchParams.get("target");
    const sig = parsed.searchParams.get("sig");
    const seq = parsed.searchParams.get("seq");

    // ── منطق دقیق streaming-worker/src/lib.rs (پس از v5.2.6) ──
    const message = `${target}:${seq}`;
    const hexKey = SERVER_HMAC_HEX; // secret در ورکر ذخیره می‌شود
    const derived = crypto.createHmac("sha256", Buffer.from(hexKey, "hex")).update(message).digest("hex");
    const validSig = derived === sig;

    seen.stream.push({ target, seq, sig, validSig });

    if (!validSig) {
      return new Response("Forbidden: Invalid HMAC signature", {
        status: 403,
        headers: { "Access-Control-Allow-Origin": "*" },
      });
    }

    return new Response("User-agent: *\nDisallow: /search", {
      status: 200,
      headers: { "Access-Control-Allow-Origin": "*", "X-Ghost-Path": "streaming" },
    });
  }

  return new Response("not found", { status: 404 });
};

// ══════════════════════════════════════════════════════════════
//  ۴. import کردن background.js واقعی
// ══════════════════════════════════════════════════════════════
console.log("=== extension under test ===");
for (const f of ["manifest.json", "background.js", "popup.html", "popup.js"]) {
  check(`exists: ${f}`, fs.existsSync(path.join(EXT, f)));
}

const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));
check("manifest is MV3", manifest.manifest_version === 3);
check("service worker is a module", manifest.background?.type === "module");
check("wasm-unsafe-eval CSP present", /wasm-unsafe-eval/.test(manifest.content_security_policy?.extension_pages || ""));
for (const p of ["proxy", "storage", "declarativeNetRequest", "tabs"]) {
  check(`permission: ${p}`, manifest.permissions.includes(p));
}

// ── Wasm را از قبل با همان specifier و همان بایت‌ها init می‌کنیم ──
// در مرورگر background.js خودش با URL افزونه init می‌کند؛ در Node
// fetch روی file:// کار نمی‌کند، پس اینجا یک‌بار init می‌شود. glue
// بعد از اولین init کش می‌کند و init دوم no-op است.
const glueSpecifier = path.join(EXT, "wasm/ghost_wasm.js") + "?v=5.2.6";
const glue = await import(glueSpecifier);
await glue.default({
  module_or_path: new Response(fs.readFileSync(path.join(EXT, "wasm/ghost_wasm_bg.wasm")), {
    headers: { "Content-Type": "application/wasm" },
  }),
});
console.log("\nWasm pre-initialized for Node (browser uses its own URL):",
  typeof glue.PhantomSession === "function" && typeof glue.SessionHandshake === "function");

// import واقعی (همان فایل، همان wasm)
const bg = await import(path.join(EXT, "background.js"));
check("background.js loaded + listener registered", typeof globalThis.__listener === "function");
check("background exports handlers", Boolean(bg.handlers?.CONNECT));

const call = (type, extra = {}) =>
  new Promise((resolve) => globalThis.__listener({ type, ...extra }, {}, resolve));

// ══════════════════════════════════════════════════════════════
//  ۵. سناریوها
// ══════════════════════════════════════════════════════════════
console.log("\n=== scenario 1: connect (real X25519 handshake) ===");
const before = await call("STATUS");
check("starts disconnected", before.ok && before.data.connected === false);

const conn = await call("CONNECT");
check("CONNECT ok", conn.ok, conn.ok ? `config=${conn.data.configVersion}` : conn.error);
check("session-init called once", seen.sessionInit === 1);

const st = await call("STATUS");
check("status reports connected", st.data.connected === true);
check("keys persisted in storage.session", typeof memorySession.ghost_session?.hmacKeyHex === "string");
check("NO private X25519 key persisted", !JSON.stringify(memorySession).match(/private|secret_key|seed/i));
const storedKeys = memorySession.ghost_session || {};
console.log(`   stored keys: hmac=${(storedKeys.hmacKeyHex || "").length} chars (hex), aes=${(storedKeys.aesKeyHex || "").length} chars`);

console.log("\n=== scenario 2: signed fetch — byte-perfect HMAC ===");
const probe = await call("SIGNED_FETCH", { target: "https://www.youtube.com/robots.txt" });
check("signed fetch HTTP 200 (not 403)", probe.ok && probe.data.status === 200, `status=${probe.data?.status}`);
check("X-Ghost-Path = streaming", probe.data?.path === "streaming");
const last = seen.stream.at(-1);
check("worker-side signature verify = true", last.validSig === true);
console.log(`   target=${last.target}`);
console.log(`   seq=${last.seq}  sig=${last.sig.slice(0, 16)}…`);
console.log(`   message="${last.target}:${last.seq}"  hex-keyed HMAC matches worker`);

// چند درخواست پشت‌سرهم (seq باید یکتا باشد)
for (let i = 0; i < 3; i++) {
  await call("SIGNED_FETCH", { target: `https://i.ytimg.com/vi/x${i}.jpg` });
}
check("all sequential requests verified", seen.stream.every((r) => r.validSig));
check("seq is unique per request", new Set(seen.stream.map((r) => r.seq)).size === seen.stream.length);

// ══════════════════════════════════════════════════════════════
//  ۶. شبیه‌سازی خواب MV3
// ══════════════════════════════════════════════════════════════
console.log("\n=== scenario 3: MV3 service worker sleep ===");
const storageBeforeSleep = structuredClone(memorySession);
check("storage.session survives (simulated)", Object.keys(storageBeforeSleep).includes("ghost_session"));

// SW کشته می‌شود: ماژول دوباره import می‌شود، حافظهٔ قبلی از بین می‌رود
const freshId = `background.js?wake=${Date.now()}`;
const bgAfterWake = await import(path.join(EXT, freshId));
check("fresh module instance loaded after wake", typeof bgAfterWake.status === "function");

// listener جدید ثبت شده؛ از آن استفاده کن
const callAfterWake = (type, extra = {}) =>
  new Promise((resolve) => globalThis.__listener({ type, ...extra }, {}, resolve));

const st2 = await callAfterWake("STATUS");
check("still connected after wake (no re-handshake)", st2.data.connected === true);
check("keys REHYDRATED from storage.session", st2.data.hydrated === true);
check("no extra session-init after wake", seen.sessionInit === 1, `session-init=${seen.sessionInit}`);

const afterWake = await callAfterWake("SIGNED_FETCH", { target: "https://www.youtube.com/robots.txt" });
check("signed fetch works after wake", afterWake.ok && afterWake.data.status === 200, `status=${afterWake.data?.status}`);
check("HMAC still valid after wake", seen.stream.at(-1).validSig === true);

// ══════════════════════════════════════════════════════════════
//  ۷. disconnect
// ══════════════════════════════════════════════════════════════
console.log("\n=== scenario 4: disconnect ===");
await callAfterWake("DISCONNECT");
check("storage.session cleared", !("ghost_session" in memorySession));

const st3 = await callAfterWake("STATUS");
check("status disconnected", st3.data.connected === false);

const blocked = await callAfterWake("SIGNED_FETCH", { target: "https://www.youtube.com/robots.txt" });
check("signed fetch refused after disconnect", blocked.ok === false);

const unknown = await callAfterWake("NOPE");
check("unknown message rejected", unknown.ok === false);

console.log(`\n${failures === 0 ? "✅ ALL PASS" : `❌ ${failures} FAILURE(S)`}`);
process.exit(failures ? 1 : 0);
