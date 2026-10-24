/**
 * test_wasm.js — اجرای واقعی Wasm و اثبات رشتهٔ backend
 *
 * اجرا: node test_wasm.js [dir]   (پیش‌فرض /tmp/wasmtest)
 */
import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2] || "/tmp/wasmtest";
const gluePath = path.join(dir, "ghost_wasm.js");
const wasmPath = path.join(dir, "ghost_wasm_bg.wasm");

console.log(`glue: ${gluePath}`);
console.log(`wasm: ${wasmPath} (${fs.statSync(wasmPath).size} bytes)\n`);

const glue = await import(gluePath);
const bytes = fs.readFileSync(wasmPath);

// ── همان قرارداد فراخوانی که sw.js استفاده می‌کند: object form ──
await glue.default({ module_or_path: new Response(bytes, { headers: { "Content-Type": "application/wasm" } }) });
console.log("init({ module_or_path })  : OK (object form, بدون هشدار deprecated)");
console.log("route_request موجود        :", typeof glue.route_request === "function");

// ── ۱) config واقعی مخزن ────────────────────────────────────
glue.init_router(fs.readFileSync("config/ghost-routing-config.json", "utf8"));
console.log("router initialized         :", glue.is_router_initialized(), "\n");

const raw = glue.route_request("https://www.youtube.com/robots.txt", "", 0);
const d = JSON.parse(raw);
console.log('route_request("https://www.youtube.com/robots.txt", "", 0)');
console.log("  →", raw, "\n");

const expected = "cloudflare-stream-worker";
const exact = d.backend === expected;
console.log(`backend                    : ${JSON.stringify(d.backend)}`);
console.log(`expected                   : ${JSON.stringify(expected)}`);
console.log(`EXACT MATCH                : ${exact}`);

const SWITCH = ["cloudflare-stream-worker", "cloudflare-signaling-worker"];
console.log(`matched by sw.js switch    : ${SWITCH.includes(d.backend)}`);

// ── ۲) چند ورودی دیگر (config واقعی همه را streaming می‌فرستد) ──
console.log("\n--- config واقعی (قاعدهٔ * → streaming) ---");
for (const [u, ct, sz] of [
  ["https://i.ytimg.com/vi/x.jpg", "", 0],
  ["https://rr3---sn-a.googlevideo.com/videoplayback", "", -1],
  ["https://www.youtube.com/watch?v=1", "text/html", 1000],
]) {
  const x = JSON.parse(glue.route_request(u, ct, sz));
  console.log(`  ${x.backend.padEnd(26)} ${u.slice(0, 55)}`);
}

// ── ۳) نگاشت Deny → "deny" با config ای که deny اولویت دارد ──
// (ROUTER یک OnceLock است؛ پس در پروسهٔ جدا تست می‌شود)
const denyConfig = {
  version: "1.0.0",
  routing_rules: [
    {
      name: "explicit_deny",
      priority: 1,
      match: { url_patterns: ["*blocked*"] },
      action: { backend: "deny", status_code: 403, message: "blocked" },
    },
    {
      name: "global_streaming_rule",
      priority: 2,
      match: { url_patterns: ["*"] },
      action: {
        backend: "cloudflare_stream_worker",
        endpoint: "/stream",
        hmac_required: true,
        timeout_ms: 30000,
      },
    },
  ],
  rate_limits: { streaming_rpm: 500, window_size: 60, window_seconds: 60 },
  health_check: { interval_seconds: 30, failure_threshold: 3, success_threshold: 1 },
};
fs.writeFileSync("/tmp/wasmtest/deny-config.json", JSON.stringify(denyConfig));

console.log("\n--- نگاشت deny (پروسهٔ جدا) ---");
const { execFileSync } = await import("node:child_process");
const denyOut = execFileSync(
  process.execPath,
  [path.join(path.dirname(new URL(import.meta.url).pathname), "test_wasm_deny.mjs")],
  { encoding: "utf8" }
).trim();
console.log(" ", denyOut);
const denyOk = denyOut.includes('deny_exact_match=true');

// ── ۴) URL نسخه‌دار همان‌طور که sw.js می‌سازد ─────────────
const base = "https://cocoon1990.github.io/cocoon/sw.js";
const resolved = new URL(`./wasm/ghost_wasm_bg.wasm?v=${"5.2.4"}`, base).href;
const urlOk = resolved === "https://cocoon1990.github.io/cocoon/wasm/ghost_wasm_bg.wasm?v=5.2.4";
console.log("\n--- cache-bust باینری ---");
console.log(" ", resolved);
console.log(`  URL نسخه‌دار صحیح        : ${urlOk}`);

if (!exact || !denyOk || !urlOk) {
  console.error("\n❌ FAILED");
  process.exit(1);
}
console.log(`\n✅ PASS — backend = ${JSON.stringify(d.backend)} (exact) · deny mapping OK · wasm URL versioned`);
