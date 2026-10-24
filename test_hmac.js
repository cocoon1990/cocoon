/**
 * test_hmac.js — اثبات ناسازگاری امضای HMAC بین کلاینت و ورکر
 *
 * کلاینت (browser-wasm/src/lib.rs:67,104):
 *     key = hex::decode(hmac_key_hex)      → 32 بایت باینری
 *     msg = format!("{}:{}", target, seq)
 *
 * ورکر (streaming-worker/src/lib.rs:verify_hmac_signature):
 *     key = secret.as_bytes()              → 64 بایت ASCII از خودِ رشتهٔ hex
 *
 * اجرا: node test_hmac.js
 */
import crypto from "node:crypto";

const HMAC_SECRET_HEX =
  "9f2c4e7a1b8d3506f4c2a9e7d1b8c5a3e6f0d2b9c7a4e1f8d6b3a0c9e5f2d7b4";
const TARGET = "https://www.youtube.com/robots.txt";
const SEQ = "7";
const MESSAGE = `${TARGET}:${SEQ}`;

const hmacHex = (key, msg) =>
  crypto.createHmac("sha256", key).update(msg).digest("hex");

const keyClient = Buffer.from(HMAC_SECRET_HEX, "hex"); // 32 bytes
const keyWorker = Buffer.from(HMAC_SECRET_HEX, "utf8"); // 64 bytes

const sigClient = hmacHex(keyClient, MESSAGE);
const sigWorker = hmacHex(keyWorker, MESSAGE);

console.log("message             :", MESSAGE);
console.log("secret (hex string) :", HMAC_SECRET_HEX);
console.log("  length            :", HMAC_SECRET_HEX.length, "chars\n");

console.log("CLIENT key  : hex-decoded  →", keyClient.length, "bytes");
console.log("WORKER key  : as_bytes()   →", keyWorker.length, "bytes\n");

console.log("client signature:", sigClient);
console.log("worker expects  :", sigWorker);
console.log("MATCH           :", sigClient === sigWorker);

if (sigClient === sigWorker) {
  console.error("\n❌ expected a mismatch — test is not modelling the bug");
  process.exit(1);
}
console.log("\n✅ BUG CONFIRMED: identical message, different key material → 403\n");

// ── رفع پیشنهادی: ورکر هم hex-decode کند ────────────────────
const sigWorkerFixed = hmacHex(Buffer.from(HMAC_SECRET_HEX, "hex"), MESSAGE);
console.log("--- after fix (worker hex-decodes the secret) ---");
console.log("client signature:", sigClient);
console.log("worker expects  :", sigWorkerFixed);
console.log("MATCH           :", sigClient === sigWorkerFixed);

const ok = sigClient === sigWorkerFixed;
console.log(ok ? "\n✅ FIX PROVEN: signatures now identical" : "\n❌ fix failed");
process.exit(ok ? 0 : 1);
