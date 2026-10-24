/**
 * vless-entry.mjs — worker مستقل و **فقط-JS** سرور VLESS.
 *
 * چرا یک worker جدا؟
 * ──────────────────
 * ثابت شد (دیباگ روی Mainnet) که:
 *   • همان wasm، وقتی entry خودِ shim باشد → 200
 *   • همان wasm، وقتی از یک entry.mjs ترکیبی import شود → 1101
 *   • هر ورکری که کد WebSocket داخل wasm داشته باشد → 1101
 *
 * پس VLESS اینجا کامل جدا شد: صفر wasm، صفر binding، صفر وابستگی. فقط
 * `WebSocketPair` و `cloudflare:sockets` که API خودِ Workers هستند —
 * همان الگوی BPB Panel. worker اصلی (`ghost-streaming-worker`) کارهای
 * اثبات‌شده‌اش را می‌کند: /health، /sub، /stream.
 *
 * مسیرها:
 *   GET /vless  → ارتقای WebSocket (بدون Upgrade → 426)
 *   GET /health → {"status":"ok","worker":"ghost-vless","version":…}
 *   دیگر       → 404
 */
import { connect } from 'cloudflare:sockets';
import { createVlessHandler, isVlessPath } from './vless.js';

const VERSION = '5.4.1';

const cache = new WeakMap();

function handlerFor(env) {
  if (env && typeof env === 'object') {
    let handler = cache.get(env);
    if (!handler) {
      handler = createVlessHandler({ connect, env });
      cache.set(env, handler);
    }
    return handler;
  }
  return createVlessHandler({ connect, env });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (isVlessPath(url.pathname, env && env.VLESS_PATH)) {
      return handlerFor(env)(request);
    }

    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({ status: 'ok', worker: 'ghost-vless', version: VERSION, runtime: 'js' }),
        { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } },
      );
    }

    return new Response('not found', { status: 404 });
  },
};
