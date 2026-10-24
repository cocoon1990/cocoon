/**
 * entry.mjs — نقطهٔ ورود worker (v5.4.1)
 *
 * دو موتور پشت یک دامنه:
 *
 *   /vless  →  همین فایل (JS): WebSocketPair + cloudflare:sockets
 *   بقیه    →  هستهٔ راست (build/worker/shim.mjs): /health، /sub، /stream
 *
 * چرا split شد؟ (بایسکت PR #35 روی production)
 * ──────────────────────────────────────────────
 * در v5.4.0 همهٔ مسیرها داخل wasm بودند و روی Mainnet هر درخواستی 1101
 * می‌گرفت (بدون هیچ لاگ)، در حالی که همان artifact در workerd محلی ۲۰۰
 * برمی‌گرداند. بایسکت سه مسیر را جدا کرد: /stream و /sub سالم بودند و
 * تنها /vless می‌مرد. یعنی وجود کد WebSocket در ماژول wasm کافی بود تا
 * نمونه‌سازی در Mainnet شکست بخورد. پس WebSocket از wasm بیرون آمد و با
 * API خودِ Workers پیاده شد؛ راست فقط کارهایی را می‌کند که در production
 * اثبات‌شده کار می‌کنند.
 */
import * as rustModule from '../build/worker/shim.mjs';
import { connect } from 'cloudflare:sockets';
import { createVlessHandler, isVlessPath } from './vless.js';

/** worker-build گاهی default می‌دهد و گاهی namespace — هر دو را بپذیر. */
const rustWorker = rustModule.default && rustModule.default.fetch ? rustModule.default : rustModule;

/**
 * کلاس Durable Object باید از **همین** entrypoint صادر شود.
 * wrangler هنگام deploy این را اعتبارسنجی می‌کند و اگر نباشد کل دیپلوی
 * رد می‌شود: «Your Worker depends on the following Durable Objects, which
 * are not exported in your entrypoint file». کلاس در crate راست
 * (`#[durable_object]`) تعریف شده و از shim صادر می‌شود؛ اینجا فقط
 * دوباره صادرش می‌کنیم.
 */
export const SlidingWindowRateLimiter = rustModule.SlidingWindowRateLimiter;

/** یک handler ساخته‌شده برای هر env (کش‌شده روی env object). */
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
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (isVlessPath(url.pathname, env && env.VLESS_PATH)) {
      return handlerFor(env)(request);
    }

    if (!rustWorker || typeof rustWorker.fetch !== 'function') {
      return new Response('rust core unavailable', { status: 500 });
    }

    return rustWorker.fetch(request, env, ctx);
  },
};
