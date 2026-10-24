/**
 * vless.js — VLESS-over-WebSocket، پیاده‌سازی کامل روی Cloudflare Workers.
 *
 * چرا JS و نه wasm؟
 * ──────────────────
 * در v5.4.0 سرور VLESS داخل crate راست بود. همان build در workerd محلی
 * ۲۰۰ می‌داد ولی روی Mainnet با خطای 1101 و **بدون هیچ لاگی** می‌مرد.
 * بایسکت روی رانتایم production (PR #35) دقیقاً مقصر را پیدا کرد:
 *
 *   /stream (HMAC)      → 200
 *   /sub    (Base64/KV) → 200
 *   /vless  (WebSocket) → 1101   ← همین تکه
 *
 * یعنی به‌محض ورود کد WebSocket به ماژول wasm، نمونه‌سازی ماژول در Mainnet
 * شکست می‌خورد — مستقل از binding، compatibility_date و پروفایل build.
 * این ماژول همان مسیر را با API خام Workers انجام می‌دهد:
 * `WebSocketPair` + `cloudflare:sockets` — همان روشی که BPB Panel و
 * هزاران worker در production استفاده می‌کنند.
 *
 * قالب هدر VLESS v0:
 *   [0]      version = 0
 *   [1..17]  uuid (۱۶ بایت خام)
 *   [17]     opt_len
 *   [...]    opts
 *   [...]    command (۱ = TCP)
 *   [...]    port (۲ بایت big-endian)
 *   [...]    atyp (۱ = IPv4، ۲ = domain، ۳ = IPv6)
 *   [...]    address
 *   [...]    payload (اختیاری، می‌تواند در فریم بعدی ادامه یابد)
 *
 * پاسخ سرور: [0x00, 0x00] و سپس جریان خام.
 *
 * این فایل هیچ import ای از `cloudflare:sockets` ندارد تا در Node هم
 * قابل تست باشد؛ تابع `connect` تزریق می‌شود.
 */

export const VLESS_VERSION = 0;
export const VLESS_CMD_TCP = 1;
export const VLESS_ATYP_IPV4 = 1;
export const VLESS_ATYP_DOMAIN = 2;
export const VLESS_ATYP_IPV6 = 3;

/** سقف هدر VLESS (بایت) — جلوی مصرف حافظه با فریم‌های بی‌پایان را می‌گیرد. */
export const VLESS_MAX_HEADER = 1024;

/** کدهای بستن WebSocket. */
export const CLOSE = {
  NORMAL: 1000,
  PROTOCOL: 1002,
  UNSUPPORTED: 1003,
  TOO_LARGE: 1009,
  FAILED: 1011,
};

/** پاسخ موفق VLESS: version=0 و opt_len=0 */
export const VLESS_ACK = new Uint8Array([0, 0]);

/** آیا این URL باید به موتور VLESS برود؟ (`/vless` و مسیر قابل‌تنظیم) */
export function isVlessPath(pathname, configured) {
  return pathname === '/vless' || pathname === normalizePath(configured);
}

/** مسیر را به شکل متعارف `/x` برمی‌گرداند (بدون اسلش انتهایی). */
export function normalizePath(value) {
  const raw = String(value ?? '/vless').trim() || '/vless';
  const withSlash = raw.startsWith('/') ? raw : `/${raw}`;
  return withSlash.length > 1 ? withSlash.replace(/\/+$/, '') : withSlash;
}

// ══════════════════════════════════════════════════════════════
//  helpers خالص (بدون I/O)
// ══════════════════════════════════════════════════════════════

/** UUID متنی (با یا بدون خط تیره) → ۱۶ بایت خام، یا null. */
export function parseUuid(value) {
  if (typeof value !== 'string') return null;
  const hex = value.trim().replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** UUID بایتی → رشتهٔ متعارف ۸-۴-۴-۴-۱۲. */
export function uuidToString(bytes) {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** به‌هم‌چسباندن دو Uint8Array. */
export function concatBytes(a, b) {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipv4ToInt(host) {
  const m = IPV4_RE.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map((p) => Number(p));
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/**
 * مقصدهایی که هرگز نباید از این پل عبور کنند (شبکهٔ داخلی / metadata).
 * فقط IPهای واقعی با روش عددی بررسی می‌شوند تا دامنه‌ای مثل
 * `fcbarcelona.com` اشتباهی رد نشود.
 */
export function isBlockedDestination(host) {
  if (typeof host !== 'string') return true;
  const lower = host.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (lower.length === 0) return true;
  if (lower === 'localhost' || lower === 'metadata.google.internal') return true;

  const v4 = ipv4ToInt(lower);
  if (v4 !== null) {
    const a = (v4 >>> 24) & 0xff;
    const b = (v4 >>> 16) & 0xff;
    if (a === 0 || a === 127) return true; // this-network / loopback
    if (a === 10) return true; // 10/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true; // 192.168/16
    if (a === 169 && b === 254) return true; // link-local
    if (a === 255) return true; // broadcast
    return false;
  }

  if (lower.includes(':')) {
    if (lower === '::' || lower === '::1') return true;
    const head = parseInt(lower.split(':')[0] || '0', 16);
    if (Number.isNaN(head)) return false;
    if ((head & 0xfe00) === 0xfc00) return true; // fc00::/7
    if ((head & 0xffc0) === 0xfe80) return true; // fe80::/10
    return false;
  }

  return false;
}

/**
 * پارس افزایشی هدر VLESS.
 * @returns {{state:'need-more'} | {state:'rejected', reason:string} |
 *           {state:'ready', addr:string, port:number, consumed:number, rest:Uint8Array}}
 */
export function parseVlessHeader(buf, expectedUuid) {
  if (buf.length < 18) return { state: 'need-more' };
  if (buf[0] !== VLESS_VERSION) return { state: 'rejected', reason: 'unsupported version' };

  for (let i = 0; i < 16; i += 1) {
    if (buf[1 + i] !== expectedUuid[i]) return { state: 'rejected', reason: 'uuid mismatch' };
  }

  const optLen = buf[17];
  let cursor = 18 + optLen;

  if (buf.length < cursor + 4) return { state: 'need-more' };

  const command = buf[cursor];
  cursor += 1;
  if (command !== VLESS_CMD_TCP) return { state: 'rejected', reason: 'unsupported command' };

  const port = (buf[cursor] << 8) | buf[cursor + 1];
  cursor += 2;
  if (port === 0) return { state: 'rejected', reason: 'invalid port' };

  const atyp = buf[cursor];
  cursor += 1;
  let addr = '';

  if (atyp === VLESS_ATYP_IPV4) {
    if (buf.length < cursor + 4) return { state: 'need-more' };
    addr = `${buf[cursor]}.${buf[cursor + 1]}.${buf[cursor + 2]}.${buf[cursor + 3]}`;
    cursor += 4;
  } else if (atyp === VLESS_ATYP_DOMAIN) {
    if (buf.length < cursor + 1) return { state: 'need-more' };
    const len = buf[cursor];
    cursor += 1;
    if (len === 0) return { state: 'rejected', reason: 'invalid domain length' };
    if (buf.length < cursor + len) return { state: 'need-more' };
    addr = new TextDecoder().decode(buf.subarray(cursor, cursor + len));
    cursor += len;
  } else if (atyp === VLESS_ATYP_IPV6) {
    if (buf.length < cursor + 16) return { state: 'need-more' };
    const groups = [];
    for (let i = 0; i < 8; i += 1) {
      groups.push(((buf[cursor + i * 2] << 8) | buf[cursor + i * 2 + 1]).toString(16));
    }
    addr = groups.join(':');
    cursor += 16;
  } else {
    return { state: 'rejected', reason: 'unsupported address type' };
  }

  if (addr.length === 0 || isBlockedDestination(addr)) {
    return { state: 'rejected', reason: 'destination not allowed' };
  }

  return { state: 'ready', addr, port, consumed: cursor, rest: buf.subarray(cursor) };
}

// ══════════════════════════════════════════════════════════════
//  handler — پمپ دوطرفه
// ══════════════════════════════════════════════════════════════

function frameToBytes(data) {
  if (typeof data === 'string') return null;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return null;
}

/**
 * ساخت handler برای `/vless`.
 *
 * @param {object}   deps
 * @param {Function} deps.connect          تابع `connect` از `cloudflare:sockets`
 * @param {object}   deps.env              محیط worker (VLESS_UUID)
 * @param {Function} [deps.makeSocketPair] سازندهٔ WebSocketPair (برای تست)
 */
export function createVlessHandler({ connect, env = {}, makeSocketPair } = {}) {
  const pairFactory = makeSocketPair || (() => new WebSocketPair());

  return async function handleVless(request) {
    const upgrade = String(request.headers.get('Upgrade') || '').toLowerCase();
    if (upgrade !== 'websocket') {
      return new Response('Expected a WebSocket upgrade on /vless', { status: 426 });
    }

    const expectedUuid = parseUuid(env.VLESS_UUID);
    if (!expectedUuid) {
      return new Response('VLESS endpoint is not configured', { status: 503 });
    }

    const pair = pairFactory();
    const client = pair[0];
    const server = pair[1];

    const state = { closed: false, buffer: new Uint8Array(0), socket: null, writer: null, queue: Promise.resolve() };

    const shutdown = (code, reason) => {
      if (state.closed) return;
      state.closed = true;
      try {
        server.close(code, reason);
      } catch {
        /* already closed */
      }
      try {
        if (state.socket) state.socket.close();
      } catch {
        /* ignore */
      }
    };

    const pumpRemoteToClient = () => {
      const writable = new WritableStream({
        write(chunk) {
          if (state.closed) return;
          try {
            server.send(chunk);
          } catch {
            shutdown(CLOSE.FAILED, 'client send failed');
          }
        },
        close() {
          shutdown(CLOSE.NORMAL, 'remote closed');
        },
      });
      state.socket.readable
        .pipeTo(writable)
        .catch(() => shutdown(CLOSE.FAILED, 'remote stream error'));
    };

    const onFrame = async (data) => {
      if (state.closed) return;
      const chunk = frameToBytes(data);
      if (!chunk) {
        shutdown(CLOSE.UNSUPPORTED, 'binary frames only');
        return;
      }

      if (state.writer) {
        await state.writer.write(chunk);
        return;
      }

      state.buffer = concatBytes(state.buffer, chunk);
      if (state.buffer.length > VLESS_MAX_HEADER) {
        shutdown(CLOSE.TOO_LARGE, 'header too large');
        return;
      }

      const parsed = parseVlessHeader(state.buffer, expectedUuid);
      if (parsed.state === 'need-more') return;
      if (parsed.state === 'rejected') {
        shutdown(CLOSE.FAILED, parsed.reason);
        return;
      }

      let socket;
      try {
        socket = connect({ hostname: parsed.addr, port: parsed.port });
      } catch {
        shutdown(CLOSE.FAILED, 'connect failed');
        return;
      }
      state.socket = socket;
      state.writer = socket.writable.getWriter();

      pumpRemoteToClient();

      try {
        server.send(VLESS_ACK);
        if (parsed.rest.length > 0) await state.writer.write(parsed.rest);
      } catch {
        shutdown(CLOSE.FAILED, 'handshake failed');
      }
    };

    server.addEventListener('message', (event) => {
      state.queue = state.queue.then(() => onFrame(event.data)).catch(() => shutdown(CLOSE.FAILED, 'internal error'));
    });
    server.addEventListener('close', () => shutdown(CLOSE.NORMAL, 'client closed'));
    server.addEventListener('error', () => shutdown(CLOSE.FAILED, 'client error'));

    server.accept();

    return new Response(null, { status: 101, webSocket: client });
  };
}
