#!/usr/bin/env node
/**
 * vless.test.mjs — تست واقعی سرور VLESS (v5.4.1)
 *
 * از v5.4.1 پیاده‌سازی VLESS در `src/vless.js` است (JS، بدون wasm) و همین
 * فایل **خودِ کد تولیدی** را تست می‌کند — نه یک آینهٔ جداگانه:
 *
 *   • کدک هدر: IPv4 / domain / IPv6، فریم‌های تکه‌تکه، همهٔ مسیرهای رد
 *   • SSRF: مقصدهای داخلی و metadata
 *   • دست‌دادن کامل: mock `connect()` + mock `WebSocketPair`
 *   • پمپ دوطرفه: ack، payload اولیه، رلهٔ بایت‌ها، انتشار بستن
 *   • پین‌های رگرسیون: کد WebSocket **نباید** به wasm برگردد (علت 1101)
 *
 * اجرا: node streaming-worker/tests/vless.test.mjs
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  CLOSE,
  VLESS_ACK,
  VLESS_MAX_HEADER,
  concatBytes,
  createVlessHandler,
  isBlockedDestination,
  isVlessPath,
  normalizePath,
  parseUuid,
  parseVlessHeader,
  uuidToString,
} from '../src/vless.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (...parts) => readFileSync(join(HERE, '..', ...parts), 'utf8');

const UUID = '6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33';
const UUID_BYTES = parseUuid(UUID);
const encoder = new TextEncoder();

let passed = 0;
const failures = [];
function test(name, fn) {
  try {
    fn();
    passed += 1;
  } catch (error) {
    failures.push(`${name}: ${error.message}`);
  }
}
async function testAsync(name, fn) {
  try {
    await fn();
    passed += 1;
  } catch (error) {
    failures.push(`${name}: ${error.message}`);
  }
}

// ══════════════════════════════════════════════════════════════
//  ساخت فریم VLESS
// ══════════════════════════════════════════════════════════════
const ATYP_IPV4 = 1;
const ATYP_DOMAIN = 2;
const ATYP_IPV6 = 3;

function buildHeader({
  uuid = UUID_BYTES,
  cmd = 1,
  port = 443,
  atyp = ATYP_DOMAIN,
  domain = 'example.com',
  ipv4 = [1, 2, 3, 4],
  ipv6 = null,
  opt = new Uint8Array(0),
  payload = new Uint8Array(0),
  version = 0,
} = {}) {
  const parts = [new Uint8Array([version]), uuid, new Uint8Array([opt.length]), opt];
  parts.push(new Uint8Array([cmd, (port >> 8) & 0xff, port & 0xff, atyp]));

  if (atyp === ATYP_IPV4) {
    parts.push(new Uint8Array(ipv4));
  } else if (atyp === ATYP_DOMAIN) {
    const bytes = encoder.encode(domain);
    parts.push(new Uint8Array([bytes.length]), bytes);
  } else if (atyp === ATYP_IPV6) {
    parts.push(ipv6);
  }
  parts.push(payload);

  return parts.reduce((acc, part) => concatBytes(acc, part), new Uint8Array(0));
}

const otherUuid = () => {
  const copy = Uint8Array.from(UUID_BYTES);
  copy[0] ^= 0xff;
  return copy;
};

// ══════════════════════════════════════════════════════════════
//  UUID
// ══════════════════════════════════════════════════════════════
test('parseUuid: با خط تیره', () => assert.equal(parseUuid(UUID).length, 16));
test('parseUuid: بدون خط تیره', () => assert.equal(parseUuid(UUID.replace(/-/g, '')).length, 16));
test('parseUuid: حروف بزرگ', () => assert.deepEqual(parseUuid(UUID.toUpperCase()), UUID_BYTES));
test('parseUuid: طول نادرست', () => assert.equal(parseUuid('6f2c1a54'), null));
test('parseUuid: کاراکتر غیرهگز', () => assert.equal(parseUuid('zz2c1a543b9d4c0e8a712d5e9f0b1c33'), null));
test('parseUuid: ورودی غیر رشته', () => assert.equal(parseUuid(undefined), null));
test('uuidToString: رفت و برگشت', () => assert.equal(uuidToString(UUID_BYTES), UUID));

// ══════════════════════════════════════════════════════════════
//  SSRF guard
// ══════════════════════════════════════════════════════════════
for (const host of [
  'localhost',
  'metadata.google.internal',
  '127.0.0.1',
  '10.1.2.3',
  '172.16.5.4',
  '172.31.255.255',
  '192.168.0.1',
  '169.254.1.1',
  '0.0.0.0',
  '::1',
  '::',
  'fc00::1',
  'fd12:3456::1',
  'fe80::1',
]) {
  test(`SSRF: ${host} مسدود است`, () => assert.equal(isBlockedDestination(host), true));
}
for (const host of ['example.com', 'fcbarcelona.com', '8.8.8.8', '172.32.0.1', '2606:4700::1111']) {
  test(`SSRF: ${host} مجاز است`, () => assert.equal(isBlockedDestination(host), false));
}

// ══════════════════════════════════════════════════════════════
//  پارسر هدر
// ══════════════════════════════════════════════════════════════
test('parser: هدر ناقص → need-more', () => {
  assert.equal(parseVlessHeader(buildHeader().subarray(0, 12), UUID_BYTES).state, 'need-more');
});
test('parser: نسخهٔ نادرست', () => {
  assert.deepEqual(parseVlessHeader(buildHeader({ version: 1 }), UUID_BYTES), {
    state: 'rejected',
    reason: 'unsupported version',
  });
});
test('parser: uuid ناهمخوان', () => {
  assert.equal(parseVlessHeader(buildHeader({ uuid: otherUuid() }), UUID_BYTES).reason, 'uuid mismatch');
});
test('parser: command غیر TCP', () => {
  assert.equal(parseVlessHeader(buildHeader({ cmd: 2 }), UUID_BYTES).reason, 'unsupported command');
});
test('parser: port صفر', () => {
  assert.equal(parseVlessHeader(buildHeader({ port: 0 }), UUID_BYTES).reason, 'invalid port');
});
test('parser: دامنه + payload', () => {
  const header = buildHeader({ payload: encoder.encode('GET / HTTP/1.1\r\n') });
  const parsed = parseVlessHeader(header, UUID_BYTES);
  assert.equal(parsed.state, 'ready');
  assert.equal(parsed.addr, 'example.com');
  assert.equal(parsed.port, 443);
  assert.equal(parsed.consumed, 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11);
  assert.equal(new TextDecoder().decode(parsed.rest), 'GET / HTTP/1.1\r\n');
});
test('parser: IPv4', () => {
  const parsed = parseVlessHeader(buildHeader({ atyp: ATYP_IPV4, ipv4: [93, 184, 216, 34] }), UUID_BYTES);
  assert.equal(parsed.addr, '93.184.216.34');
});
test('parser: IPv6', () => {
  const ipv6 = new Uint8Array(16);
  ipv6.set([0x26, 0x06, 0x47, 0x00], 0);
  ipv6.set([0x00, 0x01], 14);
  const parsed = parseVlessHeader(buildHeader({ atyp: ATYP_IPV6, ipv6 }), UUID_BYTES);
  assert.equal(parsed.state, 'ready');
  assert.equal(parsed.addr, '2606:4700:0:0:0:0:0:1');
});
test('parser: atyp ناشناخته', () => {
  assert.equal(parseVlessHeader(buildHeader({ atyp: 9 }), UUID_BYTES).reason, 'unsupported address type');
});
test('parser: مقصد مسدود', () => {
  const buf = buildHeader({ atyp: ATYP_IPV4, ipv4: [127, 0, 0, 1] });
  assert.equal(parseVlessHeader(buf, UUID_BYTES).reason, 'destination not allowed');
});
test('parser: دامنهٔ خالی', () => {
  assert.equal(parseVlessHeader(buildHeader({ domain: '' }), UUID_BYTES).reason, 'invalid domain length');
});
test('parser: طول دامنه بیشتر از بافر', () => {
  const full = buildHeader({ domain: 'example.com' });
  assert.equal(parseVlessHeader(full.subarray(0, full.length - 3), UUID_BYTES).state, 'need-more');
});
test('parser: opt_len پشتیبانی می‌شود', () => {
  const parsed = parseVlessHeader(buildHeader({ opt: new Uint8Array([1, 2, 3, 4]) }), UUID_BYTES);
  assert.equal(parsed.state, 'ready');
  assert.equal(parsed.addr, 'example.com');
});

// ══════════════════════════════════════════════════════════════
//  routing
// ══════════════════════════════════════════════════════════════
test('normalizePath: پیش‌فرض و اسلش انتهایی', () => {
  assert.equal(normalizePath(undefined), '/vless');
  assert.equal(normalizePath(''), '/vless');
  assert.equal(normalizePath('tunnel'), '/tunnel');
  assert.equal(normalizePath('/tunnel/'), '/tunnel');
  assert.equal(normalizePath('/'), '/');
});
test('isVlessPath: /vless همیشه، مسیر دلخواه هم', () => {
  assert.equal(isVlessPath('/vless', undefined), true);
  assert.equal(isVlessPath('/tunnel', '/tunnel'), true);
  assert.equal(isVlessPath('/health', undefined), false);
  assert.equal(isVlessPath('/sub', '/tunnel'), false);
});

// ══════════════════════════════════════════════════════════════
//  mock های Workers runtime
// ══════════════════════════════════════════════════════════════
class FakeWebSocket {
  constructor() {
    this.listeners = new Map();
    this.sent = [];
    this.closed = null;
    this.accepted = false;
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  emit(type, event = {}) {
    for (const fn of this.listeners.get(type) || []) fn(event);
  }
  accept() {
    this.accepted = true;
  }
  send(data) {
    if (this.closed) throw new Error('socket closed');
    this.sent.push(data);
  }
  close(code, reason) {
    if (this.closed) return;
    this.closed = { code, reason };
    this.emit('close', { code, reason });
  }
}

class FakeResponse {
  constructor(body, init = {}) {
    this.body = body;
    this.status = init.status ?? 200;
    this.webSocket = init.webSocket ?? null;
  }
}

function makeFakeSocket() {
  let controller;
  const readable = new ReadableStream({ start: (c) => (controller = c) });
  const written = [];
  const writable = new WritableStream({ write: (chunk) => written.push(chunk) });
  return {
    socket: {
      readable,
      writable,
      closed: false,
      close() {
        this.closed = true;
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      },
    },
    written,
    push: (bytes) => controller.enqueue(bytes),
  };
}

const UPGRADE = { headers: { get: (n) => (String(n).toLowerCase() === 'upgrade' ? 'websocket' : null) } };
const PLAIN = { headers: { get: () => null } };
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

async function withFakeResponse(fn) {
  const original = globalThis.Response;
  globalThis.Response = FakeResponse;
  try {
    return await fn();
  } finally {
    globalThis.Response = original;
  }
}

function harness({ uuid = UUID } = {}) {
  const client = new FakeWebSocket();
  const server = new FakeWebSocket();
  const fake = makeFakeSocket();
  const calls = [];
  const handler = createVlessHandler({
    connect: (options) => {
      calls.push(options);
      return fake.socket;
    },
    env: { VLESS_UUID: uuid },
    makeSocketPair: () => [client, server],
  });
  return { client, server, fake, calls, handler };
}

// ══════════════════════════════════════════════════════════════
//  دست‌دادن کامل
// ══════════════════════════════════════════════════════════════
await testAsync('handler: بدون Upgrade → 426', async () => {
  await withFakeResponse(async () => {
    const res = await harness().handler(PLAIN);
    assert.equal(res.status, 426);
  });
});

await testAsync('handler: بدون VLESS_UUID → 503 (fail-closed)', async () => {
  await withFakeResponse(async () => {
    const res = await harness({ uuid: '' }).handler(UPGRADE);
    assert.equal(res.status, 503);
  });
});

await testAsync('handler: ارتقای موفق → 101 + webSocket', async () => {
  await withFakeResponse(async () => {
    const { handler, client, server } = harness();
    const res = await handler(UPGRADE);
    assert.equal(res.status, 101);
    assert.equal(res.webSocket, client);
    assert.equal(server.accepted, true);
  });
});

await testAsync('handler: هدر تکه‌تکه → یک connect و یک ack', async () => {
  await withFakeResponse(async () => {
    const { handler, server, fake, calls } = harness();
    await handler(UPGRADE);

    const header = buildHeader({ payload: encoder.encode('HELLO') });
    server.emit('message', { data: header.subarray(0, 10) });
    await tick();
    assert.equal(calls.length, 0, 'قبل از کامل‌شدن هدر نباید connect شود');

    server.emit('message', { data: header.subarray(10) });
    await tick();

    assert.deepEqual(calls, [{ hostname: 'example.com', port: 443 }]);
    assert.deepEqual(server.sent[0], VLESS_ACK);
    assert.equal(new TextDecoder().decode(fake.written[0]), 'HELLO');
  });
});

await testAsync('handler: فریم‌های بعدی مستقیم رله می‌شوند', async () => {
  await withFakeResponse(async () => {
    const { handler, server, fake } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader() });
    await tick();
    server.emit('message', { data: encoder.encode('ping') });
    await tick();
    assert.equal(new TextDecoder().decode(fake.written.at(-1)), 'ping');
  });
});

await testAsync('handler: دادهٔ مقصد به کلاینت می‌رسد', async () => {
  await withFakeResponse(async () => {
    const { handler, server, fake } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader() });
    await tick();
    fake.push(encoder.encode('HTTP/1.1 200 OK'));
    await tick(20);
    assert.deepEqual(
      server.sent.slice(1).map((c) => new TextDecoder().decode(c)),
      ['HTTP/1.1 200 OK'],
    );
  });
});

await testAsync('handler: بستن کلاینت → سوکت مقصد بسته می‌شود', async () => {
  await withFakeResponse(async () => {
    const { handler, server, fake } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader() });
    await tick();
    server.emit('close', {});
    await tick();
    assert.equal(fake.socket.closed, true);
  });
});

// ══════════════════════════════════════════════════════════════
//  مسیرهای خطا
// ══════════════════════════════════════════════════════════════
await testAsync('handler: uuid ناهمخوان → 1011', async () => {
  await withFakeResponse(async () => {
    const { handler, server } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader({ uuid: otherUuid() }) });
    await tick();
    assert.equal(server.closed.code, CLOSE.FAILED);
    assert.equal(server.closed.reason, 'uuid mismatch');
  });
});

await testAsync('handler: فریم متنی → 1003', async () => {
  await withFakeResponse(async () => {
    const { handler, server } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: 'GET / HTTP/1.1' });
    await tick();
    assert.equal(server.closed.code, CLOSE.UNSUPPORTED);
  });
});

await testAsync('handler: هدر بزرگ‌تر از سقف → 1009', async () => {
  await withFakeResponse(async () => {
    const { handler, server } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: new Uint8Array(VLESS_MAX_HEADER + 1) });
    await tick();
    assert.equal(server.closed.code, CLOSE.TOO_LARGE);
  });
});

await testAsync('handler: مقصد مسدود → 1011 و بدون connect', async () => {
  await withFakeResponse(async () => {
    const { handler, server, calls } = harness();
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader({ atyp: ATYP_IPV4, ipv4: [127, 0, 0, 1] }) });
    await tick();
    assert.equal(server.closed.reason, 'destination not allowed');
    assert.equal(calls.length, 0);
  });
});

await testAsync('handler: connect خطا بدهد → 1011', async () => {
  await withFakeResponse(async () => {
    const client = new FakeWebSocket();
    const server = new FakeWebSocket();
    const handler = createVlessHandler({
      connect: () => {
        throw new Error('blocked');
      },
      env: { VLESS_UUID: UUID },
      makeSocketPair: () => [client, server],
    });
    await handler(UPGRADE);
    server.emit('message', { data: buildHeader() });
    await tick();
    assert.equal(server.closed.reason, 'connect failed');
  });
});

// ══════════════════════════════════════════════════════════════
//  پین‌های رگرسیون — علت 1101 در v5.4.0
// ══════════════════════════════════════════════════════════════
test('pin: wasm دیگر کد WebSocket ندارد', () => {
  assert.equal(/WebSocketPair|from_websocket|pipe_vless|handle_vless/.test(read('src', 'lib.rs')), false);
});
test('pin: /vless از wasm حذف شده است', () => {
  assert.equal(read('src', 'lib.rs').includes('"/vless", handle_vless'), false);
});
test('pin: entry.mjs هر دو موتور را می‌شناسد', () => {
  const entry = read('src', 'entry.mjs');
  assert.match(entry, /from '\.\.\/build\/worker\/shim\.mjs'/);
  assert.match(entry, /from 'cloudflare:sockets'/);
  assert.match(entry, /createVlessHandler/);
});
test('pin: wrangler به entry.mjs اشاره می‌کند', () => {
  assert.match(read('wrangler.toml'), /main\s*=\s*"src\/entry\.mjs"/);
});
test('pin: /sub همچنان URI استاندارد می‌سازد', () => {
  assert.match(read('src', 'lib.rs'), /vless:\/\/\{\}@\{\}:443\?encryption=none&security=tls&sni=/);
});

// ══════════════════════════════════════════════════════════════
console.log(`\n${passed} passed, ${failures.length} failed`);
for (const failure of failures) console.log(`  ✗ ${failure}`);
if (failures.length > 0) process.exit(1);
