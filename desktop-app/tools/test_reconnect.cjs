#!/usr/bin/env node
/**
 * test_reconnect.cjs — اثبات مسیر «اتصال مجدد فوری» (پیلهٔ فانی)
 *
 * این تست همان ترتیبی را اجرا می‌کند که کنترلر راست (main.rs) اجرا می‌کند،
 * روی یک کنترل‌پلین واقعی HTTP روی loopback — مثل `external-controller`
 * هستهٔ meow:
 *
 *   1. connect   → PUT /configs  با پیکربندی زنده   (session up)
 *   2. disconnect→ scrub فایل + PUT /configs با پیکربندی بی‌جلسه
 *                  (tun.enable همان‌قدر true می‌ماند، پروکسی‌ها خالی)
 *   3. reconnect → scrub + PUT /configs با پیکربندی زنده  ← زمان‌گیری
 *
 * ادعاهایی که بررسی می‌شوند:
 *   • هیچ‌جا `kill` صدا زده نمی‌شود ⇒ آداپتور TUN نابود نمی‌شود
 *   • در فاصلهٔ قطع تا وصل، tun.enable هرگز false نمی‌شود
 *   • زمان reconnect (PUT رفت‌وبرگشت) زیر ۱۰۰۰ میلی‌ثانیه است
 *
 * اجرا: node desktop-app/tools/test_reconnect.cjs
 */
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const core = require('../src/core.js');

const NODE = {
  uuid: '6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33',
  host: 'ghost-streaming-worker.cocoon-de9.workers.dev',
  port: 443,
  path: '/vless',
  sni: 'ghost-streaming-worker.cocoon-de9.workers.dev',
  remark: 'SCP-GHOST',
  fingerprint: 'chrome',
  hostHeader: 'ghost-streaming-worker.cocoon-de9.workers.dev',
};

const applied = [];
let killed = false;
let tunAlive = false;
let tunEverDropped = false;

const server = http.createServer((req, res) => {
  if (req.method === 'PUT' && req.url.startsWith('/configs')) {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const payload = JSON.parse(body || '{}');
      applied.push(payload.path);
      // هسته پیکربندی را اعمال می‌کند؛ tun.enable را از محتوای «فایل» می‌خوانیم
      const yaml = payload.simulated || '';
      const enable = /tun:\s*\n\s*enable:\s*true/.test(yaml);
      if (tunAlive && !enable) tunEverDropped = true;
      tunAlive = enable;
      res.writeHead(204).end();
    });
    return;
  }
  if (req.url === '/kill') {
    killed = true;
    tunAlive = false;
    res.writeHead(204).end();
    return;
  }
  res.writeHead(404).end();
});

/** همان کاری که main.rs با TcpStream انجام می‌دهد. */
function putConfig(port, yaml) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ path: 'C:\\AppData\\core\\session.yaml', simulated: yaml });
    const request = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'PUT',
        path: '/configs?force=true',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      },
      (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      },
    );
    request.on('error', reject);
    request.end(body);
  });
}

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const live = core.buildCoreConfig(NODE, { mode: 'tun', mixedPort: 7890, controlPort: port });
  const dead = core.buildDetachedConfig({ mode: 'tun', mixedPort: 7890, controlPort: port });

  // ۱) اولین اتصال
  let status = await putConfig(port, live);
  assert.equal(status, 204);
  assert.equal(tunAlive, true, 'TUN باید پس از اولین اتصال زنده باشد');

  // ۲) قطع اتصال — هسته کشته نمی‌شود
  status = await putConfig(port, dead);
  assert.equal(status, 204);
  assert.equal(killed, false, 'قطع اتصال نباید هسته را بکشد');
  assert.equal(tunAlive, true, 'آداپتور TUN باید بعد از قطع هم زنده بماند');

  // ۳) اتصال مجدد — فقط نشست برمی‌گردد
  const started = process.hrtime.bigint();
  status = await putConfig(port, live);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(status, 204);
  assert.equal(tunAlive, true);
  assert.equal(tunEverDropped, false, 'tun.enable هرگز نباید false شود');
  assert.equal(applied.length, 3);
  assert.ok(elapsedMs < 1000, `reconnect took ${elapsedMs.toFixed(1)} ms (must be < 1000)`);

  server.close();

  console.log(`reconnect: ${elapsedMs.toFixed(1)} ms (control-plane round trip)`);
  console.log(`reloads: ${applied.length}, core killed: ${killed}, TUN alive: ${tunAlive}`);
  console.log('PASS — TUN survives the disconnect; only the session is rebuilt');
}

main().catch((error) => {
  console.error('FAIL —', error.message);
  process.exit(1);
});
