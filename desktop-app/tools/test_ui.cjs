#!/usr/bin/env node
/* آزمون رابط کاربری بدون باز کردن پنجرهٔ واقعی.
 *
 * `index.html` + `core-config.js` + `main.js` داخل یک DOM مجازی (jsdom)
 * بالا می‌آیند و پل Tauri با یک ماک جایگزین می‌شود؛ سپس مسیرهای واقعی
 * کاربر اجرا می‌شوند: دریافت اشتراک، اتصال، قطع، خطای هسته، حالت بدون پل.
 *
 * پیش‌نیاز (فقط برای این تست):  npm install jsdom
 * اجرا:                          NODE_PATH=<dir با node_modules> node desktop-app/tools/test_ui.cjs
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

let JSDOM;
try {
  ({ JSDOM } = require('jsdom'));
} catch {
  console.log('SKIP: jsdom نصب نیست (npm install jsdom)');
  process.exit(0);
}

const ROOT = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'src', 'index.html'), 'utf8');
const coreConfig = fs.readFileSync(path.join(ROOT, 'src', 'core-config.js'), 'utf8');
const mainJs = fs.readFileSync(path.join(ROOT, 'src', 'main.js'), 'utf8');

const WS_URI =
  'vless://11111111-2222-3333-4444-555555555555@edge.example.com:443' +
  '?encryption=none&security=tls&sni=edge.example.com&fp=chrome&type=ws' +
  '&host=edge.example.com&path=%2Fvless#GHOST';

let checks = 0;
const failures = [];

function check(condition, label) {
  checks += 1;
  if (condition) {
    console.log(`  PASS ${label}`);
  } else {
    console.log(`  FAIL ${label}`);
    failures.push(label);
  }
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 6));

function boot({ withBridge = true, subscription = WS_URI, running = false } = {}) {
  const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://localhost/' });
  const { window } = dom;
  const calls = [];

  const backend = {
    subscription,
    running,
    startedConfig: null,
    startError: null,
    fetchError: null,
    log: ['[meow] core ready'],
  };

  if (withBridge) {
    window.__TAURI__ = {
      core: {
        invoke: async (command, args) => {
          calls.push({ command, args });
          if (command === 'fetch_subscription') {
            if (backend.fetchError) throw backend.fetchError;
            return {
              body: backend.subscription,
              bytes: backend.subscription.length,
              status: 200,
            };
          }
          if (command === 'start_core') {
            if (backend.startError) throw backend.startError;
            backend.startedConfig = args.config;
            backend.running = true;
            backend.log = ['[meow] listening', '[meow] tun up'];
            return {
              running: true,
              mode: args.mode,
              pid: 4242,
              configPath: 'C:\\Users\\x\\AppData\\Local\\io.cocoon.scpghost\\core\\config.yaml',
              proxyUrl: 'http://127.0.0.1:7890',
              log: backend.log,
            };
          }
          if (command === 'stop_core') {
            backend.running = false;
            backend.log = [];
            return {
              running: false,
              mode: null,
              pid: null,
              configPath: null,
              proxyUrl: 'http://127.0.0.1:7890',
              log: [],
            };
          }
          if (command === 'core_status') {
            return {
              running: backend.running,
              mode: backend.running ? 'tun' : null,
              pid: backend.running ? 4242 : null,
              configPath: backend.running ? 'C:\\…\\config.yaml' : null,
              proxyUrl: 'http://127.0.0.1:7890',
              log: backend.log,
            };
          }
          throw new Error(`unknown command ${command}`);
        },
      },
    };
  }

  window.eval(coreConfig);
  window.eval(mainJs);

  return { dom, window, doc: window.document, calls, backend };
}

const $ = (doc, id) => doc.getElementById(id);

async function main() {
  // ── ۱) ساخت اولیه ────────────────────────────────────────────
  console.log('== boot ==');
  const app = boot();
  await tick();
  check(app.calls.some((c) => c.command === 'core_status'), 'core status is polled on boot');
  check($(app.doc, 'btn-connect').disabled === false, 'connect enabled at rest');
  check($(app.doc, 'btn-disconnect').disabled === true, 'disconnect disabled at rest');
  check($(app.doc, 'mode-badge').textContent === 'TUN', 'TUN mode is the default');
  check($(app.doc, 'dot').dataset.state === 'off', 'dot starts idle');

  // ── ۲) بررسی اشتراک ──────────────────────────────────────────
  console.log('\n== subscription inspect ==');
  $(app.doc, 'btn-fetch').click();
  await tick();
  check($(app.doc, 'node-info').hidden === false, 'node details are shown');
  check(
    $(app.doc, 'node-server').textContent === 'edge.example.com:443',
    'server:port rendered'
  );
  check($(app.doc, 'node-network').textContent === 'ws', 'transport rendered');
  check(
    $(app.doc, 'node-security').textContent.startsWith('tls'),
    'security rendered'
  );
  check(
    $(app.doc, 'sub-state').textContent.includes('دریافت شد'),
    'subscription size reported'
  );
  app.dom.window.close();

  // ── ۳) اتصال کامل ────────────────────────────────────────────
  console.log('\n== connect flow ==');
  const run = boot();
  await tick();
  $(run.doc, 'btn-connect').click();
  await tick();

  const startCall = run.calls.find((c) => c.command === 'start_core');
  check(Boolean(startCall), 'start_core invoked');
  check(startCall.args.mode === 'tun', 'mode forwarded to the backend');
  check(
    typeof startCall.args.config === 'string' &&
      startCall.args.config.includes('proxies:') &&
      startCall.args.config.includes('type: "vless"'),
    'generated YAML forwarded to the core'
  );
  check(
    startCall.args.config.includes('tun:\n  enable: true'),
    'TUN enabled in the generated config'
  );
  check($(run.doc, 'dot').dataset.state === 'on', 'dot turns green');
  check($(run.doc, 'status-label').textContent === 'متصل', 'label reads «متصل»');
  check($(run.doc, 'pid').textContent === '4242', 'core pid displayed');
  check(
    $(run.doc, 'proxy').textContent === 'http://127.0.0.1:7890',
    'local proxy url displayed'
  );
  check(
    $(run.doc, 'core-log').textContent.includes('tun up'),
    'core log streamed into the UI'
  );
  check($(run.doc, 'btn-disconnect').disabled === false, 'disconnect unlocked');

  $(run.doc, 'btn-disconnect').click();
  await tick();
  check(run.calls.some((c) => c.command === 'stop_core'), 'stop_core invoked');
  check($(run.doc, 'dot').dataset.state === 'off', 'dot returns to idle');
  check($(run.doc, 'pid').textContent === '—', 'pid cleared');
  run.dom.window.close();

  // ── ۴) حالت پراکسی محلی ──────────────────────────────────────
  console.log('\n== proxy mode ==');
  const proxy = boot();
  await tick();
  $(proxy.doc, 'mode-proxy').click();
  check($(proxy.doc, 'mode-badge').textContent === 'PROXY', 'badge switches to PROXY');
  check(
    $(proxy.doc, 'mode-tun').classList.contains('active') === false,
    'TUN segment deactivated'
  );
  $(proxy.doc, 'btn-connect').click();
  await tick();
  const proxyStart = proxy.calls.find((c) => c.command === 'start_core');
  check(proxyStart.args.mode === 'proxy', 'proxy mode forwarded');
  check(
    proxyStart.args.config.includes('tun:\n  enable: false'),
    'TUN disabled in proxy mode config'
  );
  proxy.dom.window.close();

  // ── ۵) خطاها ─────────────────────────────────────────────────
  console.log('\n== error paths ==');
  const failing = boot();
  await tick();
  failing.backend.startError = 'sidecar «meow» پیدا نشد: not found';
  $(failing.doc, 'btn-connect').click();
  await tick();
  check($(failing.doc, 'dot').dataset.state === 'error', 'dot turns red');
  check(
    $(failing.doc, 'status-hint').textContent.includes('sidecar'),
    'backend error surfaced verbatim'
  );
  check(
    failing.calls.some((c) => c.command === 'stop_core'),
    'cleanup stop attempted after failure'
  );
  failing.dom.window.close();

  const badSub = boot({ subscription: '{"error":"Subscription endpoint is disabled"}' });
  await tick();
  $(badSub.doc, 'btn-connect').click();
  await tick();
  check($(badSub.doc, 'dot').dataset.state === 'error', 'invalid subscription blocks connect');
  check(
    /JSON/.test($(badSub.doc, 'status-hint').textContent),
    'subscription parse error is explained'
  );
  badSub.dom.window.close();

  // ── ۶) بدون پل Tauri ─────────────────────────────────────────
  console.log('\n== no Tauri bridge ==');
  const plain = boot({ withBridge: false });
  check($(plain.doc, 'bridge-warning').hidden === false, 'warning banner visible');
  check($(plain.doc, 'btn-connect').disabled === true, 'connect disabled outside Tauri');
  plain.dom.window.close();

  console.log(`\n== summary: ${checks - failures.length}/${checks} passed ==`);
  if (failures.length) {
    failures.forEach((f) => console.log(`  - ${f}`));
    process.exit(1);
  }
  console.log('UI wiring matches the controller surface');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
