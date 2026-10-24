#!/usr/bin/env node
/* آزمون رابط کاربری بدون باز کردن پنجرهٔ واقعی.
 *
 * `index.html` + `main.js` داخل یک DOM مجازی (jsdom) بالا می‌آیند و پل
 * Tauri با یک ماک جایگزین می‌شود؛ سپس مسیرهای واقعی کاربر اجرا می‌شوند:
 * اتصال، قطع، تست تونل و حالت «بدون پل».
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
const script = fs.readFileSync(path.join(ROOT, 'src', 'main.js'), 'utf8');

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

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 5));
}

function makeStatus(overrides) {
  return Object.assign(
    {
      connected: false,
      proxyPort: null,
      configVersion: null,
      seq: 0,
      version: '5.2.6',
      streamingUrl: 'https://ghost-streaming-worker.cocoon-de9.workers.dev',
    },
    overrides
  );
}

function boot(withBridge) {
  const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://localhost/' });
  const { window } = dom;
  const calls = [];

  const backend = {
    status: makeStatus(),
    connectResult: makeStatus({ connected: true, proxyPort: 8899, configVersion: '5.1.1' }),
    disconnectResult: makeStatus(),
    testResult: { status: 200, ok: true, ghostPath: 'streaming', body: 'User-agent: *\nAllow: /' },
    failConnect: null,
  };

  if (withBridge) {
    window.__TAURI__ = {
      core: {
        invoke: async (command, args) => {
          calls.push({ command, args });
          if (command === 'status') return backend.status;
          if (command === 'connect') {
            if (backend.failConnect) throw backend.failConnect;
            backend.status = backend.connectResult;
            return backend.connectResult;
          }
          if (command === 'disconnect') {
            backend.status = backend.disconnectResult;
            return backend.disconnectResult;
          }
          if (command === 'tunnel_test') return backend.testResult;
          throw new Error(`unknown command ${command}`);
        },
      },
    };
  }

  window.eval(script);
  return { dom, window, calls, backend, doc: window.document };
}

function button(doc, id) {
  return doc.getElementById(id);
}

async function main() {
  // ── ۱) مسیر عادی: اتصال → تست → قطع ─────────────────────────
  console.log('== connected flow ==');
  const app = boot(true);
  const { doc, calls, backend } = app;

  await tick();
  check(calls.some((c) => c.command === 'status'), 'status is polled on boot');
  check(button(doc, 'btn-connect').disabled === false, 'connect is enabled at rest');
  check(button(doc, 'btn-disconnect').disabled === true, 'disconnect is disabled at rest');
  check(button(doc, 'btn-test').disabled === true, 'tunnel test needs a session');
  check(doc.getElementById('version').textContent === 'v5.2.6', 'version badge rendered');

  button(doc, 'btn-connect').click();
  await tick();
  check(doc.getElementById('dot').dataset.state === 'on', 'status dot turns green');
  check(
    doc.getElementById('status-label').textContent === 'متصل و امن',
    'label reads «متصل و امن»'
  );
  check(
    doc.getElementById('proxy').textContent === '127.0.0.1:8899',
    'local proxy address is displayed'
  );
  check(
    doc.getElementById('config-version').textContent === '5.1.1',
    'config version comes from the handshake'
  );
  check(button(doc, 'btn-connect').disabled === true, 'connect locks after success');
  check(button(doc, 'btn-disconnect').disabled === false, 'disconnect unlocks');
  check(button(doc, 'btn-test').disabled === false, 'tunnel test unlocks');

  doc.getElementById('test-target').value = 'https://www.youtube.com/robots.txt';
  button(doc, 'btn-test').click();
  await tick();
  const testCall = calls.find((c) => c.command === 'tunnel_test');
  check(
    testCall && testCall.args && testCall.args.target === 'https://www.youtube.com/robots.txt',
    'tunnel_test receives { target } in camelCase'
  );
  check(
    doc.getElementById('test-result').textContent.startsWith('HTTP 200 · streaming'),
    'result shows status + X-Ghost-Path'
  );
  check(doc.getElementById('test-result').className.includes('ok'), 'result marked as ok');

  button(doc, 'btn-disconnect').click();
  await tick();
  check(doc.getElementById('dot').dataset.state === 'off', 'dot returns to idle');
  check(doc.getElementById('proxy').textContent === '—', 'proxy address cleared');
  check(button(doc, 'btn-test').disabled === true, 'tunnel test locks again');
  app.dom.window.close();

  // ── ۲) خطای اتصال ────────────────────────────────────────────
  console.log('\n== handshake failure ==');
  const failing = boot(true);
  failing.backend.failConnect = 'signaling HTTP 429: Too many session-init requests.';
  failing.window.document.getElementById('btn-connect').click();
  await tick();
  check(
    failing.window.document.getElementById('dot').dataset.state === 'error',
    'dot turns red on failure'
  );
  check(
    failing.window.document.getElementById('status-hint').textContent.includes('429'),
    'server message is surfaced to the user'
  );
  check(
    failing.window.document.getElementById('btn-connect').disabled === false,
    'connect can be retried'
  );
  failing.dom.window.close();

  // ── ۳) تست ناموفق (۴۰۳ ورکر) ─────────────────────────────────
  console.log('\n== denied tunnel test ==');
  const denied = boot(true);
  denied.backend.connectResult = makeStatus({ connected: true, proxyPort: 8899 });
  denied.backend.testResult = {
    status: 403,
    ok: false,
    ghostPath: 'denied',
    body: 'Forbidden: Target URL not allowed.',
  };
  denied.window.document.getElementById('btn-connect').click();
  await tick();
  denied.window.document.getElementById('btn-test').click();
  await tick();
  const resultEl = denied.window.document.getElementById('test-result');
  check(resultEl.textContent.startsWith('HTTP 403 · denied'), 'denied path is shown');
  check(resultEl.className.includes('fail'), 'failure styling applied');
  denied.dom.window.close();

  // ── ۴) بدون پل Tauri ─────────────────────────────────────────
  console.log('\n== no Tauri bridge ==');
  const plain = boot(false);
  const plainDoc = plain.window.document;
  check(plainDoc.getElementById('bridge-warning').hidden === false, 'warning banner is visible');
  check(plainDoc.getElementById('btn-connect').disabled === true, 'connect disabled in a plain browser');
  check(plainDoc.getElementById('dot').dataset.state === 'error', 'dot shows the error state');
  plain.dom.window.close();

  console.log(`\n== summary: ${checks - failures.length}/${checks} passed ==`);
  if (failures.length) {
    failures.forEach((f) => console.log(`  - ${f}`));
    process.exit(1);
  }
  console.log('UI wiring matches the Rust command surface');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
