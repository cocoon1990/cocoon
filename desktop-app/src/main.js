/* SCP-GHOST desktop — منطق رابط کاربری
 *
 * هیچ وابستگی خارجی ندارد: فقط پل `window.__TAURI__.core.invoke`.
 * تمام کارهای رمزنگاری و شبکه در Rust انجام می‌شود؛ این فایل فقط نمایش است.
 */

'use strict';

const bridge = window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;

const el = {
  version: document.getElementById('version'),
  dot: document.getElementById('dot'),
  label: document.getElementById('status-label'),
  hint: document.getElementById('status-hint'),
  connect: document.getElementById('btn-connect'),
  disconnect: document.getElementById('btn-disconnect'),
  proxy: document.getElementById('proxy'),
  copy: document.getElementById('btn-copy'),
  configVersion: document.getElementById('config-version'),
  seq: document.getElementById('seq'),
  endpoint: document.getElementById('endpoint'),
  testTarget: document.getElementById('test-target'),
  test: document.getElementById('btn-test'),
  testResult: document.getElementById('test-result'),
  log: document.getElementById('log'),
  warning: document.getElementById('bridge-warning'),
};

const STATE_TEXT = {
  off: ['قطع', 'برای شروع، اتصال را برقرار کنید.'],
  busy: ['در حال اتصال…', 'تبادل کلید X25519 با سرور signaling'],
  on: ['متصل و امن', 'کلیدها فقط در حافظهٔ همین فرایند نگهداری می‌شوند.'],
  error: ['خطا', 'جزئیات در بخش رویدادها آمده است.'],
};

let pollTimer = null;
let busy = false;

/* ── ابزارک‌ها ─────────────────────────────────────────────── */

function stamp() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

function log(message, level = 'info') {
  const li = document.createElement('li');
  li.dataset.level = level;

  const time = document.createElement('time');
  time.textContent = stamp();

  const text = document.createElement('span');
  text.textContent = message;

  li.append(time, text);
  el.log.prepend(li);

  while (el.log.children.length > 40) {
    el.log.lastElementChild.remove();
  }
}

function setState(state, hint) {
  el.dot.dataset.state = state;
  const [label, defaultHint] = STATE_TEXT[state] || STATE_TEXT.off;
  el.label.textContent = label;
  el.hint.textContent = hint || defaultHint;
}

function setBusy(value) {
  busy = value;
  el.connect.disabled = value || el.disconnect.dataset.connected === 'true';
  el.disconnect.disabled = value || el.disconnect.dataset.connected !== 'true';
  el.test.disabled = value || el.disconnect.dataset.connected !== 'true';
}

function errorMessage(err) {
  if (typeof err === 'string') return err;
  if (err && typeof err.message === 'string') return err.message;
  return String(err);
}

async function invoke(command, args) {
  if (!bridge) throw new Error('Tauri bridge unavailable');
  return bridge.invoke(command, args);
}

/* ── رندر وضعیت ────────────────────────────────────────────── */

function render(status) {
  el.version.textContent = `v${status.version || '—'}`;
  el.endpoint.textContent = status.streamingUrl || '—';
  el.seq.textContent = String(status.seq ?? 0);
  el.configVersion.textContent = status.configVersion || '—';

  const connected = Boolean(status.connected);

  el.disconnect.dataset.connected = connected ? 'true' : 'false';
  el.connect.disabled = busy || connected;
  el.disconnect.disabled = busy || !connected;
  el.test.disabled = busy || !connected;

  if (!busy) setState(connected ? 'on' : 'off');

  if (status.proxyPort) {
    el.proxy.textContent = `127.0.0.1:${status.proxyPort}`;
    el.copy.disabled = false;
  } else {
    el.proxy.textContent = '—';
    el.copy.disabled = true;
  }

  if (connected && !pollTimer) {
    pollTimer = setInterval(refresh, 2000);
  } else if (!connected && pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function renderError(message) {
  setState('error', message);
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  el.disconnect.dataset.connected = 'false';
  el.connect.disabled = false;
  el.disconnect.disabled = true;
  el.test.disabled = true;
  el.proxy.textContent = '—';
}

/* ── عملیات ────────────────────────────────────────────────── */

async function refresh() {
  try {
    render(await invoke('status'));
  } catch (err) {
    /* polling نباید UI را خراب کند */
    console.warn('status poll failed', err);
  }
}

async function connect() {
  if (busy) return;
  setState('busy');
  setBusy(true);
  log('شروع تبادل کلید…');

  try {
    const status = await invoke('connect');
    setBusy(false);
    render(status);
    log('اتصال برقرار شد؛ کلید امضا در حافظه فعال است.', 'ok');
    if (status.proxyPort) {
      log(`پراکسی محلی روی 127.0.0.1:${status.proxyPort} گوش می‌دهد.`);
    } else {
      log('پراکسی محلی فعال نشد (پورت اشغال بود) — تست تونل همچنان کار می‌کند.', 'error');
    }
  } catch (err) {
    const message = errorMessage(err);
    setBusy(false);
    renderError(message);
    log(`اتصال ناموفق: ${message}`, 'error');
  }
}

async function disconnect() {
  if (busy) return;
  setBusy(true);
  log('قطع اتصال…');

  try {
    const status = await invoke('disconnect');
    setBusy(false);
    render(status);
    log('اتصال قطع شد و کلید امضا پاک‌سازی شد.', 'ok');
    el.testResult.hidden = true;
  } catch (err) {
    const message = errorMessage(err);
    setBusy(false);
    renderError(message);
    log(`قطع اتصال ناموفق: ${message}`, 'error');
  }
}

async function runTest() {
  const target = el.testTarget.value.trim();
  if (!target) {
    log('آدرس تست خالی است.', 'error');
    return;
  }

  el.test.disabled = true;
  el.testResult.hidden = false;
  el.testResult.className = 'result';
  el.testResult.textContent = 'در حال ارسال…';

  try {
    const result = await invoke('tunnel_test', { target });
    const header = `HTTP ${result.status}${result.ghostPath ? ` · ${result.ghostPath}` : ''}`;
    el.testResult.textContent = `${header}\n${result.body || '(بدون بدنه)'}`;
    el.testResult.className = `result ${result.ok ? 'ok' : 'fail'}`;
    log(
      result.ok
        ? `تست تونل موفق بود (HTTP ${result.status}).`
        : `تست تونل شکست خورد (HTTP ${result.status}).`,
      result.ok ? 'ok' : 'error'
    );
  } catch (err) {
    const message = errorMessage(err);
    el.testResult.textContent = message;
    el.testResult.className = 'result fail';
    log(`تست تونل ناموفق: ${message}`, 'error');
  } finally {
    setBusy(false);
    el.test.disabled = el.disconnect.dataset.connected !== 'true';
  }
}

async function copyProxy() {
  const value = el.proxy.textContent.trim();
  if (!value || value === '—') return;

  try {
    await navigator.clipboard.writeText(value);
    log(`آدرس پراکسی کپی شد: ${value}`, 'ok');
  } catch {
    log('کپی خودکار ممکن نشد؛ آدرس را دستی انتخاب کنید.', 'error');
  }
}

/* ── راه‌اندازی ────────────────────────────────────────────── */

function boot() {
  el.connect.addEventListener('click', connect);
  el.disconnect.addEventListener('click', disconnect);
  el.test.addEventListener('click', runTest);
  el.copy.addEventListener('click', copyProxy);
  el.testTarget.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !el.test.disabled) runTest();
  });

  if (!bridge) {
    el.warning.hidden = false;
    setState('error', 'این صفحه در مرورگر معمولی باز شده است.');
    el.connect.disabled = true;
    return;
  }

  log('برنامه آماده است.');
  refresh();
}

boot();
