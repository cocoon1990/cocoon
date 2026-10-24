/* SCP-GHOST desktop — رابط کاربری و کنترل‌کنندهٔ نازک
 *
 * جریان کار:
 *   ۱) متن اشتراک را از بک‌اند می‌گیرد (Rust، بدون درگیری CORS)
 *   ۲) URI را به کانفیگ هسته تبدیل می‌کند (core-config.js — تست‌شده)
 *   ۳) کانفیگ را به بک‌اند می‌دهد تا بنویسد و sidecar را اجرا کند
 *
 * هیچ منطق شبکه‌ای اینجا نیست؛ نه سوکت، نه TUN، نه رمزنگاری.
 */

'use strict';

const bridge = window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;
const cfg = window.SCPGhostConfig;

const el = {
  dot: document.getElementById('dot'),
  label: document.getElementById('status-label'),
  hint: document.getElementById('status-hint'),
  connect: document.getElementById('btn-connect'),
  disconnect: document.getElementById('btn-disconnect'),
  badge: document.getElementById('mode-badge'),
  subUrl: document.getElementById('sub-url'),
  fetch: document.getElementById('btn-fetch'),
  subState: document.getElementById('sub-state'),
  nodeInfo: document.getElementById('node-info'),
  nodeServer: document.getElementById('node-server'),
  nodeNetwork: document.getElementById('node-network'),
  nodeSecurity: document.getElementById('node-security'),
  nodeName: document.getElementById('node-name'),
  modeTun: document.getElementById('mode-tun'),
  modeProxy: document.getElementById('mode-proxy'),
  modeNote: document.getElementById('mode-note'),
  proxy: document.getElementById('proxy'),
  copy: document.getElementById('btn-copy'),
  pid: document.getElementById('pid'),
  configPath: document.getElementById('config-path'),
  log: document.getElementById('core-log'),
  warning: document.getElementById('bridge-warning'),
};

const MODE_NOTE = {
  tun:
    'TUN همهٔ ترافیک ویندوز را از هسته عبور می‌دهد و به دسترسی مدیر نیاز دارد ' +
    '(برنامه با UAC بالا می‌آید).',
  proxy:
    'فقط برنامه‌هایی که از پراکسی سیستم استفاده می‌کنند از این مسیر عبور می‌کنند. ' +
    'بدون نیاز به دسترسی مدیر.',
};

let mode = 'tun';
let busy = false;
let pollTimer = null;
let lastLog = '';
let lastPayload = '';

/* ── ابزار ─────────────────────────────────────────────────── */

function errorMessage(err) {
  if (typeof err === 'string') return err;
  if (err && typeof err.message === 'string') return err.message;
  return String(err);
}

async function invoke(command, args) {
  if (!bridge) throw new Error('پل Tauri در دسترس نیست.');
  return bridge.invoke(command, args);
}

function setState(state, hint) {
  el.dot.dataset.state = state;
  const labels = {
    off: 'قطع',
    busy: 'در حال کار…',
    on: 'متصل',
    error: 'خطا',
  };
  el.label.textContent = labels[state] || labels.off;
  if (hint !== undefined) el.hint.textContent = hint;
}

function setMode(next) {
  mode = next === 'proxy' ? 'proxy' : 'tun';
  el.badge.textContent = mode === 'tun' ? 'TUN' : 'PROXY';
  el.badge.dataset.mode = mode;
  el.modeTun.classList.toggle('active', mode === 'tun');
  el.modeProxy.classList.toggle('active', mode === 'proxy');
  el.modeNote.textContent = MODE_NOTE[mode];
}

function updateButtons(running) {
  el.connect.disabled = busy || running;
  el.disconnect.disabled = busy || !running;
  el.fetch.disabled = busy;
}

function renderLog(log) {
  const text = (log || []).join('\n');
  if (text === lastLog) return;
  lastLog = text;
  el.log.textContent = text || '(بدون خروجی)';
  el.log.scrollTop = el.log.scrollHeight;
}

function renderStatus(status) {
  updateButtons(status.running);
  el.pid.textContent = status.pid ? String(status.pid) : '—';
  el.proxy.textContent = status.proxyUrl || '—';
  el.configPath.textContent = status.configPath || '—';
  el.configPath.title = status.configPath || '';
  renderLog(status.log);

  if (status.running) {
    setState('on', 'هستهٔ پراکسی در حال اجراست.');
    if (!pollTimer) pollTimer = setInterval(poll, 1200);
  } else {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (!busy) setState('off', 'برای شروع، دکمهٔ «اتصال» را بزنید.');
  }
}

async function poll() {
  try {
    const status = await invoke('core_status');
    const wasRunning = el.disconnect.disabled === false;
    renderStatus(status);
    if (!status.running && !busy && wasRunning) {
      setState('error', 'هسته متوقف شد؛ لاگ را بررسی کنید.');
    }
  } catch (err) {
    console.warn('status poll failed', err);
  }
}

/* ── اشتراک ────────────────────────────────────────────────── */

async function loadSubscription(showState) {
  const url = el.subUrl.value.trim();
  if (!url) throw new Error('آدرس اشتراک خالی است.');

  if (showState) {
    el.subState.textContent = 'در حال دریافت…';
    el.subState.className = 'muted';
  }

  const payload = await invoke('fetch_subscription', { url });
  const node = cfg.parseVlessUri(cfg.extractVlessUri(payload.body));

  el.nodeInfo.hidden = false;
  el.nodeServer.textContent = `${node.server}:${node.port}`;
  el.nodeNetwork.textContent = node.network;
  el.nodeSecurity.textContent = node['reality-opts']
    ? 'reality'
    : node.tls
      ? `tls (${node['client-fingerprint']})`
      : 'none';
  el.nodeName.textContent = node.name;

  if (showState) {
    el.subState.textContent = `دریافت شد (${payload.bytes} بایت)`;
    el.subState.className = 'muted ok';
  }

  lastPayload = payload.body;
  return node;
}

/* ── عملیات ────────────────────────────────────────────────── */

async function connect() {
  if (busy) return;
  busy = true;
  updateButtons(true);
  setState('busy', 'دریافت اشتراک و ساخت کانفیگ…');

  try {
    const node = await loadSubscription(true);
    setState('busy', 'نوشتن کانفیگ و اجرای هسته…');

    const config = cfg.buildCoreConfig({ node, mode });
    const status = await invoke('start_core', { config, mode });

    busy = false;
    renderStatus(status);

    if (!status.running) {
      setState('error', 'هسته بالا نیامد؛ لاگ را بررسی کنید.');
    } else {
      setState('on', `هسته با حالت ${mode === 'tun' ? 'TUN' : 'پراکسی محلی'} در حال اجراست.`);
    }
  } catch (err) {
    busy = false;
    const message = errorMessage(err);
    setState('error', message);
    updateButtons(false);
    try {
      await invoke('stop_core');
    } catch {
      /* هسته‌ای نبوده */
    }
  }
}

async function disconnect() {
  if (busy) return;
  busy = true;
  updateButtons(true);

  try {
    const status = await invoke('stop_core');
    busy = false;
    renderStatus(status);
    setState('off', 'اتصال قطع شد.');
  } catch (err) {
    busy = false;
    const message = errorMessage(err);
    setState('error', message);
    updateButtons(false);
  }
}

async function inspectSubscription() {
  try {
    await loadSubscription(true);
  } catch (err) {
    const message = errorMessage(err);
    el.subState.textContent = message;
    el.subState.className = 'muted fail';
  }
}

async function copyProxy() {
  const value = el.proxy.textContent.trim();
  if (!value || value === '—') return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    /* بی‌اهمیت */
  }
}

/* ── راه‌اندازی ────────────────────────────────────────────── */

function boot() {
  setMode('tun');

  el.connect.addEventListener('click', connect);
  el.disconnect.addEventListener('click', disconnect);
  el.fetch.addEventListener('click', inspectSubscription);
  el.copy.addEventListener('click', copyProxy);
  el.modeTun.addEventListener('click', () => setMode('tun'));
  el.modeProxy.addEventListener('click', () => setMode('proxy'));
  window.addEventListener('beforeunload', () => {
    if (pollTimer) clearInterval(pollTimer);
  });

  if (!bridge || !cfg) {
    el.warning.hidden = false;
    setState('error', 'این صفحه در مرورگر معمولی باز شده است.');
    updateButtons(false);
    el.connect.disabled = true;
    el.fetch.disabled = true;
    return;
  }

  poll();
}

boot();
