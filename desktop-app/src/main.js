/*!
 * main.js — SCP-GHOST desktop UI controller.
 *
 * The Rust side is only a controller (config file + meow sidecar process).
 * Everything user-facing — subscription fetch, parsing, YAML — lives in
 * core.js so it can be unit-tested under Node.
 */
(function () {
  'use strict';

  const core = window.SCPGhost;
  const bridge = window.__TAURI__ && window.__TAURI__.core;

  const el = (id) => document.getElementById(id);
  const ui = {
    body: document.body,
    pill: el('status-pill'),
    statusText: el('status-text'),
    connect: el('btn-connect'),
    connectLabel: el('connect-label'),
    hint: el('hint'),
    modeSwitch: el('mode-switch'),
    modeNote: el('mode-note'),
    subUrl: el('sub-url'),
    fetchBtn: el('btn-fetch'),
    copyBtn: el('btn-copy'),
    nodeBadge: el('node-badge'),
    nodeInfo: el('node-info'),
    nodeHost: el('node-host'),
    nodePort: el('node-port'),
    nodeUuid: el('node-uuid'),
    nodePath: el('node-path'),
    proxyLine: el('proxy-line'),
    proxyAddr: el('proxy-addr'),
    advancedBtn: el('btn-advanced'),
    advanced: el('advanced'),
    mixedPort: el('mixed-port'),
    updateBtn: el('btn-update'),
    log: el('log'),
    clearLog: el('btn-clear-log'),
    toast: el('toast'),
    version: el('app-version'),
    lastError: el('last-error'),
    tunChip: el('tun-chip'),
  };

  const STORAGE = {
    subUrl: 'scpghost.subUrl',
    node: 'scpghost.node',
    mode: 'scpghost.mode',
    port: 'scpghost.port',
  };

  const state = {
    node: null,
    mode: 'tun',
    // session = نشست رمزنگاری؛ adapter = آداپتور TUN زنده (پس از قطع هم می‌ماند)
    session: false,
    adapter: false,
    running: false,
    busy: false,
    version: '',
    port: 7890,
    pendingUpdate: null,
    logCount: 0,
  };

  const MESSAGES = {
    EMPTY_SUBSCRIPTION: 'پاسخ اشتراک خالی است.',
    INVALID_SUBSCRIPTION: 'پاسخ اشتراک معتبر نیست (Base64 یا لینک یافت نشد).',
    NOT_VLESS: 'لینک اشتراک از نوع VLESS نیست.',
    NO_VLESS_NODE: 'در اشتراک هیچ نود VLESS پیدا نشد.',
    INVALID_VLESS: 'ساختار لینک VLESS ناقص است.',
    INVALID_UUID: 'UUID موجود در لینک معتبر نیست.',
    INVALID_HOST: 'دامنهٔ نود معتبر نیست.',
    INVALID_SNI: 'مقدار SNI معتبر نیست.',
    INVALID_PORT: 'پورت معتبر نیست.',
    INVALID_PATH: 'مسیر WebSocket معتبر نیست.',
    UNSUPPORTED_TRANSPORT: 'فقط انتقال WebSocket پشتیبانی می‌شود.',
    UNSUPPORTED_SECURITY: 'نود باید TLS داشته باشد.',
    UNSUPPORTED_ENCRYPTION: 'رمزنگاری VLESS باید none باشد.',
    YAML_INJECTION: 'مقدار نامعتبر در پیکربندی.',
    NO_BRIDGE: 'پوستهٔ دسکتاپ پیدا نشد؛ این صفحه فقط پیش‌نمایش است.',
  };

  /* ── helpers ─────────────────────────────────────────────── */

  let toastTimer = null;
  function toast(message, kind) {
    ui.toast.textContent = message;
    ui.toast.dataset.kind = kind || 'info';
    ui.toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => ui.toast.classList.remove('show'), 3600);
  }

  /**
   * متن دقیق و قابل‌اقدام برای هر خطا. عدد HTTP و نوع خطای شبکه هرگز
   * پنهان نمی‌شوند: «HTTP 403»، «Timeout»، «Network».
   */
  function describe(err) {
    if (!err) return 'خطای نامشخص';
    if (err.code && MESSAGES[err.code]) return MESSAGES[err.code];

    const name = err.name || '';
    const raw = typeof err === 'string' ? err : err.message || String(err);

    if (name === 'AbortError') return 'Timeout — سرور در ۲۰ ثانیه پاسخ نداد';
    if (name === 'TypeError' || /failed to fetch|networkerror|load failed/i.test(raw)) {
      return 'Network — اتصال برقرار نشد (DNS/فیلترینگ/CORS)';
    }
    const http = /^HTTP (\d{3})$/.exec(raw.trim());
    if (http) {
      const code = Number(http[1]);
      if (code === 401 || code === 403) return 'HTTP ' + code + ' — دسترسی رد شد (توکن اشتراک را بررسی کنید)';
      if (code === 404) return 'HTTP 404 — مسیر اشتراک پیدا نشد';
      if (code === 429) return 'HTTP 429 — درخواست‌ها زیاد شد؛ چند لحظه صبر کنید';
      if (code === 503) return 'HTTP 503 — سرویس اشتراک تنظیم نشده است (SUB_TOKEN / VLESS_UUID)';
      if (code >= 500) return 'HTTP ' + code + ' — خطای سرور (worker را بررسی کنید)';
      return 'HTTP ' + code;
    }

    const text = raw.length > 220 ? raw.slice(0, 217) + '…' : raw;
    return text;
  }

  /** ثبت فوری خطا در پنل گزارش (و خط راهنما زیر دکمه). */
  function reportError(err, kind) {
    const message = describe(err);
    if (ui.lastError) {
      ui.lastError.textContent = message;
      ui.lastError.dataset.kind = kind || 'error';
      ui.lastError.hidden = false;
    }
    writeLog('[' + (kind || 'error') + '] ' + message);
    return message;
  }

  function clearError() {
    if (ui.lastError) ui.lastError.hidden = true;
  }

  /** یک خط به بافر لاگ سمت راست (تا با لاگ هسته یکی شود). */
  function writeLog(line) {
    if (bridge) invoke('log_line', { line }).catch(() => {});
    appendLogLine('[ui] ' + line);
  }

  function setStatus(kind, label) {
    ui.pill.dataset.state = kind;
    ui.body.dataset.state = kind === 'on' ? 'on' : kind === 'busy' ? 'busy' : 'idle';
    ui.statusText.textContent = label;
  }

  function setBusy(busy) {
    state.busy = busy;
    ui.connect.disabled = busy;
    ui.fetchBtn.disabled = busy;
  }

  function save(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (_err) {
      /* storage is a nicety, never fatal */
    }
  }

  function load(key) {
    try {
      return localStorage.getItem(key);
    } catch (_err) {
      return null;
    }
  }

  async function invoke(command, args) {
    if (!bridge) throw { code: 'NO_BRIDGE' };
    return bridge.invoke(command, args);
  }

  /* ── rendering ───────────────────────────────────────────── */

  function renderNode() {
    const node = state.node;
    if (!node) {
      ui.nodeInfo.hidden = true;
      ui.nodeBadge.textContent = 'بدون نود';
      ui.nodeBadge.classList.remove('ready');
      return;
    }
    ui.nodeHost.textContent = node.host;
    ui.nodePort.textContent = String(node.port);
    ui.nodeUuid.textContent = core.maskUuid(node.uuid);
    ui.nodePath.textContent = node.path;
    ui.nodeInfo.hidden = false;
    ui.nodeBadge.textContent = node.remark;
    ui.nodeBadge.classList.add('ready');
  }

  function renderMode() {
    const buttons = ui.modeSwitch.querySelectorAll('button[data-mode]');
    buttons.forEach((button) => {
      const active = button.dataset.mode === state.mode;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    ui.modeSwitch.dataset.index = state.mode === 'proxy' ? '1' : '0';
    ui.modeNote.textContent =
      state.mode === 'tun'
        ? 'همهٔ ترافیک سیستم از تونل عبور می‌کند (نیازمند دسترسی مدیر).'
        : 'یک پروکسی محلی روی 127.0.0.1 فعال می‌شود؛ بدون دسترسی مدیر.';
  }

  function renderConnect() {
    const connected = state.session;
    ui.connectLabel.textContent = connected ? 'قطع' : state.busy ? 'صبر…' : 'اتصال';
    ui.proxyLine.hidden = !connected;
    ui.proxyAddr.textContent = '127.0.0.1:' + state.port;

    // آداپتور TUN بعد از قطع هم زنده می‌ماند → نشانش می‌دهیم.
    if (ui.tunChip) ui.tunChip.hidden = !(state.adapter && !connected);

    if (connected) {
      setStatus('on', 'متصل');
      ui.hint.textContent =
        state.mode === 'tun'
          ? 'تونل کامل برقرار است؛ ترافیک سیستم از SCP-GHOST عبور می‌کند.'
          : 'پروکسی محلی فعال است: 127.0.0.1:' + state.port;
    } else if (!state.busy) {
      setStatus('idle', state.node ? 'آماده' : 'قطع');
      ui.hint.textContent = state.adapter
        ? 'آداپتور TUN زنده است؛ اتصال مجدد بدون ساخت دوبارهٔ آداپتور انجام می‌شود.'
        : state.node
          ? 'نود آماده است؛ برای اتصال دکمهٔ بالا را بزنید.'
          : 'برای شروع، لینک اشتراک را وارد کنید.';
    }
  }

  function logClass(line) {
    if (/\[ui\]|\[error\]|\[warn\]|HTTP \d{3}|Timeout|Network —/.test(line)) return 'ln err';
    if (/session (resumed|up)|core started/i.test(line)) return 'ln ok';
    return 'ln';
  }

  function renderLogs(lines) {
    ui.log.replaceChildren();
    for (const line of lines) {
      const row = document.createElement('span');
      row.className = logClass(line);
      row.textContent = line;
      ui.log.appendChild(row);
    }
    ui.log.scrollTop = ui.log.scrollHeight;
  }

  function appendLogLine(line) {
    const row = document.createElement('span');
    row.className = logClass(line);
    row.textContent = line;
    ui.log.appendChild(row);
    while (ui.log.childElementCount > 400) ui.log.removeChild(ui.log.firstChild);
    ui.log.scrollTop = ui.log.scrollHeight;
  }

  /* ── actions ─────────────────────────────────────────────── */

  async function fetchSubscription() {
    const url = ui.subUrl.value.trim();
    if (!url) {
      toast('لینک اشتراک را وارد کنید.', 'error');
      ui.subUrl.focus();
      return;
    }
    setBusy(true);
    setStatus('busy', 'دریافت…');
    ui.fetchBtn.textContent = '…';
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      let response;
      try {
        response = await fetch(url, { signal: controller.signal, cache: 'no-store' });
      } finally {
        clearTimeout(timer);
      }
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const body = await response.text();
      const node = core.extractNode(body);

      state.node = node;
      state.port = Number(ui.mixedPort.value) || state.port;
      save(STORAGE.subUrl, url);
      save(STORAGE.node, JSON.stringify(node));
      renderNode();
      renderConnect();
      toast('نود «' + node.remark + '» دریافت شد.', 'ok');
    } catch (err) {
      toast(reportError(err, 'fetch'), 'error');
      setStatus('error', 'خطا');
      setTimeout(() => renderConnect(), 2200);
    } finally {
      setBusy(false);
      ui.fetchBtn.textContent = 'دریافت';
    }
  }

  async function connect() {
    if (!state.node) {
      toast('اول اشتراک را دریافت کنید.', 'error');
      return;
    }
    const port = Number(ui.mixedPort.value);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      toast('پورت پروکسی محلی بین ۱۰۲۴ و ۶۵۵۳۵ باشد.', 'error');
      return;
    }
    state.port = port;
    save(STORAGE.port, String(port));
    save(STORAGE.mode, state.mode);

    setBusy(true);
    setStatus('busy', 'اتصال…');
    ui.connectLabel.textContent = 'صبر…';
    clearError();
    const warm = state.adapter;
    try {
      const config = core.buildCoreConfig(state.node, { mode: state.mode, mixedPort: port });
      const status = await invoke('start_core', { config, mode: state.mode });
      applyStatus(status);
      const ms = status && status.elapsed_ms;
      if (warm && typeof ms === 'number') {
        toast('اتصال مجدد در ' + ms + ' میلی‌ثانیه (TUN بدون تغییر).', 'ok');
      } else if (typeof ms === 'number') {
        toast('هستهٔ SCP-GHOST اجرا شد (' + ms + ' میلی‌ثانیه).', 'ok');
      } else {
        toast('هستهٔ SCP-GHOST اجرا شد.', 'ok');
      }
    } catch (err) {
      toast(reportError(err, 'connect'), 'error');
      state.session = false;
      setStatus('error', 'خطا');
      setTimeout(() => renderConnect(), 2200);
    } finally {
      setBusy(false);
      renderConnect();
    }
  }

  async function disconnect() {
    setBusy(true);
    setStatus('busy', 'قطع…');
    clearError();
    try {
      // فقط نشست پاک می‌شود؛ آداپتور TUN سر جایش می‌ماند.
      const status = await invoke('stop_core');
      applyStatus(status);
      toast(
        status && status.adapter
          ? 'نشست بسته شد؛ آداپتور TUN زنده ماند.'
          : 'اتصال قطع شد.'
      );
    } catch (err) {
      toast(reportError(err, 'disconnect'), 'error');
    } finally {
      setBusy(false);
      renderConnect();
    }
  }

  function applyStatus(status) {
    if (!status || typeof status !== 'object') return;
    state.session = Boolean(status.session);
    state.adapter = Boolean(status.adapter);
    state.running = state.session;
    if (status.mode === 'tun' || status.mode === 'proxy') state.mode = status.mode;
    if (typeof status.version === 'string' && status.version) {
      state.version = status.version;
      ui.version.textContent = 'v' + status.version;
    }
    renderMode();
    renderConnect();
  }

  async function poll() {
    if (!bridge) return;
    try {
      const status = await invoke('core_state');
      const wasSession = state.session;
      applyStatus(status);
      if (wasSession && !state.session) setStatus('idle', 'قطع');
      const lines = await invoke('read_logs');
      if (Array.isArray(lines) && lines.length !== state.logCount) {
        state.logCount = lines.length;
        renderLogs(lines);
      }
    } catch (_err) {
      /* transient IPC hiccups must not spam the UI */
    }
  }

  const RELEASES_API = 'https://api.github.com/repos/cocoon1990/cocoon/releases/latest';

  /**
   * اگر پلاگین updater نتواند کار کند (مثلاً امضای انتشار تنظیم نشده)،
   * همین اطلاعات از GitHub Releases خوانده می‌شود تا کاربر هرگز پیام
   * مبهم نبیند. خطای دقیق هر دو مسیر در پنل گزارش می‌آید.
   */
  async function checkReleasesFallback(current) {
    try {
      const response = await fetch(RELEASES_API, {
        headers: { Accept: 'application/vnd.github+json' },
        cache: 'no-store',
      });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const release = core.readLatestRelease(await response.json());
      const newer = core.compareVersions(release.version, current) > 0;
      writeLog('github releases: ' + release.tag + ' (current v' + current + ')');
      return { release, newer };
    } catch (err) {
      reportError(err, 'update');
      return null;
    }
  }

  async function checkUpdates() {
    if (!bridge) {
      toast(MESSAGES.NO_BRIDGE, 'error');
      return;
    }
    ui.updateBtn.disabled = true;
    const previous = ui.updateBtn.textContent;
    ui.updateBtn.textContent = 'بررسی…';
    clearError();
    try {
      const result = await invoke('check_updates');
      if (result && result.available) {
        state.pendingUpdate = result;
        ui.updateBtn.textContent = 'نصب v' + result.latest;
        toast('نسخهٔ ' + result.latest + ' موجود است.', 'ok');
      } else if (result && result.error) {
        // مسیر رسمی updater بسته است → گزارش دقیق + بررسی Releases
        ui.updateBtn.textContent = previous;
        reportError(result.error, 'update');
        if (result.current) {
          const fallback = await checkReleasesFallback(result.current);
          if (fallback && fallback.newer) {
            toast('نسخهٔ ' + fallback.release.version + ' منتشر شده است.', 'ok');
          }
        }
      } else {
        ui.updateBtn.textContent = previous;
        toast('برنامه به‌روز است.');
      }
    } catch (err) {
      ui.updateBtn.textContent = previous;
      toast(reportError(err, 'update'), 'error');
    } finally {
      ui.updateBtn.disabled = false;
    }
  }

  async function installUpdate() {
    ui.updateBtn.disabled = true;
    ui.updateBtn.textContent = 'در حال نصب…';
    try {
      await invoke('install_update');
      toast('نصب‌کننده اجرا شد؛ برنامه بسته می‌شود.', 'ok');
    } catch (err) {
      toast(reportError(err, 'update'), 'error');
      ui.updateBtn.disabled = false;
      ui.updateBtn.textContent = 'بررسی به‌روزرسانی';
      state.pendingUpdate = null;
    }
  }

  /* ── wiring ──────────────────────────────────────────────── */

  ui.connect.addEventListener('click', () => {
    if (state.busy) return;
    if (state.running) disconnect();
    else connect();
  });

  ui.fetchBtn.addEventListener('click', fetchSubscription);

  ui.subUrl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') fetchSubscription();
  });

  ui.copyBtn.addEventListener('click', async () => {
    const value = ui.subUrl.value.trim();
    if (!value) {
      toast('چیزی برای کپی نیست.', 'error');
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      toast('لینک کپی شد.', 'ok');
    } catch (_err) {
      ui.subUrl.select();
      toast('کپی نشد؛ لینک انتخاب شد.', 'error');
    }
  });

  ui.modeSwitch.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-mode]');
    if (!button) return;
    if (state.mode === button.dataset.mode) return;
    state.mode = button.dataset.mode;
    save(STORAGE.mode, state.mode);
    renderMode();
    if (state.running) {
      toast('برای اعمال حالت جدید، اتصال را دوباره برقرار کنید.');
    }
  });

  ui.advancedBtn.addEventListener('click', () => {
    const open = ui.advancedBtn.getAttribute('aria-expanded') === 'true';
    ui.advancedBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
    ui.advanced.hidden = open;
  });

  ui.mixedPort.addEventListener('change', () => {
    const port = Number(ui.mixedPort.value);
    if (Number.isInteger(port) && port >= 1024 && port <= 65535) {
      state.port = port;
      save(STORAGE.port, String(port));
      ui.proxyAddr.textContent = '127.0.0.1:' + port;
    } else {
      toast('پورت معتبر نیست.', 'error');
      ui.mixedPort.value = String(state.port);
    }
  });

  // خروج پنجره = نابودی آداپتور TUN و پاک‌سازی حافظه.
  if (bridge) {
    window.addEventListener('beforeunload', () => {
      try {
        invoke('shutdown_core');
      } catch (_err) {
        /* the process is going away anyway */
      }
    });
  }

  ui.updateBtn.addEventListener('click', () => {
    if (state.pendingUpdate) installUpdate();
    else checkUpdates();
  });

  ui.clearLog.addEventListener('click', async () => {
    if (!bridge) return;
    try {
      await invoke('clear_logs');
      state.logCount = 0;
      renderLogs([]);
    } catch (err) {
      toast(describe(err), 'error');
    }
  });

  function boot() {
    const savedUrl = load(STORAGE.subUrl);
    if (savedUrl) ui.subUrl.value = savedUrl;

    const savedMode = load(STORAGE.mode);
    if (savedMode === 'proxy' || savedMode === 'tun') state.mode = savedMode;

    const savedPort = Number(load(STORAGE.port));
    if (Number.isInteger(savedPort) && savedPort >= 1024 && savedPort <= 65535) {
      state.port = savedPort;
      ui.mixedPort.value = String(savedPort);
    }

    try {
      const savedNode = JSON.parse(load(STORAGE.node) || 'null');
      if (savedNode && savedNode.uuid && savedNode.host) state.node = savedNode;
    } catch (_err) {
      /* ignore corrupted cache */
    }

    renderMode();
    renderNode();
    renderConnect();

    if (!bridge) {
      ui.hint.textContent = MESSAGES.NO_BRIDGE;
      setStatus('error', 'پیش‌نمایش');
      ui.connect.disabled = true;
      ui.updateBtn.disabled = true;
      return;
    }

    poll();
    setInterval(poll, 1500);
  }

  boot();
})();
