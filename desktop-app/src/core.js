/*!
 * core.js — SCP-GHOST desktop, pure logic layer (no DOM, no Tauri).
 *
 * Everything here is deterministic and side-effect free so the Node test
 * harness can exercise it without a browser:
 *   - subscription decoding (plain text or Base64 / Base64URL)
 *   - vless:// URI parsing + validation
 *   - mihomo-compatible YAML generation (the meow core consumes this)
 *   - semver comparison for the updater banner
 *
 * UMD: `window.SCPGhost` in the webview, `require()` in Node.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SCPGhost = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const HOST_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  const PATH_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/;
  const IPV6_RE = /^[0-9a-f:]{2,45}$/i;

  /** Hostname or bracketed IPv6 literal (without the brackets). */
  function isHostLike(value) {
    if (typeof value !== 'string' || value === '') return false;
    if (value.includes(':')) return IPV6_RE.test(value);
    return HOST_RE.test(value);
  }

  /** Error carrying a stable machine code the UI can translate. */
  function fail(code, message) {
    const err = new Error(message || code);
    err.code = code;
    return err;
  }

  const B64_ALPHABET = /^[A-Za-z0-9+/=_-]+$/;

  function b64ToBytes(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);

    if (typeof atob === 'function') {
      const binary = atob(padded);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
      return out;
    }
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(padded, 'base64'));
    }
    throw fail('NO_BASE64', 'No base64 decoder available in this runtime');
  }

  function bytesToUtf8(bytes) {
    if (typeof TextDecoder === 'function') return new TextDecoder('utf-8').decode(bytes);
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('utf8');
    let out = '';
    for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes[i]);
    return out;
  }

  /**
   * Subscription endpoints answer with Base64 (that is what the worker does),
   * but a raw text list must also work. Detect instead of guessing.
   */
  function decodeSubscriptionBody(body) {
    if (typeof body !== 'string' || body.trim() === '') {
      throw fail('EMPTY_SUBSCRIPTION', 'Subscription body is empty');
    }

    const text = body.replace(/^\uFEFF/, '').trim();

    if (text.includes('://')) {
      return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    }
    if (!B64_ALPHABET.test(text)) {
      throw fail('INVALID_SUBSCRIPTION', 'Subscription is neither a URI list nor Base64');
    }

    const decoded = bytesToUtf8(b64ToBytes(text)).replace(/^\uFEFF/, '').trim();
    if (!decoded.includes('://')) {
      throw fail(
        'INVALID_SUBSCRIPTION',
        'Base64 decoded, but the payload contains no share link (is the token wrong?)'
      );
    }
    return decoded.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function safeDecode(value) {
    try {
      return decodeURIComponent(value);
    } catch (_err) {
      return value;
    }
  }

  function parseVlessUri(uri) {
    if (typeof uri !== 'string' || !/^vless:\/\//i.test(uri.trim())) {
      throw fail('NOT_VLESS', 'Expected a vless:// link');
    }

    let rest = uri.trim().slice('vless://'.length);
    let remark = '';
    const hash = rest.indexOf('#');
    if (hash >= 0) {
      remark = safeDecode(rest.slice(hash + 1));
      rest = rest.slice(0, hash);
    }

    let query = '';
    const question = rest.indexOf('?');
    if (question >= 0) {
      query = rest.slice(question + 1);
      rest = rest.slice(0, question);
    }

    const at = rest.lastIndexOf('@');
    if (at <= 0) throw fail('INVALID_VLESS', 'Missing uuid@host:port');

    const uuid = safeDecode(rest.slice(0, at));
    if (!UUID_RE.test(uuid)) throw fail('INVALID_UUID', 'Link uuid is not a valid UUID');

    const authority = rest.slice(at + 1);
    let host;
    let portString;
    if (authority.startsWith('[')) {
      const end = authority.indexOf(']');
      if (end < 0) throw fail('INVALID_VLESS', 'Unterminated IPv6 literal');
      host = authority.slice(1, end);
      const tail = authority.slice(end + 1);
      portString = tail.startsWith(':') ? tail.slice(1) : '';
    } else {
      const colon = authority.lastIndexOf(':');
      if (colon <= 0) {
        host = authority;
        portString = '';
      } else {
        host = authority.slice(0, colon);
        portString = authority.slice(colon + 1);
      }
    }

    if (!isHostLike(host)) throw fail('INVALID_HOST', 'Link host is not a valid hostname');

    const port = portString === '' ? 443 : Number(portString);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw fail('INVALID_PORT', 'Link port is out of range');
    }

    const params = new URLSearchParams(query);
    const type = (params.get('type') || 'tcp').toLowerCase();
    const security = (params.get('security') || 'none').toLowerCase();
    const encryption = (params.get('encryption') || 'none').toLowerCase();

    if (type !== 'ws') throw fail('UNSUPPORTED_TRANSPORT', 'Only type=ws is supported');
    if (security !== 'tls') throw fail('UNSUPPORTED_SECURITY', 'Only security=tls is supported');
    if (encryption !== 'none') throw fail('UNSUPPORTED_ENCRYPTION', 'encryption must be none');

    const path = params.get('path') || '/vless';
    if (!PATH_RE.test(path)) throw fail('INVALID_PATH', 'WebSocket path is not valid');

    const hostHeader = params.get('host') || host;
    if (!isHostLike(hostHeader)) throw fail('INVALID_HOST', 'WebSocket Host header is not valid');

    const sni = params.get('sni') || host;
    if (!HOST_RE.test(sni)) throw fail('INVALID_SNI', 'SNI is not a valid hostname');

    return {
      uuid: uuid.toLowerCase(),
      host,
      port,
      sni,
      path,
      hostHeader,
      remark: remark || 'SCP-GHOST',
      transport: type,
      security,
      fingerprint: params.get('fp') || 'chrome',
      source: uri.trim(),
    };
  }

  /** Picks the first vless link in a decoded subscription. */
  function extractNode(body) {
    const lines = decodeSubscriptionBody(body);
    const link = lines.find((line) => /^vless:\/\//i.test(line));
    if (!link) throw fail('NO_VLESS_NODE', 'Subscription contains no vless:// node');
    return parseVlessUri(link);
  }

  function yamlString(value) {
    const text = String(value);
    if (/[\r\n]/.test(text)) throw fail('YAML_INJECTION', 'Value must not contain line breaks');
    return '"' + text.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  /**
   * mihomo / meow configuration. `mode: "tun"` routes the whole machine,
   * `mode: "proxy"` only exposes the local mixed proxy (no admin needed).
   */
  function buildCoreConfig(node, options) {
    const opts = options || {};
    const mode = opts.mode === 'proxy' ? 'proxy' : 'tun';
    const mixedPort = opts.mixedPort === undefined ? 7890 : Number(opts.mixedPort);
    if (!Number.isInteger(mixedPort) || mixedPort < 1 || mixedPort > 65535) {
      throw fail('INVALID_PORT', 'mixedPort is out of range');
    }
    if (!node || typeof node !== 'object') throw fail('INVALID_NODE', 'Missing node');
    if (!UUID_RE.test(String(node.uuid || ''))) throw fail('INVALID_UUID', 'Node uuid is invalid');

    const tun = mode === 'tun';
    const controlPort = opts.controlPort === undefined ? 9090 : Number(opts.controlPort);
    if (!Number.isInteger(controlPort) || controlPort < 1 || controlPort > 65535) {
      throw fail('INVALID_PORT', 'controlPort is out of range');
    }
    const head = [
      '# SCP-GHOST — generated by the desktop app. Do not edit by hand.',
      '# node: ' + yamlString(node.remark || 'SCP-GHOST'),
      '# mode: ' + mode,
      'mixed-port: ' + mixedPort,
      'allow-lan: false',
      'bind-address: ' + yamlString('127.0.0.1'),
      // کنترل‌پلین محلی: به‌روزرسانی داغ پیکربندی بدون ری‌استارت هسته.
      // همان چیزی که «اتصال مجدد < ۱ ثانیه» را ممکن می‌کند.
      'external-controller: ' + yamlString('127.0.0.1:' + controlPort),
      'mode: rule',
      'log-level: ' + yamlString(opts.logLevel === 'debug' ? 'debug' : 'info'),
      'ipv6: false',
    ];
    const lines = head.concat([
      'proxies:',
      '  - name: ' + yamlString('SCP-GHOST'),
      '    type: vless',
      '    server: ' + yamlString(node.host),
      '    port: ' + Number(node.port || 443),
      '    uuid: ' + yamlString(node.uuid),
      '    udp: false',
      '    tls: true',
      '    servername: ' + yamlString(node.sni || node.host),
      '    network: ws',
      '    client-fingerprint: ' + yamlString(node.fingerprint || 'chrome'),
      '    ws-opts:',
      '      path: ' + yamlString(node.path || '/vless'),
      '      headers:',
      '        Host: ' + yamlString(node.hostHeader || node.host),
      'proxy-groups:',
      '  - name: ' + yamlString('PROXY'),
      '    type: select',
      '    proxies:',
      '      - ' + yamlString('SCP-GHOST'),
      '      - ' + yamlString('DIRECT'),
      'rules:',
      '  - ' + yamlString('MATCH,PROXY'),
      'tun:',
      '  enable: ' + (tun ? 'true' : 'false'),
      '  stack: ' + yamlString('mixed'),
      '  auto-route: true',
      '  auto-detect-interface: true',
      '  mtu: 1500',
      '  dns-hijack:',
      '    - ' + yamlString('any:53'),
      '',
    ]);
    return lines.join('\n');
  }

  /**
   * پیکربندی «بی‌جلسه» (detached) برای قطع اتصال بدون کشتن آداپتور TUN.
   *
   * همان TUN با همان پارامترها باز می‌ماند — پس Wintun ساخته و پاک نمی‌شود —
   * ولی هیچ پروکسی/گروه/قاعده‌ای وجود ندارد: هیچ بایتی از تونل عبور نمی‌کند.
   * UUID و سرور هم در فایل نیست، پس کلید نشست عملاً صفر شده است.
   */
  function buildDetachedConfig(options) {
    const opts = options || {};
    const mode = opts.mode === 'proxy' ? 'proxy' : 'tun';
    const mixedPort = opts.mixedPort === undefined ? 7890 : Number(opts.mixedPort);
    const controlPort = opts.controlPort === undefined ? 9090 : Number(opts.controlPort);
    if (!Number.isInteger(mixedPort) || mixedPort < 1 || mixedPort > 65535) {
      throw fail('INVALID_PORT', 'mixedPort is out of range');
    }
    if (!Number.isInteger(controlPort) || controlPort < 1 || controlPort > 65535) {
      throw fail('INVALID_PORT', 'controlPort is out of range');
    }
    const tun = mode === 'tun';
    return [
      '# SCP-GHOST — detached session (no tunnel, adapter kept alive).',
      '# mode: ' + mode,
      'mixed-port: ' + mixedPort,
      'allow-lan: false',
      'bind-address: ' + yamlString('127.0.0.1'),
      'external-controller: ' + yamlString('127.0.0.1:' + controlPort),
      'mode: direct',
      'log-level: ' + yamlString('warning'),
      'ipv6: false',
      'proxies: []',
      'proxy-groups: []',
      'rules:',
      '  - ' + yamlString('MATCH,DIRECT'),
      'tun:',
      '  enable: ' + (tun ? 'true' : 'false'),
      '  stack: ' + yamlString('mixed'),
      '  auto-route: true',
      '  auto-detect-interface: true',
      '  mtu: 1500',
      '  dns-hijack:',
      '    - ' + yamlString('any:53'),
      '',
    ].join('\n');
  }

  /** آخرین نسخه از پاسخ api.github.com/repos/.../releases/latest */
  function readLatestRelease(json) {
    if (!json || typeof json !== 'object') throw fail('BAD_RELEASE', 'Release payload is not an object');
    const tag = String(json.tag_name || json.name || '').trim();
    if (!tag) throw fail('BAD_RELEASE', 'Release has no tag_name');
    const version = tag.replace(/^desktop-?v?/i, '').replace(/^v/i, '');
    const assets = Array.isArray(json.assets) ? json.assets : [];
    const installer = assets.find((a) => /\.(exe|msi)$/i.test(String(a && a.name))) || null;
    return {
      tag,
      version,
      url: typeof json.html_url === 'string' ? json.html_url : '',
      installer: installer ? { name: installer.name, url: installer.browser_download_url } : null,
      published: json.published_at || null,
    };
  }

  /** -1 / 0 / 1, tolerating a leading "v" and pre-release suffixes. */
  function compareVersions(a, b) {
    const norm = (value) =>
      String(value || '')
        .trim()
        .replace(/^v/i, '')
        .split(/[-+]/)[0]
        .split('.')
        .map((part) => Number.parseInt(part, 10) || 0);
    const left = norm(a);
    const right = norm(b);
    for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
      const diff = (left[i] || 0) - (right[i] || 0);
      if (diff !== 0) return diff > 0 ? 1 : -1;
    }
    return 0;
  }

  function maskUuid(uuid) {
    const text = String(uuid || '');
    if (text.length < 18) return text;
    return text.slice(0, 8) + '-••••-••••-••••-' + text.slice(-4);
  }

  return {
    decodeSubscriptionBody,
    parseVlessUri,
    extractNode,
    buildCoreConfig,
    buildDetachedConfig,
    readLatestRelease,
    compareVersions,
    maskUuid,
    isHostLike,
    yamlString,
  };
});
