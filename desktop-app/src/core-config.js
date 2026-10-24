/* SCP-GHOST desktop — ساخت کانفیگ هستهٔ پراکسی
 *
 * تنها تبدیل «داده‌ای» برنامه: یک URI استاندارد `vless://` (یا اشتراک
 * Base64 شامل آن) را به کانفیگ YAML هستهٔ mihomo-compatible تبدیل می‌کند.
 *
 * هیچ منطق شبکه‌ای اینجا نیست: نه سوکت، نه TUN، نه TLS. تمام آن‌ها کار
 * هستهٔ پراکسی (sidecar) است. این فایل فقط متن تولید می‌کند و به همین
 * دلیل کاملاً unit-test شدنی است.
 *
 * هم در مرورگر (window.SCPGhostConfig) و هم در Node (require) کار می‌کند.
 */

(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.SCPGhostConfig = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const DEFAULT_PORTS = { tls: 443, reality: 443 };

  /* ── Base64 ─────────────────────────────────────────────────
   * اشتراک‌های V2Ray معمولاً Base64 هستند (standard یا URL-safe، با یا
   * بدون padding). هر دو حالت پذیرفته می‌شود؛ اگر متن از قبل URI باشد،
   * دست‌نخورده برمی‌گردد.
   */
  function normalizeSubscription(body) {
    const text = String(body || '').trim();
    if (!text) throw new Error('اشتراک خالی است.');

    // اگر از قبل URI یا چندخطی URI است، کاری لازم نیست
    if (/vless:\/\//i.test(text)) return text;

    // پاسخ‌های خطای سرور را با پیام روشن برگردان (نه «Base64 نامعتبر»)
    if (/^[[{]/.test(text)) {
      throw new Error(
        'سرور به‌جای اشتراک، پاسخ JSON برگرداند: ' + text.slice(0, 180)
      );
    }
    if (/^</.test(text)) {
      throw new Error('سرور به‌جای اشتراک، صفحهٔ HTML برگرداند (احتمالاً آدرس یا توکن غلط است).');
    }

    const cleaned = text.replace(/\s+/g, '');
    const padded = cleaned.replace(/-/g, '+').replace(/_/g, '/');
    const withPadding =
      padded + '='.repeat((4 - (padded.length % 4)) % 4);

    let decoded;
    try {
      if (typeof atob === 'function') {
        const binary = atob(withPadding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
        decoded = new TextDecoder('utf-8').decode(bytes);
      } else {
        // Node
        decoded = Buffer.from(withPadding, 'base64').toString('utf-8');
      }
    } catch {
      throw new Error('اشتراک نه Base64 معتبر است و نه URI.');
    }

    if (!/vless:\/\//i.test(decoded)) {
      throw new Error(
        'در پاسخ اشتراک هیچ نود vless:// پیدا نشد. ' +
          'احتمالاً سرور، خطا یا صفحهٔ HTML برگردانده است.'
      );
    }
    return decoded;
  }

  /** اولین URI از نوع vless را از متن اشتراک بیرون می‌کشد. */
  function extractVlessUri(body) {
    const text = normalizeSubscription(body);
    const line = text
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .find((entry) => /^vless:\/\//i.test(entry));

    if (!line) throw new Error('نود vless:// در اشتراک نبود.');
    return line;
  }

  /* ── پارس URI ─────────────────────────────────────────────── */

  function decodeComponent(value) {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  /**
   * vless://UUID@HOST:PORT?query#remark  →  شیء نود Clash
   */
  function parseVlessUri(uri) {
    const raw = String(uri || '').trim();
    if (!/^vless:\/\//i.test(raw)) {
      throw new Error('URI باید با vless:// شروع شود.');
    }

    // بخش #remark و ?query جدا می‌شوند (توجه: ? ممکن است داخل path باشد)
    let rest = raw.slice('vless://'.length);
    let remark = '';
    const hashIndex = rest.indexOf('#');
    if (hashIndex >= 0) {
      remark = decodeComponent(rest.slice(hashIndex + 1));
      rest = rest.slice(0, hashIndex);
    }

    let query = '';
    const queryIndex = rest.indexOf('?');
    if (queryIndex >= 0) {
      query = rest.slice(queryIndex + 1);
      rest = rest.slice(0, queryIndex);
    }

    const atIndex = rest.lastIndexOf('@');
    if (atIndex <= 0) {
      throw new Error('URI شناسهٔ کاربر (UUID@host) ندارد.');
    }

    const uuid = decodeComponent(rest.slice(0, atIndex));
    let authority = rest.slice(atIndex + 1);
    if (authority.startsWith('[')) {
      // IPv6
      const close = authority.indexOf(']');
      if (close < 0) throw new Error('آدرس IPv6 ناقص است.');
      authority = authority.slice(1, close) + authority.slice(close + 1);
    }

    let server = authority;
    let port = null;
    const colon = authority.lastIndexOf(':');
    if (colon > 0) {
      server = authority.slice(0, colon);
      port = Number(authority.slice(colon + 1));
    }

    if (!uuid) throw new Error('UUID در URI خالی است.');
    if (!server) throw new Error('دامنهٔ سرور در URI خالی است.');

    const params = new URLSearchParams(query);
    const security = (params.get('security') || 'none').toLowerCase();
    const type = (params.get('type') || 'tcp').toLowerCase();
    const sni = params.get('sni') || params.get('peer') || params.get('host') || '';
    const fingerprint = params.get('fp') || 'chrome';

    if (!port) port = DEFAULT_PORTS[security] || 443;

    const node = {
      name: remark || 'SCP-GHOST',
      type: 'vless',
      server: server,
      port: port,
      uuid: uuid,
      network: type,
      udp: true,
      tls: security === 'tls' || security === 'reality' || security === 'xtls',
    };

    if (node.tls) {
      node['client-fingerprint'] = fingerprint;
      if (sni) node.servername = sni;
      if (security === 'reality') {
        const publicKey = params.get('pbk');
        if (!publicKey) throw new Error('security=reality بدون pbk معتبر نیست.');
        node['reality-opts'] = {
          'public-key': publicKey,
          ...(params.get('sid') ? { 'short-id': params.get('sid') } : {}),
        };
        if (!node.servername) node.servername = params.get('sni') || server;
      }
    }

    if (params.get('allowInsecure') === '1' || params.get('insecure') === '1') {
      node['skip-cert-verify'] = true;
    }
    if (params.get('flow')) node.flow = params.get('flow');

    if (type === 'ws' || type === 'httpupgrade') {
      node['ws-opts'] = {
        path: decodeComponent(params.get('path') || '/'),
        ...(params.get('host')
          ? { headers: { Host: decodeComponent(params.get('host')) } }
          : {}),
      };
      node.network = 'ws';
    } else if (type === 'grpc') {
      node['grpc-opts'] = {
        'grpc-service-name': decodeComponent(params.get('serviceName') || ''),
      };
    } else if (type === 'h2' || type === 'http') {
      node['h2-opts'] = {
        path: decodeComponent(params.get('path') || '/'),
        ...(params.get('host')
          ? { host: [decodeComponent(params.get('host'))] }
          : {}),
      };
      node.network = 'h2';
    } else if (type === 'tcp') {
      node.network = 'tcp';
      if (params.get('sni') && node.tls && !node.servername) {
        node.servername = params.get('sni');
      }
    }

    return node;
  }

  /* ── YAML ─────────────────────────────────────────────────── */

  /** رشته‌ها همیشه دابل‌کوت می‌شوند تا مقدار نتواند ساختار YAML را بشکند. */
  function q(value) {
    const text = String(value)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\r/g, '\\r')
      .replace(/\n/g, '\\n')
      .replace(/\t/g, '\\t');
    return '"' + text + '"';
  }

  /** کلیدها فقط وقتی کوت می‌شوند که کاراکتر خاصی داشته باشند. */
  function key(name) {
    const text = String(name);
    return /^[A-Za-z0-9_-]+$/.test(text) ? text : q(text);
  }

  function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function scalar(value) {
    if (typeof value === 'boolean' || typeof value === 'number') return String(value);
    return q(value);
  }

  /**
   * تبدیل بازگشتی به YAML.
   * خروجی هر شاخهٔ غیراسکالر با '\n' شروع می‌شود؛ همین قرارداد اجازه می‌دهد
   * ورودی‌های آرایه‌ای بدون دوباره‌کاری تو‌رفتگی، درست سرهم شوند.
   */
  function toYaml(value, indent) {
    const pad = ' '.repeat(indent);

    if (Array.isArray(value)) {
      if (!value.length) return ' []';
      let out = '';
      for (const item of value) {
        if (isPlainObject(item) || Array.isArray(item)) {
          const body = toYaml(item, indent + 2);
          if (body.startsWith('\n')) {
            const inner = body.slice(1);
            const firstPad = ' '.repeat(indent + 2);
            const first = inner.startsWith(firstPad)
              ? inner.slice(firstPad.length)
              : inner.replace(/^ +/, '');
            out += `\n${pad}- ` + first;
          } else {
            // ' []' یا ' {}'
            out += `\n${pad}-` + body;
          }
        } else {
          out += `\n${pad}- ${scalar(item)}`;
        }
      }
      return out;
    }

    if (isPlainObject(value)) {
      const entries = Object.entries(value).filter(([, item]) => item !== undefined);
      if (!entries.length) return ' {}';
      let out = '';
      for (const [name, item] of entries) {
        if (isPlainObject(item) || Array.isArray(item)) {
          out += `\n${pad}${key(name)}:` + toYaml(item, indent + 2);
        } else {
          out += `\n${pad}${key(name)}: ${scalar(item)}`;
        }
      }
      return out;
    }

    return ' ' + scalar(value);
  }

  /**
   * کانفیگ کامل هسته را می‌سازد.
   * @param {{node: object, mode: 'tun'|'proxy', mixedPort?: number}} options
   */
  function buildCoreConfig(options) {
    const opts = options || {};
    const node = opts.node;
    if (!node || node.type !== 'vless') {
      throw new Error('نود VLESS برای ساخت کانفیگ لازم است.');
    }

    const mode = opts.mode === 'proxy' ? 'proxy' : 'tun';
    const mixedPort = Number(opts.mixedPort) || 7890;

    const config = {
      'mixed-port': mixedPort,
      'allow-lan': false,
      'bind-address': '127.0.0.1',
      mode: 'rule',
      'log-level': 'info',
      ipv6: false,
      dns: {
        enable: true,
        ipv6: false,
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        nameserver: ['1.1.1.1', '8.8.8.8'],
      },
      tun: {
        enable: mode === 'tun',
        'auto-route': true,
        'dns-hijack': ['any:53'],
        mtu: 1500,
      },
      proxies: [node],
      'proxy-groups': [
        {
          name: 'PROXY',
          type: 'select',
          proxies: [node.name, 'DIRECT'],
        },
      ],
      rules: ['MATCH,PROXY'],
    };

    const header = [
      '# SCP-GHOST — کانفیگی که به‌صورت خودکار تولید شده است.',
      `# mode: ${mode}`,
      '# هسته: meow (mihomo-compatible) — این فایل فقط توسط sidecar خوانده می‌شود.',
      '',
    ].join('\n');

    return header + toYaml(config, 0).replace(/^\n/, '') + '\n';
  }

  return {
    normalizeSubscription,
    extractVlessUri,
    parseVlessUri,
    buildCoreConfig,
  };
});
