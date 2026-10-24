#!/usr/bin/env node
/* آزمون تولید کانفیگ هسته (URI → YAML).
 *
 * این تنها بخش «داده‌ای» برنامه است و به همین دلیل کامل تست می‌شود:
 * پارس URI های ws / reality / grpc / h2 / tcp، اشتراک Base64، خطاها،
 * و اعتبار ساختاری YAML تولیدشده. فایل‌های YAML در tools/out/ نوشته
 * می‌شوند تا verify_config.py آن‌ها را با یک پارسر واقعی YAML بخواند.
 *
 * اجرا:  node desktop-app/tools/test_core_config.cjs
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const api = require('../src/core-config.js');

const OUT_DIR = path.join(__dirname, 'out');
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

function checkThrows(fn, label) {
  try {
    fn();
    check(false, label);
  } catch {
    check(true, label);
  }
}

function toBase64(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64url(text) {
  return toBase64(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const WS_URI =
  'vless://11111111-2222-3333-4444-555555555555@edge.example.com:443' +
  '?encryption=none&security=tls&sni=edge.example.com&fp=chrome&type=ws' +
  '&host=edge.example.com&path=%2Fvless%3Fed%3D2048#SCP-GHOST';

const REALITY_URI =
  'vless://22222222-3333-4444-5555-666666666666@203.0.113.10:443' +
  '?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome' +
  '&pbk=PUBLIC_KEY_BASE64URL&sid=0123abcd&flow=xtls-rprx-vision&type=tcp' +
  '#Reality%20Node';

const GRPC_URI =
  'vless://33333333-4444-5555-6666-777777777777@cdn.example.net:443' +
  '?encryption=none&security=tls&sni=cdn.example.net&type=grpc' +
  '&serviceName=ghost&mode=gun#gRPC%20Node';

const H2_URI =
  'vless://44444444-5555-6666-7777-888888888888@h2.example.org:8443' +
  '?encryption=none&security=tls&type=h2&host=h2.example.org&path=%2Fapi#H2';

const PLAIN_URI =
  'vless://55555555-6666-7777-8888-999999999999@plain.example.org:8443' +
  '?encryption=none&security=none&type=tcp#Plain';

// ────────────────────────────────────────────────────────────────
console.log('== parsing ==');

const ws = api.parseVlessUri(WS_URI);
check(ws.type === 'vless', 'type is vless');
check(ws.server === 'edge.example.com', 'server parsed');
check(ws.port === 443, 'port parsed');
check(ws.uuid === '11111111-2222-3333-4444-555555555555', 'uuid parsed');
check(ws.network === 'ws', 'network ws');
check(ws.tls === true, 'tls enabled');
check(ws['client-fingerprint'] === 'chrome', 'fingerprint forwarded');
check(ws.servername === 'edge.example.com', 'sni mapped to servername');
check(ws['ws-opts'].path === '/vless?ed=2048', 'ws path percent-decoded');
check(ws['ws-opts'].headers.Host === 'edge.example.com', 'ws Host header set');
check(ws.name === 'SCP-GHOST', 'remark used as node name');

const reality = api.parseVlessUri(REALITY_URI);
check(reality['reality-opts']['public-key'] === 'PUBLIC_KEY_BASE64URL', 'reality public-key');
check(reality['reality-opts']['short-id'] === '0123abcd', 'reality short-id');
check(reality.flow === 'xtls-rprx-vision', 'vision flow forwarded');
check(reality.servername === 'www.microsoft.com', 'reality sni kept');
check(reality.name === 'Reality Node', 'percent-decoded remark');

const grpc = api.parseVlessUri(GRPC_URI);
check(grpc.network === 'grpc', 'network grpc');
check(grpc['grpc-opts']['grpc-service-name'] === 'ghost', 'grpc service name');

const h2 = api.parseVlessUri(H2_URI);
check(h2.network === 'h2', 'network h2');
check(h2['h2-opts'].host[0] === 'h2.example.org', 'h2 host list');
check(h2.port === 8443, 'non-standard port kept');

const plain = api.parseVlessUri(PLAIN_URI);
check(plain.tls === false, 'plain tcp has no tls');
check(plain.servername === undefined, 'no servername without tls');
check(plain.port === 8443, 'plain port kept');

// IPv6
const v6 = api.parseVlessUri(
  'vless://66666666-7777-8888-9999-000000000000@[2001:db8::1]:443?security=tls&type=ws&path=%2Fws#v6'
);
check(v6.server === '2001:db8::1', 'IPv6 literal parsed');
check(v6.port === 443, 'IPv6 port parsed');

// ────────────────────────────────────────────────────────────────
console.log('\n== subscriptions ==');

check(
  api.extractVlessUri(toBase64(WS_URI)) === WS_URI,
  'base64 subscription is decoded'
);
check(
  api.extractVlessUri(b64url(WS_URI)) === WS_URI,
  'URL-safe base64 without padding is decoded'
);
check(
  api.extractVlessUri(WS_URI + '\n' + REALITY_URI) === WS_URI,
  'first node wins in a plain multi-line subscription'
);
check(
  api.extractVlessUri(Buffer.from(WS_URI + '\r\n' + REALITY_URI).toString('base64')) === WS_URI,
  'multi-line base64 subscription is decoded'
);

checkThrows(() => api.extractVlessUri(''), 'empty subscription rejected');
checkThrows(() => api.extractVlessUri('{"error":"Subscription endpoint is disabled"}'), 'JSON error body rejected');
try {
  api.extractVlessUri('{"error":"Subscription endpoint is disabled"}');
} catch (err) {
  check(/JSON/.test(err.message), 'JSON error body produces a readable message');
}
try {
  api.extractVlessUri('<html><body>404</body></html>');
} catch (err) {
  check(/HTML/.test(err.message), 'HTML body produces a readable message');
}
checkThrows(() => api.extractVlessUri(toBase64('hello world')), 'non-vless base64 rejected');
checkThrows(() => api.parseVlessUri('vless://host:443?type=tcp'), 'missing uuid rejected');
checkThrows(() => api.parseVlessUri('vmess://abc'), 'non-vless scheme rejected');
checkThrows(
  () => api.parseVlessUri('vless://u@h:443?security=reality&type=tcp'),
  'reality without pbk rejected'
);

// ────────────────────────────────────────────────────────────────
console.log('\n== yaml ==');

const tunConfig = api.buildCoreConfig({ node: ws, mode: 'tun' });
const proxyConfig = api.buildCoreConfig({ node: reality, mode: 'proxy' });

check(/^mixed-port: 7890$/m.test(tunConfig), 'mixed-port emitted');
check(/\ntun:\n  enable: true\n/.test(tunConfig), 'TUN enabled in tun mode');
check(/\ntun:\n  enable: false\n/.test(proxyConfig), 'TUN disabled in proxy mode');
check(/auto-route: true/.test(tunConfig), 'auto-route on');
check(/dns-hijack:\n    - "any:53"/.test(tunConfig), 'DNS hijack configured');
check(/enhanced-mode: "fake-ip"/.test(tunConfig), 'fake-ip DNS');
check(/proxies:\n  - name: "SCP-GHOST"\n    type: "vless"/.test(tunConfig), 'proxy node block');
check(/proxy-groups:\n  - name: "PROXY"/.test(tunConfig), 'proxy group');
check(/- "MATCH,PROXY"/.test(tunConfig), 'catch-all rule');
check(/reality-opts:\n      public-key: "PUBLIC_KEY_BASE64URL"/.test(proxyConfig), 'reality block in yaml');
check(tunConfig.includes('ws-opts:\n      path: "/vless?ed=2048"'), 'ws opts nested correctly');

// تزریق YAML از طریق remark نباید ساختار را بشکند
const evil = api.buildCoreConfig({
  node: api.parseVlessUri(WS_URI.replace(/#.*$/, '#x%0Aproxies:%20%5B%5D')),
  mode: 'tun',
});
check(!/\nproxies: \[\]/.test(evil), 'newline injection in remark cannot add top-level keys');
check(
  evil.includes('name: "x\\nproxies: []"') || evil.includes('name: "x%0Aproxies:%20%5B%5D"'),
  'injected remark stays a single quoted scalar'
);

// ────────────────────────────────────────────────────────────────
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, 'tun-ws.yaml'), tunConfig);
fs.writeFileSync(path.join(OUT_DIR, 'proxy-reality.yaml'), proxyConfig);
fs.writeFileSync(path.join(OUT_DIR, 'tun-grpc.yaml'), api.buildCoreConfig({ node: grpc, mode: 'tun' }));
fs.writeFileSync(path.join(OUT_DIR, 'tun-h2.yaml'), api.buildCoreConfig({ node: h2, mode: 'tun' }));
fs.writeFileSync(path.join(OUT_DIR, 'proxy-plain.yaml'), api.buildCoreConfig({ node: plain, mode: 'proxy' }));
console.log(`\n  wrote 5 configs to ${path.relative(process.cwd(), OUT_DIR)}/`);

// ────────────────────────────────────────────────────────────────
console.log(`\n== summary: ${checks - failures.length}/${checks} passed ==`);
if (failures.length) {
  failures.forEach((f) => console.log(`  - ${f}`));
  process.exit(1);
}
console.log('core config generator is consistent');
