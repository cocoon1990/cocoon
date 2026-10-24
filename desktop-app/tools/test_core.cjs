#!/usr/bin/env node
/**
 * test_core.cjs — unit tests for desktop-app/src/core.js
 *
 * No dependencies: plain node:assert + a 20-line runner. Writes the two
 * generated configs into tools/out/ so verify_config.py can parse them with
 * a real YAML parser (JS has none built in).
 *
 * Usage: node desktop-app/tools/test_core.cjs
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const core = require('../src/core.js');

const OUT = path.join(__dirname, 'out');
fs.mkdirSync(OUT, { recursive: true });

const NODE = {
  uuid: '6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33',
  host: 'ghost-streaming-worker.cocoon-de9.workers.dev',
  port: 443,
  sni: 'ghost-streaming-worker.cocoon-de9.workers.dev',
  path: '/vless',
  hostHeader: 'ghost-streaming-worker.cocoon-de9.workers.dev',
  remark: 'SCP-GHOST',
  fingerprint: 'chrome',
};

const URI =
  'vless://6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33@ghost-streaming-worker.cocoon-de9.workers.dev:443' +
  '?encryption=none&security=tls&sni=ghost-streaming-worker.cocoon-de9.workers.dev&fp=chrome' +
  '&type=ws&host=ghost-streaming-worker.cocoon-de9.workers.dev&path=%2Fvless#SCP-GHOST';

let passed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed += 1;
    process.stdout.write(`  ok   ${name}\n`);
  } catch (err) {
    failures.push({ name, err });
    process.stdout.write(`  FAIL ${name}\n       ${err.message}\n`);
  }
}

function expectCode(fn, code) {
  try {
    fn();
  } catch (err) {
    assert.equal(err.code, code, `expected code ${code}, got ${err.code || err.message}`);
    return;
  }
  assert.fail(`expected an error with code ${code}, nothing was thrown`);
}

process.stdout.write('\ncore.js — subscription decoding\n');

test('decodes standard Base64 with padding', () => {
  const body = Buffer.from(URI + '\n', 'utf8').toString('base64');
  assert.deepEqual(core.decodeSubscriptionBody(body), [URI]);
});

test('decodes Base64URL without padding', () => {
  const body = Buffer.from(URI + '\n', 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  assert.deepEqual(core.decodeSubscriptionBody(body), [URI]);
});

test('keeps a plain-text URI list as-is', () => {
  assert.deepEqual(core.decodeSubscriptionBody(URI + '\r\n'), [URI]);
});

test('ignores a UTF-8 BOM', () => {
  const body = '\uFEFF' + Buffer.from(URI, 'utf8').toString('base64');
  assert.deepEqual(core.decodeSubscriptionBody(body), [URI]);
});

test('rejects an empty body', () => {
  expectCode(() => core.decodeSubscriptionBody('   '), 'EMPTY_SUBSCRIPTION');
});

test('rejects an HTML error page', () => {
  expectCode(() => core.decodeSubscriptionBody('<html><body>404</body></html>'), 'INVALID_SUBSCRIPTION');
});

test('rejects Base64 that hides no link', () => {
  const body = Buffer.from('{"error":"subscription_not_configured"}', 'utf8').toString('base64');
  expectCode(() => core.decodeSubscriptionBody(body), 'INVALID_SUBSCRIPTION');
});

process.stdout.write('\ncore.js — vless:// parsing\n');

test('parses the worker subscription link', () => {
  const node = core.parseVlessUri(URI);
  assert.equal(node.uuid, NODE.uuid);
  assert.equal(node.host, NODE.host);
  assert.equal(node.port, 443);
  assert.equal(node.sni, NODE.host);
  assert.equal(node.path, '/vless');
  assert.equal(node.hostHeader, NODE.host);
  assert.equal(node.remark, 'SCP-GHOST');
  assert.equal(node.transport, 'ws');
  assert.equal(node.security, 'tls');
  assert.equal(node.fingerprint, 'chrome');
});

test('defaults port, path and remark', () => {
  const node = core.parseVlessUri(
    'vless://6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33@example.com?encryption=none&security=tls&type=ws'
  );
  assert.equal(node.port, 443);
  assert.equal(node.path, '/vless');
  assert.equal(node.remark, 'SCP-GHOST');
  assert.equal(node.sni, 'example.com');
});

test('supports an IPv6 literal with brackets', () => {
  const node = core.parseVlessUri(
    'vless://6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33@[2606:4700:3033::6815:1]:8443' +
      '?encryption=none&security=tls&type=ws&path=%2Fws&sni=example.com'
  );
  assert.equal(node.host, '2606:4700:3033::6815:1');
  assert.equal(node.port, 8443);
  assert.equal(node.path, '/ws');
});

test('URL-decodes the remark', () => {
  const node = core.parseVlessUri(URI.replace('#SCP-GHOST', '#SCP%20GHOST'));
  assert.equal(node.remark, 'SCP GHOST');
});

test('rejects a non-vless scheme', () => {
  expectCode(() => core.parseVlessUri('trojan://x@example.com:443'), 'NOT_VLESS');
});

test('rejects an invalid uuid', () => {
  expectCode(() => core.parseVlessUri(URI.replace(NODE.uuid, 'not-a-uuid')), 'INVALID_UUID');
});

test('rejects a port out of range', () => {
  expectCode(() => core.parseVlessUri(URI.replace(':443?', ':70000?')), 'INVALID_PORT');
});

test('rejects tcp transport', () => {
  expectCode(() => core.parseVlessUri(URI.replace('type=ws', 'type=tcp')), 'UNSUPPORTED_TRANSPORT');
});

test('rejects missing TLS', () => {
  expectCode(() => core.parseVlessUri(URI.replace('security=tls', 'security=none')), 'UNSUPPORTED_SECURITY');
});

test('rejects bad encryption', () => {
  expectCode(() => core.parseVlessUri(URI.replace('encryption=none', 'encryption=aes')), 'UNSUPPORTED_ENCRYPTION');
});

process.stdout.write('\ncore.js — extractNode\n');

test('picks the vless line out of a mixed list', () => {
  const body = Buffer.from(['ss://abc@1.2.3.4:8388#x', URI].join('\n'), 'utf8').toString('base64');
  assert.equal(core.extractNode(body).uuid, NODE.uuid);
});

test('errors when no vless node exists', () => {
  const body = Buffer.from('ss://abc@1.2.3.4:8388#x\n', 'utf8').toString('base64');
  expectCode(() => core.extractNode(body), 'NO_VLESS_NODE');
});

process.stdout.write('\ncore.js — YAML generation\n');

test('tun mode enables the tun block', () => {
  const yaml = core.buildCoreConfig(NODE, { mode: 'tun', mixedPort: 7890 });
  assert.match(yaml, /^mixed-port: 7890$/m);
  assert.match(yaml, /^tun:$/m);
  assert.match(yaml, /^ {2}enable: true$/m);
  fs.writeFileSync(path.join(OUT, 'config-tun.yaml'), yaml);
});

test('proxy mode disables the tun block', () => {
  const yaml = core.buildCoreConfig(NODE, { mode: 'proxy', mixedPort: 7891 });
  assert.match(yaml, /^mixed-port: 7891$/m);
  assert.match(yaml, /^ {2}enable: false$/m);
  fs.writeFileSync(path.join(OUT, 'config-proxy.yaml'), yaml);
});

test('emits a vless + ws outbound for the worker', () => {
  const yaml = core.buildCoreConfig(NODE, { mode: 'tun', mixedPort: 7890 });
  assert.match(yaml, /type: vless/);
  assert.match(yaml, new RegExp(`server: "${NODE.host.replace(/\./g, '\\.')}"`));
  assert.match(yaml, /uuid: "6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33"/);
  assert.match(yaml, /tls: true/);
  assert.match(yaml, /network: ws/);
  assert.match(yaml, /path: "\/vless"/);
  assert.match(yaml, /Host: "ghost-streaming-worker/);
  assert.match(yaml, /MATCH,PROXY/);
});

test('never emits tabs or unterminated quotes', () => {
  const yaml = core.buildCoreConfig(NODE, { mode: 'tun', mixedPort: 7890 });
  assert.ok(!yaml.includes('\t'), 'YAML must not contain tabs');
  for (const line of yaml.split('\n')) {
    const quotes = (line.match(/(?<!\\)"/g) || []).length;
    assert.equal(quotes % 2, 0, `unbalanced quotes: ${line}`);
  }
});

test('blocks YAML injection through a remark', () => {
  const hostile = Object.assign({}, NODE, { remark: 'x"\nproxies: []' });
  expectCode(() => core.buildCoreConfig(hostile, { mode: 'tun' }), 'YAML_INJECTION');
});

test('rejects an invalid mixed port', () => {
  expectCode(() => core.buildCoreConfig(NODE, { mode: 'tun', mixedPort: 0 }), 'INVALID_PORT');
});

test('rejects a bad uuid before writing config', () => {
  const hostile = Object.assign({}, NODE, { uuid: 'nope' });
  expectCode(() => core.buildCoreConfig(hostile, { mode: 'tun' }), 'INVALID_UUID');
});

process.stdout.write('\ncore.js — helpers\n');

test('masks the uuid for display', () => {
  assert.equal(core.maskUuid(NODE.uuid), '6f2c1a54-••••-••••-••••-1c33');
});

test('compares versions', () => {
  assert.equal(core.compareVersions('5.4.0', '5.3.0'), 1);
  assert.equal(core.compareVersions('v5.4.0', '5.4.0'), 0);
  assert.equal(core.compareVersions('5.10.0', '5.9.9'), 1);
  assert.equal(core.compareVersions('5.4.0-beta.1', '5.4.0'), 0);
});

process.stdout.write(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
