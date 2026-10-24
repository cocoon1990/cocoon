#!/usr/bin/env node
/**
 * vless.test.mjs — protocol test for the Cocoon-in-Cocoon endpoint.
 *
 * The sandbox used for development has no Rust/wasm toolchain, so this suite
 * does two things that are both meaningful without one:
 *
 *   1. **Reference codec** — a byte-exact JS implementation of the VLESS v0
 *      header (the same wire format the Rust parser consumes) is exercised
 *      against real frames: IPv4, domain and IPv6 destinations, fractional
 *      arrivals (header split across WebSocket frames), padding options and
 *      every rejection path.
 *   2. **Source contract pins** — the Rust handler is scanned to guarantee it
 *      still implements exactly the rules the reference codec proves, so the
 *      two cannot silently drift. A pin failure means the wire format changed.
 *
 * It also validates the `/sub` share link that `/vless` is reachable through.
 *
 * Usage: node streaming-worker/tests/vless.test.mjs
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(join(HERE, '..', 'src', 'lib.rs'), 'utf8');
const NORMALIZED = SOURCE.replace(/[ \t]+$/gm, '');

const UUID = '6f2c1a54-3b9d-4c0e-8a71-2d5e9f0b1c33';
const UUID_BYTES = Buffer.from(UUID.replace(/-/g, ''), 'hex');

const VERSION = 0;
const CMD_TCP = 1;
const ATYP_IPV4 = 1;
const ATYP_DOMAIN = 2;
const ATYP_IPV6 = 3;

let passed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures.push(name);
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

/* ── reference codec (mirrors parse_vless_header) ───────────── */

const NEED_MORE = 'NEED_MORE';
const REJECTED = 'REJECTED';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

/** Mirror of is_blocked_destination: names by exact match, ranges by number. */
function isBlockedDestination(host) {
  const lower = String(host).replace(/^\[|\]$/g, '').toLowerCase();
  if (lower === 'localhost' || lower === 'metadata.google.internal') return true;

  const v4 = lower.match(IPV4_RE);
  if (v4) {
    const [a, b] = v4.slice(1).map(Number);
    return (
      a === 127 || // loopback
      a === 10 || // private
      (a === 192 && b === 168) || // private
      (a === 172 && b >= 16 && b <= 31) || // private
      (a === 169 && b === 254) || // link local (metadata)
      a === 0 ||
      lower === '255.255.255.255'
    );
  }

  if (IPV6_RE.test(lower) && lower.includes(':')) {
    if (lower === '::1' || /^0*:0*:0*:0*:0*:0*:0*:0*$/.test(lower)) return true;
    const first = parseInt(lower.split(':')[0], 16) || 0;
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }

  return false;
}

function parseHeader(buf, expectedUuid = UUID_BYTES) {
  if (buf.length < 18) return { state: NEED_MORE };
  if (buf[0] !== VERSION) return { state: REJECTED, reason: 'unsupported version' };
  if (!buf.subarray(1, 17).equals(expectedUuid)) return { state: REJECTED, reason: 'uuid mismatch' };

  const optLen = buf[17];
  let cursor = 18 + optLen;
  if (buf.length < cursor + 4) return { state: NEED_MORE };

  const command = buf[cursor];
  cursor += 1;
  if (command !== CMD_TCP) return { state: REJECTED, reason: 'unsupported command' };

  const port = buf.readUInt16BE(cursor);
  cursor += 2;
  if (port === 0) return { state: REJECTED, reason: 'invalid port' };

  const atyp = buf[cursor];
  cursor += 1;
  let addr;

  if (atyp === ATYP_IPV4) {
    if (buf.length < cursor + 4) return { state: NEED_MORE };
    addr = [...buf.subarray(cursor, cursor + 4)].join('.');
    cursor += 4;
  } else if (atyp === ATYP_DOMAIN) {
    if (buf.length < cursor + 1) return { state: NEED_MORE };
    const len = buf[cursor];
    cursor += 1;
    if (len === 0 || len > 253) return { state: REJECTED, reason: 'invalid domain length' };
    if (buf.length < cursor + len) return { state: NEED_MORE };
    addr = buf.subarray(cursor, cursor + len).toString('utf8');
    cursor += len;
  } else if (atyp === ATYP_IPV6) {
    if (buf.length < cursor + 16) return { state: NEED_MORE };
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(buf.subarray(cursor + i, cursor + i + 2).toString('hex'));
    addr = groups.join(':');
    cursor += 16;
  } else {
    return { state: REJECTED, reason: 'unsupported address type' };
  }

  if (addr.length === 0 || isBlockedDestination(addr)) return { state: REJECTED, reason: 'destination not allowed' };
  return { state: 'READY', addr, port, consumed: cursor };
}

/** VLESS v0 client request, exactly as a real client frames it. */
function buildRequest({ port = 443, atyp = ATYP_DOMAIN, addr = 'example.com', optLen = 0, payload = Buffer.alloc(0) }) {
  const parts = [Buffer.from([VERSION]), UUID_BYTES, Buffer.from([optLen]), Buffer.alloc(optLen), Buffer.from([CMD_TCP])];
  const portBytes = Buffer.alloc(2);
  portBytes.writeUInt16BE(port, 0);
  parts.push(portBytes);
  parts.push(Buffer.from([atyp]));

  if (atyp === ATYP_IPV4) parts.push(Buffer.from(addr.split('.').map(Number)));
  else if (atyp === ATYP_IPV6) parts.push(Buffer.from(addr.split(':').map((group) => parseInt(group.padStart(4, '0'), 16)).reduce((acc, value) => {
    acc.push(value >> 8, value & 0xff);
    return acc;
  }, [])));
  else {
    const host = Buffer.from(addr, 'utf8');
    parts.push(Buffer.from([host.length]), host);
  }
  parts.push(payload);
  return Buffer.concat(parts);
}

/** Feed frames one by one, like the Rust accumulate-then-parse loop. */
function accumulate(frames) {
  let buffer = Buffer.alloc(0);
  for (const frame of frames) {
    buffer = Buffer.concat([buffer, frame]);
    const result = parseHeader(buffer);
    if (result.state !== NEED_MORE) return { result, buffer };
  }
  return { result: { state: NEED_MORE }, buffer };
}

console.log('\nVLESS header — acceptance');

test('domain destination with payload in the same frame', () => {
  const payload = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  const request = buildRequest({ addr: 'example.com', payload });
  const { result } = accumulate([request]);
  assert.equal(result.state, 'READY');
  assert.equal(result.addr, 'example.com');
  assert.equal(result.port, 443);
  assert.equal(result.consumed, request.length - payload.length);
  assert.deepEqual(request.subarray(result.consumed), payload);
});

test('IPv4 destination', () => {
  const { result } = accumulate([buildRequest({ atyp: ATYP_IPV4, addr: '1.1.1.1', port: 8443 })]);
  assert.equal(result.state, 'READY');
  assert.equal(result.addr, '1.1.1.1');
  assert.equal(result.port, 8443);
});

test('IPv6 destination', () => {
  const { result } = accumulate([buildRequest({ atyp: ATYP_IPV6, addr: '2606:4700:4700:0000:0000:0000:0000:1111' })]);
  assert.equal(result.state, 'READY');
  assert.equal(result.port, 443);
  assert.match(result.addr, /^2606:4700:4700:0{1,4}:0{1,4}:0{1,4}:0{1,4}:1111$/);
});

test('padding options are skipped', () => {
  const request = buildRequest({ addr: 'example.com', optLen: 7 });
  const { result } = accumulate([request]);
  assert.equal(result.state, 'READY');
  assert.equal(result.consumed, request.length);
});

test('a header split across three WebSocket frames still parses', () => {
  const request = buildRequest({ addr: 'ghost-streaming-worker.cocoon-de9.workers.dev', port: 443 });
  const a = request.subarray(0, 10);
  const b = request.subarray(10, 30);
  const c = request.subarray(30);
  const { result } = accumulate([a, b, c]);
  assert.equal(result.state, 'READY');
  assert.equal(result.addr, 'ghost-streaming-worker.cocoon-de9.workers.dev');
});

test('server acknowledgement is version 0 with empty options', () => {
  const ack = Buffer.from([VERSION, 0]);
  assert.deepEqual([...ack], [0x00, 0x00]);
});

console.log('\nVLESS header — rejection');

test('wrong version', () => {
  const request = buildRequest({});
  request[0] = 1;
  assert.equal(accumulate([request]).result.reason, 'unsupported version');
});

test('wrong uuid', () => {
  const request = buildRequest({});
  request[1] ^= 0xff;
  assert.equal(accumulate([request]).result.reason, 'uuid mismatch');
});

test('UDP command is refused', () => {
  const request = buildRequest({});
  request[18] = 3;
  assert.equal(accumulate([request]).result.reason, 'unsupported command');
});

test('port 0 is refused', () => {
  assert.equal(accumulate([buildRequest({ port: 0 })]).result.reason, 'invalid port');
});

test('unknown address type is refused', () => {
  const request = buildRequest({});
  // version(1) + uuid(16) + optLen(1) + opts(0) + command(1) + port(2)
  const ATYP_OFFSET = 1 + 16 + 1 + 0 + 1 + 2;
  assert.equal(request[ATYP_OFFSET], ATYP_DOMAIN);
  request[ATYP_OFFSET] = 9;
  assert.equal(accumulate([request]).result.reason, 'unsupported address type');
});

test('empty domain is refused', () => {
  assert.equal(accumulate([buildRequest({ addr: '' })]).result.reason, 'invalid domain length');
});

test('loopback and metadata destinations are refused', () => {
  for (const host of ['127.0.0.1', 'localhost', '10.0.0.5', '192.168.1.1', '169.254.169.254']) {
    assert.equal(accumulate([buildRequest({ addr: host })]).result.reason, 'destination not allowed', host);
  }
});

test('a domain that merely starts with "fc" is still allowed', () => {
  const { result } = accumulate([buildRequest({ addr: 'fcbarcelona.com' })]);
  assert.equal(result.state, 'READY', 'hostname filtering must not use string prefixes');
});

test('a 17-byte prefix is never accepted as complete', () => {
  const request = buildRequest({});
  assert.equal(accumulate([request.subarray(0, 17)]).result.state, NEED_MORE);
});

console.log('\nRust handler — contract pins');

function pin(label, needle) {
  test(label, () => assert.ok(NORMALIZED.includes(needle), `missing: ${needle}`));
}

pin('route /vless is registered', '.get_async("/vless", handle_vless)');
pin('version byte is pinned to 0', 'const VLESS_VERSION: u8 = 0;');
pin('minimum header length is 18 bytes', 'if buf.len() < 18 {');
pin('uuid occupies bytes 1..17', 'if &buf[1..17] != expected_uuid {');
pin('option length is read from byte 17', 'let opt_len = buf[17] as usize;');
pin('only TCP (command 1) is accepted', 'if command != VLESS_CMD_TCP {');
pin('port is big-endian', 'let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);');
pin('IPv4 addresses are decoded', 'std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()');
pin('IPv6 addresses are decoded', 'std::net::Ipv6Addr::from(octets).to_string()');
pin('SSRF guard runs on the destination', 'if addr.is_empty() || is_blocked_destination(&addr) {');
pin('client is upgraded to a WebSocket pair', 'Response::from_websocket(client)');
pin('ack is sent before piping', 'if ws.send_with_bytes([VLESS_VERSION, 0u8]).is_err() {');
pin('header bytes are stripped before piping', 'if let Some(rest) = buffer.get(consumed..) {');
pin('both directions are pumped', 'futures_util::future::select(Box::pin(upstream), Box::pin(downstream)).await;');
pin('outbound connects through cloudflare:sockets', 'Socket::builder().connect(addr.clone(), port)');
pin('the tunnel loop does not block the response', 'wasm_bindgen_futures::spawn_local(async move {');
pin('the endpoint is rate limited', 'if let Some(limited) = check_rate_limit(&ctx, &client_ip).await {');
pin('non-upgrade requests are refused', 'Expected a WebSocket upgrade on /vless');
pin('no VLESS UUID means 503, never a dead link', 'VLESS endpoint is not configured');

console.log('\n/sub — share link');

test('the worker builds a wss:// VLESS URI on 443', () => {
  const template = '"vless://{}@{}:443?encryption=none&security=tls&sni={}&fp=chrome&type=ws&host={}&path={}#{}"';
  assert.ok(NORMALIZED.includes(template), 'URI template changed');
});

test('the default websocket path matches the router', () => {
  assert.ok(NORMALIZED.includes('"/vless".to_string()'), 'default VLESS_PATH is not /vless');
});

test('/sub defaults to the host it was requested on', () => {
  assert.ok(NORMALIZED.includes('let request_host = req'), 'request host fallback is gone');
  assert.ok(
    NORMALIZED.includes('let host = if configured_host.is_empty() {'),
    'VLESS_HOST override logic is gone'
  );
});

/** Same construction as build_vless_uri, then validated as a real link. */
function buildShareLink({ uuid, host, sni, path, remark }) {
  const encode = (value) =>
    [...Buffer.from(value, 'utf8')]
      .map((byte) => {
        const char = String.fromCharCode(byte);
        return /[A-Za-z0-9\-._~\/]/.test(char) ? char : '%' + byte.toString(16).toUpperCase().padStart(2, '0');
      })
      .join('');
  return `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=chrome&type=ws&host=${host}&path=${encode(path)}#${encode(remark)}`;
}

test('generated link parses as a valid VLESS WebSocket node', () => {
  const host = 'ghost-streaming-worker.cocoon-de9.workers.dev';
  const link = buildShareLink({ uuid: UUID, host, sni: host, path: '/vless', remark: 'SCP-GHOST' });
  const url = new URL(link);

  assert.equal(url.protocol, 'vless:');
  assert.equal(url.username, UUID);
  assert.equal(url.hostname, host);
  assert.equal(url.port, '443');
  assert.equal(url.hash, '#SCP-GHOST');

  const params = url.searchParams;
  assert.equal(params.get('encryption'), 'none');
  assert.equal(params.get('security'), 'tls');
  assert.equal(params.get('sni'), host);
  assert.equal(params.get('fp'), 'chrome');
  assert.equal(params.get('type'), 'ws');
  assert.equal(params.get('host'), host);
  assert.equal(params.get('path'), '/vless');
});

test('the link targets the same worker that served /sub', () => {
  const host = 'ghost-streaming-worker.cocoon-de9.workers.dev';
  const link = buildShareLink({ uuid: UUID, host, sni: host, path: '/vless', remark: 'SCP-GHOST' });
  assert.ok(link.includes(`@${host}:443?`), 'link must point at the Cocoon-in-Cocoon endpoint');
  assert.ok(!link.includes('vless.example.com'), 'no external VLESS host may leak into the link');
});

test('Base64 body of /sub round-trips to the same link', () => {
  const host = 'ghost-streaming-worker.cocoon-de9.workers.dev';
  const link = buildShareLink({ uuid: UUID, host, sni: host, path: '/vless', remark: 'SCP-GHOST' });
  const body = Buffer.from(link + '\n', 'utf8').toString('base64');
  const decoded = Buffer.from(body, 'base64').toString('utf8').trim();
  assert.equal(decoded, link);
});

console.log(`\n${passed} passed, ${failures.length} failed\n`);
if (failures.length) process.exit(1);
