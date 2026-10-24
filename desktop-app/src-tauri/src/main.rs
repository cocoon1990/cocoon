// جلوگیری از باز شدن پنجرهٔ کنسول در نسخهٔ release ویندوز
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! main.rs — SCP-GHOST Desktop (Tauri v2)
//!
//! این crate کاملاً مستقل است و هیچ‌کدام از crateهای ریپو را import نمی‌کند.
//! فقط از طریق اینترنت با دو worker موجود صحبت می‌کند.
//!
//! ── پروتکل (عیناً همان `x25519-hkdf-sha256-aesgcm-v1`) ──────────
//!   1. کلاینت keypair موقت X25519 می‌سازد (کلید خصوصی هرگز خارج نمی‌شود)
//!   2. POST /session-init  {"client_pubkey": base64(32)}
//!   3. KEK = HKDF-SHA256(ikm = shared, salt, info = "ghost/session-kek/v1")
//!   4. worker کلیدهای اصلی را با AES-256-GCM زیر KEK می‌فرستد
//!      AAD = "ghost/session/v1" || client_pub || server_pub
//!   5. کلاینت باز می‌کند → hmac_key_hex / aes_key_hex
//!
//! ── امضا (عیناً همان streaming-worker) ─────────────────────────
//!   message = "{target}:{seq}"
//!   sig     = hex(HMAC-SHA256(key = hex::decode(hmac_key_hex), message))
//!   GET {STREAMING}/stream?target=percent(target)&sig=..&seq=..
//!
//! ⚠️ نکتهٔ مهم دربارهٔ «پراکسی محلی»: `/stream` یک پل GET است، نه
//! forward-proxy. فقط دامنه‌های allowlist و فقط GET/HEAD را می‌پذیرد و
//! CONNECT (تونل TLS خام) ندارد. بنابراین پراکسی محلی این برنامه فقط
//! همان چیزی را عبور می‌دهد که بک‌اند واقعاً پشتیبانی می‌کند و برای
//! بقیهٔ مقاصد پاسخ ۴۰۳/۵۰۱ صریح می‌دهد — هیچ تونل جعلی ساخته نمی‌شود.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tauri::State;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// ══════════════════════════════════════════════════════════════
//  ثابت‌ها — باید دقیقاً با workerها یکی باشند
// ══════════════════════════════════════════════════════════════

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const SIGNALING_URL: &str = "https://ghost-signaling-worker.cocoon-de9.workers.dev";
const STREAMING_URL: &str = "https://ghost-streaming-worker.cocoon-de9.workers.dev";

const PROTOCOL: &str = "x25519-hkdf-sha256-aesgcm-v1";
const HKDF_INFO_KEK: &[u8] = b"ghost/session-kek/v1";
const AAD_PREFIX: &[u8] = b"ghost/session/v1";

/// پورت پیش‌فرض پراکسی محلی (127.0.0.1)
const PROXY_PORT: u16 = 8899;

/// همان allowlist ورکر — پراکسی محلی هم قبل از ارسال همین را چک می‌کند
const ALLOWED_TARGET_DOMAINS: [&str; 5] = [
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    "googleapis.com",
];

type HmacSha256 = Hmac<Sha256>;

// ══════════════════════════════════════════════════════════════
//  State
// ══════════════════════════════════════════════════════════════

struct Session {
    hmac_key: Vec<u8>,
    config_version: Option<String>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

struct ProxyHandle {
    port: u16,
    running: Arc<AtomicBool>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct AppState {
    session: Mutex<Option<Session>>,
    seq: AtomicU64,
    proxy: Mutex<Option<ProxyHandle>>,
}

type Shared = Arc<AppState>;

// ══════════════════════════════════════════════════════════════
//  DTO برای فرانت‌اند
// ══════════════════════════════════════════════════════════════

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Status {
    connected: bool,
    proxy_port: Option<u16>,
    config_version: Option<String>,
    seq: u64,
    version: String,
    streaming_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestResult {
    status: u16,
    ok: bool,
    ghost_path: Option<String>,
    body: String,
}

// ══════════════════════════════════════════════════════════════
//  رمزنگاری — پورت‌شده از browser-wasm (همان کد تست‌شدهٔ وب)
// ══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct SessionInitResponse {
    #[serde(default)]
    protocol: Option<String>,
    server_pubkey: String,
    salt: String,
    wrapped: String,
    #[serde(default)]
    config_version: Option<String>,
}

#[derive(Deserialize)]
struct SessionKeys {
    hmac_key_hex: String,
}

/// انجام handshake کامل و برگرداندن کلید HMAC
fn perform_handshake() -> Result<(Vec<u8>, Option<String>), String> {
    // ۱. keypair موقت — کلید خصوصی فقط در این scope زندگی می‌کند
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let client_secret = StaticSecret::from(seed);
    let client_public = PublicKey::from(&client_secret);
    let client_pub_bytes = client_public.as_bytes();

    // ۲. فقط کلید عمومی به شبکه می‌رود
    let request_body = serde_json::json!({
        "client_pubkey": B64.encode(client_pub_bytes),
        "client_version": APP_VERSION,
    });

    let endpoint = format!("{SIGNALING_URL}/session-init");
    let raw = ureq::post(&endpoint)
        .timeout(Duration::from_secs(20))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(request_body);

    let body_text = match raw {
        Ok(response) => response
            .into_string()
            .map_err(|e| format!("reading /session-init body failed: {e}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let detail = response.into_string().unwrap_or_default();
            return Err(format!("signaling HTTP {code}: {}", detail.trim()));
        }
        Err(err) => return Err(format!("signaling unreachable: {err}")),
    };

    let parsed: SessionInitResponse = serde_json::from_str(&body_text)
        .map_err(|e| format!("invalid /session-init JSON: {e}"))?;

    if let Some(protocol) = parsed.protocol.as_deref() {
        if protocol != PROTOCOL {
            return Err(format!("unexpected protocol: {protocol}"));
        }
    }

    // ۳. کلید عمومی سرور
    let server_pub_vec = B64
        .decode(parsed.server_pubkey.trim())
        .map_err(|_| "server_pubkey is not valid base64".to_string())?;
    if server_pub_vec.len() != 32 {
        return Err("server_pubkey must be 32 bytes".to_string());
    }
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(&server_pub_vec);
    let server_public = PublicKey::from(server_pub_arr);

    // ۴. shared secret
    let shared = client_secret.diffie_hellman(&server_public);
    if !shared.was_contributory() {
        return Err("server public key is a low-order point".to_string());
    }

    // ۵. KEK با HKDF-SHA256
    let salt = B64
        .decode(parsed.salt.trim())
        .map_err(|_| "salt is not valid base64".to_string())?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared.as_bytes());
    let mut kek = [0u8; 32];
    hkdf.expand(HKDF_INFO_KEK, &mut kek)
        .map_err(|_| "HKDF expand failed".to_string())?;

    // ۶. AES-256-GCM decrypt — AAD هر دو کلید عمومی را bind می‌کند
    let wrapped = B64
        .decode(parsed.wrapped.trim())
        .map_err(|_| "wrapped payload is not valid base64".to_string())?;
    if wrapped.len() < 12 + 16 {
        return Err("wrapped payload is too short".to_string());
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(12);

    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 64);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(client_pub_bytes);
    aad.extend_from_slice(&server_pub_arr);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "AES-GCM decryption failed (wrong key or tampered payload)".to_string())?;

    let keys: SessionKeys = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("decrypted payload is not valid JSON: {e}"))?;

    let hmac_key = hex::decode(keys.hmac_key_hex.trim())
        .map_err(|e| format!("hmac_key_hex is not valid hex: {e}"))?;
    if hmac_key.len() < 32 {
        return Err("hmac key must be at least 32 bytes".to_string());
    }

    Ok((hmac_key, parsed.config_version))
}

// ══════════════════════════════════════════════════════════════
//  امضا و ساخت URL — عیناً همان PhantomSession در Wasm
// ══════════════════════════════════════════════════════════════

/// percent-encode مطابق RFC 3986 (فقط unreserved دست‌نخورده می‌ماند)
/// worker با `query_pairs()` آن را decode می‌کند و به رشتهٔ اصلی می‌رسد.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn build_signed_url(target: &str, seq: u64, hmac_key: &[u8]) -> Result<String, String> {
    // message دقیقاً "{target}:{seq}" — همان چیزی که worker می‌سازد
    let message = format!("{target}:{seq}");

    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(message.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    Ok(format!(
        "{STREAMING_URL}/stream?target={}&sig={}&seq={}",
        percent_encode(target),
        signature,
        seq
    ))
}

/// آیا این host در allowlist است؟ (anchored — نه substring)
fn host_allowed(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    ALLOWED_TARGET_DOMAINS.iter().any(|domain| {
        host == *domain
            || host
                .strip_suffix(domain)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false)
    })
}

// ══════════════════════════════════════════════════════════════
//  درخواست امضاشده
// ══════════════════════════════════════════════════════════════

/// پاسخ خام تونل — بدنه به‌صورت بایت نگه داشته می‌شود تا پراکسی محلی
/// بتواند محتوای دودویی (تصویر/ویدیو) را هم عبور بدهد.
struct RawResponse {
    status: u16,
    ghost_path: Option<String>,
    content_type: String,
    body: Vec<u8>,
}

/// سقف بدنه در هر hop (۸ مگابایت) — این پل برای پیش‌نمایش است، نه دانلود انبوه.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

fn fetch_raw(target: &str, key: &[u8], seq: u64) -> Result<RawResponse, String> {
    let signed = build_signed_url(target, seq, key)?;

    let response = match ureq::get(&signed).timeout(Duration::from_secs(25)).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(code, response)) => {
            // خطاهای ۴xx/۵xx ورکر هم بدنهٔ توضیحی دارند — همان را برمی‌گردانیم
            let content_type = response
                .header("Content-Type")
                .unwrap_or("text/plain; charset=utf-8")
                .to_string();
            let mut body = Vec::new();
            let _ = response
                .into_reader()
                .take(MAX_BODY_BYTES)
                .read_to_end(&mut body);
            return Ok(RawResponse {
                status: code,
                ghost_path: None,
                content_type,
                body,
            });
        }
        Err(err) => return Err(format!("tunnel unreachable: {err}")),
    };

    let status = response.status();
    let ghost_path = response.header("X-Ghost-Path").map(|v| v.to_string());
    let content_type = response
        .header("Content-Type")
        .unwrap_or("application/octet-stream")
        .to_string();

    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_BODY_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| format!("reading stream body failed: {e}"))?;

    Ok(RawResponse {
        status,
        ghost_path,
        content_type,
        body,
    })
}

/// نسخهٔ متنی برای نمایش در رابط کاربری
fn fetch_through_tunnel(target: &str, key: &[u8], seq: u64) -> Result<TestResult, String> {
    let raw = fetch_raw(target, key, seq)?;
    let text = String::from_utf8_lossy(&raw.body);
    Ok(TestResult {
        status: raw.status,
        ok: (200..300).contains(&raw.status),
        ghost_path: raw.ghost_path,
        body: text.chars().take(4000).collect(),
    })
}

// ══════════════════════════════════════════════════════════════
//  پراکسی محلی (127.0.0.1) — فقط آنچه بک‌اند واقعاً پشتیبانی می‌کند
// ══════════════════════════════════════════════════════════════

/// عبارت وضعیت استاندارد برای کدهای HTTPی که ممکن است از تونل برگردند
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

fn write_http(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    write_http_bytes(
        stream,
        status,
        reason,
        "text/plain; charset=utf-8",
        body.as_bytes(),
    );
}

fn write_http_bytes(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// خواندن هدرهای درخواست تا رسیدن به `\r\n\r\n`
fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];

    while buffer.len() < 16 * 1024 {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    Some(String::from_utf8_lossy(&buffer).into_owned())
}

fn handle_proxy_client(mut stream: TcpStream, shared: Shared) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let head = match read_request_head(&mut stream) {
        Some(head) => head,
        None => return,
    };

    let request_line = head.lines().next().unwrap_or_default().trim_end().to_string();

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let uri = parts.next().unwrap_or_default();

    // ── CONNECT: بک‌اند تونل TLS خام ندارد ───────────────────
    if method.eq_ignore_ascii_case("CONNECT") {
        write_http(
            &mut stream,
            501,
            "Not Implemented",
            "CONNECT (raw TLS tunnel) is not supported by the SCP-GHOST streaming backend.\n\
             /stream is a GET bridge over an allowlisted host list, not a forward proxy.\n\
             Use the app's 'Tunnel test' button to verify connectivity instead.\n",
        );
        return;
    }

    if !method.eq_ignore_ascii_case("GET") {
        write_http(&mut stream, 405, "Method Not Allowed", "Only GET is supported.\n");
        return;
    }

    // absolute-URI لازم است (proxied request)
    let Some(rest) = uri.strip_prefix("http://") else {
        write_http(
            &mut stream,
            400,
            "Bad Request",
            "Expected an absolute http:// URI (configure this address as an HTTP proxy).\n",
        );
        return;
    };

    let host_end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..host_end];
    let hostname = authority.split(':').next().unwrap_or(authority);

    if !host_allowed(hostname) {
        write_http(
            &mut stream,
            403,
            "Forbidden",
            &format!(
                "Host '{hostname}' is not in the streaming allowlist\n\
                 ({ALLOWED}).\n",
                ALLOWED = ALLOWED_TARGET_DOMAINS.join(", ")
            ),
        );
        return;
    }

    // کلید و seq را بگیر
    let (key, seq) = {
        let guard = match shared.session.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        match guard.as_ref() {
            Some(session) => (
                session.hmac_key.clone(),
                shared.seq.fetch_add(1, Ordering::Relaxed),
            ),
            None => {
                drop(guard);
                write_http(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "No active session. Connect first.\n",
                );
                return;
            }
        }
    };

    let target = uri.to_string();
    match fetch_raw(&target, &key, seq) {
        Ok(raw) => {
            write_http_bytes(
                &mut stream,
                raw.status,
                reason_phrase(raw.status),
                &raw.content_type,
                &raw.body,
            );
        }
        Err(err) => {
            write_http(&mut stream, 502, "Bad Gateway", &format!("{err}\n"));
        }
    }
}

fn start_proxy(shared: Shared) -> Result<ProxyHandle, String> {
    // پورت ترجیحی 8899؛ در صورت اشغال، پورت آزاد سیستم
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, PROXY_PORT))
        .or_else(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| format!("cannot bind 127.0.0.1:{PROXY_PORT} — {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking failed: {e}"))?;

    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr failed: {e}"))?
        .port();

    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);

    thread::spawn(move || {
        while flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _peer)) => {
                    let shared = Arc::clone(&shared);
                    thread::spawn(move || handle_proxy_client(stream, shared));
                }
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ProxyHandle { port, running })
}

// ══════════════════════════════════════════════════════════════
//  پیاده‌سازی عملیات (sync — در spawn_blocking اجرا می‌شوند)
// ══════════════════════════════════════════════════════════════

fn read_status(shared: &Shared) -> Status {
    // ترتیب قفل‌گیری همیشه session → proxy است تا deadlock رخ ندهد
    let (connected, config_version) = {
        let guard = shared.session.lock().ok();
        let session = guard.as_ref().and_then(|s| s.as_ref());
        (
            session.is_some(),
            session.and_then(|s| s.config_version.clone()),
        )
    };

    let proxy_port = shared
        .proxy
        .lock()
        .ok()
        .and_then(|p| p.as_ref().map(|handle| handle.port));

    Status {
        connected,
        proxy_port,
        config_version,
        seq: shared.seq.load(Ordering::Relaxed),
        version: APP_VERSION.to_string(),
        streaming_url: STREAMING_URL.to_string(),
    }
}

fn connect_inner(shared: &Shared) -> Result<Status, String> {
    if read_status(shared).connected {
        return Ok(read_status(shared));
    }

    let (hmac_key, config_version) = perform_handshake()?;

    {
        let mut guard = shared
            .session
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        *guard = Some(Session {
            hmac_key,
            config_version,
        });
    }

    shared.seq.store(0, Ordering::Relaxed);

    // پراکسی محلی را بالا بیاور (اگر پورت اشغال بود، اتصال را خراب نکن)
    let mut proxy_guard = shared
        .proxy
        .lock()
        .map_err(|_| "proxy lock poisoned".to_string())?;
    if proxy_guard.is_none() {
        match start_proxy(Arc::clone(shared)) {
            Ok(handle) => *proxy_guard = Some(handle),
            Err(err) => {
                eprintln!("[SCP-GHOST] local proxy disabled: {err}");
            }
        }
    }
    drop(proxy_guard);

    Ok(read_status(shared))
}

fn disconnect_inner(shared: &Shared) -> Result<Status, String> {
    if let Ok(mut guard) = shared.session.lock() {
        // Drop برای Session کلید را zeroize می‌کند
        *guard = None;
    }
    if let Ok(mut guard) = shared.proxy.lock() {
        *guard = None; // Drop پرچم running را false می‌کند
    }
    shared.seq.store(0, Ordering::Relaxed);
    Ok(read_status(shared))
}

fn tunnel_test_inner(shared: &Shared, target: &str) -> Result<TestResult, String> {
    if target.is_empty() {
        return Err("target URL is empty".to_string());
    }
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Err("target must start with http:// or https://".to_string());
    }

    let key = {
        let guard = shared
            .session
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        match guard.as_ref() {
            Some(session) => session.hmac_key.clone(),
            None => return Err("not connected — press Connect first".to_string()),
        }
    };

    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    fetch_through_tunnel(target, &key, seq)
}

// ══════════════════════════════════════════════════════════════
//  دستورهای Tauri
// ══════════════════════════════════════════════════════════════

#[tauri::command]
async fn connect(state: State<'_, Shared>) -> Result<Status, String> {
    let shared = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || connect_inner(&shared))
        .await
        .map_err(|e| format!("connect task failed: {e}"))?
}

#[tauri::command]
async fn disconnect(state: State<'_, Shared>) -> Result<Status, String> {
    let shared = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || disconnect_inner(&shared))
        .await
        .map_err(|e| format!("disconnect task failed: {e}"))?
}

#[tauri::command]
fn status(state: State<'_, Shared>) -> Status {
    read_status(state.inner())
}

#[tauri::command]
async fn tunnel_test(state: State<'_, Shared>, target: String) -> Result<TestResult, String> {
    let shared = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || tunnel_test_inner(&shared, &target))
        .await
        .map_err(|e| format!("test task failed: {e}"))?
}

// ══════════════════════════════════════════════════════════════
//  Entry point
// ══════════════════════════════════════════════════════════════

fn main() {
    tauri::Builder::default()
        .manage(Arc::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            status,
            tunnel_test
        ])
        .run(tauri::generate_context!())
        .expect("error while running SCP-GHOST desktop application");
}
