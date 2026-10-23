//! lib.rs — نقطه ورودی Browser Wasm Module
//!
//! این فایل تمام ماژول‌ها را یکجا کرده و
//! PhantomSession (مدیریت کلیدها) را export می‌کند.

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod router;

// panic hook برای debug بهتر در browser console
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

type HmacSha256 = Hmac<Sha256>;

// ══════════════════════════════════════════════════════════════
//  PhantomSession — مدیریت کلیدهای رمزنگاری
//  ZeroizeOnDrop: کلیدها هنگام drop() از حافظه پاک می‌شوند
//  با 'beforeunload' event در Service Worker ترکیب می‌شود
// ══════════════════════════════════════════════════════════════

#[wasm_bindgen]
pub struct PhantomSession {
    #[wasm_bindgen(skip)]
    pub hmac_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub aes_key: Vec<u8>,
    streaming_endpoint: String,
    signaling_endpoint: String,
    gas_endpoints: Vec<String>,
    request_counter: u64,
}

// ZeroizeOnDrop را دستی پیاده می‌کنیم چون wasm_bindgen با derive ناسازگار است
impl Drop for PhantomSession {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
        self.aes_key.zeroize();
    }
}

#[wasm_bindgen]
impl PhantomSession {
    /// ساخت Session جدید
    /// hmac_key_hex: کلید HMAC به صورت hex string (از Signaling Worker دریافت می‌شود)
    /// aes_key_hex: کلید AES-256-GCM به صورت hex string
    #[wasm_bindgen(constructor)]
    pub fn new(
        hmac_key_hex: &str,
        aes_key_hex: &str,
        streaming_endpoint: &str,
        signaling_endpoint: &str,
        gas_endpoints_json: &str,
    ) -> Result<PhantomSession, JsValue> {
        let hmac_key = hex::decode(hmac_key_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid HMAC key hex: {e}")))?;

        let aes_key = hex::decode(aes_key_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid AES key hex: {e}")))?;

        if hmac_key.len() < 32 {
            return Err(JsValue::from_str("HMAC key must be at least 32 bytes"));
        }

        if aes_key.len() != 32 {
            return Err(JsValue::from_str("AES key must be exactly 32 bytes (256-bit)"));
        }

        let gas_endpoints: Vec<String> = serde_json::from_str(gas_endpoints_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid GAS endpoints JSON: {e}")))?;

        Ok(PhantomSession {
            hmac_key,
            aes_key,
            streaming_endpoint: streaming_endpoint.to_string(),
            signaling_endpoint: signaling_endpoint.to_string(),
            gas_endpoints,
            request_counter: 0,
        })
    }

    /// ساخت HMAC-signed URL برای Streaming Worker
    /// این URL به Worker ثابت می‌کند که درخواست از client معتبر می‌آید
    pub fn build_stream_url(&mut self, target_url: &str) -> Result<String, JsValue> {
        let seq = self.request_counter;
        self.request_counter = self.request_counter.wrapping_add(1);

        let message = format!("{}:{}", target_url, seq);

        // ابهام‌زدایی: هم KeyInit و هم Mac متد new_from_slice دارند.
        // برای HMAC باید نسخهٔ Mac صدا زده شود (کلید با طول دلخواه).
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .map_err(|e| JsValue::from_str(&format!("HMAC init error: {e}")))?;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // URL encode کردن target
        let encoded_target = js_sys::encode_uri_component(target_url);

        Ok(format!(
            "{}/stream?target={}&sig={}&seq={}",
            self.streaming_endpoint,
            encoded_target,
            signature,
            seq
        ))
    }

    /// رمزنگاری payload برای Apps Script با AES-256-GCM
    pub fn encrypt_payload(&self, plaintext: &str) -> Result<String, JsValue> {
        let key = Key::<Aes256Gcm>::from_slice(&self.aes_key);
        let cipher = Aes256Gcm::new(key);

        // Nonce تصادفی ۱۲ بایتی — هرگز تکرار نمی‌شود
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Encryption error: {e}")))?;

        // فرمت: nonce_hex:ciphertext_hex
        Ok(format!(
            "{}:{}",
            hex::encode(nonce),
            hex::encode(ciphertext)
        ))
    }

    /// آمارگیری session — برای debugging در browser console
    pub fn stats(&self) -> String {
        format!(
            r#"{{"requests_made":{},"gas_endpoints":{},"streaming_ep":"{}"}}"#,
            self.request_counter,
            self.gas_endpoints.len(),
            self.streaming_endpoint
        )
    }

    /// از بین بردن صریح session — فراخوانی در 'beforeunload' event
    /// ZeroizeOnDrop هم به صورت خودکار در drop() اجرا می‌شود
    pub fn destroy(mut self) {
        self.hmac_key.zeroize();
        self.aes_key.zeroize();
        // drop() به صورت خودکار فراخوانی می‌شود
    }
}

// ══════════════════════════════════════════════════════════════
//  Utility Functions — قابل استفاده از JavaScript
// ══════════════════════════════════════════════════════════════

/// Constant-time string comparison — جلوگیری از timing attack
#[wasm_bindgen]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ══════════════════════════════════════════════════════════════
//  SessionHandshake — تبادل کلید X25519 با signaling-worker
//
//  پروتکل `x25519-hkdf-sha256-aesgcm-v1` (باید دقیقاً با
//  signaling-worker/src/lib.rs یکی باشد):
//
//    1. new()                → keypair موقت؛ کلید خصوصی هرگز خارج نمی‌شود
//    2. public_key_b64()     → به /session-init فرستاده می‌شود
//    3. complete(...)        → KEK را می‌سازد و payload را باز می‌کند
//
//  ⚠️ کلید خصوصی در حافظهٔ Wasm می‌ماند و با drop پاک (zeroize) می‌شود.
// ══════════════════════════════════════════════════════════════

/// info در HKDF — باید با سمت سرور یکی باشد
const HKDF_INFO_KEK: &[u8] = b"ghost/session-kek/v1";

/// پیشوند AAD — باید با سمت سرور یکی باشد
const AAD_PREFIX: &[u8] = b"ghost/session/v1";

fn handshake_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

#[wasm_bindgen]
pub struct SessionHandshake {
    secret: StaticSecret,
    public: PublicKey,
}

#[wasm_bindgen]
impl SessionHandshake {
    /// ساخت keypair موقت X25519
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<SessionHandshake, JsValue> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| handshake_err(&format!("RNG error: {e}")))?;

        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);

        Ok(SessionHandshake { secret, public })
    }

    /// کلید عمومی به base64 — همین رشته به `/session-init` می‌رود
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }

    /// باز کردن پاسخ سرور.
    /// خروجی: JSON به شکل `{"hmac_key_hex":"...","aes_key_hex":"..."}`
    pub fn complete(
        &self,
        server_pubkey_b64: &str,
        salt_b64: &str,
        wrapped_b64: &str,
    ) -> Result<String, JsValue> {
        // ── ۱. public key سرور ──────────────────────────────────
        let server_pub_vec = B64
            .decode(server_pubkey_b64.trim())
            .map_err(|_| handshake_err("server_pubkey is not valid base64"))?;

        if server_pub_vec.len() != 32 {
            return Err(handshake_err("server_pubkey must be 32 bytes"));
        }

        let mut server_pub_arr = [0u8; 32];
        server_pub_arr.copy_from_slice(&server_pub_vec);
        let server_public = PublicKey::from(server_pub_arr);

        // ── ۲. shared secret ───────────────────────────────────
        let shared = self.secret.diffie_hellman(&server_public);
        if !shared.was_contributory() {
            return Err(handshake_err("invalid server public key (low order point)"));
        }

        // ── ۳. KEK با HKDF-SHA256 ──────────────────────────────
        let salt = B64
            .decode(salt_b64.trim())
            .map_err(|_| handshake_err("salt is not valid base64"))?;

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut kek = [0u8; 32];
        hk.expand(HKDF_INFO_KEK, &mut kek)
            .map_err(|_| handshake_err("HKDF expand failed"))?;

        // ── ۴. AES-256-GCM decrypt ─────────────────────────────
        let wrapped = B64
            .decode(wrapped_b64.trim())
            .map_err(|_| handshake_err("wrapped is not valid base64"))?;

        // nonce(12) || ciphertext+tag(16+)
        if wrapped.len() < 12 + 16 {
            return Err(handshake_err("wrapped payload is too short"));
        }
        let (nonce_bytes, ciphertext) = wrapped.split_at(12);

        // AAD = "ghost/session/v1" || client_pub || server_pub
        let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 64);
        aad.extend_from_slice(AAD_PREFIX);
        aad.extend_from_slice(self.public.as_bytes());
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
            .map_err(|_| handshake_err("AES-GCM decryption failed — wrong key or tampered payload"))?;

        // ── ۵. اعتبارسنجی محتوا ────────────────────────────────
        let parsed: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|_| handshake_err("decrypted payload is not valid JSON"))?;

        let hmac_ok = parsed
            .get("hmac_key_hex")
            .and_then(|v| v.as_str())
            .map(|v| v.len() >= 64)
            .unwrap_or(false);
        let aes_ok = parsed
            .get("aes_key_hex")
            .and_then(|v| v.as_str())
            .map(|v| v.len() == 64)
            .unwrap_or(false);

        if !hmac_ok || !aes_ok {
            return Err(handshake_err("decrypted payload is missing valid keys"));
        }

        String::from_utf8(plaintext)
            .map_err(|_| handshake_err("decrypted payload is not valid UTF-8"))
    }
}
