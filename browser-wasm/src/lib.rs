//! lib.rs — نقطه ورودی Browser Wasm Module
//!
//! این فایل تمام ماژول‌ها را یکجا کرده و
//! PhantomSession (مدیریت کلیدها) را export می‌کند.

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

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
