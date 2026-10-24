# SCP-GHOST Desktop (Tauri v2)

کلاینت دسکتاپ ویندوز برای تونل موجود. این پوشه کاملاً **مستقل** است: هیچ crate یا
فایلی از `streaming-worker/`، `signaling-worker/`، `browser-wasm/`، `docs/` یا
`config/` را import یا تغییر نمی‌دهد. ارتباط فقط از طریق اینترنت و همان قرارداد
عمومی workerها انجام می‌شود.

```
desktop-app/
├── src/                        رابط کاربری — HTML/CSS/JS خالص، بدون باندلر
│   ├── index.html
│   ├── styles.css
│   └── main.js                 فقط نمایش؛ هیچ رمزنگاری‌ای در JS نیست
├── src-tauri/                  هستهٔ Rust
│   ├── Cargo.toml              tauri 2 + x25519-dalek + aes-gcm + hkdf + ureq
│   ├── build.rs
│   ├── tauri.conf.json         پنجره، بسته‌بندی nsis/msi، آیکون‌ها
│   ├── capabilities/           مجوز حداقلی (core:default)
│   ├── icons/                  تولیدشده توسط tools/gen_icons.py
│   └── src/main.rs             handshake + امضا + پراکسی محلی
└── tools/                      اسکریپت‌های اعتبارسنجی (بدون وابستگی به Rust)
    ├── verify_config.py        ساختار config، آیکون‌ها، هم‌خوانی دستورها
    ├── protocol_parity.py      هم‌خوانی بایت‌به‌بایت با workerها
    ├── test_ui.cjs             آزمون DOM رابط کاربری (jsdom)
    └── gen_icons.py            تولید آیکون‌ها بدون وابستگی خارجی
```

## معماری

| لایه | مسئولیت |
|---|---|
| `main.js` | دکمه‌ها، وضعیت، لاگ، نمایش نتیجه. صفر رمزنگاری. |
| `main.rs` | X25519 + HKDF + AES-GCM (handshake)، HMAC-SHA256 (امضا)، HTTP، پراکسی |
| `ureq` (blocking) | تنها کلاینت شبکه، روی یک thread جدا (`spawn_blocking`) |

**چرا کلید خصوصی هیچ‌وقت ذخیره نمی‌شود؟** کلید X25519 در همان تابع
`perform_handshake` ساخته و مصرف می‌شود و از scope آن بیرون نمی‌رود. تنها چیزی که
نگه داشته می‌شود `hmac_key` است که با `zeroize` در `Drop` پاک می‌شود.

## قرارداد پروتکل (عیناً همان نسخهٔ وب)

```
POST {SIGNALING}/session-init
  → {"client_pubkey": base64(32 raw bytes), "client_version": "5.2.6"}
  ← {"protocol": "x25519-hkdf-sha256-aesgcm-v1",
     "server_pubkey": b64(32), "salt": b64(32),
     "wrapped": b64(nonce12 ‖ ct ‖ tag16), "config_version": "..."}

shared = X25519(client_priv, server_pub)
kek    = HKDF-SHA256(salt, shared, info="ghost/session-kek/v1", len=32)
AAD    = "ghost/session/v1" ‖ client_pub_raw ‖ server_pub_raw
plain  = AES-256-GCM-decrypt(kek, wrapped)  → {"hmac_key_hex", "aes_key_hex"}

GET {STREAMING}/stream?target=percent(target)&sig=&seq=
  message = "{target}:{seq}"
  key     = hex::decode(hmac_key_hex)        ← ۳۲ بایت، نه ۶۴ بایت ASCII
  sig     = hex(HMAC-SHA256(key, message))   ← ۶۴ کاراکتر hex
```

سه نکته که دقیقاً همان اشتباهات گذشته را تکرار نمی‌کنند:

1. **کلید HMAC** با `hex::decode` ساخته می‌شود (۳۲ بایت). استفاده از
   `hex_string.as_bytes()` (۶۴ بایت ASCII) همان باگ v5.2.5 است.
2. **خروجی امضا** با `hex::encode` به رشته تبدیل می‌شود، نه بایت خام.
3. **target** با درصدگذاری RFC 3986 در query می‌رود (`+` → `%2B`). بدون این،
   ورکر `+` را فاصله decode می‌کند و امضا نمی‌خواند.

## پراکسی محلی — دامنهٔ واقعی

روی `127.0.0.1:8899` گوش می‌دهد (اگر اشغال باشد: پورت آزاد سیستم).

| درخواست | رفتار |
|---|---|
| `GET http://<allowlist>/...` | امضا و عبور از `/stream` |
| `GET http://<سایر دامنه‌ها>/...` | `403` با توضیح allowlist |
| `CONNECT host:443` | `501` — بک‌اند تونل TLS خام ندارد |
| متد غیر GET | `405` |
| بدون اتصال | `503` |

این یک **forward-proxy کامل نیست** و ادعای آن هم نمی‌شود: `/stream` یک پل GET روی
پنج دامنهٔ مجاز است، نه `CONNECT`. بنابراین نمی‌تواند ترافیک کل ویندوز را حمل کند؛
برای آن معماری بک‌اند باید یک تونل واقعی (CONNECT/QUIC) داشته باشد. کاری که این
برنامه واقعاً انجام می‌دهد: handshake واقعی، امضای واقعی، عبور واقعی محتوا از
دامنه‌های مجاز، و گزارش شفاف `X-Ghost-Path` برای هر hop.

## ساخت

### خودکار (توصیه‌شده)

`.github/workflows/build-desktop.yml` روی هر push به `main` که `desktop-app/**` را
تغییر دهد، ویندوز را می‌سازد و نصب‌کننده‌ها را به GitHub Releases می‌گذارد.

| رویداد | نتیجه |
|---|---|
| Pull Request | `cargo check` + اعتبارسنجی + ساخت کامل ویندوز (بدون انتشار) |
| Push به `main` | همان + انتشار در Release با تگ `desktop-v5.2.6` |
| اجرای دستی | ساخت؛ انتشار فقط اگر روی `main` باشد |

### دستی (روی ویندوز)

```powershell
# پیش‌نیازها: Rust stable (MSVC)، Node.js، WebView2 (در ویندوز ۱۱ از پیش نصب است)
npm install -g @tauri-apps/cli@v2
cd desktop-app
tauri build            # یا: tauri dev
```

خروجی:

```
src-tauri/target/release/bundle/nsis/SCP-GHOST_5.2.6_x64-setup.exe
src-tauri/target/release/bundle/msi/SCP-GHOST_5.2.6_x64_en-US.msi
```

## اعتبارسنجی بدون ویندوز

```bash
python3 desktop-app/tools/verify_config.py     # ساختار config، آیکون‌ها، دستورها
python3 desktop-app/tools/protocol_parity.py   # نیازمند: pip install cryptography
node    desktop-app/tools/test_ui.cjs          # نیازمند: npm install jsdom
python3 desktop-app/tools/gen_icons.py         # بازتولید آیکون‌ها
```

سه مورد اول در CI هم اجرا می‌شوند و `cargo check` تنها دروازهٔ کامپایل Rust است.
