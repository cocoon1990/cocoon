# SCP-GHOST Desktop (Tauri v2 + هستهٔ meow)

کلاینت دسکتاپ ویندوز. این پوشه کاملاً **مستقل** است: هیچ crate یا فایلی از
`streaming-worker/`، `signaling-worker/`، `browser-wasm/`، `docs/` یا `config/`
را import یا تغییر نمی‌دهد.

> **بازطراحی (v5.3.0):** تمام کد پراکسی دست‌ساز (X25519، HMAC، سوکت TCP، ساخت
> TUN) حذف شد. حالا یک هستهٔ پراکسی واقعی و متن‌باز (`meow`) به‌صورت **sidecar**
> اجرا می‌شود و Tauri فقط رابط کاربری و کنترل‌کننده است.

## چرا «meow»؟

| کاندید | زبان | VLESS | REALITY | TUN ویندوز | وضعیت |
|---|---|---|---|---|---|
| **meow-rs** | Rust | ✅ + XTLS-Vision | ✅ | ✅ Wintun | v0.26.1 (۲۰۲۶-۱۰-۲۱) |
| mihomo | Go | ✅ | ✅ | ✅ Wintun | v1.19.33 — بالغ‌ترین مرجع |
| sing-box | Go | ✅ | ✅ | ✅ | v1.13.x |
| Xray-core | Go | ✅ (مرجع) | ✅ | TUN حداقلی | v26.3.x |
| shoes | Rust | — | — | — | کتابخانه، نه هستهٔ کامل |

`meow` ری‌رایت Rust هستهٔ mihomo است: کانفیگ YAML سازگار، VLESS/REALITY/XTLS-Vision،
آداپتور Wintun روی ویندوز (فایل‌های رسمی `wintun.dll` را همراه دارند)، و REST API
سازگار با Clash. تنها کاندید Rust است که هر سه نیاز (VLESS + REALITY + TUN) را
پوشش می‌دهد.

**صادقانه:** نسخهٔ ۰.x است و در حال حاضر باگ‌های TUN فعالانه رفع می‌شوند؛ به
بلوغ mihomo نیست. به همین دلیل:

- کانفیگ تولیدشده **mihomo-compatible** است؛ اگر پایداری meow کافی نبود، فقط
  باینری sidecar را با `mihomo.exe` عوض کنید — هیچ خط دیگری تغییر نمی‌کند.
- نسخه در `.github/workflows/build-desktop.yml` (متغیر `CORE_VERSION`) پین شده و
  checksum SHA-256 آن پیش از بسته‌بندی تأیید می‌شود.

## معماری

```
┌──────────────────────────── SCP-GHOST.exe (Tauri) ───────────────────────────┐
│  src/index.html + styles.css + main.js     رابط کاربری (فقط نمایش)           │
│  src/core-config.js                        URI → YAML  (تنها تبدیل داده‌ای)   │
│  src-tauri/src/main.rs                     کنترلر: GET اشتراک، نوشتن فایل،   │
│                                            اجرا/توقف sidecar، جمع‌آوری لاگ     │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │  spawn  meow -d <dir> -f <config.yaml>
┌───────────────────────────────────▼──────────────────────────────────────────┐
│  meow.exe  (sidecar، Rust)                                                   │
│  TUN/Wintun + DNS fake-ip + VLESS(WS/TLS یا REALITY) + قوانین مسیریابی       │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │  VLESS over TLS/WS
                            ┌───────▼────────┐
                            │ Cloudflare      │   /sub  → URI نود
                            │ streaming-worker│
                            └───────┬────────┘
                                    │  (VLESS_HOST)
                            سرور VLESS واقعی (Xray/sing-box/…)
```

هیچ کد شبکه/TUN/TLS در Rust این برنامه نیست؛ `verify_config.py` این را به‌صورت
خودکار بررسی می‌کند (`TcpListener`، `X25519`، `aes_gcm`، `Hmac` و `create_tun`
نباید در `main.rs` باشند).

## جریان کار

1. کاربر آدرس اشتراک (`https://…/sub?token=…`) را می‌دهد.
2. Rust متن اشتراک را می‌گیرد (بدون درگیری CORS در webview).
3. `core-config.js` آن را Base64-decode می‌کند، نود `vless://` را پارس می‌کند و
   YAML می‌سازد.
4. Rust فایل را در `%LOCALAPPDATA%\io.cocoon.scpghost\core\config.yaml` می‌نویسد.
5. `meow.exe -d <همان پوشه> -f config.yaml` اجرا می‌شود.
6. لاگ هسته هر ۱٫۲ ثانیه به UI خوانده می‌شود؛ توقف = `kill` واقعی فرایند.

### حالت‌ها

| حالت | چه چیزی عبور می‌کند | دسترسی |
|---|---|---|
| **TUN** | همهٔ ترافیک ویندوز (آداپتور Wintun) | مدیر (برنامه با UAC بالا می‌آید) |
| **پراکسی محلی** | برنامه‌هایی که از `http://127.0.0.1:7890` استفاده می‌کنند | کاربر عادی |

## بسته‌بندی sidecar

`tauri.conf.json` → `bundle.externalBin: ["binaries/meow"]`، و فایل باید با نام
هدف سه‌گانه موجود باشد:

```
src-tauri/binaries/meow-x86_64-pc-windows-msvc.exe
```

این پوشه gitignore شده است؛ CI آن را در زمان build دانلود و checksum را تأیید
می‌کند. برای build محلی:

```powershell
$v = 'v0.26.1'; $a = "meow-$v-x86_64-pc-windows-msvc.zip"
$b = "https://github.com/meow-rs/meow-rs/releases/download/$v"
Invoke-WebRequest "$b/$a" -OutFile core.zip
Expand-Archive core.zip -DestinationPath core -Force
New-Item -ItemType Directory -Force desktop-app/src-tauri/binaries | Out-Null
Copy-Item core/meow.exe desktop-app/src-tauri/binaries/meow-x86_64-pc-windows-msvc.exe
Copy-Item core/wintun.dll desktop-app/src-tauri/binaries/ -ErrorAction SilentlyContinue
```

## ساخت و اجرا

```powershell
npm install -g @tauri-apps/cli@v2
cd desktop-app
tauri dev      # یا: tauri build
```

خروجی:

```
src-tauri/target/release/bundle/nsis/SCP-GHOST_5.3.0_x64-setup.exe
src-tauri/target/release/bundle/msi/SCP-GHOST_5.3.0_x64_en-US.msi
```

## آزمون‌ها (بدون نیاز به Rust)

```bash
node   desktop-app/tools/test_core_config.cjs   # ۵۱ آزمون — پارس URI و YAML
python3 desktop-app/tools/verify_config.py     # config، آیکون، مانیفست، sidecar، «نبود کد سفارشی»
NODE_PATH=<node_modules> node desktop-app/tools/test_ui.cjs   # ۳۴ آزمون DOM با jsdom
python3 desktop-app/tools/gen_icons.py         # بازتولید آیکون‌ها
```

`tools/out/*.yaml` خروجی تست اول است و `verify_config.py` همان‌ها را با یک پارسر
واقعی YAML بازمی‌خواند. آزمون DOM اختیاری است (نیازمند `npm install jsdom`).

## نکتهٔ مهم دربارهٔ این بک‌اند

`streaming-worker` خودش **سرور VLESS نیست** (در سورس هم همین را می‌گوید). `/sub`
فقط یک URI استاندارد می‌سازد که به `VLESS_HOST` اشاره می‌کند و بدون تنظیم
`SUB_TOKEN` / `VLESS_UUID` / `VLESS_HOST` با خطا بسته می‌شود (fail-closed).

یعنی این برنامه وقتی تونل واقعی می‌شود که آن upstream وجود داشته باشد. اگر `/sub`
خطا برگرداند، برنامه همان پیام سرور را نشان می‌دهد و هسته را اجرا نمی‌کند —
هیچ تونل جعلی ساخته نمی‌شود.
