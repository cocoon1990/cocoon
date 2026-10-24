# SCP-GHOST Desktop — v5.4.0

پوستهٔ دسکتاپ ویندوز برای تونل **Cocoon in Cocoon** (نامرئی در نامرئی).
Tauri v2 + هستهٔ `meow` به‌صورت sidecar. این پوشه مستقل است و هیچ فایلی از
`docs/`، `browser-extension/` یا `signaling-worker/` را تغییر نمی‌دهد.

> **v5.4.0:** رابط کاربری کامل بازنویسی شد، `tauri-plugin-updater` اضافه شد و
> `streaming-worker` خودش سرور VLESS شد؛ اشتراک `/sub` اکنون به همان worker
> اشاره می‌کند (`wss://<worker>/vless`) — نه به یک سرور بیرونی.

## چرا meow؟

| کاندید | زبان | VLESS | REALITY | TUN ویندوز | وضعیت |
|---|---|---|---|---|---|
| **meow-rs** | Rust | ✅ + XTLS-Vision | ✅ | ✅ Wintun | v0.26.1 |
| mihomo | Go | ✅ | ✅ | ✅ Wintun | v1.19.33 — بالغ‌ترین مرجع |
| sing-box | Go | ✅ | ✅ | ✅ | v1.13.x |

`meow` ری‌رایت Rust هستهٔ mihomo است: کانفیگ YAML سازگار، VLESS/REALITY/XTLS-Vision،
آداپتور Wintun و REST API سازگار با Clash. نسخهٔ ۰.x است؛ اگر پایداری کافی نبود
فقط باینری sidecar را با `mihomo.exe` عوض کنید — کانفیگ تولیدی mihomo-compatible است.

## معماری

```
┌──────────────────── SCP-GHOST.exe (Tauri v2) ────────────────────┐
│  src/index.html + styles.css     رابط کاربری (RTL، تم تیره)      │
│  src/core.js                     منطق خالص: Base64 → vless → YAML│
│  src/main.js                     کنترلر UI + fetch اشتراک        │
│  src-tauri/src/main.rs           نوشتن فایل، spawn/kill sidecar، │
│                                  لاگ، updater                    │
└──────────────────────────────┬───────────────────────────────────┘
                               │  spawn  meow -d <dir> -f config.yaml
┌──────────────────────────────▼───────────────────────────────────┐
│  meow.exe (sidecar): TUN/Wintun + DNS + VLESS(WS/TLS) + rules    │
└──────────────────────────────┬───────────────────────────────────┘
                               │  VLESS over TLS/WebSocket :443
┌──────────────────────────────▼───────────────────────────────────┐
│  streaming-worker  /vless  →  cloudflare:sockets  →  مقصد        │
└──────────────────────────────────────────────────────────────────┘
```

**هیچ کد شبکه/TUN/TLS در Rust این برنامه نیست.** `verify_config.py` حضور
`TcpStream`، `UdpSocket`، `tokio::net`، `wintun` و `kill_on_drop` را در
`main.rs` ممنوع می‌کند. تمام تونل کار sidecar است.

## جریان کار

1. کاربر آدرس اشتراک (`https://…/sub?token=…`) را می‌گذارد.
2. `main.js` با `fetch` خودِ webview متن را می‌گیرد (بدون CORS، بدون کلاینت HTTP در Rust).
3. `core.js` آن را Base64-decode می‌کند، نود `vless://` را اعتبارسنجی می‌کند و
   YAML سازگار با mihomo می‌سازد (TUN یا پراکسی، پورت محلی قابل تغییر).
4. Rust فایل را در `%LOCALAPPDATA%\io.cocoon.scpghost\core\config.yaml` می‌نویسد.
5. `meow.exe -d <همان پوشه> -f config.yaml` اجرا می‌شود؛ لاگ زنده به UI می‌آید.
6. «قطع» = `kill` واقعی فرایند (نه orphan)؛ در `RunEvent::Exit` هم kill می‌شود.

## رابط کاربری

- تم تیره: `#0f172a` / `#1e293b`، اکسنت فیروزه‌ای `#06b6d4`، موفقیت زمردی `#10b981`
- فونت: Vazirmatn (فارسی) + Inter (لاتین)، RTL کامل، `dir="rtl"`
- نوار بالا با لوگو و pill وضعیت (متصل / قطع / خطا)
- دکمهٔ گرد اتصال با هالهٔ نئونی و انیمیشن hover
- فیلد اشتراک با دکمهٔ کپی + «دریافت» اصلی
- کلید TUN/Proxy با thumb لغزنده
- «تنظیمات پیشرفته» (چرخ‌دنده): پورت محلی، لاگ هسته، بررسی به‌روزرسانی
- fade-in ملایم روی کارت‌ها + احترام به `prefers-reduced-motion`

## به‌روزرسانی خودکار

`tauri-plugin-updater` با endpoint:

```
https://github.com/cocoon1990/cocoon/releases/latest/download/latest.json
```

برای فعال‌سازی انتشار امضاشده (یک‌بار):

```bash
npm run tauri signer generate -- -w ~/.tauri/scpghost.key
# 1) کلید عمومی را در tauri.conf.json → plugins.updater.pubkey بگذارید
# 2) در GitHub Secrets: TAURI_SIGNING_PRIVATE_KEY (+ PASSWORD در صورت وجود)
# 3) در workflow: includeUpdaterJson: true
```

تا وقتی کلید تنظیم نشده، دکمهٔ «بررسی به‌روزرسانی» پیام «کانال در دسترس نیست»
را نشان می‌دهد و چیزی را نصب نمی‌کند (fail-safe).

## ساخت

```powershell
npm install -g @tauri-apps/cli@v2
cd desktop-app
tauri dev
tauri build
```

خروجی:

```
src-tauri/target/release/bundle/nsis/SCP-GHOST_5.4.0_x64-setup.exe
src-tauri/target/release/bundle/msi/SCP-GHOST_5.4.0_x64_en-US.msi
```

sidecar باید با نام هدف سه‌گانه موجود باشد (`src-tauri/binaries/meow-x86_64-pc-windows-msvc.exe`)؛
CI آن را دانلود و SHA-256 را تأیید می‌کند. این پوشه gitignore شده است.

## آزمون‌ها (بدون نیاز به Rust)

```bash
node   desktop-app/tools/test_core.cjs            # ۲۸ آزمون — اشتراک، VLESS، YAML
node   streaming-worker/tests/vless.test.mjs      # ۴۰ آزمون — هدر VLESS، پین‌های سورس، لینک /sub
python3 desktop-app/tools/verify_config.py        # config/آیکون/sidecar/updater/پریتی دستورها
```

`tools/out/*.yaml` خروجی تست اول است و `verify_config.py` همان‌ها را با PyYAML
بازمی‌خواند. کامپایل واقعی Rust فقط در CI انجام می‌شود (`cargo check` + `tauri build`).
