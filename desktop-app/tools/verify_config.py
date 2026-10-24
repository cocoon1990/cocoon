#!/usr/bin/env python3
"""verify_config.py — packaging + contract gate for the desktop shell.

Run it after the Node suites:

    node desktop-app/tools/test_core.cjs
    python3 desktop-app/tools/verify_config.py

It fails (exit 1) on anything that would break a release build:
tauri.conf.json shape, sidecar/icon presence, updater wiring, banned
proxy/TUN code in the Rust controller, and frontend <-> backend command parity.
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "desktop-app"
TAURI = APP / "src-tauri"
SRC = APP / "src"
WORKER = ROOT / "streaming-worker"
VERSION = "5.4.1"

problems: list[str] = []
notes: list[str] = []


def fail(message: str) -> None:
    problems.append(message)


def ok(message: str) -> None:
    notes.append(message)


def read(path: Path) -> str:
    if not path.exists():
        fail(f"missing file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8")


# ── 1. tauri.conf.json ─────────────────────────────────────────
conf_path = TAURI / "tauri.conf.json"
conf = json.loads(read(conf_path) or "{}")

if conf.get("productName") != "SCP-GHOST":
    fail("productName must stay SCP-GHOST")
if conf.get("version") != VERSION:
    fail(f"tauri.conf.json version must be {VERSION}, got {conf.get('version')}")
if conf.get("identifier") != "io.cocoon.scpghost":
    fail("bundle identifier changed")

build = conf.get("build", {})
dist = (TAURI / build.get("frontendDist", "")).resolve()
if not dist.is_dir():
    fail(f"frontendDist does not resolve to a directory: {build.get('frontendDist')}")
else:
    ok(f"frontendDist -> {dist.relative_to(ROOT)}")
if (dist / "src-tauri").exists():
    fail("frontendDist must not contain src-tauri (it would embed target/)")

app = conf.get("app", {})
windows = app.get("windows") or []
if not windows or windows[0].get("label") != "main":
    fail("the first window must be labelled 'main'")
if not app.get("withGlobalTauri"):
    fail("withGlobalTauri must be true: the frontend has no bundler and uses __TAURI__")

cap_path = TAURI / "capabilities" / "default.json"
cap = json.loads(read(cap_path) or "{}")
permissions = cap.get("permissions", [])
if "core:default" not in permissions:
    fail("capabilities must include core:default")
if "updater:default" not in permissions:
    fail("capabilities must include updater:default")
if cap.get("windows") != ["main"]:
    fail("capabilities must target the 'main' window only")

# ── 2. bundle ─────────────────────────────────────────────────
bundle = conf.get("bundle", {})
targets = bundle.get("targets")
if sorted(targets or []) != ["msi", "nsis"]:
    fail(f"bundle.targets must be [nsis, msi], got {targets}")

external = bundle.get("externalBin") or []
if external != ["binaries/meow"]:
    fail(f"externalBin must be exactly ['binaries/meow'], got {external}")
else:
    sidecars = list((TAURI / "binaries").glob("meow-*.exe"))
    if not sidecars:
        notes.append("sidecar not vendored locally (CI downloads it before building)")
    else:
        ok(f"sidecar present: {sidecars[0].name}")

icons = bundle.get("icon") or []
if "icons/icon.ico" not in icons:
    fail("bundle.icon must include icons/icon.ico for Windows")

for icon in icons:
    path = TAURI / icon
    if not path.exists():
        fail(f"missing icon: {icon}")
        continue
    raw = path.read_bytes()
    if icon.endswith(".png"):
        if raw[:8] != b"\x89PNG\r\n\x1a\n":
            fail(f"{icon} is not a PNG")
    elif icon.endswith(".ico"):
        if raw[:4] != b"\x00\x00\x01\x00":
            fail(f"{icon} is not an ICO")
        else:
            count = struct.unpack("<H", raw[4:6])[0]
            if count < 4:
                fail(f"{icon} carries only {count} images")

win = bundle.get("windows", {})
if (win.get("nsis") or {}).get("installMode") != "currentUser":
    fail("NSIS installMode must be currentUser (no admin needed to install)")
if not win.get("webviewInstallMode"):
    fail("webviewInstallMode must be set so end users get WebView2")

# ── 3. updater plugin ─────────────────────────────────────────
updater = (conf.get("plugins") or {}).get("updater")
if not updater:
    fail("plugins.updater is missing: auto-update is not wired")
else:
    endpoints = updater.get("endpoints") or []
    if not endpoints or not all(url.startswith("https://") for url in endpoints):
        fail("updater endpoints must be a non-empty https list")
    if "pubkey" not in updater:
        fail("updater.pubkey must exist (empty until a signing key is generated)")
    ok(f"updater endpoint -> {endpoints[0] if endpoints else '(none)'}")

cargo = read(TAURI / "Cargo.toml")
if f'version = "{VERSION}"' not in cargo:
    fail(f"src-tauri/Cargo.toml must be version {VERSION}")
if "tauri-plugin-updater" not in cargo:
    fail("Cargo.toml must depend on tauri-plugin-updater")
if "tauri-plugin-shell" not in cargo:
    fail("Cargo.toml must depend on tauri-plugin-shell (sidecar control)")

BANNED_CRATES = ["windivert", "wintun", "smoltcp", "pnet", "netstack", "tun ="]
for crate in BANNED_CRATES:
    if crate in cargo.lower():
        fail(f"banned crate in Cargo.toml: {crate}")

# ── 4. Rust controller ────────────────────────────────────────
main_rs = read(TAURI / "src" / "main.rs")
BANNED_RUST = [
    "TcpStream",
    "UdpSocket",
    "tokio::net",
    "std::net::",
    "WinDivert",
    "wintun",
    "kill_on_drop",
]
# تنها استثنا: بلوک کنترل‌پلین لوکال (PUT /configs روی 127.0.0.1) که برای
# hot-reload لازم است. بقیهٔ فایل نباید هیچ سوکتی داشته باشد.
CONTROL = re.search(r"// \[control-plane\].*?// \[/control-plane\]", main_rs, re.S)
shell_only = main_rs.replace(CONTROL.group(0), "") if CONTROL else main_rs
for token in BANNED_RUST:
    if token in shell_only:
        fail(f"banned token in main.rs: {token} (the shell must not do networking)")
if CONTROL is None:
    fail("the control-plane exception is not documented in main.rs")

if "tauri_plugin_updater::Builder::new().build()" not in main_rs:
    fail("the updater plugin is not registered in main.rs")
if "tauri_plugin_shell::init()" not in main_rs:
    fail("the shell plugin is not registered in main.rs")
if "RunEvent::Exit" not in main_rs or "guard.kill()" not in main_rs:
    fail("the sidecar must be killed on RunEvent::Exit")
if "sidecar(SIDECAR)" not in main_rs:
    fail("main.rs does not spawn the sidecar")

handlers = re.search(r"generate_handler!\[(.*?)\]", main_rs, re.S)
if not handlers:
    fail("generate_handler! list not found")
    rust_commands: set[str] = set()
else:
    rust_commands = {item.strip().split("::")[-1] for item in handlers.group(1).split(",") if item.strip()}

main_js = read(SRC / "main.js")
js_commands = set(re.findall(r"invoke\('([a-z_]+)'", main_js))
missing_in_js = rust_commands - js_commands
missing_in_rs = {cmd for cmd in js_commands if cmd not in rust_commands}
if missing_in_js:
    fail(f"commands exposed but never called from main.js: {sorted(missing_in_js)}")
if missing_in_rs:
    fail(f"main.js calls commands that do not exist: {sorted(missing_in_rs)}")
if not rust_commands:
    fail("no commands exposed by the shell")
ok(f"commands: {', '.join(sorted(rust_commands))}")

# ── 5. frontend ───────────────────────────────────────────────
index = read(SRC / "index.html")
for asset in ("styles.css", "core.js", "main.js"):
    if not (SRC / asset).exists():
        fail(f"missing frontend asset: {asset}")
    if asset not in index:
        fail(f"index.html does not reference {asset}")

if 'dir="rtl"' not in index or 'lang="fa"' not in index:
    fail("index.html must be Persian and RTL")
for leftover in ("core-config.js", "styles.css.bak"):
    if (SRC / leftover).exists():
        fail(f"stale asset left behind: {leftover}")
for removed in ("index.html", "main.js", "styles.css"):
    if (APP / removed).exists():
        fail(f"{removed} must live in desktop-app/src/, not the package root")

styles = read(SRC / "styles.css")
for token in ("#0f172a", "#1e293b", "#06b6d4", "#10b981"):
    if token not in styles.lower():
        fail(f"design token {token} missing from styles.css")
for family in ("Vazirmatn", "Inter"):
    if family not in styles:
        fail(f"{family} is not part of the font stack")

if "connect" not in index or "btn-connect" not in index:
    fail("the connect button is missing")
if "data-mode=\"tun\"" not in index or "data-mode=\"proxy\"" not in index:
    fail("the TUN/Proxy segmented control is missing")
if "btn-fetch" not in index or "btn-copy" not in index:
    fail("the subscription field must have Fetch + Copy")
if "btn-advanced" not in index:
    fail("advanced settings must be behind an accordion")

# ── 6. generated YAML ─────────────────────────────────────────
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    fail("PyYAML is required: run this with the venv that has pyyaml")
    yaml = None

out_dir = APP / "tools" / "out"
configs = sorted(out_dir.glob("config-*.yaml")) if out_dir.exists() else []
if not configs:
    fail("no generated configs found: run `node desktop-app/tools/test_core.cjs` first")

if yaml is not None:
    for config_path in configs:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        proxy = (data.get("proxies") or [{}])[0]
        if proxy.get("type") != "vless":
            fail(f"{config_path.name}: first proxy must be vless")
        if proxy.get("network") != "ws" or proxy.get("tls") is not True:
            fail(f"{config_path.name}: proxy must be vless over ws with tls")
        if not re.fullmatch(r"[0-9a-f-]{36}", str(proxy.get("uuid"))):
            fail(f"{config_path.name}: invalid uuid")
        if (proxy.get("ws-opts") or {}).get("path") != "/vless":
            fail(f"{config_path.name}: ws path must be /vless")
        if data.get("mixed-port") not in (7890, 7891):
            fail(f"{config_path.name}: unexpected mixed-port")
        if "tun" in config_path.name:
            if (data.get("tun") or {}).get("enable") is not True:
                fail(f"{config_path.name}: tun mode must enable tun")
        else:
            if (data.get("tun") or {}).get("enable") is not False:
                fail(f"{config_path.name}: proxy mode must disable tun")
    ok(f"parsed {len(configs)} generated configs")

# ── 7. worker lockstep + topology ─────────────────────────────
# از v5.4.1 سرور VLESS در JS است (src/entry.mjs + src/vless.js) و راست
# فقط /health، /sub و /stream را سرو می‌کند. دلیلش در vless.js مستند شده:
# هر build از wasm که کد WebSocket داشت روی Mainnet با 1101 می‌مرد.
worker_cargo = read(WORKER / "Cargo.toml")
worker_toml = read(WORKER / "wrangler.toml")
worker_rs = read(WORKER / "src" / "lib.rs")
worker_entry = read(WORKER / "src" / "entry.mjs")
worker_vless = read(WORKER / "src" / "vless.js")

if f'version      = "{VERSION}"' not in worker_cargo and f'version = "{VERSION}"' not in worker_cargo:
    fail(f"streaming-worker/Cargo.toml must be {VERSION}")
if f'WORKER_VERSION   = "{VERSION}"' not in worker_toml and f'WORKER_VERSION = "{VERSION}"' not in worker_toml:
    fail(f"wrangler WORKER_VERSION must be {VERSION}")
if 'main             = "build/worker/shim.mjs"' not in worker_toml and 'main = "build/worker/shim.mjs"' not in worker_toml:
    fail("wrangler main must be build/worker/shim.mjs (the proven entry)")
worker_vless_entry = read(WORKER / "src" / "vless-entry.mjs")
worker_vless_toml = read(WORKER / "wrangler.vless.toml")
if "createVlessHandler" not in worker_vless_entry:
    fail("vless-entry.mjs does not route /vless to the VLESS core")
if "cloudflare:sockets" not in worker_vless_entry:
    fail("vless-entry.mjs does not import connect() from cloudflare:sockets")
if re.search(r"shim\.mjs|build/worker|\.wasm", worker_vless_entry):
    fail("the VLESS worker imports wasm — that is what caused 1101 on Mainnet")
if '"ghost-vless-worker"' not in worker_vless_toml:
    fail("wrangler.vless.toml must deploy the standalone VLESS worker")
if "status: 101" not in worker_vless:
    fail("vless.js does not upgrade /vless to a WebSocket")
if "WebSocketPair" in worker_rs or "from_websocket" in worker_rs:
    fail("wasm still contains WebSocket code (this is what caused 1101 on Mainnet)")
ok("worker + desktop versions are in lockstep")

# ── 8. پیلهٔ فانی: قطع اتصال نباید هسته را بکشد ───────────────
core_js = read(APP / "src" / "core.js")
main_js = read(APP / "src" / "main.js")
main_rs = read(APP / "src-tauri" / "src" / "main.rs")

if "buildDetachedConfig" not in core_js:
    fail("core.js has no detached (session-less) config — the TUN adapter would die")
if "external-controller" not in core_js:
    fail("generated configs lack external-controller (hot reload is impossible)")
if "hot_reload" not in main_rs:
    fail("main.rs does not hot-reload the core (reconnect would restart the process)")
if "scrub_write" not in main_rs:
    fail("main.rs does not scrub the session file on disconnect")
if "shutdown_core" not in main_rs:
    fail("main.rs has no shutdown path that destroys the adapter on exit")
if "log_line" not in main_rs or "log_line" not in main_js:
    fail("UI errors are not forwarded into the live log panel")
if "buildDetachedConfig" not in main_js and "buildDetachedConfig" not in core_js:
    fail("the UI cannot produce a detached config")
ok("ephemeral cocoon wired: adapter kept, session wiped, memory cleared on exit")

# ── report ────────────────────────────────────────────────────
for line in notes:
    print(f"  · {line}")

if problems:
    print()
    for line in problems:
        print(f"  ✗ {line}")
    print(f"\n{len(problems)} problem(s) found")
    sys.exit(1)

print(f"\n✓ desktop shell {VERSION} passed every packaging check")
