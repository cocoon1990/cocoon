#!/usr/bin/env python3
"""اعتبارسنجی خودکار بستهٔ دسکتاپ پیش از ساخت.

چیزهایی که بدون ویندوز قابل سنجش‌اند:

  * ساختار `tauri.conf.json` و وجود sidecar در `externalBin`
  * آیکون‌ها (PNG + ICO با ۶ سایز)
  * مانیفست ویندوز (Common-Controls + requireAdministrator)
  * نبود کد پراکسی/TUN دست‌ساز در `main.rs`  ← تأیید «حذف کد سفارشی»
  * هم‌خوانی نام دستورهای `invoke(...)` در JS با `generate_handler!`
  * اعتبار YAML کانفیگ‌های تولیدشده در `tools/out/`

اجرا:  python3 desktop-app/tools/verify_config.py [--require-sidecar]
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_TAURI = ROOT / "src-tauri"
CONF_PATH = SRC_TAURI / "tauri.conf.json"
CARGO_PATH = SRC_TAURI / "Cargo.toml"
MAIN_RS = SRC_TAURI / "src" / "main.rs"
BUILD_RS = SRC_TAURI / "build.rs"
MANIFEST = SRC_TAURI / "app.manifest"
CAPS = SRC_TAURI / "capabilities" / "default.json"
UI = ROOT / "src"
TOOLS_OUT = ROOT / "tools" / "out"

REQUIRE_SIDECAR = "--require-sidecar" in sys.argv

errors: list[str] = []
notes: list[str] = []


def ok(message: str) -> None:
    print(f"  OK   {message}")


def fail(message: str) -> None:
    errors.append(message)
    print(f"  FAIL {message}")


def check(condition: bool, message: str) -> bool:
    if condition:
        ok(message)
    else:
        fail(message)
    return condition


def png_size(data: bytes) -> tuple[int, int]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    return struct.unpack(">II", data[16:24])


def main() -> int:
    print("== tauri.conf.json ==")
    if not CONF_PATH.exists():
        fail(f"missing {CONF_PATH}")
        return 1

    try:
        conf = json.loads(CONF_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")
        return 1

    ok("valid JSON")

    product = conf.get("productName", "")
    version = str(conf.get("version", ""))
    identifier = conf.get("identifier", "")

    check(bool(product), f"productName = {product!r}")
    check(bool(re.fullmatch(r"\d+\.\d+\.\d+", version)), f"version is MSI-safe ({version!r})")
    check(
        bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9-]*)+", identifier))
        and not identifier.endswith(".app"),
        f"identifier = {identifier!r}",
    )

    # ── sidecar ─────────────────────────────────────────────────
    print("== sidecar (externalBin) ==")
    external = conf.get("bundle", {}).get("externalBin", [])
    check(external == ["binaries/meow"], f"externalBin = {external}")

    sidecar_stem = "binaries/meow"
    triple = "x86_64-pc-windows-msvc"
    sidecar_path = SRC_TAURI / f"{sidecar_stem}-{triple}.exe"
    if sidecar_path.is_file():
        size_mb = sidecar_path.stat().st_size / (1024 * 1024)
        check(size_mb > 1, f"sidecar present ({size_mb:.1f} MB) — {sidecar_path.name}")
    elif REQUIRE_SIDECAR:
        fail(f"sidecar missing at {sidecar_path.name} (download step must run first)")
    else:
        notes.append(f"sidecar not downloaded yet ({sidecar_path.name}); build needs it")

    # ── فرانت‌اند ───────────────────────────────────────────────
    frontend = conf.get("build", {}).get("frontendDist")
    check(bool(frontend), f"build.frontendDist = {frontend!r}")
    if frontend:
        frontend_dir = (SRC_TAURI / frontend).resolve()
        check(frontend_dir.is_dir(), f"frontendDist exists ({frontend_dir.name}/)")
        check((frontend_dir / "index.html").is_file(), "frontendDist contains index.html")

    app = conf.get("app", {})
    windows = app.get("windows", [])
    labels = [w.get("label", "main") for w in windows]
    check("main" in labels, f"window labels = {labels}")
    check(app.get("withGlobalTauri") is True, "withGlobalTauri enabled (no bundler)")

    # ── مانیفست ویندوز ──────────────────────────────────────────
    print("== windows manifest ==")
    if check(MANIFEST.is_file(), "app.manifest exists"):
        manifest = MANIFEST.read_text(encoding="utf-8")
        check(
            'level="requireAdministrator"' in manifest,
            "requests administrator (TUN needs it)",
        )
        check(
            "Microsoft.Windows.Common-Controls" in manifest,
            "keeps Common-Controls v6 dependency",
        )
    if check(BUILD_RS.is_file(), "build.rs exists"):
        build = BUILD_RS.read_text(encoding="utf-8")
        check("try_build" in build, "build.rs uses tauri_build::try_build")
        check("app_manifest" in build, "build.rs installs the custom manifest")

    # ── قابلیت‌ها ───────────────────────────────────────────────
    print("== capabilities/default.json ==")
    if check(CAPS.is_file(), "capability file exists"):
        try:
            cap = json.loads(CAPS.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"capability JSON invalid: {exc}")
            cap = {}
        perms = cap.get("permissions", [])
        check("core:default" in perms, f"permissions = {perms}")
        unknown = [w for w in cap.get("windows", []) if w not in labels]
        check(not unknown, f"capability windows {cap.get('windows')} ⊆ {labels}")

    # ── آیکون‌ها ────────────────────────────────────────────────
    print("== icons ==")
    icons = conf.get("bundle", {}).get("icon", [])
    check(len(icons) >= 3, f"bundle.icon has {len(icons)} entries")

    for rel in icons:
        path = SRC_TAURI / rel
        if not path.is_file():
            fail(f"missing icon {rel}")
            continue
        data = path.read_bytes()
        if path.suffix == ".png":
            width, height = png_size(data)
            ok(f"{rel} → {width}x{height}")
        elif path.suffix == ".ico":
            reserved, kind, count = struct.unpack("<HHH", data[:6])
            if reserved != 0 or kind != 1:
                fail(f"{rel}: bad ICONDIR header")
                continue
            sizes = []
            bad = False
            for index in range(count):
                entry = data[6 + 16 * index : 6 + 16 * (index + 1)]
                width, _, _, _, _, bpp, size, offset = struct.unpack("<BBBBHHII", entry)
                if offset + size > len(data) or bpp != 32:
                    fail(f"{rel}: entry {index} corrupt")
                    bad = True
                    break
                sizes.append(width or 256)
            if not bad:
                ok(f"{rel} → {count} sizes {sizes}")

    # ── Cargo ───────────────────────────────────────────────────
    print("== Cargo.toml ==")
    cargo = CARGO_PATH.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    check(match is not None, "package.version present")
    if match:
        check(match.group(1) == version, f"Cargo {match.group(1)!r} == tauri.conf {version!r}")
    check('tauri-build' in cargo, "tauri-build in [build-dependencies]")
    check('tauri-plugin-shell' in cargo, "tauri-plugin-shell dependency present")
    for banned in ("x25519-dalek", "aes-gcm", "hkdf", "hmac", "tun ="):
        check(banned not in cargo, f"no crypto/TUN crate ({banned})")

    # ── کد سفارشی حذف شده؟ ─────────────────────────────────────
    print("== no hand-written proxy code ==")
    if check(MAIN_RS.is_file(), "src/main.rs exists"):
        rust = MAIN_RS.read_text(encoding="utf-8")
        for banned, why in (
            ("TcpListener", "custom TCP proxy"),
            ("TcpStream", "raw socket handling"),
            ("X25519", "custom handshake"),
            ("aes_gcm", "custom crypto"),
            ("Hmac", "custom signing"),
            ("create_tun", "custom TUN device"),
        ):
            check(banned not in rust, f"main.rs has no {banned} — {why}")
        check(
            "sidecar(SIDECAR_NAME)" in rust or 'sidecar("meow")' in rust,
            "main.rs launches the sidecar",
        )
        check(
            rust.count("child.kill()") >= 1 and "kill_on_drop" not in rust,
            "child process is killed explicitly (no orphan on exit)",
        )

    # ── هم‌خوانی دستورها ────────────────────────────────────────
    print("== commands ==")
    if MAIN_RS.is_file():
        rust = MAIN_RS.read_text(encoding="utf-8")
        handler = re.search(r"generate_handler!\s*\[(.*?)\]", rust, re.DOTALL)
        if check(handler is not None, "generate_handler! block found"):
            registered = {n.strip() for n in handler.group(1).split(",") if n.strip()}
            ok(f"registered: {sorted(registered)}")

            used: set[str] = set()
            for js in sorted(UI.glob("*.js")):
                used |= set(re.findall(r"invoke\(\s*['\"]([a-z_]+)['\"]", js.read_text(encoding="utf-8")))
            ok(f"invoked from JS: {sorted(used)}")
            check(not (used - registered), f"every invoked command is registered (missing: {sorted(used - registered)})")
            missing_binding = sorted(registered - used)
            if missing_binding:
                notes.append(f"registered but never invoked: {missing_binding}")

    # ── فرانت‌اند ───────────────────────────────────────────────
    print("== frontend assets ==")
    index = UI / "index.html"
    if check(index.is_file(), "src/index.html exists"):
        html = index.read_text(encoding="utf-8")
        for asset in ("styles.css", "core-config.js", "main.js"):
            check((UI / asset).is_file(), f"src/{asset} exists")
            check(asset in html, f"index.html references {asset}")
        check(
            html.index("core-config.js") < html.index('"main.js"')
            if "core-config.js" in html and '"main.js"' in html
            else False,
            "core-config.js loads before main.js",
        )

    # ── YAML تولیدشده ──────────────────────────────────────────
    print("== generated core configs ==")
    yaml_files = sorted(TOOLS_OUT.glob("*.yaml")) if TOOLS_OUT.is_dir() else []
    if not yaml_files:
        notes.append("tools/out/ خالی است — ابتدا node tools/test_core_config.cjs را اجرا کنید")
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            notes.append("PyYAML نصب نیست — اعتبار YAML بررسی نشد (pip install pyyaml)")
        else:
            for path in yaml_files:
                try:
                    data = yaml.safe_load(path.read_text(encoding="utf-8"))
                except Exception as exc:  # noqa: BLE001
                    fail(f"{path.name}: invalid YAML ({exc})")
                    continue
                proxy = (data.get("proxies") or [{}])[0]
                checks = [
                    proxy.get("type") == "vless",
                    isinstance(data.get("tun"), dict),
                    data.get("rules") == ["MATCH,PROXY"],
                    data.get("proxy-groups", [{}])[0].get("name") == "PROXY",
                ]
                if all(checks):
                    ok(f"{path.name} (network={proxy.get('network')}, tls={proxy.get('tls')})")
                else:
                    fail(f"{path.name}: unexpected structure ({checks})")

    print("\n== summary ==")
    for note in notes:
        print(f"  NOTE {note}")

    if errors:
        print(f"\n{len(errors)} problem(s) found:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
