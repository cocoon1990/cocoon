#!/usr/bin/env python3
"""اعتبارسنجی خودکار بستهٔ دسکتاپ پیش از ساخت.

این اسکریپت همان چیزی را چک می‌کند که در نبود ویندوز نمی‌توان با
`tauri build` سنجید:

  * ساختار و کلیدهای الزامی `tauri.conf.json`
  * وجود و صحت آیکون‌ها (PNG + ICO با ۶ سایز)
  * وجود فایل‌های فرانت‌اند و ارجاع‌هایشان
  * هم‌خوانی نام دستورهای `invoke(...)` در JS با `generate_handler!` در Rust
  * برابری نسخهٔ Cargo با نسخهٔ tauri.conf.json

اجرا:  python3 desktop-app/tools/verify_config.py
خروج: کد ۰ در صورت موفقیت، ۱ در صورت خطا.
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
CAPS = SRC_TAURI / "capabilities" / "default.json"
UI = ROOT / "src"

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
    width, height = struct.unpack(">II", data[16:24])
    return width, height


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
    version = conf.get("version", "")
    identifier = conf.get("identifier", "")

    check(bool(product), f"productName = {product!r}")
    check(
        bool(re.fullmatch(r"\d+\.\d+\.\d+", str(version))),
        f"version is MSI-safe ({version!r})",
    )
    check(
        bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9-]*)+", identifier))
        and not identifier.endswith(".app"),
        f"identifier = {identifier!r}",
    )

    # ── فرانت‌اند ────────────────────────────────────────────────
    frontend = conf.get("build", {}).get("frontendDist")
    check(bool(frontend), f"build.frontendDist = {frontend!r}")
    if frontend:
        frontend_dir = (SRC_TAURI / frontend).resolve()
        check(frontend_dir.is_dir(), f"frontendDist exists ({frontend_dir.name}/)")
        check(
            (frontend_dir / "index.html").is_file(),
            "frontendDist contains index.html",
        )

    app = conf.get("app", {})
    windows = app.get("windows", [])
    check(isinstance(windows, list) and len(windows) >= 1, "app.windows is non-empty")
    labels = [w.get("label", "main") for w in windows]
    check("main" in labels, f"window labels = {labels}")

    # ── قابلیت‌ها ────────────────────────────────────────────────
    print("== capabilities/default.json ==")
    if check(CAPS.is_file(), "capability file exists"):
        try:
            cap = json.loads(CAPS.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"capability JSON invalid: {exc}")
            cap = {}
        check(bool(cap.get("identifier")), f"identifier = {cap.get('identifier')!r}")
        perms = cap.get("permissions", [])
        check("core:default" in perms, f"permissions = {perms}")
        unknown = [w for w in cap.get("windows", []) if w not in labels]
        check(not unknown, f"capability windows {cap.get('windows')} ⊆ {labels}")

    # ── آیکون‌ها ─────────────────────────────────────────────────
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
            try:
                width, height = png_size(data)
                ok(f"{rel} → {width}x{height}")
            except ValueError as exc:
                fail(f"{rel}: {exc}")
        elif path.suffix == ".ico":
            try:
                reserved, kind, count = struct.unpack("<HHH", data[:6])
                if reserved != 0 or kind != 1:
                    raise ValueError("bad ICONDIR header")
                total = 6 + 16 * count
                sizes = []
                for index in range(count):
                    entry = data[6 + 16 * index : 6 + 16 * (index + 1)]
                    width, _, _, _, _, bpp, size, offset = struct.unpack(
                        "<BBBBHHII", entry
                    )
                    if offset + size > len(data):
                        raise ValueError(f"entry {index} out of bounds")
                    sizes.append(width or 256)
                    if bpp != 32:
                        raise ValueError(f"entry {index} is not 32bpp")
                ok(f"{rel} → {count} sizes {sizes}")
            except (ValueError, struct.error) as exc:
                fail(f"{rel}: {exc}")
        else:
            notes.append(f"icon {rel} has unexpected extension")

    # ── نسخه‌ها ──────────────────────────────────────────────────
    print("== Cargo.toml ==")
    cargo = CARGO_PATH.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    check(match is not None, "package.version present")
    if match:
        check(
            match.group(1) == str(version),
            f"Cargo version {match.group(1)!r} == tauri.conf {version!r}",
        )
    check('tauri-build' in cargo, "tauri-build in [build-dependencies]")
    check(
        re.search(r'^tauri\s*=\s*\{\s*version\s*=\s*"2"', cargo, re.MULTILINE) is not None,
        "tauri = 2.x",
    )

    # ── هم‌خوانی دستورها ─────────────────────────────────────────
    print("== commands ==")
    if check(MAIN_RS.is_file(), "src/main.rs exists"):
        rust = MAIN_RS.read_text(encoding="utf-8")
        handler = re.search(r"generate_handler!\s*\[(.*?)\]", rust, re.DOTALL)
        if check(handler is not None, "generate_handler! block found"):
            registered = {
                name.strip() for name in handler.group(1).split(",") if name.strip()
            }
            ok(f"registered: {sorted(registered)}")

            js_files = sorted(UI.glob("*.js"))
            used: set[str] = set()
            for js in js_files:
                used |= set(re.findall(r"invoke\(\s*['\"]([a-z_]+)['\"]", js.read_text(encoding="utf-8")))
            ok(f"invoked from JS: {sorted(used)}")
            missing = sorted(used - registered)
            check(not missing, f"every invoked command is registered (missing: {missing})")
            unused = sorted(registered - used)
            if unused:
                notes.append(f"registered but never invoked: {unused}")

    # ── فرانت‌اند ────────────────────────────────────────────────
    print("== frontend assets ==")
    index = UI / "index.html"
    if check(index.is_file(), "src/index.html exists"):
        html = index.read_text(encoding="utf-8")
        for asset in ("styles.css", "main.js"):
            check(asset in html, f"index.html references {asset}")
            check((UI / asset).is_file(), f"src/{asset} exists")
        check(
            "<script" in html and "src=\"main.js\"" in html,
            "main.js loaded as a plain script (no bundler)",
        )
        check("http://" not in html and "https://" not in html.replace(
            "https://www.youtube.com/robots.txt", ""
        ), "no external assets in index.html")

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
