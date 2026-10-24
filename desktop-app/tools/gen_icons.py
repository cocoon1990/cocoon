#!/usr/bin/env python3
"""تولید آیکون‌های برنامهٔ دسکتاپ بدون هیچ وابستگی خارجی.

خروجی‌ها (در `src-tauri/icons/`):
    32x32.png, 128x128.png, 128x128@2x.png (256), icon.png (512), icon.ico

`icon.ico` شامل رکوردهای BMP/DIB برای ۱۶…۱۲۸ و یک رکورد PNG برای ۲۵۶ است؛
این ترکیب هم توسط پارسر Rust (`ico`/`image`) و هم توسط شِل ویندوز خوانده می‌شود.

اجرا:  python3 desktop-app/tools/gen_icons.py
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

ICONS_DIR = Path(__file__).resolve().parent.parent / "src-tauri" / "icons"

BG_TOP = (0x17, 0x20, 0x2C)
BG_BOTTOM = (0x0E, 0x13, 0x1B)
BORDER = (0x1F, 0x26, 0x34)
ACCENT = (0x35, 0xD3, 0x99)

CORNER_RATIO = 0.22      # شعاع گوشه‌ها نسبت به ضلع
RING_MID = 0.225         # شعاع میانی حلقه
RING_HALF_W = 0.045      # نیم‌ضخامت حلقه
CORE_R = 0.062           # نقطهٔ مرکزی


def _rounded_rect_sdf(x: float, y: float, half: float, radius: float) -> float:
    dx = abs(x) - (half - radius)
    dy = abs(y) - (half - radius)
    outside = math.hypot(max(dx, 0.0), max(dy, 0.0))
    inside = min(max(dx, dy), 0.0)
    return outside + inside - radius


def _coverage(distance: float) -> float:
    """حداکثر ۱ پیکسل نرمی لبه."""
    return min(max(0.5 - distance, 0.0), 1.0)


def _blend(dst: list[float], src: tuple[int, int, int], alpha: float) -> None:
    if alpha <= 0.0:
        return
    for i in range(3):
        dst[i] = dst[i] * (1.0 - alpha) + src[i] * alpha
    dst[3] = max(dst[3], alpha)


def render(size: int) -> bytes:
    """RGBA خام برای یک مربع `size`."""
    half = 0.5
    radius = CORNER_RATIO
    border_width = 0.014 if size >= 48 else 0.0
    pixels = bytearray(size * size * 4)

    for py in range(size):
        y = (py + 0.5) / size - 0.5
        t = (y + 0.5)  # 0..1 از بالا به پایین
        bg = tuple(
            int(round(BG_TOP[i] * (1.0 - t) + BG_BOTTOM[i] * t)) for i in range(3)
        )

        for px in range(size):
            x = (px + 0.5) / size - 0.5
            acc = [0.0, 0.0, 0.0, 0.0]

            body = _rounded_rect_sdf(x, y, half, radius)
            body_cov = _coverage(body * size)
            if body_cov <= 0.0:
                continue

            _blend(acc, bg, body_cov)

            # حاشیهٔ نازک (فقط از ۴۸ پیکسل به بالا دیده می‌شود)
            if border_width > 0.0:
                edge = abs(body) - border_width
                edge_cov = _coverage(edge * size) * body_cov
                if edge_cov > 0.0:
                    acc[0] = acc[0] * (1 - edge_cov) + BORDER[0] * edge_cov
                    acc[1] = acc[1] * (1 - edge_cov) + BORDER[1] * edge_cov
                    acc[2] = acc[2] * (1 - edge_cov) + BORDER[2] * edge_cov

            # حلقهٔ سبز
            radial = math.hypot(x, y)
            ring = abs(radial - RING_MID) - RING_HALF_W
            ring_cov = _coverage(ring * size) * body_cov
            _blend(acc, ACCENT, ring_cov)

            # نقطهٔ مرکزی
            core_cov = _coverage((radial - CORE_R) * size) * body_cov
            _blend(acc, ACCENT, core_cov)

            offset = (py * size + px) * 4
            pixels[offset + 0] = int(round(min(max(acc[0], 0), 255)))
            pixels[offset + 1] = int(round(min(max(acc[1], 0), 255)))
            pixels[offset + 2] = int(round(min(max(acc[2], 0), 255)))
            pixels[offset + 3] = int(round(min(max(acc[3], 0), 1) * 255))

    return bytes(pixels)


def to_png(size: int, rgba: bytes) -> bytes:
    raw = bytearray()
    stride = size * 4
    for row in range(size):
        raw.append(0)  # filter: none
        raw.extend(rgba[row * stride : (row + 1) * stride])

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def to_dib(size: int, rgba: bytes) -> bytes:
    """BITMAPINFOHEADER + پیکسل‌های BGRA از پایین به بالا + AND mask."""
    header = struct.pack(
        "<IiiHHIIiiII",
        40,          # biSize
        size,        # biWidth
        size * 2,    # biHeight (XOR + AND)
        1,           # biPlanes
        32,          # biBitCount
        0,           # biCompression = BI_RGB
        0,           # biSizeImage
        0, 0,        # ppm
        0,           # biClrUsed
        0,           # biClrImportant
    )

    xor = bytearray()
    for row in range(size - 1, -1, -1):
        for col in range(size):
            offset = (row * size + col) * 4
            r, g, b, a = rgba[offset : offset + 4]
            xor.extend((b, g, r, a))

    mask_stride = ((size + 31) // 32) * 4
    mask = bytearray(mask_stride * size)  # همه صفر: تمام پیکسل‌ها مات

    return header + bytes(xor) + bytes(mask)


def to_ico(entries: list[tuple[int, bytes]]) -> bytes:
    """ورودی‌ها: [(size, payload)] — payload یا PNG یا DIB."""
    count = len(entries)
    out = bytearray(struct.pack("<HHH", 0, 1, count))
    offset = 6 + 16 * count

    for size, payload in entries:
        dim = 0 if size >= 256 else size
        out.extend(
            struct.pack(
                "<BBBBHHII",
                dim,          # width
                dim,          # height
                0,            # palette
                0,            # reserved
                1,            # color planes
                32,           # bits per pixel
                len(payload),
                offset,
            )
        )
        offset += len(payload)

    for _, payload in entries:
        out.extend(payload)

    return bytes(out)


def main() -> None:
    ICONS_DIR.mkdir(parents=True, exist_ok=True)

    rendered: dict[int, bytes] = {}
    for size in (16, 32, 48, 64, 128, 256, 512):
        rendered[size] = render(size)

    targets = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 512,
    }

    for name, size in targets.items():
        path = ICONS_DIR / name
        path.write_bytes(to_png(size, rendered[size]))
        print(f"wrote {path.relative_to(ICONS_DIR.parent.parent)} ({size}px)")

    ico_entries: list[tuple[int, bytes]] = [
        (size, to_dib(size, rendered[size])) for size in (16, 32, 48, 64, 128)
    ]
    ico_entries.append((256, to_png(256, rendered[256])))

    ico_path = ICONS_DIR / "icon.ico"
    ico_path.write_bytes(to_ico(ico_entries))
    print(f"wrote {ico_path.relative_to(ICONS_DIR.parent.parent)} (6 sizes)")


if __name__ == "__main__":
    main()
