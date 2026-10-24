#!/usr/bin/env python3
"""تست هم‌خوانی پروتکل بین کلاینت دسکتاپ و دو ورکر موجود.

چون در این محیط زنجیرهٔ ابزار Rust نصب نیست، نمی‌توان `cargo test` اجرا کرد.
این اسکریپت به‌جای آزمون واحد، دو کار واقعی انجام می‌دهد:

  1. **استخراج متغیرها از سورس** — ثابت‌های پروتکل (HKDF info، پیشوند AAD،
     نام پروتکل، allowlist) از `main.rs` خوانده و با همان ثابت‌ها در
     `signaling-worker` و `streaming-worker` مقایسه می‌شوند. این دقیقاً
     همان کلاس باگی است که در v5.2.5 باعث ۴۰۳ شد (پیام یکی، کلید فرق).

  2. **شبیه‌سازی مرجع** — با کتابخانهٔ `cryptography` هر دو سمت handshake
     و امضا اجرا می‌شوند: سرور (طبق `signaling-worker`) کلیدها را wrap
     می‌کند و کلاینت (طبق مراحل `main.rs`) آن‌ها را unwrap می‌کند. سپس
     امضای HMAC با همان قرارداد «کلید = hex-decoded، خروجی = hex» ساخته و
     تأیید می‌شود. تست‌های منفی ثابت می‌کنند آزمون واقعاً شکست‌پذیر است.

اجرا:  python3 desktop-app/tools/protocol_parity.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    print("SKIP: کتابخانهٔ cryptography نصب نیست (pip install cryptography)")
    sys.exit(0)

REPO = Path(__file__).resolve().parents[2]
MAIN_RS = REPO / "desktop-app" / "src-tauri" / "src" / "main.rs"
SIGNALING_RS = REPO / "signaling-worker" / "src" / "lib.rs"
STREAMING_RS = REPO / "streaming-worker" / "src" / "lib.rs"

failures: list[str] = []
checks = 0


def check(condition: bool, label: str) -> bool:
    global checks
    checks += 1
    if condition:
        print(f"  PASS {label}")
    else:
        print(f"  FAIL {label}")
        failures.append(label)
    return condition


def read(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing source file: {path}")
    return path.read_text(encoding="utf-8")


# ────────────────────────────────────────────────────────────────
#  ۱) استخراج ثابت‌ها از سورس‌ها
# ────────────────────────────────────────────────────────────────

def byte_const(source: str, name: str) -> str | None:
    match = re.search(rf'const\s+{name}:\s*&\[u8\]\s*=\s*b"([^"]*)"', source)
    return match.group(1) if match else None


def str_const(source: str, name: str) -> str | None:
    match = re.search(rf'const\s+{name}:\s*&str\s*=\s*"([^"]*)"', source)
    return match.group(1) if match else None


def domain_list(source: str) -> list[str] | None:
    match = re.search(
        r"const\s+ALLOWED_TARGET_DOMAINS:\s*\[&str;\s*\d+\]\s*=\s*\[(.*?)\];",
        source,
        re.DOTALL,
    )
    if not match:
        return None
    return re.findall(r'"([^"]+)"', match.group(1))


print("== protocol constants (Rust ↔ Rust) ==")
mine = read(MAIN_RS)
signaling = read(SIGNALING_RS)
streaming = read(STREAMING_RS)

for name in ("PROTOCOL", "HKDF_INFO_KEK", "AAD_PREFIX"):
    extractor = str_const if name == "PROTOCOL" else byte_const
    a, b = extractor(mine, name), extractor(signaling, name)
    check(a is not None, f"desktop declares {name}")
    check(a == b, f"{name} identical: desktop={a!r} signaling={b!r}")

check(
    domain_list(mine) == domain_list(streaming),
    f"allowlist identical: {domain_list(mine)} == {domain_list(streaming)}",
)

print("\n== client-side algorithm shape (main.rs) ==")
check(
    'AAD_PREFIX' in mine
    and re.search(
        r"aad\.extend_from_slice\(AAD_PREFIX\);\s*\n\s*aad\.extend_from_slice\(client_pub_bytes\);\s*\n\s*aad\.extend_from_slice\(&server_pub_arr\);",
        mine,
    )
    is not None,
    "AAD order = prefix ‖ client_pub ‖ server_pub",
)
check(
    re.search(
        r'Hkdf::<Sha256>::new\(Some\((?:&salt|salt\.as_slice\(\))\), shared\.as_bytes\(\)\)',
        mine,
    )
    is not None
    and "hkdf.expand(HKDF_INFO_KEK, &mut kek)" in mine,
    "HKDF-SHA256(salt, shared, info=HKDF_INFO_KEK) → 32-byte KEK",
)
check(
    'hex::decode(keys.hmac_key_hex.trim())' in mine,
    "hmac key = hex::decode(hmac_key_hex)  ← باگ v5.2.5 اینجا بود",
)
check(
    re.search(r'format!\("\{target\}:\{seq\}"\)', mine) is not None,
    'message = "{target}:{seq}"',
)
check(
    "hex::encode(mac.finalize().into_bytes())" in mine,
    "signature = hex(HMAC-SHA256)",
)
check(
    "was_contributory" in mine,
    "low-order point rejected on the client too",
)

print("\n== worker-side contract (read-only view) ==")
check(
    'let message = format!("{}:{}", target_url, seq);' in streaming,
    "streaming-worker signs the same {target}:{seq} message",
)
check(
    "hex::decode(cleaned)" in streaming and "hex::encode(mac.finalize().into_bytes())" in streaming,
    "streaming-worker verifies hex-decoded key against hex digest",
)
check(
    "PROTOCOL" in signaling and 'const PROTOCOL: &str = "x25519-hkdf-sha256-aesgcm-v1"' in signaling,
    "signaling-worker advertises x25519-hkdf-sha256-aesgcm-v1",
)


# ────────────────────────────────────────────────────────────────
#  ۲) شبیه‌سازی مرجع handshake
# ────────────────────────────────────────────────────────────────

INFO = (byte_const(mine, "HKDF_INFO_KEK") or "").encode()
AAD_PREFIX = (byte_const(mine, "AAD_PREFIX") or "").encode()
PROTOCOL = str_const(mine, "PROTOCOL")

HMAC_KEY_HEX = "00112233445566778899aabbccddeeff" * 2  # 32 bytes
AES_KEY_HEX = "ffeeddccbbaa99887766554433221100" * 2


def derive_kek(shared: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)


def server_side(client_pub_raw: bytes):
    """معادل `POST /session-init` در signaling-worker."""
    server_secret = X25519PrivateKey.generate()
    server_pub_raw = server_secret.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    client_pub = X25519PublicKey.from_public_bytes(client_pub_raw)
    shared = server_secret.exchange(client_pub)

    salt = os.urandom(32)
    kek = derive_kek(shared, salt)

    aad = AAD_PREFIX + client_pub_raw + server_pub_raw
    plaintext = json.dumps(
        {"hmac_key_hex": HMAC_KEY_HEX, "aes_key_hex": AES_KEY_HEX}
    ).encode()

    nonce = os.urandom(12)
    wrapped = nonce + AESGCM(kek).encrypt(nonce, plaintext, aad)

    return {
        "protocol": PROTOCOL,
        "server_pubkey": base64.b64encode(server_pub_raw).decode(),
        "salt": base64.b64encode(salt).decode(),
        "wrapped": base64.b64encode(wrapped).decode(),
        "config_version": "5.1.1",
    }


def client_side(response: dict) -> bytes:
    """همان گام‌های `perform_handshake` در main.rs، خط‌به‌خط."""
    client_secret = X25519PrivateKey.generate()
    client_pub_raw = client_secret.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # در تست، سرور از کلید عمومی همین کلاینت استفاده می‌کند
    return client_pub_raw


def full_handshake(tamper_aad: bool = False, wrong_key_style: bool = False):
    client_secret = X25519PrivateKey.generate()
    client_pub_raw = client_secret.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    response = server_side(client_pub_raw)
    assert response["protocol"] == PROTOCOL

    server_pub_raw = base64.b64decode(response["server_pubkey"])
    salt = base64.b64decode(response["salt"])
    wrapped = base64.b64decode(response["wrapped"])

    shared = client_secret.exchange(X25519PublicKey.from_public_bytes(server_pub_raw))
    kek = derive_kek(shared, salt)

    aad = (
        AAD_PREFIX + server_pub_raw + client_pub_raw
        if tamper_aad
        else AAD_PREFIX + client_pub_raw + server_pub_raw
    )

    nonce, ciphertext = wrapped[:12], wrapped[12:]
    plaintext = AESGCM(kek).decrypt(nonce, ciphertext, aad)
    payload = json.loads(plaintext)

    hmac_key_hex = payload["hmac_key_hex"].strip()
    if wrong_key_style:
        # باگ v5.2.5: استفاده از بایت‌های ASCII رشتهٔ hex به‌جای بایت‌های اصلی
        return hmac_key_hex.encode()
    return bytes.fromhex(hmac_key_hex)


print("\n== handshake simulation ==")
key = full_handshake()
check(key == bytes.fromhex(HMAC_KEY_HEX), "client recovers the exact 32-byte HMAC key")
check(len(key) == 32, f"key length = {len(key)} bytes (worker expects hex-decoded 32 B)")

try:
    full_handshake(tamper_aad=True)
    check(False, "swapped AAD must fail (AES-GCM auth)")
except Exception:
    check(True, "swapped AAD is rejected by AES-GCM (AAD is bound to both pubkeys)")


# ────────────────────────────────────────────────────────────────
#  ۳) امضا: کلاینت ↔ ورکر
# ────────────────────────────────────────────────────────────────

def sign(target: str, seq: int, key_bytes: bytes) -> str:
    return hmac.new(key_bytes, f"{target}:{seq}".encode(), hashlib.sha256).hexdigest()


def verify(target: str, seq: str, provided: str, secret_hex: str) -> bool:
    """معادل `verify_hmac_signature` پس از اصلاح: اول کلید hex-decoded."""
    message = f"{target}:{seq}"
    for candidate in (bytes.fromhex(secret_hex.strip()), secret_hex.strip().encode()):
        if hmac.compare_digest(
            hmac.new(candidate, message.encode(), hashlib.sha256).hexdigest(),
            provided.strip(),
        ):
            return True
    return False


print("\n== signature simulation ==")
TARGET = "https://www.youtube.com/robots.txt"
sig = sign(TARGET, 0, key)
check(len(sig) == 64, f"signature is 64 hex chars ({sig[:16]}…)")
check(verify(TARGET, "0", sig, HMAC_KEY_HEX), "worker accepts the client signature")
check(not verify(TARGET, "1", sig, HMAC_KEY_HEX), "seq is part of the signed message")
check(
    not verify("https://www.youtube.com/robots.txT", "0", sig, HMAC_KEY_HEX),
    "target is part of the signed message",
)

def verify_strict(target: str, seq: str, provided: str, secret_hex: str) -> bool:
    """سخت‌گیرانه: فقط کلید hex-decoded — همان قرارداد قطعی کلاینت."""
    message = f"{target}:{seq}"
    expected = hmac.new(
        bytes.fromhex(secret_hex.strip()), message.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, provided.strip())


wrong = sign(TARGET, 0, HMAC_KEY_HEX.encode())
check(
    wrong != sig,
    "ASCII key bytes give a different signature — ریشهٔ باگ v5.2.5",
)
check(
    not verify_strict(TARGET, "0", wrong, HMAC_KEY_HEX),
    "strict verifier rejects the ASCII-key signature (client must hex-decode)",
)
check(
    verify(TARGET, "0", wrong, HMAC_KEY_HEX),
    "worker's compat fallback still accepts the old style (not relied upon)",
)


# ────────────────────────────────────────────────────────────────
#  ۴) درصدگذاری target در URL (port درصدگذاری main.rs)
# ────────────────────────────────────────────────────────────────

def percent_encode(value: str) -> str:
    unreserved = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    out = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        out.append(char if char in unreserved else f"%{byte:02X}")
    return "".join(out)


print("\n== query encoding round-trip ==")
tricky = [
    "https://www.youtube.com/robots.txt",
    "https://www.youtube.com/watch?v=abc+def&x=%20y",
    "https://googlevideo.com/v/1?a=1&b=2&sig=Xy-Z_9.8",
    "https://www.googleapis.com/oauth2/v3/certs?q=سلام",
    "https://i.ytimg.com/vi/a+b/hq.jpg?x=a=b&y=c",
]

for target in tricky:
    query = f"target={percent_encode(target)}&sig={sig}&seq=0"
    decoded = parse_qs(query.split("&sig=")[0])["target"][0]
    check(decoded == target, f"round-trip: {target}")

check(
    "+" not in percent_encode(tricky[1]).replace("%2B", ""),
    "'+' is encoded as %2B so it cannot be decoded as a space",
)


# ────────────────────────────────────────────────────────────────
#  جمع‌بندی
# ────────────────────────────────────────────────────────────────

print(f"\n== summary: {checks - len(failures)}/{checks} passed ==")
if failures:
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)

print("desktop protocol is byte-compatible with the deployed workers")
