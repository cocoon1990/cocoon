"""Mirror test of the Rust pure functions added to streaming-worker/src/lib.rs.

These are line-for-line ports used to validate the *algorithm* (boundary
behaviour), because the sandbox has no Rust toolchain. Rust syntax is
validated separately by ci-workers.yml (`cargo check`).
"""
import base64

ALLOWED = ["googlevideo.com", "youtube.com", "ytimg.com", "ggpht.com", "googleapis.com"]


def host_matches_domain(host: str, domain: str) -> bool:
    if host == domain:
        return True
    if host.endswith(domain):
        return host[: -len(domain)].endswith(".")
    return False


def is_allowed_target(raw_url: str) -> bool:
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c == " " for c in raw_url):
        return False
    lower = raw_url.lower()  # ascii lowercase in Rust; inputs here are ascii
    if not lower.startswith("https://"):
        return False
    rest = lower[len("https://"):]
    if not rest:
        return False
    end = len(rest)
    for i, c in enumerate(rest):
        if c in "/?#":
            end = i
            break
    authority = rest[:end]
    if not authority or "@" in authority:
        return False
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        if port != "443":
            return False
    else:
        host = authority
    host = host.rstrip(".").lower()
    if not host or len(host) > 253 or ".." in host:
        return False
    if not all(c.isalnum() or c in "-." for c in host):
        return False
    return any(host_matches_domain(host, d) for d in ALLOWED)


def is_valid_uuid(v: str) -> bool:
    if len(v) != 36:
        return False
    for i, c in enumerate(v):
        if i in (8, 13, 18, 23):
            if c != "-":
                return False
        elif c not in "0123456789abcdefABCDEF":
            return False
    return True


def is_valid_hostname(h: str) -> bool:
    if not h or len(h) > 253 or ".." in h:
        return False
    if h.startswith(".") or h.endswith("."):
        return False
    if not all(c.isalnum() or c in "-." for c in h):
        return False
    if "." not in h or not any(c.isalpha() for c in h):
        return False
    return all(lbl and not lbl.startswith("-") and not lbl.endswith("-") for lbl in h.split("."))


def is_valid_sub_path(p: str) -> bool:
    if not p.startswith("/") or len(p) > 256:
        return False
    return all(0x21 <= ord(c) <= 0x7E and c not in '?#"\'\\' for c in p)


def percent_encode(s: str) -> str:
    out = []
    for b in s.encode("utf-8"):
        ch = chr(b)
        if ch.isalnum() and b < 0x80 or ch in "-._~/":
            out.append(ch)
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def build_vless_uri(uuid, host, sni, path, remark):
    return (
        f"vless://{uuid}@{host}:443?encryption=none&security=tls&sni={sni}"
        f"&fp=chrome&type=ws&host={host}&path={percent_encode(path)}#{percent_encode(remark)}"
    )


cases = [
    # (url, expected)
    ("https://rr3---sn-4g5e6nz7.googlevideo.com/videoplayback?x=1", True),
    ("https://www.youtube.com/watch?v=1", True),
    ("https://youtube.com/", True),
    ("https://i.ytimg.com/vi/x.jpg", True),
    ("https://yt3.ggpht.com/a", True),
    ("https://www.googleapis.com/youtube/v3", True),
    ("https://www.youtube.com:443/", True),
    ("https://WWW.YOUTUBE.COM/", True),
    ("https://www.youtube.com./", True),
    ("https://example.com/?x=googlevideo.com", False),
    ("https://googlevideo.com.attacker.example/", False),
    ("https://evilyoutube.com/", False),
    ("https://attacker.example/googlevideo.com", False),
    ("https://attacker.example#googlevideo.com", False),
    ("https://attacker.example?googlevideo.com", False),
    ("http://www.youtube.com/", False),
    ("https://user@www.youtube.com/", False),
    ("https://www.youtube.com@attacker.example/", False),
    ("https://www.youtube.com:444/", False),
    ("https://[::1]:443/", False),
    (" https://www.youtube.com/", False),
    ("https://www.youtube.com\n/", False),
    ("//www.youtube.com/", False),
    ("https://youtube.com.evil/", False),
    ("https://notyoutube.com/", False),
    ("https://youtube.co/", False),
]

fails = 0
for url, exp in cases:
    got = is_allowed_target(url)
    ok = got == exp
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  allow({url!r}) = {got} (want {exp})")

print()
uuid_cases = [
    ("550e8400-e29b-41d4-a716-446655440000", True),
    ("550E8400-E29B-41D4-A716-446655440000", True),
    ("550e8400e29b41d4a716446655440000", False),
    ("550e8400-e29b-41d4-a716-44665544000", False),
    ("not-a-uuid", False),
    ("", False),
    ("550e8400-e29b-41d4-a716-44665544000z", False),
]
for v, exp in uuid_cases:
    got = is_valid_uuid(v)
    ok = got == exp
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  uuid({v!r}) = {got} (want {exp})")

print()
host_cases = [
    ("ghost.example.com", True),
    ("sub.domain.co.uk", True),
    ("x.y", True),
    ("localhost", False),
    ("https://x.com", False),
    ("x", False),
    ("-bad.com", False),
    ("bad-.com", False),
    ("a..b", False),
    ("1.2.3.4", False),
    ("exa mple.com", False),
    ("", False),
]
for h, exp in host_cases:
    got = is_valid_hostname(h)
    ok = got == exp
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  host({h!r}) = {got} (want {exp})")

print()
path_cases = [
    ("/vless", True),
    ("/", True),
    ("/a/b-c_d.e~f", True),
    ("vless", False),
    ("/v less", False),
    ("/vless?ed=2048", False),
    ("/vless#frag", False),
    ("/a\\b", False),
    ("", False),
]
for p, exp in path_cases:
    got = is_valid_sub_path(p)
    ok = got == exp
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  path({p!r}) = {got} (want {exp})")

print()
print("percent_encode('/vless')       =", percent_encode("/vless"))
print("percent_encode('SCP-GHOST')    =", percent_encode("SCP-GHOST"))
print("percent_encode('/a b')         =", percent_encode("/a b"))
print("percent_encode('سلام')         =", percent_encode("سلام"))

uri = build_vless_uri(
    "550e8400-e29b-41d4-a716-446655440000",
    "ghost.example.com",
    "ghost.example.com",
    "/vless",
    "SCP-GHOST",
)
print("\nURI:", uri)
enc = base64.b64encode(uri.encode()).decode()
print("B64:", enc)
dec = base64.b64decode(enc).decode()
assert dec == uri
assert dec.startswith("vless://")
assert "security=tls" in dec and ":443" in dec
print("\nbase64 round-trip: OK")

# deep-check the URI parses like v2rayN expects
from urllib.parse import urlparse, parse_qs
u = urlparse(uri)
q = parse_qs(u.query)
assert u.scheme == "vless"
assert u.username == "550e8400-e29b-41d4-a716-446655440000"
assert u.hostname == "ghost.example.com"
assert u.port == 443
assert q["security"] == ["tls"] and q["type"] == ["ws"] and q["encryption"] == ["none"]
assert q["sni"] == ["ghost.example.com"]
assert q["path"] == ["/vless"]
print("URI parse (scheme/user/port/params): OK")

print("\nFAILURES:", fails)
raise SystemExit(1 if fails else 0)
