from __future__ import annotations
import hashlib

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def normalize_hex(s: str) -> str:
    s = (s or "").replace("0x","").replace("0X","").replace(":","").replace(" ","")
    return "".join(ch for ch in s if ch in "0123456789abcdefABCDEF").lower()

def is_hex_even(h: str) -> bool:
    return len(h) % 2 == 0 and all(c in "0123456789abcdef" for c in h)

def hex_to_ascii_best(h: str) -> str:
    try:
        if not is_hex_even(h): return ""
        b = bytes.fromhex(h).replace(b"\x00", b"")
        return "".join(chr(x) for x in b if 32 <= x <= 126)
    except Exception:
        return ""

def ascii_label_pref(raw: str) -> str:
    nh = normalize_hex(raw)
    if nh:
        dec = hex_to_ascii_best(nh)
        return dec if dec else nh
    return "".join(ch for ch in (raw or "") if 32 <= ord(ch) <= 126)

def mac_is_laa(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0x02) != 0
    except Exception:
        return False
