from __future__ import annotations
import hashlib
import re

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
    """Return a readable label for an SSID.
    - If hex-only and decodes to nothing or all zeros, treat as hidden.
    - Otherwise prefer decoded ASCII; else return the hex.
    - Finally, fall back to filtered raw printable characters.
    """
    val = (raw or "").strip()
    # Treat common tshark placeholders as hidden
    if val.upper() in {"<MISSING>", "<NONE>", "<NULL>", "<EMPTY>"}:
        return "<Hidden>"
    nh = normalize_hex(raw)
    if nh:
        # All zeros or decodes to empty -> hidden network
        if set(nh) == {"0"}:
            return "<Hidden>"
        dec = hex_to_ascii_best(nh)
        if dec:
            return dec
        # If undecodable and looks like zero-ish, mark hidden
        if not dec:
            return "<Hidden>" if set(nh) <= {"0"} else nh
    label = "".join(ch for ch in (raw or "") if 32 <= ord(ch) <= 126)
    return label or "<Hidden>"

def iso_utc_seconds(epoch: float | None) -> str | None:
    """Format epoch seconds to ISO8601 Z (second precision)."""
    if epoch is None:
        return None
    try:
        from datetime import datetime, timezone
        return (
            datetime.fromtimestamp(float(epoch), tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except Exception:
        return None

def mac_is_laa(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0x02) != 0
    except Exception:
        return False

def normalize_eap_identity(value: str | None) -> str:
    """Normalize EAP identity strings from tshark.
    - Collapse multiple backslashes to a single (e.g., CONTOSO\\\\juan -> CONTOSO\juan).
    - Strip surrounding whitespace; keep content as-is otherwise.
    """
    if value is None:
        return ""
    s = str(value).strip()
    # Replace any run of backslashes with a single backslash
    s = re.sub(r"\\+", r"\\", s)
    return s

def fs_safe(name: str) -> str:
    """Make a filesystem-safe name (ascii-ish)."""
    s = name or ""
    # Replace path separators and control chars
    s = re.sub(r"[\\/\0\n\r\t]+", "_", s)
    # Allow alnum, space, dash, underscore, dot; replace others with '_'
    s = re.sub(r"[^A-Za-z0-9._ -]", "_", s)
    # Collapse multiple underscores/spaces
    s = re.sub(r"[ _]+", " ", s).strip()
    return s or "Unnamed"
