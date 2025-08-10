from __future__ import annotations
import functools

@functools.lru_cache(maxsize=4096)
def prefer(v: str|None) -> str|None:
    if not v: return None
    v = v.strip()
    return v or None
