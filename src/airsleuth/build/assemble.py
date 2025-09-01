from __future__ import annotations
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib

import orjson

# Global thread pool reused across passes
from concurrent.futures import ThreadPoolExecutor as _TP
_EXECUTOR = _TP()


def _to_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    if isinstance(v, (int,)):
        return bool(v)
    s = str(v).strip().lower()
    if s in {"1","true","yes","y","on"}:
        return True
    if s in {"0","false","no","n","off",""}:
        return False
    return None

from airsleuth import SCHEMA_VERSION
from ..io.tshark import (
    run_tshark,
    MGMT_FILTER,
    MGMT_FIELDS,
    JOIN_FILTER_BASE,
    JOIN_FIELDS,
    DATA_FILTER_BASE,
    DATA_FIELDS,
    ID_FILTER_BASE,
    ID_FIELDS,
    PMKID_EAPOL_FILTER_BASE,
    PMKID_EAPOL_FIELDS,
    PMKID_ASSOC_FILTER_BASE,
    PMKID_ASSOC_FIELDS,
    CERT_FILTER_BASE,
    CERT_FIELDS,
)
from ..io.utils import ascii_label_pref, sha256_file, mac_is_laa, iso_utc_seconds, normalize_eap_identity, fs_safe

# --------- maps ----------
AKM_MAP = {
    "1": "802.1X",
    "2": "PSK",
    "3": "FT-802.1X",
    "4": "FT-PSK",
    "5": "802.1X-SHA256",
    "6": "PSK-SHA256",
    "7": "TDLS",
    "8": "SAE",
    "9": "FT-SAE",
    "11": "OWE",
    "12": "FT-OWE",
}
CIPHER_MAP = {
    "1": "WEP-40",
    "2": "TKIP",
    "4": "CCMP",
    "5": "WEP-104",
    "8": "GCMP",
    "9": "GCMP-256",
    "10": "CCMP-256",
}

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# --------- WPS decoding helpers ----------
def _to_int_hex(s: str) -> int | None:
    if not s:
        return None
    s = s.strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)
    except Exception:
        return None

def _map_wps_state(s: str | None) -> str | None:
    """0x01=unconfigured, 0x02=configured; otherwise return None/unknown."""
    if not s:
        return None
    v = _to_int_hex(s)
    if v == 0x01:
        return "unconfigured"
    if v == 0x02:
        return "configured"
    return None  # unknown

# Config Methods bit flags per WSC spec (common subset)
_WPS_CM = [
    (0x0001, "usb"),
    (0x0002, "ethernet"),
    (0x0004, "label"),
    (0x0008, "display"),
    (0x0010, "nfc-token-ext"),
    (0x0020, "nfc-token-int"),
    (0x0040, "nfc-interface"),
    (0x0080, "pushbutton"),
    (0x0100, "keypad"),
    (0x0200, "virtual-pushbutton"),
    (0x0400, "physical-pushbutton"),
    (0x2008, "virtual-display-pin"),
    (0x4008, "physical-display-pin"),
]

def _decode_wps_config_methods(tokens: list[str]) -> list[str]:
    """
    tokens may contain one or more hex strings; OR them and decode to names.
    If the final mask is 0 (e.g., '0x0000'), return [] (nothing advertised).
    Only fall back to a hex string if mask>0 but no known bits matched.
    """
    if not tokens:
        return []
    mask = 0
    any_hex = False
    for t in tokens:
        v = _to_int_hex(t)
        if v is not None:
            any_hex = True
            mask |= v
    if not any_hex:
        # Already strings? normalize
        return sorted({t.strip().lower() for t in tokens if t.strip()})

    if mask == 0:
        return []  # explicit "no methods"

    out = [name for bit, name in _WPS_CM if (mask & bit)]
    # If hex seen but none of our known bits matched, keep raw mask for transparency
    return out if out else [f"0x{mask:04x}"]

def _map_wps_version(s: str | None) -> str | None:
    """
    WPS Version: 0x10 -> '1.0'; Version2: 0x20 -> '2.0'.
    If unknown, return None.
    """
    if not s:
        return None
    v = _to_int_hex(s)
    if v == 0x10:
        return "1.0"
    if v == 0x20:
        return "2.0"
    return None

# --------- top-level worker for process pools (pickle-safe) ----------
def _tshark_worker(args: tuple[str, list[str], str]) -> tuple[str, list[str]]:
    cap, fields, dfilter = args
    return cap, run_tshark(fields, cap, dfilter)

# --------- local helpers ---------
def _pick_pmkid(*vals: str) -> str | None:
    """Return the first non-empty PMKID hex string among candidates."""
    for v in vals:
        v = (v or "").strip().lower()
        if v:
            return v
    return None

def _safe_float(s: str) -> float | None:
    try:
        return float(s)
    except Exception:
        return None

def _is_dfs_channel(ch: int) -> bool:
    # DFS typically applies to 52–64 and 100–144 in 5 GHz. 2.4 GHz/6 GHz are non-DFS.
    return (52 <= ch <= 64) or (100 <= ch <= 144)

def _split_csv_like(s: str) -> list[str]:
    if not s:
        return []
    parts = []
    for tok in s.replace(";", ",").split(","):
        tok = tok.strip()
        if tok:
            parts.append(tok)
    return parts

def _classify_outer_identity(identity: str) -> dict:
    """
    Classify the 802.1X outer identity for realm/username leakage.
    Returns: {value, outer_username, realm, outer_id_type, leaks_username}
      outer_id_type in {"empty","anonymous","username_only","full_id","other"}
    """
    val = (identity or "").strip()
    if val == "":
        return {
            "value": identity,
            "outer_username": None,
            "realm": None,
            "outer_id_type": "empty",
            "leaks_username": False,
        }
    if "@" in val:
        user, realm = val.split("@", 1)
        user_s = user.strip().lower()
        if user_s in ("anonymous", "anon"):
            return {
                "value": identity,
                "outer_username": user if user else None,
                "realm": realm or None,
                "outer_id_type": "anonymous",
                "leaks_username": False,
            }
        return {
            "value": identity,
            "outer_username": user if user else None,
            "realm": realm or None,
            "outer_id_type": "full_id",
            "leaks_username": user != "",
        }
    return {
        "value": identity,
        "outer_username": val,
        "realm": None,
        "outer_id_type": "username_only",
        "leaks_username": True,
    }

# --------- parsers / summarizers ----------
def parse_mgmt_line(ln: str):
    parts = (ln.split("|") + [""] * 18)[:18]
    (
        ssid,
        bssid,
        bvendor,
        ch,
        freq,
        akm,
        pcs,
        mfpc,
        mfpr,
        rsn_caps,
        wps_state,
        wps_methods,
        wps_sel,
        wps_sel_methods,
        wps_locked,
        wps_ver,
        wps_v2,
        rssi_dbm,
    ) = [p.strip() for p in parts]

    bssid = (bssid or "").lower()
    if not bssid or _is_broadcast_or_zero(bssid):
        return None

    label = ascii_label_pref(ssid)
    if not label:
        return None

    # Fill MFPC/MFPR from RSN capabilities if one of them was blank
    if rsn_caps and (mfpc == "" or mfpr == ""):
        try:
            v = int(rsn_caps, 16)
            if mfpc == "":
                mfpc = "1" if (v & 0x80) else "0"
            if mfpr == "":
                mfpr = "1" if (v & 0x40) else "0"
        except Exception:
            pass

    return {
        "label": label,
        "bssid": bssid,
        "vendor": bvendor or None,
        "ch": ch,
        "freq": freq,
        "akm": akm.replace(",", ";"),
        "pair": pcs.replace(",", ";"),
        "mfpc": mfpc,
        "mfpr": mfpr,
        # WPS raw fields (summarized later)
        "wps": {
            "present": bool(wps_ver or wps_v2 or wps_state or wps_methods),
            "state": wps_state or None,
            "config_methods": _split_csv_like(wps_methods),
            "selected_registrar": (wps_sel == "1" or wps_sel.lower() == "true"),
            "selected_registrar_config_methods": _split_csv_like(wps_sel_methods),
            "ap_setup_locked": (wps_locked == "1" or wps_locked.lower() == "true"),
            "version": wps_ver or None,
            "version2": wps_v2 or None,
        },
        # RF
        "rssi": _safe_float(rssi_dbm),
    }

def summarize_security(rows_for_bssid):
    akms = Counter()
    pairwise = Counter()
    pmf = {"mfpc_true": 0, "mfpc_false": 0, "mfpr_true": 0, "mfpr_false": 0}
    wps_rows = []

    for r in rows_for_bssid:
        for a in r["akm"].split(";"):
            a = a.strip()
            if not a:
                continue
            akms[AKM_MAP.get(a, a)] += 1
        for c in r["pair"].split(";"):
            c = c.strip()
            if c:
                pairwise[CIPHER_MAP.get(c, c)] += 1
        if r["mfpc"] in ("1", "True"):
            pmf["mfpc_true"] += 1
        elif r["mfpc"] in ("0", "False"):
            pmf["mfpc_false"] += 1
        if r["mfpr"] in ("1", "True"):
            pmf["mfpr_true"] += 1
        elif r["mfpr"] in ("0", "False"):
            pmf["mfpr_false"] += 1

        if r.get("wps"):
            wps_rows.append(r["wps"])

    # ---- Summarize WPS (readable) ----
    present_count = sum(1 for w in wps_rows if w.get("present"))
    if present_count == 0:
        wps_summary: bool | dict = False
    else:
        all_methods_tokens = []
        all_sel_methods_tokens = []
        states = []
        versions = set()

        for w in wps_rows:
            all_methods_tokens.extend(w.get("config_methods", []) or [])
            all_sel_methods_tokens.extend(w.get("selected_registrar_config_methods", []) or [])
            if w.get("state"):
                states.append(w.get("state"))
            for vx in (w.get("version"), w.get("version2")):
                mv = _map_wps_version(vx)
                if mv:
                    versions.add(mv)

        decoded_methods = _decode_wps_config_methods(all_methods_tokens)
        decoded_sel_methods = _decode_wps_config_methods(all_sel_methods_tokens)

        # Choose most common raw state, then map to readable
        state_val = None
        if states:
            state_val = Counter(states).most_common(1)[0][0]
        readable_state = _map_wps_state(state_val)

        any_selected = any(w.get("selected_registrar") for w in wps_rows)
        any_locked = any(w.get("ap_setup_locked") for w in wps_rows)

        wps_summary = {
            "state": readable_state,  # "configured" | "unconfigured" | None
            "config_methods": decoded_methods,  # list[str], [] when 0x0000
            "selected_registrar": True if any_selected else False,
            "selected_registrar_config_methods": decoded_sel_methods,  # list[str]
            "ap_setup_locked": True if any_locked else False,
            "versions": sorted(versions) if versions else [],
        }

    # Build security object
    security = {
        "akm_counts": dict(akms),
        "pairwise_counts": dict(pairwise),
        # PMF: keep counts only; no mfpc/mfpr booleans
        "pmf": {
            "mfpc_true": pmf["mfpc_true"],
            "mfpc_false": pmf["mfpc_false"],
            "mfpr_true": pmf["mfpr_true"],
            "mfpr_false": pmf["mfpr_false"],
        },
        # Flags inside security
        "ft": any(
            a in ("FT-802.1X", "FT-PSK", "FT-SAE", "FT-OWE") for a in akms.keys()
        ),
        "owe": any(a in ("OWE", "FT-OWE") for a in akms.keys()),
        "wps": wps_summary,
    }
    return security

def build_addr_or_filter(bssids: set[str]) -> str:
    if not bssids:
        return ""
    fields = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.ta", "wlan.ra"]
    terms = []
    for f in fields:
        terms.extend(f"({f}=={b})" for b in sorted(bssids))
    return "(" + " or ".join(terms) + ")"

# --------- helpers to bind frames to a BSSID when wlan.bssid is blank ----------


def _is_broadcast_or_zero(mac: str) -> bool:
    mac = (mac or "").lower()
    return mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
def _derive_bssid_if_empty(
    bssid: str, sa: str, da: str, known_bssids: set[str]
) -> str | None:
    bssid = (bssid or "").lower()
    sa = (sa or "").lower()
    da = (da or "").lower()
    if bssid:
        return bssid
    if sa in known_bssids:
        return sa
    if da in known_bssids:
        return da
    return None

def _dedupe_eap_identities(clients: dict[str, dict]):
    for bssid, cmap in clients.items():
        for sta, rec in cmap.items():
            arts = rec.get("artifacts", {})
            idents = arts.get("eap_identities", [])
            seen = set()
            out = []
            for it in idents:
                key = (it.get("value"), it.get("capture"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(it)
            arts["eap_identities"] = out


def _dedupe_pmkids_in_clients(clients: dict[str, dict]):
    for bssid, cmap in clients.items():
        for sta, rec in cmap.items():
            arts = rec.get("artifacts", {})
            pmkids = arts.get("pmkids", [])
            seen = set()
            out = []
            for p in pmkids:
                key = (p.get("pmkid"), p.get("source"), p.get("capture"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(dict(p))
            arts["pmkids"] = out
            rec["artifacts"] = arts


def _dedupe_eap_identities(clients: dict[str, dict]):
    for bssid, cmap in clients.items():
        for sta, rec in cmap.items():
            arts = rec.get("artifacts", {})
            idents = arts.get("eap_identities", [])
            seen = set()
            out = []
            for it in idents:
                key = (it.get("value"), it.get("capture"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(it)
            arts["eap_identities"] = out

def _merge_handshake(
    ap: str,
    sta: str,
    rc: str,
    msgs_sorted: list[int],
    capture: str,
    clients: dict[str, dict],
):
    if ap not in clients or sta not in clients[ap]:
        return
    rec = clients[ap][sta]
    arts = rec.setdefault("artifacts", {})
    arr = arts.setdefault("handshakes", [])
    key = (rc, tuple(msgs_sorted), capture)
    for e in arr:
        if (e.get("replay_counter", ""), tuple(e.get("messages", [])), e.get("capture")) == key:
            return
    arr.append(
        {
            "replay_counter": rc,
            "messages": msgs_sorted,
            "capture": capture,
        }
    )

def _collapse_handshakes_in_clients(clients: dict[str, dict]):
    """Merge split 1-2 and 3-4 handshake halves into full 1-4 when likely same session.
    Heuristic: within the same capture for (AP, STA), if there exist entries with
    messages including any of {1,2} and another including any of {3,4}, merge them
    into a single entry with the union of messages. Keep the replay_counter from
    the entry that contains message 1 when available, else from the first.
    """
    for ap, cmap in clients.items():
        for sta, rec in cmap.items():
            arts = rec.get("artifacts", {})
            hs = arts.get("handshakes", [])
            if not hs or len(hs) < 2:
                continue
            # Group by capture
            by_cap = {}
            for h in hs:
                by_cap.setdefault(h.get("capture"), []).append(dict(h))
            merged = []
            for cap, arr in by_cap.items():
                # Prefer pairing 12 with 34 if rc equal or next rc
                firsts = []
                seconds = []
                others = []
                for h in arr:
                    s = set(h.get("messages", []))
                    if s <= {1,2}:
                        firsts.append(h)
                    elif s <= {3,4}:
                        seconds.append(h)
                    else:
                        others.append(h)
                # Attempt to match by replay_counter proximity
                used_s = [False]*len(seconds)
                def rc_int(h):
                    try:
                        return int(str(h.get("replay_counter") or "0"), 0)
                    except Exception:
                        return 0
                seconds_sorted = list(enumerate(seconds))
                seconds_sorted.sort(key=lambda t: rc_int(t[1]))
                out = []
                for a in firsts:
                    ai = rc_int(a)
                    match_idx = -1
                    for idx,(j,b) in enumerate(seconds_sorted):
                        if used_s[j]:
                            continue
                        bi = rc_int(b)
                        if bi == ai or bi == ai+1:
                            match_idx = j
                            sb = b
                            break
                    if match_idx == -1:
                        # fallback: take any unused second
                        for j,b in enumerate(seconds):
                            if not used_s[j]:
                                match_idx = j
                                sb = b
                                break
                    if match_idx != -1:
                        used_s[match_idx] = True
                        union = sorted(set(a.get("messages", [])) | set(sb.get("messages", [])))
                        new = {
                            "replay_counter": a.get("replay_counter") or sb.get("replay_counter"),
                            "messages": union,
                            "capture": cap,
                        }
                        out.append(new)
                    else:
                        out.append(a)
                # append any remaining seconds and others
                for j,b in enumerate(seconds):
                    if not used_s[j]:
                        out.append(b)
                out.extend(others)
                merged.extend(out)
            arts["handshakes"] = merged
            rec["artifacts"] = arts

# --------- main builder ----------
def build_manifest(files: list[str], essids: list[str], progress=None):
    by_bssid_rows: dict[str, list[dict]] = defaultdict(list)
    essid_to_bssids: dict[str, set[str]] = defaultdict(set)
    channels_seen, freqs_seen = set(), set()
    mgmt_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Pass 1: mgmt (parallel) — precollect to compute accurate totals
    mgmt_tasks = [(f, MGMT_FIELDS, MGMT_FILTER) for f in files]
    with ThreadPoolExecutor() as ex:
        mgmt_results = list(ex.map(_tshark_worker, mgmt_tasks))
    for fpath, lines in mgmt_results:
        for ln in lines:
            row = parse_mgmt_line(ln)
            if not row:
                continue
            bssid = row["bssid"]
            label = row["label"]
            row["capture"] = fpath
            by_bssid_rows[bssid].append(row)
            essid_to_bssids[label].add(bssid)
            mgmt_counts[bssid][fpath] += 1
            ch, fq = row["ch"], row["freq"]
            if ch.isdigit():
                channels_seen.add(int(ch))
            if fq.isdigit():
                freqs_seen.add(int(fq))
            # progress handled by consolidated task later

    selected = set(essids) if essids else set(essid_to_bssids.keys())
    missing = [e for e in sorted(selected) if e not in essid_to_bssids]
    if missing:
        raise ValueError("No matching ESSIDs found: " + ", ".join(missing))

    selected_bssids = set()
    for e in selected:
        selected_bssids |= essid_to_bssids.get(e, set())
    addrf = build_addr_or_filter(selected_bssids)

    # Pass 2: Assoc/EAPOL (parallel, filtered) — precollect
    join_filter = f"({JOIN_FILTER_BASE}) && ({addrf})" if addrf else JOIN_FILTER_BASE

    subtype_map = {
        "0": "assoc_req",
        "1": "assoc_resp",
        "2": "reassoc_req",
        "3": "reassoc_resp",
        "10": "disassoc",
        "12": "deauth",
    }
    clients = defaultdict(
        lambda: defaultdict(
            lambda: {
                "vendor": None,
                "evidence": defaultdict(int),
                "first": None,
                "last": None,
                "total": 0,
                "artifacts": {"eap_identities": [], "pmkids": [], "handshakes": [], "client_certificates": []},
            }
        )
    )
    # Global client tracking (not tied to a specific BSSID)
    global_clients = defaultdict(
        lambda: {
            "vendor": None,
            "first": None,
            "last": None,
            "total": 0,
            "evidence": defaultdict(int),
            "probed_essids": set(),
        }
    )
    in_network_stas = set()
    orphan_hs = defaultdict(lambda: {"msgs": {"1": 0, "2": 0, "3": 0, "4": 0}})

    join_tasks = [(f, JOIN_FIELDS, join_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        join_results = list(ex.map(_tshark_worker, join_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
                parts = (ln.split("|") + [""] * 7)[:7]
                t, bssid, sa, sa_vendor, da, subtype, msgnr = [
                    p.strip() for p in parts
                ]
                bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
                if not bssid:
                    continue
                sa = (sa or "").lower()
                da = (da or "").lower()
                try:
                    ts = float(t) if t else None
                except Exception:
                    ts = None

                label = subtype_map.get(subtype, "eapol")

                sta = None
                if label in ("assoc_req", "reassoc_req"):
                    sta = sa
                elif label in ("assoc_resp", "reassoc_resp"):
                    sta = da
                else:
                    cand = sa if sa and sa != bssid else (da if da and da != bssid else None)
                    if cand and not _is_broadcast_or_zero(cand):
                        sta = cand

                if label == "eapol" and msgnr in ("1", "2", "3", "4") and not sta:
                    orphan_hs[bssid]["msgs"][msgnr] += 1

                if not sta:
                    continue

                rec = clients[bssid][sta]
                in_network_stas.add(sta)
                rec["evidence"][label] += 1
                rec["total"] += 1
                if ts is not None:
                    rec["first"] = ts if (rec["first"] is None or ts < rec["first"]) else rec["first"]
                    rec["last"] = ts if (rec["last"] is None or ts > rec["last"]) else rec["last"]
                if (not rec["vendor"]) and sa_vendor:
                    rec["vendor"] = sa_vendor
                # progress handled by consolidated task

    # Pass 3: Data frames (parallel, filtered) — precollect
    data_filter = f"({DATA_FILTER_BASE}) && ({addrf})" if addrf else DATA_FILTER_BASE
    data_tasks = [(f, DATA_FIELDS, data_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        data_results = list(ex.map(_tshark_worker, data_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, ta, ta_vendor, ra, tods, fromds = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, ta, ra, selected_bssids)
            if not bssid:
                continue
            ta = (ta or "").lower()
            ra = (ra or "").lower()
            try:
                ts = float(t) if t else None
            except Exception:
                ts = None

            sta = None
            vend = None
            if tods == "1" and ta and ta != bssid:
                sta = ta
                vend = ta_vendor
            elif fromds == "1" and ra and ra != bssid:
                sta = ra
            else:
                continue
            if not sta or _is_broadcast_or_zero(sta):
                continue

            rec = clients[bssid][sta]
            if vend and not rec["vendor"]:
                rec["vendor"] = vend
            rec["evidence"]["data"] += 1
            rec["total"] += 1
            if ts is not None:
                rec["first"] = ts if (rec["first"] is None or ts < rec["first"]) else rec["first"]
                rec["last"] = ts if (rec["last"] is None or ts > rec["last"]) else rec["last"]
        # progress handled by consolidated task

    # Artifact passes (parallel, filtered)
    id_filter = f"({ID_FILTER_BASE}) && ({addrf})" if addrf else ID_FILTER_BASE
    pmkid_eapol_filter = f"({PMKID_EAPOL_FILTER_BASE}) && ({addrf})" if addrf else PMKID_EAPOL_FILTER_BASE
    pmkid_assoc_filter = f"({PMKID_ASSOC_FILTER_BASE}) && ({addrf})" if addrf else PMKID_ASSOC_FILTER_BASE
    cert_filter = f"({CERT_FILTER_BASE}) && ({addrf})" if addrf else CERT_FILTER_BASE

    # EAP identities — precollect
    id_tasks = [(f, ID_FIELDS, id_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        id_results = list(ex.map(_tshark_worker, id_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
            t, bssid, sa, da, ident = (ln.split("|") + [""] * 5)[:5]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid:
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                continue
            rec = clients[bssid][sa]
            parsed = _classify_outer_identity(ident)
            parsed["capture"] = fpath
            rec["artifacts"]["eap_identities"].append(parsed)
        # progress handled by consolidated task

    
    # PMKID (EAPOL msg1) — precollect
    pmk1_tasks = [(f, PMKID_EAPOL_FIELDS, pmkid_eapol_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        pmk1_results = list(ex.map(_tshark_worker, pmk1_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, sa, da, msgnr, pmkid_rsn, pmkid_akms = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            pmkid = _pick_pmkid(pmkid_rsn, pmkid_akms)
            if not bssid or not pmkid:
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                continue
            clients[bssid][sa]["artifacts"]["pmkids"].append(
                {
                    "pmkid": pmkid,
                    "capture": fpath,
                    "source": "eapol",
                    "msgnr": msgnr,
                }
            )
        # progress handled by consolidated task

    # PMKID (Assoc/Reassoc) — precollect
    pmk2_tasks = [(f, PMKID_ASSOC_FIELDS, pmkid_assoc_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        pmk2_results = list(ex.map(_tshark_worker, pmk2_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
            parts = (ln.split("|") + [""] * 6)[:6]
            t, bssid, sa, da, pmkid_rsn, pmkid_akms = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            pmkid = _pick_pmkid(pmkid_rsn, pmkid_akms)
            if not bssid or not pmkid:
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                continue
            clients[bssid][sa]["artifacts"]["pmkids"].append(
                {
                    "pmkid": pmkid,
                    "capture": fpath,
                    "source": "assoc",
                }
            )
        # progress handled by consolidated task

    # EAP-TLS certificates — precollect
    server_certs = defaultdict(list)  # bssid -> [{fingerprint, capture}]
    client_server_certs = defaultdict(list)  # (bssid, sta) -> [{fingerprint, capture}] (client-side certs only)
    cert_tasks = [(f, CERT_FIELDS, cert_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        cert_results = list(ex.map(_tshark_worker, cert_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        for ln in lines:
            t, bssid, sa, da, certhex = (ln.split("|") + [""] * 5)[:5]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid or not certhex:
                continue
            sa = (sa or "").lower()
            da = (da or "").lower()
            blobs = certhex.replace(",", " ").replace(";", " ").split()
            for blob in blobs:
                hb = blob.replace(":", "")
                if len(hb) < 40:
                    continue
                try:
                    data = bytes.fromhex(hb)
                except Exception:
                    continue
                fp = sha256_bytes(data)
                if sa == bssid:
                    # AP -> STA: server certificate
                    server_certs[bssid].append({"fingerprint": fp, "capture": fpath})
                else:
                    # STA -> AP: client certificate
                    sta = sa
                    if sta and (sta != bssid) and (not _is_broadcast_or_zero(sta)):
                        client_server_certs[(bssid, sta)].append({"fingerprint": fp, "capture": fpath})
        # progress handled by consolidated task

    # Dedicated EAPOL 4-way handshake extraction
    hs_fields = [
        "frame.number",
        "wlan.bssid",
        "wlan.sa",
        "wlan.da",
        "wlan_rsna_eapol.keydes.msgnr",
        "eapol.keydes.replay_counter",
        "wlan_rsna_eapol.keydes.key_info.key_mic",
    ]
    hs_filter = "eapol && wlan_rsna_eapol.keydes.msgnr"
    if addrf:
        hs_filter = f"({hs_filter}) && ({addrf})"

    hs_tasks = [(f, hs_fields, hs_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        hs_results = list(ex.map(_tshark_worker, hs_tasks))
    # Progress handled by a consolidated task
    for fpath, lines in []:
        msgs_by_tuple = defaultdict(set)
        m2_mic = set()

        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            fn, bssid, sa, da, msg, rc, mic = [p.strip() for p in parts]
            bssid = (bssid or "").lower()
            sa = (sa or "").lower()
            da = (da or "").lower()
            if not bssid:
                continue
            try:
                m = int(msg)
            except Exception:
                continue
            sta = da if sa == bssid else sa
            sta = (sta or "").lower()
            if not sta or _is_broadcast_or_zero(sta):
                continue
            rc_norm = rc
            key = (bssid, sta, rc_norm)
            msgs_by_tuple[key].add(m)
            mic_flag = False
            try:
                mic_flag = int(mic) != 0
            except Exception:
                mic_flag = bool(mic)
            if m == 2 and mic_flag:
                m2_mic.add(key)
            # progress handled by consolidated task

        for (ap, sta, rc), mset in msgs_by_tuple.items():
            if (ap not in clients) or (sta not in clients[ap]):
                continue
            if 1 not in mset:
                continue
            if (ap, sta, rc) not in m2_mic:
                continue
            if 3 in mset and 4 in mset:
                msgs_out = [1, 2, 3, 4]
            else:
                msgs_out = [1, 2]
            _merge_handshake(ap, sta, rc, msgs_out, fpath, clients)

        # progress handled by consolidated task

    _dedupe_pmkids_in_clients(clients)
    _dedupe_eap_identities(clients)

    # Pass: Probe Requests (not filtered by BSSID) to build per-STA probed SSIDs
    from ..io.tshark import PROBE_REQ_FIELDS, PROBE_REQ_FILTER
    probe_tasks = [(f, PROBE_REQ_FIELDS, PROBE_REQ_FILTER) for f in files]
    with ThreadPoolExecutor() as ex:
        probe_results = list(ex.map(_tshark_worker, probe_tasks))

    # Pass: EAP authentication overview per BSSID (precollect)
    from ..io.tshark import AUTH_FIELDS, AUTH_FILTER_BASE
    auth_filter = f"({AUTH_FILTER_BASE}) && ({addrf})" if addrf else AUTH_FILTER_BASE
    auth_tasks = [(f, AUTH_FIELDS, auth_filter) for f in files]
    eap_auth = defaultdict(lambda: {"by_type": defaultdict(lambda: {"successes": 0, "failures": 0}), "success": 0, "failure": 0})
    with ThreadPoolExecutor() as ex:
        auth_results = list(ex.map(_tshark_worker, auth_tasks))

    # PMF-protected mgmt frames (client-side)
    from ..io.tshark import PMF_MGMT_ALL_FIELDS, PMF_MGMT_ALL_FILTER_BASE
    pmf_filter = f"({PMF_MGMT_ALL_FILTER_BASE}) && ({addrf})" if addrf else PMF_MGMT_ALL_FILTER_BASE
    with ThreadPoolExecutor() as ex:
        pmf_results = list(ex.map(_tshark_worker, [(f, PMF_MGMT_ALL_FIELDS, pmf_filter) for f in files]))

    # Consolidated progress bar across all passes
    adv = None
    if progress:
        total_all = (
            sum(len(x) for _, x in join_results)
            + sum(len(x) for _, x in data_results)
            + sum(len(x) for _, x in id_results)
            + sum(len(x) for _, x in pmk1_results)
            + sum(len(x) for _, x in pmk2_results)
            + sum(len(x) for _, x in cert_results)
            + sum(len(x) for _, x in hs_results)
            + sum(len(x) for _, x in probe_results)
            + sum(len(x) for _, x in auth_results)
            + sum(len(x) for _, x in pmf_results)
        )
        if total_all <= 0:
            total_all = 1
        task_all = progress.add_task("[cyan]Initializing", total=total_all)
        current_phase = None
        def adv(n: int, phase: str):
            nonlocal current_phase
            if phase != current_phase:
                progress.update(task_all, description=f"[cyan]{phase}")
                current_phase = phase
            progress.update(task_all, advance=n)

    # Process passes in order, updating the consolidated bar
    # 1) Assoc/EAPOL
    for fpath, lines in join_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, sa, sa_vendor, da, subtype, msgnr = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid:
                if adv: adv(1, "Assoc/EAPOL")
                continue
            sa = (sa or "").lower()
            da = (da or "").lower()
            try:
                ts = float(t) if t else None
            except Exception:
                ts = None
            label = subtype_map.get(subtype, "eapol")
            sta = None
            if label in ("assoc_req", "reassoc_req"):
                sta = sa
            elif label in ("assoc_resp", "reassoc_resp"):
                sta = da
            else:
                cand = sa if sa and sa != bssid else (da if da and da != bssid else None)
                if cand and not _is_broadcast_or_zero(cand):
                    sta = cand
            if label == "eapol" and msgnr in ("1", "2", "3", "4") and not sta:
                orphan_hs[bssid]["msgs"][msgnr] += 1
            if not sta:
                if adv: adv(1, "Assoc/EAPOL")
                continue
            rec = clients[bssid][sta]
            in_network_stas.add(sta)
            rec["evidence"][label] += 1
            rec["total"] += 1
            if ts is not None:
                rec["first"] = ts if (rec["first"] is None or ts < rec["first"]) else rec["first"]
                rec["last"] = ts if (rec["last"] is None or ts > rec["last"]) else rec["last"]
            if (not rec["vendor"]) and sa_vendor:
                rec["vendor"] = sa_vendor
            if adv: adv(1, "Assoc/EAPOL")

    # 2) Data frames
    for fpath, lines in data_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, ta, ta_vendor, ra, tods, fromds = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, ta, ra, selected_bssids)
            if not bssid:
                if adv: adv(1, "Data frames")
                continue
            ta = (ta or "").lower()
            ra = (ra or "").lower()
            try:
                ts = float(t) if t else None
            except Exception:
                ts = None
            sta = None
            vend = None
            if tods == "1" and ta and ta != bssid:
                sta = ta
                vend = ta_vendor
            elif fromds == "1" and ra and ra != bssid:
                sta = ra
            else:
                if adv: adv(1, "Data frames")
                continue
            if not sta or _is_broadcast_or_zero(sta):
                if adv: adv(1, "Data frames")
                continue
            rec = clients[bssid][sta]
            if vend and not rec["vendor"]:
                rec["vendor"] = vend
            rec["evidence"]["data"] += 1
            rec["total"] += 1
            if ts is not None:
                rec["first"] = ts if (rec["first"] is None or ts < rec["first"]) else rec["first"]
                rec["last"] = ts if (rec["last"] is None or ts > rec["last"]) else rec["last"]
            if adv: adv(1, "Data frames")

    # 3) EAP identities
    for fpath, lines in id_results:
        for ln in lines:
            t, bssid, sa, da, ident = (ln.split("|") + [""] * 5)[:5]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid:
                if adv: adv(1, "EAP identities")
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                if adv: adv(1, "EAP identities")
                continue
            rec = clients[bssid][sa]
            val = normalize_eap_identity(ident)
            rec["artifacts"]["eap_identities"].append({"value": val, "capture": fpath})
            if adv: adv(1, "EAP identities")

    # 4) PMKID (EAPOL msg1)
    for fpath, lines in pmk1_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, sa, da, msgnr, pmkid_rsn, pmkid_akms = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            pmkid = _pick_pmkid(pmkid_rsn, pmkid_akms)
            if not bssid or not pmkid:
                if adv: adv(1, "PMKID (EAPOL)")
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                if adv: adv(1, "PMKID (EAPOL)")
                continue
            clients[bssid][sa]["artifacts"]["pmkids"].append(
                {"pmkid": pmkid, "capture": fpath, "source": "eapol", "msgnr": msgnr}
            )
            if adv: adv(1, "PMKID (EAPOL)")

    # 5) PMKID (Assoc/Reassoc)
    for fpath, lines in pmk2_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 6)[:6]
            t, bssid, sa, da, pmkid_rsn, pmkid_akms = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            pmkid = _pick_pmkid(pmkid_rsn, pmkid_akms)
            if not bssid or not pmkid:
                if adv: adv(1, "PMKID (Assoc/Reassoc)")
                continue
            sa = (sa or "").lower()
            if not sa or sa == bssid:
                if adv: adv(1, "PMKID (Assoc/Reassoc)")
                continue
            clients[bssid][sa]["artifacts"]["pmkids"].append(
                {"pmkid": pmkid, "capture": fpath, "source": "assoc"}
            )
            if adv: adv(1, "PMKID (Assoc/Reassoc)")

    # 6) EAP-TLS certs
    for fpath, lines in cert_results:
        for ln in lines:
            t, bssid, sa, da, eap_code, certhex = (ln.split("|") + [""] * 6)[:6]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid or not certhex:
                if adv: adv(1, "EAP-TLS certs")
                continue
            sa = (sa or "").lower()
            da = (da or "").lower()
            blobs = certhex.replace(",", " ").replace(";", " ").split()
            added = False
            for blob in blobs:
                hb = blob.replace(":", "")
                if len(hb) < 40:
                    continue
                try:
                    data = bytes.fromhex(hb)
                except Exception:
                    continue
                fp = sha256_bytes(data)
                # Classify by EAP code: 1=Request (server), 2=Response (client)
                if eap_code == "1":
                    server_certs[bssid].append({"fingerprint": fp, "capture": fpath})
                elif eap_code == "2":
                    sta = (sa or "").lower()
                    if sta and (sta != bssid) and (not _is_broadcast_or_zero(sta)):
                        client_server_certs[(bssid, sta)].append({"fingerprint": fp, "capture": fpath})
                added = True
            if adv:
                adv(1, "EAP-TLS certs")

    # 7) EAPOL handshakes (sessionized like the working extraction)
    for fpath, lines in hs_results:
        # cur session index per (ap,sta)
        cur_idx: dict[tuple[str, str], int] = {}
        sessions: dict[tuple[str, str, int], dict] = {}
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            fn, bssid, sa, da, msg, rc, mic = [p.strip() for p in parts]
            ap = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            sa = (sa or "").lower(); da = (da or "").lower()
            if not ap:
                if adv: adv(1, "EAPOL handshakes")
                continue
            try:
                m = int(msg)
            except Exception:
                if adv: adv(1, "EAPOL handshakes")
                continue
            sta = da if sa == ap else sa
            sta = (sta or "").lower()
            if not sta or _is_broadcast_or_zero(sta):
                if adv: adv(1, "EAPOL handshakes")
                continue
            key = (ap, sta)
            if m == 1:
                idx = cur_idx.get(key, 0)
                # finalize current session implicitly by starting a new index
                cur_idx[key] = idx + 1
            if key not in cur_idx or cur_idx[key] == 0:
                cur_idx[key] = 1
            idx = cur_idx[key]
            skey = (ap, sta, idx)
            sess = sessions.setdefault(skey, {"msgs": set(), "frames": [], "rc_m1": None, "rc_any": None})
            sess["msgs"].add(m)
            sess["frames"].append(fn)
            if m == 1 and not sess["rc_m1"]:
                sess["rc_m1"] = rc
            if not sess["rc_any"] and rc:
                sess["rc_any"] = rc
            # On M4 we logically close session; next M1 will bump index
            if adv: adv(1, "EAPOL handshakes")
        # Emit sessions
        for (ap, sta, idx), sess in sessions.items():
            if (ap not in clients) or (sta not in clients[ap]):
                continue
            msgs_out = sorted(n for n in (1,2,3,4) if n in sess["msgs"])
            if not msgs_out:
                continue
            rc_val = sess["rc_m1"] or sess["rc_any"] or ""
            _merge_handshake(ap, sta, rc_val, msgs_out, fpath, clients)

    # 8) Probe requests
    for fpath, lines in probe_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 5)[:5]
            t, sa, sa_vendor, da, ssid = [p.strip() for p in parts]
            sta = (sa or "").lower()
            if not sta or _is_broadcast_or_zero(sta):
                if adv: adv(1, "Probe requests")
                continue
            try:
                ts = float(t) if t else None
            except Exception:
                ts = None
            gl = global_clients[sta]
            gl["evidence"]["probe_req"] += 1
            gl["total"] += 1
            if ts is not None:
                gl["first"] = ts if (gl["first"] is None or ts < gl["first"]) else gl["first"]
                gl["last"] = ts if (gl["last"] is None or ts > gl["last"]) else gl["last"]
            if (not gl["vendor"]) and sa_vendor:
                gl["vendor"] = sa_vendor
            label = ascii_label_pref(ssid)
            if label:
                gl["probed_essids"].add(label)
            if adv: adv(1, "Probe requests")

    # 9) EAP auth
    for fpath, lines in auth_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 7)[:7]
            t, bssid, sa, da, code, etype, etype_name = [p.strip() for p in parts]
            bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
            if not bssid:
                if adv: adv(1, "EAP auth")
                continue
            tname = etype_name or etype or "unknown"
            if code == "3":
                eap_auth[bssid]["success"] += 1
                eap_auth[bssid]["by_type"][tname]["successes"] += 1
            elif code == "4":
                eap_auth[bssid]["failure"] += 1
                eap_auth[bssid]["by_type"][tname]["failures"] += 1
            else:
                _ = eap_auth[bssid]["by_type"][tname]
            if adv: adv(1, "EAP auth")

    # 10) PMF mgmt (clients)
    pmf_enabled = defaultdict(lambda: defaultdict(int))  # bssid -> sta -> enabled count
    pmf_disabled = defaultdict(lambda: defaultdict(int))  # bssid -> sta -> disabled count
    for fpath, lines in pmf_results:
        for ln in lines:
            parts = (ln.split("|") + [""] * 3)[:3]
            bssid, sa, prot = [p.strip().lower() for p in parts]
            if not bssid or not sa or bssid == sa:
                if adv: adv(1, "PMF clients")
                continue
            if prot in ("1", "true"):
                pmf_enabled[bssid][sa] += 1
            else:
                pmf_disabled[bssid][sa] += 1
            if adv: adv(1, "PMF clients")

    # build networks
    networks = []
    for essid in sorted(selected):
        bssid_entries = []
        for bssid in sorted(essid_to_bssids.get(essid, [])):
            rows_for_b = [r for r in by_bssid_rows[bssid] if r["label"] == essid]
            if not rows_for_b:
                continue
            vend_counts = Counter([r["vendor"] for r in rows_for_b if r.get("vendor")])
            vendor = vend_counts.most_common(1)[0][0] if vend_counts else None

            # Channels (+ DFS flag), stickiness
            chs = Counter([int(r["ch"]) for r in rows_for_b if r["ch"].isdigit()])
            total_samples = sum(chs.values()) or 1
            ch_list = []
            for c, n in chs.items():
                ch_list.append({"ch": c, "samples": n, "dfs": _is_dfs_channel(c)})
            ch_list.sort(key=lambda x: -x["samples"])
            stickiness = (max(chs.values()) / total_samples) if chs else None
            stickiness = float(f"{stickiness:.2f}") if stickiness is not None else None

            sec = summarize_security(rows_for_b)

            # clients
            clist = []
            for sta, rec in sorted(clients.get(bssid, {}).items()):
                vendor_val = rec["vendor"] or ("Randomized (LAA)" if mac_is_laa(sta) else None)
                # Attach certificates observed for this AP/STA tuple
                if client_server_certs.get((bssid, sta)):
                    rec["artifacts"]["client_certificates"] = client_server_certs[(bssid, sta)]
                # Build evidence counts including artifacts
                ev = dict(rec["evidence"])  # copy
                ev["pmkids"] = len(rec["artifacts"].get("pmkids", []))
                ev["handshakes"] = len(rec["artifacts"].get("handshakes", []))
                ev["certificates"] = len(rec["artifacts"].get("client_certificates", []))
                en = int(pmf_enabled.get(bssid, {}).get(sta, 0))
                dis = int(pmf_disabled.get(bssid, {}).get(sta, 0))
                clist.append(
                    {
                        "mac": sta,
                        "vendor": vendor_val,
                        "evidence": ev,
                        "first_seen": iso_utc_seconds(rec["first"]),
                        "last_seen": iso_utc_seconds(rec["last"]),
                        "total_frames": rec["total"],
                        "artifacts": rec["artifacts"],
                        "probed_essids": sorted(global_clients.get(sta, {}).get("probed_essids", [])),
                        "pmf": {"pmf_enabled": en, "pmf_disabled": dis},
                    }
                )
            clist.sort(key=lambda x: (-x["total_frames"], x["mac"]))

            # seen_in (from mgmt_counts only)
            sin = []
            if bssid in mgmt_counts:
                for cap, cnt in sorted(mgmt_counts[bssid].items()):
                    sin.append({"capture": cap, "frames": {"count": cnt}})

            # RF: max RSSI seen across mgmt rows of this BSSID
            rssi_vals = [r.get("rssi") for r in rows_for_b if r.get("rssi") is not None]
            rssi_est = max(rssi_vals) if rssi_vals else None

            entry = {
                "bssid": bssid,
                "vendor": vendor,
                "channels": ch_list,
                "rf": {
                    "rssi_max": rssi_est,
                    "stickiness": stickiness,
                },
                "security": sec,
                "seen_in": sin,
                "clients": clist,
                "artifacts": {
                    "server_certificates": server_certs.get(bssid, []),
                },
            }
            # Attach EAP auth overview for enterprise networks
            if eap_auth.get(bssid):
                by_type = {k: v for k, v in sorted(eap_auth[bssid]["by_type"].items())}
                entry.setdefault("security", {})["authentication"] = {
                    "eap": {
                        "by_type": by_type,
                        "successes": eap_auth[bssid]["success"],
                        "failures": eap_auth[bssid]["failure"],
                    }
                }
            if bssid in orphan_hs and any(orphan_hs[bssid]["msgs"].values()):
                entry["artifacts"]["orphan_handshakes"] = {
                    "type": "EAPOL-4W",
                    "msgs": orphan_hs[bssid]["msgs"],
                }
            bssid_entries.append(entry)

        networks.append(
            {
                "essid": essid,
                "enterprise_observed": any(
                    any(
                        a in ("802.1X", "FT-802.1X", "802.1X-SHA256")
                        for a in (b.get("security", {}).get("akm_counts", {}) or {}).keys()
                    )
                    for b in bssid_entries
                ),
                "bssids": bssid_entries,
            }
        )

    # Build top-level clients not attached to any network
    top_clients = []
    for sta, rec in global_clients.items():
        if sta in in_network_stas:
            continue
        vendor_val = rec["vendor"] or ("Randomized (LAA)" if mac_is_laa(sta) else None)
        ev = dict(rec.get("evidence", {}))  # do not add pmkid/handshake/cert keys
        top_clients.append(
            {
                "mac": sta,
                "vendor": vendor_val,
                "first_seen": iso_utc_seconds(rec["first"]),
                "last_seen": iso_utc_seconds(rec["last"]),
                "total_frames": rec["total"],
                "evidence": ev,
            "probed_essids": sorted(rec.get("probed_essids", [])),
        }
        )
    top_clients.sort(key=lambda x: (-x["total_frames"], x["mac"]))

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_ts": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "generated_by": {
            "tool": "airsleuth",
            "subcommand": "profile",
            "version": "1.0.0",
        },
        "source_captures": [{"path": f, "sha256": sha256_file(f)} for f in files],
        "stats": {
            "total_bssids": sum(len(n["bssids"]) for n in networks),
            "channels_seen": sorted(
                {ch_samp["ch"] for n in networks for b in n["bssids"] for ch_samp in b["channels"]}
            ),
            "frequencies_seen": sorted(
                {
                    int(r["freq"])
                    for bssid, rows in by_bssid_rows.items()
                    for r in rows
                    if r["label"] in selected and r.get("freq", "").isdigit()
                }
            ),
        },
        "networks": networks,
        "clients": top_clients,
    }
    return manifest

def dumps_json(obj) -> bytes:
    return orjson.dumps(obj, option=orjson.OPT_INDENT_2)


def export_artifacts(manifest: dict, artifacts_dir: str):
    """Export PMKIDs, handshakes (JSON summary), and certificates to disk.
    Creates structure:
      artifacts/
        pmkids/<ESSID>/...
        handshakes/<ESSID>/...
        certificates/<ESSID>/...
    Updates manifest in place by adding 'path' to each artifact entry.
    """
    import os, subprocess
    from ..io.tshark import CERT_FIELDS, CERT_FILTER_BASE, run_tshark

    os.makedirs(artifacts_dir, exist_ok=True)

    # Map BSSID -> ESSID label for folder names
    bssid_to_essid = {}
    for net in manifest.get("networks", []):
        essid = net.get("essid", "")
        for b in net.get("bssids", []):
            bssid_to_essid[b.get("bssid")] = essid

    def ensure_dir(*parts):
        path = os.path.join(*parts)
        os.makedirs(path, exist_ok=True)
        return path

    # PMKIDs and Handshakes from manifest
    for net in manifest.get("networks", []):
        essid = fs_safe(net.get("essid", ""))
        pm_dir = None
        hs_dir = None
        for b in net.get("bssids", []):
            ap = b.get("bssid")
            # Clients artifacts
            for c in b.get("clients", []):
                sta = c.get("mac")
                arts = c.get("artifacts", {})
                # PMKIDs
                for i, p in enumerate(arts.get("pmkids", []), 1):
                    if pm_dir is None:
                        pm_dir = ensure_dir(artifacts_dir, "pmkids", essid)
                    fname = f"pmkid-{ap}-{sta}-{p.get('source','')}-{i}.txt"
                    fpath = os.path.join(pm_dir, fname)
                    try:
                        with open(fpath, "w", encoding="utf-8") as fh:
                            fh.write((p.get("pmkid") or "").strip() + "\n")
                        p["path"] = os.path.relpath(fpath, os.path.dirname(artifacts_dir))
                    except Exception:
                        pass
                # Handshakes: now exported in a separate pass per capture (see below)

    # Certificates: re-run tshark on captures to obtain DER and classify roles
    cert_cat_dir = ensure_dir(artifacts_dir, "certificates")
    # Build quick index to assign paths into manifest entries
    server_index = {}
    client_index = {}
    for net in manifest.get("networks", []):
        essid = fs_safe(net.get("essid", ""))
        for b in net.get("bssids", []):
            ap = b.get("bssid")
            server_index.setdefault(ap, [])
            for sc in b.get("artifacts", {}).get("server_certificates", []):
                server_index[ap].append(sc)
            for c in b.get("clients", []):
                sta = c.get("mac")
                for cc in c.get("artifacts", {}).get("client_certificates", []):
                    client_index.setdefault((ap, sta), []).append(cc)

    # Run tshark per capture
    for cap in manifest.get("source_captures", []):
        cap_path = cap.get("path")
        if not cap_path:
            continue
        try:
            lines = run_tshark(CERT_FIELDS, cap_path, CERT_FILTER_BASE)
        except Exception:
            continue
        for ln in lines:
            parts = (ln.split("|") + [""] * 6)[:6]
            t, bssid, sa, da, eap_code, certhex = [p.strip() for p in parts]
            ap = (bssid or "").lower()
            essid = fs_safe(bssid_to_essid.get(ap, "Unknown"))
            if not ap or not certhex:
                continue
            # Extract DERs (may be multiple in one field)
            for blob in certhex.replace(",", " ").replace(";", " ").split():
                hb = blob.replace(":", "")
                if len(hb) < 40:
                    continue
                try:
                    data = bytes.fromhex(hb)
                except Exception:
                    continue
                fp = sha256_bytes(data)
                if eap_code == "1":
                    # server
                    target_dir = ensure_dir(cert_cat_dir, essid)
                    fname = f"server-{ap}-{fp[:12]}.der"
                    fpath = os.path.join(target_dir, fname)
                    try:
                        with open(fpath, "wb") as fh:
                            fh.write(data)
                        # assign into manifest entry by matching fingerprint+capture
                        for entry in server_index.get(ap, []):
                            if entry.get("fingerprint") == fp and entry.get("capture") == cap_path and not entry.get("path"):
                                entry["path"] = os.path.relpath(fpath, os.path.dirname(artifacts_dir))
                                break
                    except Exception:
                        pass
                elif eap_code == "2":
                    # client
                    sta = (sa or "").lower()
                    if not sta or sta == ap or sta == "ff:ff:ff:ff:ff:ff":
                        continue
                    target_dir = ensure_dir(cert_cat_dir, essid)
                    fname = f"client-{ap}-{sta}-{fp[:12]}.der"
                    fpath = os.path.join(target_dir, fname)
                    try:
                        with open(fpath, "wb") as fh:
                            fh.write(data)
                        for entry in client_index.get((ap, sta), []):
                            if entry.get("fingerprint") == fp and entry.get("capture") == cap_path and not entry.get("path"):
                                entry["path"] = os.path.relpath(fpath, os.path.dirname(artifacts_dir))
                                break
                    except Exception:
                        pass

    # Handshake PCAP slices — per capture using frame-number grouping
    from ..io.tshark import run_tshark as _rt
    hs_fields = [
        "frame.number",
        "wlan.bssid",
        "wlan.sa",
        "wlan.da",
        "wlan_rsna_eapol.keydes.msgnr",
    ]
    hs_filter = (
        "eapol && (wlan_rsna_eapol.keydes.msgnr==1 || "
        "wlan_rsna_eapol.keydes.msgnr==2 || "
        "wlan_rsna_eapol.keydes.msgnr==3 || "
        "wlan_rsna_eapol.keydes.msgnr==4)"
    )

    # Build assignment slots from manifest to attach paths back
    hs_slots = {}
    for net in manifest.get("networks", []):
        for b in net.get("bssids", []):
            ap = (b.get("bssid") or "").lower()
            for c in b.get("clients", []):
                sta = (c.get("mac") or "").lower()
                for h in c.get("artifacts", {}).get("handshakes", []):
                    cap = h.get("capture")
                    hs_slots.setdefault((ap, sta, cap), []).append(h)

    # Process per capture
    for cap in manifest.get("source_captures", []):
        cap_path = cap.get("path")
        if not cap_path:
            continue
        try:
            lines = _rt(hs_fields, cap_path, hs_filter)
        except Exception:
            continue
        # State: current session index per (ap,sta)
        cur = {}
        frames = {}
        def sanitize(mac: str) -> str:
            return (mac or "").replace(":", "-")
        def finalize(ap: str, sta: str, sess: int):
            key = (ap, sta, sess)
            fl = frames.get(key)
            if not fl:
                return
            start = int(fl[0])
            essid = fs_safe(bssid_to_essid.get(ap, "Unknown"))
            hs_dir = ensure_dir(artifacts_dir, "handshakes", essid)
            outf = f"hs_{sanitize(sta)}_{sanitize(ap)}_f{start:06d}.pcapng"
            outp = os.path.join(hs_dir, outf)
            fexpr = " or ".join(f"frame.number=={int(n)}" for n in fl)
            try:
                subprocess.run(["tshark", "-nr", cap_path, "-Y", fexpr, "-w", outp, "-F", "pcapng"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if os.path.exists(outp) and os.path.getsize(outp) > 24:
                    # attach to first available handshake entry for this (ap,sta,cap)
                    for h in hs_slots.get((ap, sta, cap_path), []):
                        if not h.get("path"):
                            h["path"] = os.path.relpath(outp, os.path.dirname(artifacts_dir))
                            break
                else:
                    try:
                        os.remove(outp)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                frames.pop(key, None)

        for ln in lines:
            parts = (ln.split("|") + [""] * 5)[:5]
            fno, bssid, sa, da, msg = [p.strip() for p in parts]
            ap = (bssid or "").lower()
            sa = (sa or "").lower(); da = (da or "").lower()
            if not ap:
                continue
            try:
                m = int(msg)
            except Exception:
                continue
            sta = da if sa == ap else sa
            if not sta or sta == "ff:ff:ff:ff:ff:ff":
                continue
            key = (ap, sta)
            if m == 1:
                if key in cur and cur[key] > 0 and frames.get((ap, sta, cur[key])):
                    finalize(ap, sta, cur[key])
                cur[key] = cur.get(key, 0) + 1
            if key not in cur or cur[key] == 0:
                cur[key] = 1
            frames.setdefault((ap, sta, cur[key]), []).append(fno)
            if m == 4:
                finalize(ap, sta, cur[key])
        # Finalize any open sessions
        for (ap, sta), sess in list(cur.items()):
            finalize(ap, sta, sess)

    # Identities aggregate per network and reference in manifest
    id_base = os.path.join(artifacts_dir, "identities")
    for net in manifest.get("networks", []):
        essid = fs_safe(net.get("essid", ""))
        values = set()
        for b in net.get("bssids", []):
            for c in b.get("clients", []):
                for e in c.get("artifacts", {}).get("eap_identities", []):
                    v = (e.get("value") or "").strip()
                    if v:
                        values.add(v)
        if values:
            ndir = ensure_dir(id_base, essid)
            fpath = os.path.join(ndir, "identities.txt")
            try:
                with open(fpath, "w", encoding="utf-8") as fh:
                    for v in sorted(values):
                        fh.write(v + "\n")
                # reference in manifest at network level
                net.setdefault("artifacts", {})["identities"] = {
                    "path": os.path.relpath(fpath, os.path.dirname(artifacts_dir))
                }
            except Exception:
                pass
