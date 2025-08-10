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
from ..io.utils import ascii_label_pref, sha256_file, mac_is_laa

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

    counts = pmf
    return {
        "akm": sorted(akms.keys()),
        "pairwise": sorted(pairwise.keys()),
        "pmf": {
            "mfpc": (
                True
                if counts["mfpc_true"] > 0
                else (False if counts["mfpc_false"] > 0 else None)
            ),
            "mfpr": (
                True
                if counts["mfpr_true"] > 0
                else (False if counts["mfpr_false"] > 0 else None)
            ),
            "counts": counts,
        },
        "ft": any(
            a in ("FT-802.1X", "FT-PSK", "FT-SAE", "FT-OWE") for a in akms.keys()
        ),
        "owe": any(a in ("OWE", "FT-OWE") for a in akms.keys()),
        "wps": wps_summary,
    }

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

# --------- main builder ----------
def build_manifest(files: list[str], essids: list[str], progress=None):
    by_bssid_rows: dict[str, list[dict]] = defaultdict(list)
    essid_to_bssids: dict[str, set[str]] = defaultdict(set)
    channels_seen, freqs_seen = set(), set()
    mgmt_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Pass 1: mgmt (parallel)
    task_mgmt = None
    if progress:
        task_mgmt = progress.add_task("[cyan]Mgmt scan", total=len(files))

    mgmt_tasks = [(f, MGMT_FIELDS, MGMT_FILTER) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, mgmt_tasks):
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
            if progress:
                progress.update(task_mgmt, advance=1)

    selected = set(essids) if essids else set(essid_to_bssids.keys())
    missing = [e for e in sorted(selected) if e not in essid_to_bssids]
    if missing:
        raise ValueError("No matching ESSIDs found: " + ", ".join(missing))

    selected_bssids = set()
    for e in selected:
        selected_bssids |= essid_to_bssids.get(e, set())
    addrf = build_addr_or_filter(selected_bssids)

    # Pass 2: Assoc/EAPOL (parallel, filtered)
    join_filter = f"({JOIN_FILTER_BASE}) && ({addrf})" if addrf else JOIN_FILTER_BASE
    task_join = None
    if progress:
        task_join = progress.add_task("[cyan]Assoc/EAPOL", total=len(files))

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
                "aid": None,
                "evidence": defaultdict(int),
                "first": None,
                "last": None,
                "total": 0,
                "artifacts": {"eap_identities": [], "pmkids": [], "handshakes": []},
            }
        )
    )
    orphan_hs = defaultdict(lambda: {"msgs": {"1": 0, "2": 0, "3": 0, "4": 0}})

    join_tasks = [(f, JOIN_FIELDS, join_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, join_tasks):
            for ln in lines:
                parts = (ln.split("|") + [""] * 8)[:8]
                t, bssid, sa, sa_vendor, da, subtype, aid, msgnr = [
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
                rec["evidence"][label] += 1
                rec["total"] += 1
                if ts is not None:
                    rec["first"] = ts if (rec["first"] is None or ts < rec["first"]) else rec["first"]
                    rec["last"] = ts if (rec["last"] is None or ts > rec["last"]) else rec["last"]
                if (not rec["vendor"]) and sa_vendor:
                    rec["vendor"] = sa_vendor
                if label in ("assoc_resp", "reassoc_resp") and aid:
                    try:
                        rec["aid"] = int(aid, 0) if aid.startswith("0x") else int(aid)
                    except Exception:
                        pass

            if progress:
                progress.update(task_join, advance=1)

    # Pass 3: Data frames (parallel, filtered)
    data_filter = f"({DATA_FILTER_BASE}) && ({addrf})" if addrf else DATA_FILTER_BASE
    task_data = None
    if progress:
        task_data = progress.add_task("[cyan]Data frames", total=len(files))

    data_tasks = [(f, DATA_FIELDS, data_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, data_tasks):
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

            if progress:
                progress.update(task_data, advance=1)

    # Artifact passes (parallel, filtered)
    id_filter = f"({ID_FILTER_BASE}) && ({addrf})" if addrf else ID_FILTER_BASE
    pmkid_eapol_filter = f"({PMKID_EAPOL_FILTER_BASE}) && ({addrf})" if addrf else PMKID_EAPOL_FILTER_BASE
    pmkid_assoc_filter = f"({PMKID_ASSOC_FILTER_BASE}) && ({addrf})" if addrf else PMKID_ASSOC_FILTER_BASE
    cert_filter = f"({CERT_FILTER_BASE}) && ({addrf})" if addrf else CERT_FILTER_BASE

    # EAP identities
    task_id = None
    if progress:
        task_id = progress.add_task("[cyan]EAP identities", total=len(files))
    id_tasks = [(f, ID_FIELDS, id_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, id_tasks):
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
            if progress:
                progress.update(task_id, advance=1)

    
    # PMKID (EAPOL msg1)
    task_pmk1 = None
    if progress:
        task_pmk1 = progress.add_task("[cyan]PMKID (EAPOL)", total=len(files))
    pmk1_tasks = [(f, PMKID_EAPOL_FIELDS, pmkid_eapol_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, pmk1_tasks):
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
            if progress:
                progress.update(task_pmk1, advance=1)

    # PMKID (Assoc/Reassoc)
    task_pmk2 = None
    if progress:
        task_pmk2 = progress.add_task("[cyan]PMKID (Assoc/Reassoc)", total=len(files))
    pmk2_tasks = [(f, PMKID_ASSOC_FIELDS, pmkid_assoc_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, pmk2_tasks):
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
            if progress:
                progress.update(task_pmk2, advance=1)

    # EAP-TLS certificates
    task_cert = None
    if progress:
        task_cert = progress.add_task("[cyan]EAP-TLS certs", total=len(files))
    server_certs = defaultdict(list)  # bssid -> [{fingerprint, capture}]
    cert_tasks = [(f, CERT_FIELDS, cert_filter) for f in files]
    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, cert_tasks):
            for ln in lines:
                t, bssid, sa, da, certhex = (ln.split("|") + [""] * 5)[:5]
                bssid = _derive_bssid_if_empty(bssid, sa, da, selected_bssids)
                if not bssid or not certhex:
                    continue
                sa = (sa or "").lower()
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
                    server_certs[bssid].append({"fingerprint": fp, "capture": fpath})
            if progress:
                progress.update(task_cert, advance=1)

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

    task_hs = None
    if progress:
        task_hs = progress.add_task("[cyan]EAPOL handshakes", total=len(files))
    hs_tasks = [(f, hs_fields, hs_filter) for f in files]

    with ThreadPoolExecutor() as ex:
        for fpath, lines in ex.map(_tshark_worker, hs_tasks):
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

            if progress:
                progress.update(task_hs, advance=1)

    _dedupe_pmkids_in_clients(clients)
    _dedupe_eap_identities(clients)

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
                clist.append(
                    {
                        "mac": sta,
                        "vendor": vendor_val,
                        "aid": rec["aid"],
                        "evidence": dict(rec["evidence"]),
                        "first_seen": rec["first"],
                        "last_seen": rec["last"],
                        "total_frames": rec["total"],
                        "artifacts": rec["artifacts"],
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
                "rssi_estimate": rssi_est,
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
                        for a in b.get("security", {}).get("akm", [])
                    )
                    for b in bssid_entries
                ),
                "bssids": bssid_entries,
            }
        )

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
        "artifacts": {},
    }
    return manifest

def dumps_json(obj) -> bytes:
    return orjson.dumps(obj, option=orjson.OPT_INDENT_2)
