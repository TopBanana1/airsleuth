from __future__ import annotations

def _dedup_list(items, key_fields):
    seen = set()
    out = []
    for it in items or []:
        key = tuple(it.get(k) for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out

def _merge_security_auth(old_sec: dict, new_sec: dict) -> dict:
    if not old_sec:
        return new_sec or {}
    if not new_sec:
        return old_sec
    oa = (old_sec.get("authentication") or {}).get("eap")
    na = (new_sec.get("authentication") or {}).get("eap")
    if not oa and not na:
        return old_sec or new_sec
    # Merge EAP successes/failures and by_type counters
    merged = dict(old_sec)
    eap = {"successes": 0, "failures": 0, "by_type": {}}
    if oa:
        eap["successes"] += int(oa.get("successes", 0))
        eap["failures"] += int(oa.get("failures", 0))
        for k, v in (oa.get("by_type") or {}).items():
            cur = eap["by_type"].setdefault(k, {"successes": 0, "failures": 0})
            cur["successes"] += int(v.get("successes", 0))
            cur["failures"] += int(v.get("failures", 0))
    if na:
        eap["successes"] += int(na.get("successes", 0))
        eap["failures"] += int(na.get("failures", 0))
        for k, v in (na.get("by_type") or {}).items():
            cur = eap["by_type"].setdefault(k, {"successes": 0, "failures": 0})
            cur["successes"] += int(v.get("successes", 0))
            cur["failures"] += int(v.get("failures", 0))
    merged.setdefault("authentication", {})["eap"] = eap
    return merged

def _merge_wps(ow, nw):
    # Normalize to either False or dict
    if not ow and not nw:
        return False
    if ow and not nw:
        return ow
    if nw and not ow:
        return nw
    # Both dicts
    o = dict(ow)
    n = dict(nw)
    # state priority: configured > unconfigured > None/other
    order = {"configured": 2, "unconfigured": 1}
    so = o.get("state"); sn = n.get("state")
    if (so in order) or (sn in order):
        if order.get(sn, 0) > order.get(so, 0):
            state = sn
        else:
            state = so
    else:
        state = so or sn
    cm = sorted(set((o.get("config_methods") or []) + (n.get("config_methods") or [])))
    srm = sorted(set((o.get("selected_registrar_config_methods") or []) + (n.get("selected_registrar_config_methods") or [])))
    versions = sorted(set((o.get("versions") or []) + (n.get("versions") or [])))
    return {
        "state": state,
        "config_methods": cm,
        "selected_registrar": bool(o.get("selected_registrar") or n.get("selected_registrar")),
        "selected_registrar_config_methods": srm,
        "ap_setup_locked": bool(o.get("ap_setup_locked") or n.get("ap_setup_locked")),
        "versions": versions,
    }

def _merge_security(os: dict, ns: dict) -> dict:
    if not os:
        os = {}
    if not ns:
        ns = {}
    merged = {}
    # counts: sum (akm/pairwise)
    oac = os.get("akm_counts") or {}
    nac = ns.get("akm_counts") or {}
    merged["akm_counts"] = {k: int(oac.get(k, 0)) + int(nac.get(k, 0)) for k in set(oac) | set(nac)}
    opc = os.get("pairwise_counts") or {}
    npc = ns.get("pairwise_counts") or {}
    merged["pairwise_counts"] = {k: int(opc.get(k, 0)) + int(npc.get(k, 0)) for k in set(opc) | set(npc)}
    # pmf counts: sum individual counters (default 0)
    opmf = os.get("pmf") or {}
    npmf = ns.get("pmf") or {}
    merged["pmf"] = {
        "mfpc_true": int(opmf.get("mfpc_true", 0)) + int(npmf.get("mfpc_true", 0)),
        "mfpc_false": int(opmf.get("mfpc_false", 0)) + int(npmf.get("mfpc_false", 0)),
        "mfpr_true": int(opmf.get("mfpr_true", 0)) + int(npmf.get("mfpr_true", 0)),
        "mfpr_false": int(opmf.get("mfpr_false", 0)) + int(npmf.get("mfpr_false", 0)),
    }
    # flags: OR
    merged["ft"] = bool(os.get("ft") or ns.get("ft"))
    merged["owe"] = bool(os.get("owe") or ns.get("owe"))
    # wps: detailed merge
    merged["wps"] = _merge_wps(os.get("wps"), ns.get("wps"))
    # authentication: take merged from original inputs, attach into merged
    auth_full = _merge_security_auth(os or {}, ns or {})
    eap = (auth_full.get("authentication") or {}).get("eap")
    if eap:
        merged.setdefault("authentication", {})["eap"] = eap
    return merged

def _iso_min(a: str | None, b: str | None) -> str | None:
    if a and b:
        return a if a <= b else b
    return a or b

def _iso_max(a: str | None, b: str | None) -> str | None:
    if a and b:
        return a if a >= b else b
    return a or b

def merge_manifests(old, new):
    by_essid = {n["essid"]: n for n in old.get("networks", [])}
    for nn in new.get("networks", []):
        essid = nn["essid"]
        if essid not in by_essid:
            by_essid[essid] = nn
            continue
        cur_net = by_essid[essid]
        cur_by_b = {b["bssid"]: b for b in cur_net.get("bssids", [])}
        for nb in nn.get("bssids", []):
            b = nb["bssid"]
            if b not in cur_by_b:
                cur_by_b[b] = nb
                continue
            cb = cur_by_b[b]
            # channels: sum samples, preserve dfs if any side marked true
            ch_map = {c["ch"]: dict(c) for c in cb.get("channels", [])}
            for c in nb.get("channels", []) or []:
                cur = ch_map.get(c["ch"], {"ch": c["ch"], "samples": 0, "dfs": bool(c.get("dfs"))})
                cur["samples"] = cur.get("samples", 0) + int(c.get("samples", 0))
                cur["dfs"] = bool(cur.get("dfs")) or bool(c.get("dfs"))
                ch_map[c["ch"]] = cur
            cb["channels"] = sorted(ch_map.values(), key=lambda x: -x.get("samples", 0))
            # recompute stickiness from merged channels
            total_samples = sum(c.get("samples", 0) for c in cb["channels"]) or 0
            if total_samples > 0:
                mx = max(c.get("samples", 0) for c in cb["channels"]) if cb["channels"] else 0
                stickiness = (mx / total_samples) if mx else 0.0
                try:
                    stickiness = float(f"{stickiness:.2f}")
                except Exception:
                    pass
            else:
                stickiness = None
            # vendor
            if not cb.get("vendor") and nb.get("vendor"): cb["vendor"] = nb["vendor"]
            # seen_in: sum frames count
            seen_map = {it["capture"]: it for it in cb.get("seen_in", [])}
            for it in nb.get("seen_in", []):
                m = seen_map.setdefault(it["capture"], {"capture": it["capture"], "frames": {"count":0}})
                m["frames"]["count"] += it.get("frames", {}).get("count", 0)
            cb["seen_in"] = sorted(seen_map.values(), key=lambda x: x.get("capture", ""))
            # rf: rssi_max = max, stickiness prefer higher fidelity (max)
            try:
                cb.setdefault("rf", {})["rssi_max"] = max(
                    x for x in [cb.get("rf", {}).get("rssi_max"), nb.get("rf", {}).get("rssi_max")] if x is not None
                )
            except ValueError:
                pass
            cb.setdefault("rf", {})["stickiness"] = stickiness
            # security merge (akm, pairwise, pmf, ft/owe, wps, authentication)
            cb["security"] = _merge_security(cb.get("security", {}), nb.get("security", {}))
            # artifacts (BSSID-level)
            o_art = cb.get("artifacts", {})
            n_art = nb.get("artifacts", {})
            # server_certificates: dedup by fingerprint+capture
            sc = _dedup_list((o_art.get("server_certificates", []) + n_art.get("server_certificates", [])), ["fingerprint", "capture"]) 
            merged_art = {}
            if sc:
                merged_art["server_certificates"] = sc
            # orphan_handshakes: sum msgs counts
            oh_o = o_art.get("orphan_handshakes") or {}
            oh_n = n_art.get("orphan_handshakes") or {}
            if oh_o or oh_n:
                ty = oh_o.get("type") or oh_n.get("type") or "EAPOL-4W"
                msgs = {}
                for k in ("1","2","3","4"):
                    msgs[k] = int((oh_o.get("msgs", {}).get(k) or 0)) + int((oh_n.get("msgs", {}).get(k) or 0))
                merged_art["orphan_handshakes"] = {"type": ty, "msgs": msgs}
            if merged_art:
                cb["artifacts"] = merged_art
            # clients (BSSID-level) merge by MAC
            obc = {c.get("mac"): dict(c) for c in cb.get("clients", []) if c.get("mac")}
            for c in nb.get("clients", []) or []:
                mac = c.get("mac")
                if not mac:
                    continue
                if mac not in obc:
                    nc = dict(c)
                    nc.pop("aid", None)  # drop legacy field if present
                    obc[mac] = nc
                    continue
                cur = obc[mac]
                cur.pop("aid", None)  # ensure removed
                # vendor
                if (not cur.get("vendor")) and c.get("vendor"):
                    cur["vendor"] = c["vendor"]
                # times
                cur["first_seen"] = _iso_min(cur.get("first_seen"), c.get("first_seen"))
                cur["last_seen"] = _iso_max(cur.get("last_seen"), c.get("last_seen"))
                # totals
                cur["total_frames"] = int(cur.get("total_frames", 0)) + int(c.get("total_frames", 0))
                # evidence (sum non-artifact counts; artifacts recomputed post merge)
                evid = dict(cur.get("evidence", {}))
                for k, v in (c.get("evidence", {}) or {}).items():
                    if k in ("pmkids", "handshakes", "certificates"):
                        continue
                    evid[k] = int(evid.get(k, 0)) + int(v or 0)
                # artifacts union + de-dup
                oa = cur.get("artifacts", {}) or {}
                na = c.get("artifacts", {}) or {}
                pmkids = _dedup_list((oa.get("pmkids", []) + na.get("pmkids", [])), ["pmkid", "source", "capture"]) 
                hss = _dedup_list((oa.get("handshakes", []) + na.get("handshakes", [])), ["replay_counter", "capture"]) 
                client_certs = _dedup_list((oa.get("client_certificates", []) + na.get("client_certificates", [])), ["fingerprint", "capture"]) 
                ids = _dedup_list((oa.get("eap_identities", []) + na.get("eap_identities", [])), ["value", "capture"]) 
                artifacts = {
                    "pmkids": pmkids,
                    "handshakes": hss,
                    "client_certificates": client_certs,
                    "eap_identities": ids,
                }
                cur["artifacts"] = artifacts
                # recompute artifact-related evidence
                evid["pmkids"] = len(pmkids)
                evid["handshakes"] = len(hss)
                evid["certificates"] = len(client_certs)
                cur["evidence"] = evid
                # probed_essids union
                pe = set(cur.get("probed_essids", []) or []) | set(c.get("probed_essids", []) or [])
                cur["probed_essids"] = sorted(pe)
            cb["clients"] = sorted(obc.values(), key=lambda x: (-int(x.get("total_frames", 0)), x.get("mac", "")))
        cur_net["bssids"] = sorted(cur_by_b.values(), key=lambda x: x.get("bssid", ""))
        cur_net["enterprise_observed"] = bool(cur_net.get("enterprise_observed")) or bool(nn.get("enterprise_observed"))
    old["networks"] = list(by_essid.values())
    # Sort networks by ESSID to mirror builder order
    old["networks"].sort(key=lambda n: n.get("essid", ""))
    # stats merge
    old_stats = old.get("stats", {})
    new_stats = new.get("stats", {})
    old_stats["channels_seen"] = sorted(set(old_stats.get("channels_seen", [])) | set(new_stats.get("channels_seen", [])))
    old_stats["frequencies_seen"] = sorted(set(old_stats.get("frequencies_seen", [])) | set(new_stats.get("frequencies_seen", [])))
    # total_bssids recompute
    merged_bssids = {b["bssid"] for net in old.get("networks", []) for b in net.get("bssids", [])}
    old_stats["total_bssids"] = len(merged_bssids)
    old["stats"] = old_stats
    # source_captures: unique by sha256 if present
    seen = set()
    sc = []
    for c in (old.get("source_captures", []) + new.get("source_captures", [])):
        key = c.get("sha256") or (c.get("path"),)
        if key in seen: continue
        seen.add(key); sc.append(c)
    old["source_captures"] = sc

    # clients (top-level): merge by MAC
    by_mac = {c.get("mac"): dict(c) for c in old.get("clients", []) if c.get("mac")}
    for c in new.get("clients", []) or []:
        mac = c.get("mac")
        if not mac:
            continue
        if mac not in by_mac:
            by_mac[mac] = dict(c)
            continue
        cur = by_mac[mac]
        # vendor: keep existing, else take new
        if (not cur.get("vendor")) and c.get("vendor"):
            cur["vendor"] = c["vendor"]
        # times: min/max on ISO strings
        cur["first_seen"] = _iso_min(cur.get("first_seen"), c.get("first_seen"))
        cur["last_seen"] = _iso_max(cur.get("last_seen"), c.get("last_seen"))
        # totals
        cur["total_frames"] = int(cur.get("total_frames", 0)) + int(c.get("total_frames", 0))
        # evidence counts per label
        evid = dict(cur.get("evidence", {}))
        for k, v in (c.get("evidence", {}) or {}).items():
            evid[k] = int(evid.get(k, 0)) + int(v or 0)
        cur["evidence"] = evid
        # probed_essids union
        pe = set(cur.get("probed_essids", []) or []) | set(c.get("probed_essids", []) or [])
        cur["probed_essids"] = sorted(pe)
    old["clients"] = sorted(by_mac.values(), key=lambda x: (-int(x.get("total_frames", 0)), x.get("mac", "")))
    # Remove legacy top-level artifacts field if present
    if "artifacts" in old:
        old.pop("artifacts", None)
    return old
