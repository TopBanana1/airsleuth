from __future__ import annotations

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
            # channels: sum samples
            ch_map = {c["ch"]: c for c in cb.get("channels", [])}
            for c in nb.get("channels", []):
                ch_map[c["ch"]] = {"ch": c["ch"], "samples": ch_map.get(c["ch"], {"samples":0})["samples"] + c["samples"]}
            cb["channels"] = sorted(ch_map.values(), key=lambda x: -x["samples"])
            # vendor
            if not cb.get("vendor") and nb.get("vendor"): cb["vendor"] = nb["vendor"]
            # seen_in: sum frames count
            seen_map = {it["capture"]: it for it in cb.get("seen_in", [])}
            for it in nb.get("seen_in", []):
                m = seen_map.setdefault(it["capture"], {"capture": it["capture"], "frames": {"count":0}})
                m["frames"]["count"] += it.get("frames", {}).get("count", 0)
            cb["seen_in"] = list(seen_map.values())
        cur_net["bssids"] = list(cur_by_b.values())
        cur_net["enterprise_observed"] = bool(cur_net.get("enterprise_observed")) or bool(nn.get("enterprise_observed"))
    old["networks"] = list(by_essid.values())
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
    return old
