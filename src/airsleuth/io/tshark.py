from __future__ import annotations
import subprocess, sys
from typing import Iterable, List, Dict, Tuple

# -------- helpers

def _or_eq(field: str, values: Iterable[str]) -> str:
    """Build '(field==v1 || field==v2 ...)' safely for tshark."""
    vals = [v.strip().lower() for v in values if v and v.strip()]
    if not vals:
        return ""
    parts = [f'{field}=={v}' for v in vals]
    return "(" + " || ".join(parts) + ")"

def run_tshark(fields: List[str], capture: str, display_filter: str) -> List[str]:
    """
    Thin wrapper around tshark. Returns decoded lines (may be empty on no matches).
    Uses -Q for quiet, -n -N m to limit name resolution to manuf.
    """
    args = [
        "tshark","-Q","-n","-N","m",
        "-r", capture,
        "-Y", display_filter,
        "-T","fields","-E","separator=|",
    ]
    for f in fields:
        args += ["-e", f]
    try:
        out = subprocess.check_output(args, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        sys.stderr.write("tshark not found in PATH.\n")
        raise
    except subprocess.CalledProcessError:
        # display filter mismatch or zero results -> empty
        return []

# -------- centralized field sets & base filters

# Beacons(8) + Probe Responses(5)
MGMT_FILTER = "(wlan.fc.type==0 && (wlan.fc.type_subtype==8 || wlan.fc.type_subtype==5))"
MGMT_FIELDS = [
    "wlan.ssid",
    "wlan.bssid",
    "wlan.bssid.oui_resolved",
    "wlan_radio.channel",
    "wlan_radio.frequency",
    "wlan.rsn.akms.type",
    "wlan.rsn.pcs.type",
    "wlan.rsn.capabilities.mfpc",
    "wlan.rsn.capabilities.mfpr",
    "wlan.rsn.capabilities",
    "wps.wifi_protected_setup_state",
    "wps.config_methods",
    "wps.selected_registrar",
    "wps.selected_registrar_config_methods",
    "wps.ap_setup_locked",
    "wps.version",
    "wps.ext.version2",
    "wlan_radio.signal_dbm",           # NEW: for RF helpers
]

# Assoc/Disassoc/Auth/Deauth/Probe(Req|Resp) + EAPOL
JOIN_FILTER_BASE = (
    "(wlan.fc.type==0 && "
    "("
    "wlan.fc.type_subtype==0 || "   # Assoc Req
    "wlan.fc.type_subtype==1 || "   # Assoc Resp
    "wlan.fc.type_subtype==2 || "   # Reassoc Req
    "wlan.fc.type_subtype==3 || "   # Reassoc Resp
    "wlan.fc.type_subtype==10 || "  # Disassoc
    "wlan.fc.type_subtype==12"      # Deauth
    ")) || eapol"
)
JOIN_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa","wlan.sa.oui_resolved",
    "wlan.da",
    "wlan.fc.type_subtype",
    # NOTE: wlan_mgt.aid is not present in all builds; omit to avoid "Some fields aren't valid"
    # "wlan_mgt.aid",
    "wlan_rsna_eapol.keydes.msgnr",
]

DATA_FILTER_BASE = "wlan.fc.type==2 && (wlan.fc.tods==1 || wlan.fc.fromds==1)"
DATA_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.ta","wlan.ta.oui_resolved",
    "wlan.ra",
    "wlan.fc.tods","wlan.fc.fromds",
]

# -------- artifacts

# 802.1X Identity Responses
ID_FILTER_BASE = "eap && eap.type==1 && eap.code==2"
ID_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "eap.identity",
]

# PMKID from EAPOL M1 (prefer byte-carrying fields; do NOT use wlan.rsn.pmkid.list)
PMKID_EAPOL_FILTER_BASE = (
    "eapol && wlan_rsna_eapol.keydes.msgnr==1 && "
    "(wlan.rsn.ie.pmkid || wlan.pmkid.akms)"
)
PMKID_EAPOL_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "wlan_rsna_eapol.keydes.msgnr",
    "wlan.rsn.ie.pmkid",   # bytes if present
    "wlan.pmkid.akms",     # bytes on some builds
]

# PMKID inside (Re)Assoc Req/Resp RSN IE
PMKID_ASSOC_FILTER_BASE = (
    "(wlan.fc.type==0) && "
    "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2 || "
    " wlan.fc.type_subtype==1 || wlan.fc.type_subtype==3) && "
    "(wlan.rsn.ie.pmkid || wlan.pmkid.akms)"
)
PMKID_ASSOC_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "wlan.rsn.ie.pmkid",
    "wlan.pmkid.akms",
]

# TLS server certs (EAP-TLS)
CERT_FILTER_BASE = "eap && tls.handshake.certificate"
CERT_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "eap.code",
    "tls.handshake.certificate",
]

# PMF-protected management frames from clients (SA != BSSID)
# PMF-protected management frames from clients (SA != BSSID)
PMF_MGMT_FILTER_BASE = "wlan.fc.type==0 && wlan.fc.protected==1 && wlan.bssid && wlan.sa!=wlan.bssid"
PMF_MGMT_FIELDS = [
    "wlan.bssid",
    "wlan.sa",
]

# All management frames (protected or not) from clients for PMF stats
PMF_MGMT_ALL_FILTER_BASE = "wlan.fc.type==0 && wlan.bssid && wlan.sa!=wlan.bssid"
PMF_MGMT_ALL_FIELDS = [
    "wlan.bssid",
    "wlan.sa",
    "wlan.fc.protected",
]

# Probe Requests (client-side SSID discovery)
PROBE_REQ_FILTER = "(wlan.fc.type==0 && wlan.fc.type_subtype==4)"
PROBE_REQ_FIELDS = [
    "frame.time_epoch",
    "wlan.sa", "wlan.sa.oui_resolved",
    "wlan.da",
    "wlan.ssid",
]

# EAP authentication overview (success/failure and types)
AUTH_FILTER_BASE = "eap && (eap.code==1 || eap.code==2 || eap.code==3 || eap.code==4)"
AUTH_FIELDS = [
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa", "wlan.da",
    "eap.code",
    "eap.type",
    "eap.type.name",
]
