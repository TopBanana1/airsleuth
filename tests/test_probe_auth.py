import types
from pathlib import Path

import pytest


def make_stub_run_tshark(fixtures):
    def _run(fields, capture, dfilter):
        key = tuple(fields)
        return fixtures.get(key, [])
    return _run


@pytest.fixture()
def temp_caps(tmp_path: Path):
    # Create small placeholder capture files; contents don't matter for stub
    p1 = tmp_path / "cap1.pcapng"
    p1.write_bytes(b"stub")
    p2 = tmp_path / "cap2.pcapng"
    p2.write_bytes(b"stub")
    return [str(p1), str(p2)]


def test_probe_and_auth(monkeypatch, temp_caps):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    from airsleuth.build.assemble import build_manifest
    from airsleuth.io import tshark

    # Shortcuts to canonical field lists
    MGMT_FIELDS = tshark.MGMT_FIELDS
    JOIN_FIELDS = tshark.JOIN_FIELDS
    DATA_FIELDS = tshark.DATA_FIELDS
    ID_FIELDS = tshark.ID_FIELDS
    PMKID_EAPOL_FIELDS = tshark.PMKID_EAPOL_FIELDS
    PMKID_ASSOC_FIELDS = tshark.PMKID_ASSOC_FIELDS
    CERT_FIELDS = tshark.CERT_FIELDS
    PROBE_REQ_FIELDS = tshark.PROBE_REQ_FIELDS
    AUTH_FIELDS = tshark.AUTH_FIELDS

    # Build fixtures keyed by fields tuple; values are lines to return
    fixtures = {}
    # Mgmt: Beacon for ESSID MyCorp (WPA2-Enterprise), BSSID 00:11:22:33:44:55
    mgmt_line = "|".join([
        "MyCorp",                 # wlan.ssid
        "00:11:22:33:44:55",     # wlan.bssid
        "ACME Corp",             # vendor
        "36",                    # channel
        "5180",                  # freq
        "1",                     # akm (802.1X)
        "4",                     # pairwise (CCMP)
        "1",                     # mfpc
        "0",                     # mfpr
        "0080",                  # rsn_caps
        "", "", "", "", "",  # wps fields
        "", "",
        "-45",                   # rssi
    ])
    fixtures[tuple(MGMT_FIELDS)] = [mgmt_line]

    # Assoc/EAPOL minimal: one EAPOL message referencing BSSID and STA
    join_line = "|".join([
        "1710000000.0",           # time
        "00:11:22:33:44:55",     # bssid
        "aa:bb:cc:dd:ee:ff",     # sa
        "ACME Client",           # sa vendor
        "00:11:22:33:44:55",     # da
        "12",                    # subtype (deauth -> counts as client evidence)
        "1",                     # msgnr (treated as eapol label)
    ])
    fixtures[tuple(JOIN_FIELDS)] = [join_line]

    # Data frames: none needed
    fixtures[tuple(DATA_FIELDS)] = []

    # Identity, PMKID, Certs: none needed
    fixtures[tuple(ID_FIELDS)] = []
    fixtures[tuple(PMKID_EAPOL_FIELDS)] = []
    fixtures[tuple(PMKID_ASSOC_FIELDS)] = []
    fixtures[tuple(CERT_FIELDS)] = []

    # Probe Request: STA probes for CafeWiFi and hidden
    probe_lines = [
        "|".join(["1710000001.0", "aa:bb:cc:dd:ee:ff", "ACME Client", "ff:ff:ff:ff:ff:ff", "CafeWiFi"]),
        "|".join(["1710000002.0", "aa:bb:cc:dd:ee:ff", "ACME Client", "ff:ff:ff:ff:ff:ff", "000000000000"]),
    ]
    fixtures[tuple(PROBE_REQ_FIELDS)] = probe_lines

    # EAP auth: one success for PEAP
    auth_line = "|".join([
        "1710000003.0",
        "00:11:22:33:44:55",
        "aa:bb:cc:dd:ee:ff",
        "00:11:22:33:44:55",
        "3",                      # eap.code == Success
        "25",                     # eap.type
        "PEAP",                   # eap.type.name
    ])
    fixtures[tuple(AUTH_FIELDS)] = [auth_line]

    monkeypatch.setattr(tshark, "run_tshark", make_stub_run_tshark(fixtures))

    # Build
    m = build_manifest(temp_caps, essids=[], progress=None)

    # Networks present
    assert m["networks"], "Expected at least one network"
    net = m["networks"][0]
    bssid = net["bssids"][0]
    # Authentication per-type counts
    auth = bssid["security"]["authentication"]["eap"]
    assert auth["successes"] == 1 and auth["failures"] == 0
    assert auth["by_type"].get("PEAP", {}).get("successes") == 1

    # Top-level clients includes STA with probed ESSIDs
    top_clients = m.get("clients", [])
    macs = [c["mac"] for c in top_clients]
    assert "aa:bb:cc:dd:ee:ff" in macs
    c = next(c for c in top_clients if c["mac"] == "aa:bb:cc:dd:ee:ff")
    assert "CafeWiFi" in c["probed_essids"]
    assert "<Hidden>" in c["probed_essids"]

