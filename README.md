# AirSleuth

AirSleuth is a modular Wi-Fi penetration testing toolkit designed to parse, analyze, and act on wireless capture files.
Currently, it includes the **Profile Tool**, which processes `.pcap`/`.pcapng` files to generate a structured JSON
manifest containing detailed information about detected networks, clients, and potential attack surfaces.

Future versions of this repository will include:
- **BPF Creation Tool** – Builds optimized Berkeley Packet Filters for targeted capture using tools like `hcxdumptool`.
- **Attack Suggestion Tool** – Uses the profile data to suggest relevant Wi-Fi attacks based on network configurations.

---

## Features

- Parses capture files for:
  - BSSIDs, ESSIDs, and vendor information
  - Security capabilities (AKM, cipher suites, PMF)
  - WPS information and configuration state
  - EAP identities
  - WPA2/WPA3 PMKIDs and EAPOL handshakes
  - Associated clients and metadata
- Supports merging multiple capture files into a single manifest
- Outputs structured, deduplicated JSON for further analysis or tooling

---

## Installation

You can install AirSleuth in an isolated environment using `pipx`:

```bash
pipx install .
```

Or directly from a local clone:

```bash
git clone https://github.com/yourusername/airsleuth.git
cd airsleuth
pipx install .
```

---

## Usage

### Profile Tool

Generate a manifest from one or more capture files:

```bash
airsleuth profile -f capture1.pcapng -f capture2.pcap
```

Example output location:

```bash
manifest.json
```

---

## Example Output

```json
{
  "schema_version": "1.0",
  "generated_ts": "2025-08-10T10:31:15Z",
  "networks": [
    {
      "essid": "ExampleWiFi",
      "bssids": [
        {
          "bssid": "00:11:22:33:44:55",
          "vendor": "Example Corp",
          "security": {
            "akm": ["PSK"],
            "pairwise": ["CCMP"],
            "pmf": {"mfpc": true, "mfpr": false}
          },
          "clients": [
            {
              "mac": "aa:bb:cc:dd:ee:ff",
              "vendor": "Randomized (LAA)",
              "artifacts": {
                "pmkids": [],
                "handshakes": []
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Roadmap

- [ ] Add BPF generation tool
- [ ] Add attack suggestion tool

---

## License

This project is licensed under the MIT License.
