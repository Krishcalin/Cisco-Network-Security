<p align="center">
  <img src="docs/banner.svg" alt="Network Security Scanner" width="800"/>
</p>

<p align="center">
  <strong>A Python-based security scanner for Cisco switches, routers, wireless access points, and next-generation firewalls</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Cisco-IOS%20%7C%20IOS--XE%20%7C%20NX--OS%20%7C%20FTD-blue?style=flat-square&logo=cisco&logoColor=white"/>
  <img src="https://img.shields.io/badge/checks-128%2B-red?style=flat-square"/>
</p>

---

## Overview

**Network Security Scanner (NSS)** parses Cisco device running-config exports and evaluates them against security baselines from CIS Benchmarks, Cisco hardening guides, and NSA Firepower guidance. It produces an interactive HTML dashboard with findings, severity ratings, and actionable remediation commands.

- **Offline config analysis** — no SNMP, SSH, or API access to devices required
- **Multi-device** — scan router, switch, WAP, and NGFW configs in one run
- **Zero dependencies** — Python 3.8+ stdlib only
- **128+ security checks** across 10 audit modules
- **CIS Benchmark aligned** — mapped to CIS Cisco IOS/IOS-XE and FTD benchmarks

---

## Supported Devices

| Platform | Config Source | Auto-Detection |
|----------|-------------|----------------|
| Cisco IOS Routers | `show running-config` | ✅ |
| Cisco IOS-XE (Catalyst) | `show running-config` | ✅ |
| Cisco NX-OS (Nexus) | `show running-config` | ✅ |
| Cisco Firepower / FTD | `show running-config` or FMC export | ✅ |
| Cisco WLC (AireOS/C9800) | `show run-config` / `show running-config` | ✅ |

---

## Audit Modules (10)

| Module | Key | Checks | Focus |
|--------|-----|--------|-------|
| 🔐 **Management Plane** | `mgmt` | 25 | Passwords, AAA, SSH, VTY, banners, HTTP, login protection |
| 🛡️ **Control Plane** | `ctrl` | 11 | CoPP, routing auth (OSPF/BGP/EIGRP), NTP, STP, CDP |
| 🌐 **Data Plane** | `data` | 9 | uRPF, DHCP snooping, DAI, storm control, ICMP, proxy ARP |
| ⚙️ **Services & Protocols** | `services` | 9 | Unused services, SNMP hardening, TCP keepalives, timestamps |
| 🔒 **Switch Security** | `switch` | 8 | Port security, VLAN, trunk, DTP, BPDU guard, IP source guard |
| 📡 **Wireless Security** | `wireless` | 10 | SSID encryption, WPA2/3, rogue AP, MFP, WLC management |
| 🔥 **NGFW Core** | `ngfw` | 9 | Access control, IPS, AMP, Security Intelligence, SSL decrypt |
| 🔑 **NGFW Platform** | `ngfwplat` | 7 | FTD mgmt access, accounts, FXOS version, DNS inspection |
| 📊 **Logging & Monitoring** | `logging` | 10 | Syslog, buffered logging, SNMP traps, NetFlow, archive |
| 🔐 **Cryptographic** | `crypto` | 10 | SSH keys, ciphers, TLS versions, IPsec, ISAKMP, DH groups |

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/Network-Security-Scanner-NSS.git
cd Network-Security-Scanner-NSS

# Scan sample configs (included)
python nss_scanner.py --data-dir ./sample_configs --output report.html

# Scan your own device configs
python nss_scanner.py --data-dir /path/to/configs --output audit_report.html

# Scan specific modules only
python nss_scanner.py --data-dir ./configs --modules mgmt ctrl crypto

# Filter by severity
python nss_scanner.py --data-dir ./configs --severity HIGH
```

### Exporting Configs from Devices

```
! Router/Switch (IOS/IOS-XE)
Router# terminal length 0
Router# show running-config

! Nexus (NX-OS)
Nexus# show running-config

! Firepower FTD (via CLI)
> show running-config

! WLC (AireOS)
(WLC) > show run-config
```

Save each output as a `.cfg`, `.txt`, or `.conf` file in your data directory.

---

## Available Modules

```
mgmt      — Management Plane (passwords, AAA, SSH, VTY, banners)
ctrl      — Control Plane (CoPP, routing auth, NTP, STP, CDP)
data      — Data Plane (uRPF, DHCP snooping, DAI, storm control)
services  — Services & Protocols (SNMP, unused services, timestamps)
switch    — Switch-Specific (port security, VLAN, trunk, DTP, BPDU guard)
wireless  — Wireless Security (SSID, WPA, rogue AP, MFP, WLC mgmt)
ngfw      — NGFW Core (access control, IPS, AMP, SI, SSL inspection)
ngfwplat  — NGFW Platform (FTD management, accounts, updates)
logging   — Logging & Monitoring (syslog, SNMP traps, NetFlow)
crypto    — Cryptographic Posture (SSH keys, TLS, IPsec, ISAKMP)
all       — Run everything (default)
```

---

## Project Structure

```
Network-Security-Scanner-NSS/
├── nss_scanner.py                  # Main entry point & CLI
├── modules/
│   ├── base.py                     # Config parser & base auditor
│   ├── mgmt_plane.py              # Management Plane checks
│   ├── ctrl_plane.py              # Control Plane checks
│   ├── data_plane.py              # Data Plane checks
│   ├── services.py                # Services & Protocols checks
│   ├── switch_security.py         # Switch-specific checks
│   ├── wireless.py                # Wireless security checks
│   ├── ngfw_core.py               # NGFW core security checks
│   ├── ngfw_platform.py           # NGFW platform checks
│   ├── logging.py                 # Logging & Monitoring checks
│   ├── crypto.py                  # Cryptographic posture checks
│   └── report_generator.py        # HTML dashboard generator
├── sample_configs/                 # Demo device configs
│   ├── router_core.cfg
│   ├── switch_access.cfg
│   ├── ftd_firewall.cfg
│   └── sample_report.html
├── docs/
│   └── banner.svg
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Requirements

**Python 3.8+** — No external packages required.

## References

- [CIS Cisco IOS 15 Benchmark](https://www.cisecurity.org/benchmark/cisco)
- [CIS Cisco IOS 17.x Benchmark](https://ncp.nist.gov/checklist/1125)
- [CIS Cisco Firepower FTD Benchmark](https://ncp.nist.gov/checklist/1236)
- [Cisco IOS XE Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening)
- [Cisco NX-OS Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/securing_nx_os.html)
- [NSA Cisco Firepower Hardening Guide](https://media.defense.gov/2023/Aug/02/2003272858/-1/-1/0/CTR_CISCO_FIREPOWER_HARDENING_GUIDE.PDF)
- [Cisco WLC Security Best Practices](https://www.cisco.com/c/en/us/td/docs/wireless/controller/best-practices/base/b_bp_wlc/security.html)

## Disclaimer

This tool is for **authorized security assessments only**. The scanner performs offline config analysis and does not connect to any network device.

## License

MIT License — see [LICENSE](LICENSE).
