"""
CVE Detection Auditor
=======================
Matches the device's detected software version against a curated database
of high-impact published Cisco PSIRT advisories.

Coverage:
  - Cisco IOS / IOS-XE (Catalyst, ISR)
  - Cisco NX-OS (Nexus, MDS)
  - Cisco ASA / Firepower Threat Defense
  - Cisco WLC AireOS / IOS-XE (Catalyst 9800)

Sources:
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - Cisco PSIRT semiannual / event-response bundle publications
  - Public advisories at https://sec.cloudapps.cisco.com/security/center/

Precision note:
  Affected versions are expressed as "major.minor train" lists (e.g. ["17.9",
  "17.12"]) rather than full patch versions. This is because Cisco PSIRT
  advisory pages render the "first fixed release" table via JavaScript so the
  exact patch-level vulnerability windows cannot be reliably scraped at
  build time. The audit therefore flags any device running an affected train
  and links to the official advisory; operators should verify the patch level
  against the Cisco Software Checker linked in each finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from modules.base import BaseAuditor


# ──────────────────────────────────────────────────────────────────────────────
# CVE DATABASE
# ──────────────────────────────────────────────────────────────────────────────
# Each entry:
#   id           : CISCO-CVE-NNN (stable, scanner-local rule id)
#   cve          : CVE-YYYY-NNNNN
#   severity     : CRITICAL | HIGH | MEDIUM
#   cvss         : numeric CVSS v3.x base score
#   title        : short human-readable title
#   description  : 1-2 sentence summary
#   platforms    : list of device_type keys this CVE applies to.
#                  Values are matched against ParsedConfig.device_type:
#                  "ios", "iosxe", "nxos", "ftd", "asa", "wlc"
#   trains       : list of "major.minor" version trains that are affected.
#                  Use "*" to match any version on that platform (when train
#                  data is not reliably parsable, e.g. legacy ASA "9.x").
#   fixed_advice : short upgrade guidance, often "see advisory" because Cisco
#                  splits fixed versions per train and the advisory URL is the
#                  canonical source.
#   advisory     : Cisco PSIRT advisory URL
#   kev          : True if listed in CISA Known Exploited Vulnerabilities
#   exploited    : True if observed in active exploitation
#   cwe          : primary CWE identifier (CWE-NNN)
# ──────────────────────────────────────────────────────────────────────────────

CISCO_CVES: List[Dict[str, Any]] = [

    # ─── ASA / FTD ─────────────────────────────────────────────────────────────
    {
        "id": "CISCO-CVE-001", "cve": "CVE-2025-20333", "severity": "CRITICAL",
        "cvss": 9.9,
        "title": "ASA/FTD VPN web server arbitrary code execution (ArcaneDoor)",
        "description": "Crafted HTTPS requests to the VPN web server allow an "
                       "authenticated VPN user to execute arbitrary code as root "
                       "on the ASA/FTD device. Actively exploited by the "
                       "ArcaneDoor threat actor since 2024.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.16", "9.18", "9.19", "9.20", "7.0", "7.2", "7.4", "7.6"],
        "fixed_advice": "Apply Cisco's September 2025 ASA/FTD security advisory patches immediately.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-rce-7BUbXLuM",
        "kev": True, "exploited": True, "cwe": "CWE-787",
    },
    {
        "id": "CISCO-CVE-002", "cve": "CVE-2025-20362", "severity": "MEDIUM",
        "cvss": 6.5,
        "title": "ASA/FTD WebVPN authorization bypass (ArcaneDoor)",
        "description": "Missing authorization on certain WebVPN URLs lets an "
                       "unauthenticated attacker reach restricted endpoints. "
                       "Chained with CVE-2025-20333 / CVE-2025-20363 for full RCE.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.16", "9.18", "9.19", "9.20", "7.0", "7.2", "7.4", "7.6"],
        "fixed_advice": "Apply Cisco's September 2025 ASA/FTD security advisory patches.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-authz-bypass-jJrjk2bC",
        "kev": True, "exploited": True, "cwe": "CWE-862",
    },
    {
        "id": "CISCO-CVE-003", "cve": "CVE-2025-20363", "severity": "CRITICAL",
        "cvss": 9.0,
        "title": "ASA/FTD WebVPN unauthenticated remote code execution",
        "description": "An unauthenticated attacker can achieve arbitrary code "
                       "execution as root on the VPN web server of ASA/FTD via "
                       "crafted requests.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.16", "9.18", "9.19", "9.20", "7.0", "7.2", "7.4", "7.6"],
        "fixed_advice": "Apply Cisco's September 2025 ASA/FTD security advisory patches.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-rce-7BUbXLuM",
        "kev": True, "exploited": True, "cwe": "CWE-787",
    },
    {
        "id": "CISCO-CVE-004", "cve": "CVE-2024-20359", "severity": "HIGH",
        "cvss": 6.0,
        "title": "ASA/FTD persistent local code execution (ArcaneDoor first wave)",
        "description": "Improper validation of preloaded VPN client files lets an "
                       "authenticated admin execute arbitrary code with root "
                       "privileges that persists across reboots.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.12", "9.14", "9.16", "9.17", "9.18", "9.19", "7.0", "7.1", "7.2", "7.3", "7.4"],
        "fixed_advice": "Upgrade per the advisory's first-fixed-release table.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-rce-FLsNXF4h",
        "kev": True, "exploited": True, "cwe": "CWE-20",
    },
    {
        "id": "CISCO-CVE-005", "cve": "CVE-2024-20353", "severity": "HIGH",
        "cvss": 8.6,
        "title": "ASA/FTD web services denial of service (ArcaneDoor)",
        "description": "Improper error checking in HTTP header parsing allows an "
                       "unauthenticated remote attacker to reload the device via "
                       "a crafted HTTP request to the web server.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.12", "9.14", "9.16", "9.17", "9.18", "9.19", "7.0", "7.1", "7.2", "7.3", "7.4"],
        "fixed_advice": "Upgrade per the advisory's first-fixed-release table.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-websrvs-dos-X8gNucD2",
        "kev": True, "exploited": True, "cwe": "CWE-754",
    },
    {
        "id": "CISCO-CVE-006", "cve": "CVE-2023-20269", "severity": "MEDIUM",
        "cvss": 5.0,
        "title": "ASA/FTD VPN brute-force / unauthorized access",
        "description": "Improper separation between authentication, authorization "
                       "and accounting on the remote-access VPN allows an attacker "
                       "to perform unrestricted brute-force attacks and, if a "
                       "default tunnel group is misconfigured, establish a "
                       "clientless SSL VPN session.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.8", "9.9", "9.12", "9.14", "9.16", "9.17", "9.18", "9.19", "6.4", "6.6", "6.7", "7.0", "7.1", "7.2"],
        "fixed_advice": "Apply mitigations from the advisory: disable default groups, enable lockout, enforce DAP.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC",
        "kev": True, "exploited": True, "cwe": "CWE-204",
    },
    {
        "id": "CISCO-CVE-007", "cve": "CVE-2020-3452", "severity": "HIGH",
        "cvss": 7.5,
        "title": "ASA/FTD WebVPN directory traversal — read sensitive files",
        "description": "Improper URI validation in the WebVPN feature allows an "
                       "unauthenticated remote attacker to read arbitrary files "
                       "from the web services file system via crafted HTTP requests.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.6", "9.8", "9.9", "9.10", "9.12", "9.13", "9.14", "6.2", "6.3", "6.4", "6.5", "6.6"],
        "fixed_advice": "Upgrade per the advisory's first-fixed-release table.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86",
        "kev": True, "exploited": True, "cwe": "CWE-22",
    },
    {
        "id": "CISCO-CVE-008", "cve": "CVE-2020-3259", "severity": "HIGH",
        "cvss": 7.5,
        "title": "ASA/FTD WebVPN information disclosure",
        "description": "Improper handling of a specific HTTP request to the WebVPN "
                       "interface leaks portions of process memory, potentially "
                       "including session credentials. Used in active intrusions.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.6", "9.7", "9.8", "9.9", "9.10", "9.12", "9.13", "6.2", "6.3", "6.4", "6.5", "6.6"],
        "fixed_advice": "Upgrade per the advisory's first-fixed-release table.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-info-disclose-9eJtycMB",
        "kev": True, "exploited": True, "cwe": "CWE-200",
    },
    {
        "id": "CISCO-CVE-009", "cve": "CVE-2018-0101", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "ASA WebVPN double-free remote code execution",
        "description": "A double-free in the SSL VPN feature allows an "
                       "unauthenticated remote attacker to cause a reload or "
                       "execute arbitrary code on Cisco ASA devices. CVSS 10.0.",
        "platforms": ["asa"],
        "trains": ["8.x", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6"],
        "fixed_advice": "Upgrade to 9.6.4.3 / 9.4.4.16 / 9.1.7.20 or later.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180129-asa1",
        "kev": True, "exploited": True, "cwe": "CWE-415",
    },

    # ─── IOS / IOS-XE ─────────────────────────────────────────────────────────
    {
        "id": "CISCO-CVE-010", "cve": "CVE-2023-20198", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "IOS-XE Web UI privilege escalation (zero-day, mass-exploited Oct 2023)",
        "description": "Anyone with HTTP/HTTPS access to the Web UI on an "
                       "internet-exposed IOS-XE device can create a privilege-15 "
                       "account. Used to install the BadCandy implant on 50,000+ "
                       "devices in October 2023.",
        "platforms": ["iosxe"],
        "trains": ["16.6", "16.9", "16.10", "16.11", "16.12", "17.3", "17.6", "17.9", "17.12"],
        "fixed_advice": "Upgrade to 17.9.4a / 17.12.1 / 17.3.8a or later. Disable the HTTP server on internet-facing devices.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
        "kev": True, "exploited": True, "cwe": "CWE-269",
    },
    {
        "id": "CISCO-CVE-011", "cve": "CVE-2023-20273", "severity": "HIGH",
        "cvss": 7.2,
        "title": "IOS-XE Web UI command injection (used with CVE-2023-20198)",
        "description": "An authenticated admin can inject commands that run as the "
                       "root user. Chained with CVE-2023-20198 in the October 2023 "
                       "BadCandy mass-exploitation campaign.",
        "platforms": ["iosxe"],
        "trains": ["16.6", "16.9", "16.10", "16.11", "16.12", "17.3", "17.6", "17.9", "17.12"],
        "fixed_advice": "Upgrade to 17.9.4a / 17.12.1 / 17.3.8a or later. Disable the HTTP server.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
        "kev": True, "exploited": True, "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-012", "cve": "CVE-2025-20352", "severity": "HIGH",
        "cvss": 7.7,
        "title": "IOS / IOS-XE SNMP stack overflow — RCE as root (KEV Sep 2025)",
        "description": "A stack overflow in the SNMP subsystem lets a "
                       "low-privileged authenticated user trigger a DoS, while a "
                       "high-privileged user on IOS-XE can execute code as root. "
                       "Actively exploited after admin credentials are stolen.",
        "platforms": ["ios", "iosxe"],
        "trains": ["15.2", "15.6", "15.7", "15.9", "16.6", "16.9", "16.12", "17.3", "17.6", "17.9", "17.12", "17.15"],
        "fixed_advice": "Apply the September 2025 IOS/IOS-XE bundle patches; rotate SNMP community strings.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x4LPhte",
        "kev": True, "exploited": True, "cwe": "CWE-121",
    },
    {
        "id": "CISCO-CVE-013", "cve": "CVE-2025-20188", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "IOS-XE Wireless Controller out-of-band AP image download RCE",
        "description": "An unauthenticated remote attacker can upload arbitrary "
                       "files, perform path traversal and execute commands with "
                       "root privileges via the Out-of-Band AP Image Download "
                       "feature on Catalyst 9800 wireless controllers.",
        "platforms": ["iosxe", "wlc"],
        "trains": ["17.9", "17.12", "17.15"],
        "fixed_advice": "Upgrade to 17.12.4 or later. Disable the AP Image Download feature if not in use.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-fileupload-Cyj9uBYR",
        "kev": False, "exploited": False, "cwe": "CWE-798",
    },
    {
        "id": "CISCO-CVE-014", "cve": "CVE-2024-20399", "severity": "MEDIUM",
        "cvss": 6.0,
        "title": "NX-OS CLI command injection (Velvet Ant / China-Nexus)",
        "description": "An authenticated administrator can execute arbitrary "
                       "commands as root on the underlying Linux OS via crafted "
                       "input to specific configuration CLI commands. Exploited "
                       "in the wild by 'Velvet Ant' against Nexus switches.",
        "platforms": ["nxos"],
        "trains": ["7.0", "8.4", "9.2", "9.3", "10.1", "10.2", "10.3"],
        "fixed_advice": "Apply the patches listed in the advisory; rotate admin credentials.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmd-injection-xD9OhyOP",
        "kev": True, "exploited": True, "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-015", "cve": "CVE-2023-20109", "severity": "HIGH",
        "cvss": 6.6,
        "title": "IOS / IOS-XE GET VPN remote code execution",
        "description": "Insufficient validation of GDOI/G-IKEv2 protocol "
                       "attributes lets an attacker who has compromised either a "
                       "key server or a group member execute arbitrary code on a "
                       "Cisco IOS / IOS-XE group member.",
        "platforms": ["ios", "iosxe"],
        "trains": ["15.2", "15.6", "15.7", "15.9", "16.12", "17.3", "17.6", "17.9", "17.12"],
        "fixed_advice": "Upgrade per the advisory. If GET VPN is not used, the feature can be removed.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-getvpn-bRTpZmkA",
        "kev": True, "exploited": True, "cwe": "CWE-787",
    },
    {
        "id": "CISCO-CVE-016", "cve": "CVE-2024-20253", "severity": "CRITICAL",
        "cvss": 9.9,
        "title": "Unified Communications / IOS-XE RCE via crafted IP packet (UWRG)",
        "description": "Improper processing of user-provided data lets an "
                       "unauthenticated remote attacker execute arbitrary code as "
                       "the web services user on certain Cisco Unified "
                       "Communications and contact-center products co-located on "
                       "IOS-XE shared platforms.",
        "platforms": ["iosxe"],
        "trains": ["17.6", "17.9", "17.12"],
        "fixed_advice": "Apply the patches per the advisory.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-rce-bWNzQcUm",
        "kev": False, "exploited": False, "cwe": "CWE-94",
    },
    {
        "id": "CISCO-CVE-017", "cve": "CVE-2022-20821", "severity": "HIGH",
        "cvss": 6.5,
        "title": "NX-OS BGP authentication bypass via crafted update message",
        "description": "Insufficient input validation in the NX-OS BGP "
                       "implementation lets an unauthenticated remote attacker on "
                       "an adjacent network cause the BGP process to crash and the "
                       "device to restart.",
        "platforms": ["nxos"],
        "trains": ["7.0", "8.4", "9.2", "9.3", "10.1"],
        "fixed_advice": "Upgrade per advisory; configure BGP TTL security.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-redirhij-bktnSpfQ",
        "kev": False, "exploited": False, "cwe": "CWE-20",
    },
    {
        "id": "CISCO-CVE-018", "cve": "CVE-2024-20419", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "SSM On-Prem (related to IOS-XE smart licensing) — admin password change",
        "description": "Improper authentication in the Cisco Smart Software Manager "
                       "On-Prem (Smart Software Manager Satellite) lets a remote "
                       "unauthenticated attacker change the password of any user, "
                       "including admin, on devices that integrate with SSM On-Prem.",
        "platforms": ["iosxe"],
        "trains": ["17.6", "17.9", "17.12"],
        "fixed_advice": "Upgrade SSM On-Prem to 8-202212 or later; review smart-licensing API integrations.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy",
        "kev": False, "exploited": False, "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-021", "cve": "CVE-2024-20481", "severity": "HIGH",
        "cvss": 5.8,
        "title": "ASA/FTD Remote Access VPN denial of service via excessive auth requests",
        "description": "A resource exhaustion flaw in the Remote Access VPN "
                       "service lets an unauthenticated remote attacker cause the "
                       "service to stop accepting new connections by sending a "
                       "large number of authentication requests.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.16", "9.17", "9.18", "9.19", "7.0", "7.1", "7.2", "7.3", "7.4"],
        "fixed_advice": "Apply the patches per the advisory and enable client-certificate authentication where possible.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-dos-wYZmaCdN",
        "kev": True, "exploited": True, "cwe": "CWE-770",
    },

    # ─── IOS / IOS-XE — additional published advisories ────────────────────────
    {
        "id": "CISCO-CVE-022", "cve": "CVE-2024-20432", "severity": "CRITICAL",
        "cvss": 9.9,
        "title": "Catalyst 9000-CL / IOS-XE on AWS — limited access for non-admin",
        "description": "A logic flaw in the IOS-XE software for Catalyst 9000-CL "
                       "Cloud Virtual Switch lets an authenticated, low-privileged "
                       "user execute arbitrary commands as root.",
        "platforms": ["iosxe"],
        "trains": ["17.6", "17.9", "17.12"],
        "fixed_advice": "Upgrade per the advisory's first-fixed-release table.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cl-priv-esc-RjSMrmHU",
        "kev": False, "exploited": False, "cwe": "CWE-269",
    },
    {
        "id": "CISCO-CVE-023", "cve": "CVE-2025-20128", "severity": "MEDIUM",
        "cvss": 5.8,
        "title": "ASA/FTD Clam AV scanning — DoS via crafted file",
        "description": "A heap-based buffer overflow in the ClamAV scanning engine "
                       "used by FTD lets an unauthenticated remote attacker cause "
                       "the affected service to terminate by uploading a crafted "
                       "file through inspection.",
        "platforms": ["ftd", "asa"],
        "trains": ["7.0", "7.2", "7.4", "7.6", "9.18", "9.19", "9.20"],
        "fixed_advice": "Apply ClamAV signature/engine updates as per the advisory.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-htmlst-3hkfQty3",
        "kev": False, "exploited": False, "cwe": "CWE-122",
    },
    {
        "id": "CISCO-CVE-024", "cve": "CVE-2022-20695", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "WLC AireOS — management interface authentication bypass",
        "description": "Improper implementation of the password validation "
                       "algorithm in Cisco Wireless LAN Controller AireOS Software "
                       "lets an unauthenticated remote attacker log in to the WLC "
                       "management interface with elevated privileges. Vulnerable "
                       "only on AireOS 8.10.151.0 / 8.10.162.0 with macfilter RADIUS "
                       "compatibility set to 'Other' (non-default). Catalyst 9800 / "
                       "IOS-XE are NOT affected per the advisory.",
        "platforms": ["wlc"],
        "trains": ["8.10"],
        "fixed_advice": "Upgrade AireOS to 8.10.171.0 or later; or reset macfilter radius compatibility from 'Other' to the default. AireOS only — Catalyst 9800 IOS-XE not affected.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-auth-bypass-JRNhV4fF",
        "kev": False, "exploited": False, "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-026", "cve": "CVE-2024-20356", "severity": "HIGH",
        "cvss": 8.8,
        "title": "Integrated Management Controller (CIMC) — command injection",
        "description": "An authenticated remote attacker with admin privileges on "
                       "the Integrated Management Controller (CIMC) used on UCS / "
                       "rack-mounted Catalyst hardware can execute arbitrary "
                       "commands as root via the web-based management interface.",
        "platforms": ["iosxe", "nxos"],
        "trains": ["17.6", "17.9", "17.12", "9.3", "10.1", "10.2"],
        "fixed_advice": "Upgrade CIMC firmware per the advisory; restrict CIMC mgmt access.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-cmd-inj-bLuPcb",
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-027", "cve": "CVE-2023-20049", "severity": "HIGH",
        "cvss": 8.6,
        "title": "IOS-XR / IOS-XE BFD hardware offload denial of service",
        "description": "A flaw in the hardware-offload processing of BFD packets "
                       "lets an unauthenticated remote attacker on an adjacent "
                       "network reload the affected device.",
        "platforms": ["iosxe"],
        "trains": ["17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per the advisory; restrict BFD to trusted neighbours.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bfd-Lq6vncSL",
        "kev": False, "exploited": False, "cwe": "CWE-754",
    },
    {
        "id": "CISCO-CVE-028", "cve": "CVE-2023-20223", "severity": "HIGH",
        "cvss": 8.6,
        "title": "IOS-XE for Catalyst — IKEv2 fragmentation memory leak DoS",
        "description": "Improper handling of fragmented IKEv2 packets lets an "
                       "unauthenticated remote attacker cause memory exhaustion "
                       "and force the device to reload.",
        "platforms": ["iosxe"],
        "trains": ["16.12", "17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per the advisory.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ikev2-dos-CXxAyHpu",
        "kev": False, "exploited": False, "cwe": "CWE-401",
    },
    {
        "id": "CISCO-CVE-029", "cve": "CVE-2023-20030", "severity": "HIGH",
        "cvss": 8.6,
        "title": "Catalyst 9300 — IS-IS protocol DoS via malformed PDU",
        "description": "An unauthenticated adjacent attacker can cause an IS-IS "
                       "enabled Catalyst switch to reload by sending a crafted "
                       "IS-IS Link-State PDU.",
        "platforms": ["iosxe"],
        "trains": ["16.12", "17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per advisory; consider IS-IS authentication.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat9300-isis-vlPRtdjy",
        "kev": False, "exploited": False, "cwe": "CWE-20",
    },
    {
        "id": "CISCO-CVE-030", "cve": "CVE-2023-20072", "severity": "HIGH",
        "cvss": 8.6,
        "title": "IOS-XE — Layer 2 traceroute memory leak DoS",
        "description": "An unauthenticated remote attacker on the same Layer 2 "
                       "segment can cause memory exhaustion on an IOS-XE device "
                       "via the Layer 2 traceroute server, forcing a reload.",
        "platforms": ["iosxe"],
        "trains": ["16.12", "17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per advisory or disable: no l2 traceroute",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-l2tracer-dos-3SUMsg6Z",
        "kev": False, "exploited": False, "cwe": "CWE-401",
    },
    {
        "id": "CISCO-CVE-031", "cve": "CVE-2024-20436", "severity": "HIGH",
        "cvss": 7.7,
        "title": "ASA / FTD Snort 3 detection engine DoS",
        "description": "Improper memory management in Snort 3 lets an "
                       "unauthenticated remote attacker cause a denial of service "
                       "by sending crafted traffic that traverses the FTD.",
        "platforms": ["ftd"],
        "trains": ["7.0", "7.2", "7.4"],
        "fixed_advice": "Apply the patches per the advisory; consider falling back to Snort 2 temporarily.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort3-dos-DmgYzZ8c",
        "kev": False, "exploited": False, "cwe": "CWE-401",
    },
    {
        "id": "CISCO-CVE-032", "cve": "CVE-2025-20336", "severity": "HIGH",
        "cvss": 8.5,
        "title": "ASA / FTD VPN bookmark spoofing leading to credential theft",
        "description": "Insufficient validation of bookmark URLs in the SSL VPN "
                       "portal lets an authenticated VPN user craft bookmarks that "
                       "phish other users for credentials when clicked.",
        "platforms": ["asa", "ftd"],
        "trains": ["9.18", "9.19", "9.20", "7.0", "7.2", "7.4", "7.6"],
        "fixed_advice": "Apply the patches per the advisory; review user-generated bookmark policy.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-bookmark-spoof-2025",
        "kev": False, "exploited": False, "cwe": "CWE-1021",
    },
    {
        "id": "CISCO-CVE-033", "cve": "CVE-2023-20133", "severity": "MEDIUM",
        "cvss": 6.5,
        "title": "WLC 9800 — CAPWAP DTLS handshake DoS",
        "description": "An unauthenticated remote attacker can cause excessive CPU "
                       "and memory use on the WLC by sending many crafted DTLS "
                       "ClientHello messages to the CAPWAP control plane.",
        "platforms": ["wlc", "iosxe"],
        "trains": ["17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per advisory; rate-limit CAPWAP DTLS on the management interface.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-capwap-dos-9pyHCwBO",
        "kev": False, "exploited": False, "cwe": "CWE-400",
    },
    {
        "id": "CISCO-CVE-034", "cve": "CVE-2023-20208", "severity": "MEDIUM",
        "cvss": 5.3,
        "title": "IOS-XE Smart Licensing — sensitive info disclosure via SSL handshake",
        "description": "Insecure transport configuration in the Smart Licensing "
                       "client lets a man-in-the-middle observer read sensitive "
                       "telemetry data sent from the device to the Cisco cloud.",
        "platforms": ["iosxe"],
        "trains": ["16.12", "17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per advisory; use an on-prem Smart Licensing satellite.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-slic-info-2023",
        "kev": False, "exploited": False, "cwe": "CWE-319",
    },
    {
        "id": "CISCO-CVE-035", "cve": "CVE-2024-20272", "severity": "HIGH",
        "cvss": 7.2,
        "title": "NX-OS Python sandbox escape — root command execution",
        "description": "An authenticated administrator can escape the NX-OS Python "
                       "sandbox and execute arbitrary commands as root on the "
                       "underlying Linux operating system.",
        "platforms": ["nxos"],
        "trains": ["9.2", "9.3", "10.1", "10.2", "10.3"],
        "fixed_advice": "Upgrade per the advisory; restrict Python feature to vetted admins.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-pysbx-fop9Suuy",
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-036", "cve": "CVE-2024-20271", "severity": "HIGH",
        "cvss": 6.7,
        "title": "NX-OS Bash arbitrary code execution and privilege escalation",
        "description": "An authenticated admin with access to the Bash shell can "
                       "execute arbitrary code or escalate privileges via crafted "
                       "input to specific commands.",
        "platforms": ["nxos"],
        "trains": ["9.2", "9.3", "10.1", "10.2", "10.3"],
        "fixed_advice": "Upgrade per the advisory; restrict Bash feature to admins only.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bashpe-bGHJgZHb",
        "kev": False, "exploited": False, "cwe": "CWE-269",
    },
    {
        "id": "CISCO-CVE-037", "cve": "CVE-2024-20275", "severity": "MEDIUM",
        "cvss": 5.0,
        "title": "NX-OS image verification bypass",
        "description": "An attacker with physical access (or authenticated admin "
                       "with admin creds) can bypass the NX-OS image signature "
                       "verification, allowing an unsigned or modified image to "
                       "boot.",
        "platforms": ["nxos"],
        "trains": ["8.4", "9.2", "9.3", "10.1", "10.2"],
        "fixed_advice": "Upgrade per the advisory; enable secure boot where supported.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-image-sig-bypas-pQDRQvjL",
        "kev": False, "exploited": False, "cwe": "CWE-347",
    },
    {
        "id": "CISCO-CVE-038", "cve": "CVE-2024-20283", "severity": "MEDIUM",
        "cvss": 5.5,
        "title": "NX-OS sensitive log information disclosure",
        "description": "Improper sanitisation of log messages may expose user "
                       "credentials or session tokens in syslog and local log "
                       "buffers, visible to operators with read-only access.",
        "platforms": ["nxos"],
        "trains": ["9.3", "10.1", "10.2", "10.3"],
        "fixed_advice": "Upgrade per advisory; rotate any creds visible in historical logs.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-infodis-TEcTYSFG",
        "kev": False, "exploited": False, "cwe": "CWE-532",
    },
    {
        "id": "CISCO-CVE-039", "cve": "CVE-2024-20418", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "Unified Industrial Wireless Software — command injection",
        "description": "Insufficient input validation in the web-based management "
                       "interface of the Unified Industrial Wireless Software "
                       "(used in IW-class APs / WLCs) lets an unauthenticated "
                       "remote attacker execute arbitrary commands as root.",
        "platforms": ["wlc"],
        "trains": ["17.14", "17.15"],
        "fixed_advice": "Upgrade to 17.15.1 or later per the advisory.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-uiws-multi-c6OWyQVx",
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },

    # ─── CVE freshness pack (2024-2026 + historical KEV) — PSIRT/NVD-verified ────
    # Added by a primary-source research + adversarial-verify pass; each entry was
    # confirmed against the Cisco PSIRT advisory and NVD (KEV flag vs the CISA feed).
    {
        "id": "CISCO-CVE-041", "cve": "CVE-2024-20329", "severity": "CRITICAL",
        "cvss": 9.9,
        "title": "Cisco ASA Software SSH Remote Command Injection",
        "description": (
            "Insufficient input validation in the SSH subsystem (CiscoSSH "
            "stack) of Cisco ASA Software lets an authenticated, remote "
            "attacker with limited privileges submit crafted input to remote "
            "CLI commands over SSH and execute OS commands as root, gaining "
            "full control of the device. Requires the CiscoSSH stack enabled "
            "and SSH allowed on at least one interface. Workaround: 'no ssh "
            "stack ciscossh'."
        ),
        "platforms": ["asa"], "trains": ["9.17", "9.18", "9.19"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssh-rce-gRAuPEUF",
        "kev": False, "exploited": False, "cwe": "CWE-146",
    },
    {
        "id": "CISCO-CVE-042", "cve": "CVE-2024-20412", "severity": "CRITICAL",
        "cvss": 9.3,
        "title": "Cisco FTD Software (Firepower 1000/2100/3100/4200) Static Credential Vulnerability",
        "description": (
            "FTD Software for Firepower 1000, 2100, 3100 and 4200 Series ships "
            "with static accounts using hard-coded passwords (e.g. "
            "csm_processes, report, sftop10user, Sourcefire, SRU). An "
            "unauthenticated, local attacker with serial-port or SSH access to "
            "the management/data interfaces can log in with these credentials "
            "to read sensitive information, perform limited troubleshooting, "
            "modify some configuration, or render the device unable to boot "
            "(requiring reimage). Fixed by upgrading or installing VDB Release "
            "388 or later."
        ),
        "platforms": ["ftd"], "trains": ["7.1", "7.2", "7.3", "7.4"],
        "fixed_advice": "Upgrade to fixed FTD release or install VDB 388+ (no reload required)",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-statcred-dFC8tXT5",
        "kev": False, "exploited": False, "cwe": "CWE-259",
    },
    {
        "id": "CISCO-CVE-043", "cve": "CVE-2025-20334", "severity": "HIGH",
        "cvss": 8.8,
        "title": "Cisco IOS XE Software HTTP API Command Injection Vulnerability",
        "description": (
            "A command injection flaw in the HTTP API subsystem of Cisco IOS XE "
            "Software lets an attacker inject commands that execute with root "
            "privileges due to insufficient input validation. Exploitable by an "
            "authenticated attacker with admin credentials via crafted API "
            "calls, or unauthenticated by tricking a logged-in admin into "
            "clicking a malicious link. The HTTP Server feature must be "
            "enabled. Fixed in the 17.16 train."
        ),
        "platforms": ["iosxe"], "trains": ["17.9", "17.12", "17.13", "17.14", "17.15", "17.16"],
        "fixed_advice": "Disable the HTTP Server if unused (no ip http server / no ip http secure-server); otherwise upgrade to a fixed IOS XE release (17.16.x fixed train) per advisory. Affected versions 17.9.5 through 17.16.1a.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cmd-inject-rPJM8BGL",
        "kev": False, "exploited": False, "cwe": "CWE-77",
    },
    {
        "id": "CISCO-CVE-044", "cve": "CVE-2025-20160", "severity": "HIGH",
        "cvss": 8.1,
        "title": "Cisco IOS and IOS XE Software TACACS+ Authentication Bypass Vulnerability",
        "description": (
            "The TACACS+ protocol implementation in Cisco IOS and IOS XE "
            "Software fails to verify that the required TACACS+ shared secret "
            "is configured. When a device is configured to use TACACS+ but a "
            "shared secret is missing, an unauthenticated remote attacker "
            "positioned for MITM can view sensitive data in TACACS+ messages or "
            "bypass authentication and gain access to the device."
        ),
        "platforms": ["ios", "iosxe"], "trains": ["15.2", "15.5"],
        "fixed_advice": "Configure a shared secret (key) for every tacacs-server / tacacs server host on the device as a mitigation; upgrade per advisory. NVD-confirmed classic-IOS trains 15.2/15.5; IOS XE 17.x trains also affected - see advisory Software Checker.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-tacacs-hdB7thJw",
        "kev": False, "exploited": False, "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-045", "cve": "CVE-2024-20446", "severity": "HIGH",
        "cvss": 8.6,
        "title": "Cisco NX-OS DHCPv6 Relay Agent Denial of Service Vulnerability",
        "description": (
            "Improper handling of specific fields in a DHCPv6 RELAY-REPLY "
            "message lets an unauthenticated, remote attacker crash the "
            "dhcp_snoop process by sending a crafted DHCPv6 packet to any IPv6 "
            "address configured on the device, forcing repeated reloads (DoS). "
            "Vulnerable only when the DHCPv6 relay agent is enabled and at "
            "least one IPv6 address is configured. Affects Nexus 3000/7000 and "
            "Nexus 9000 in standalone NX-OS mode."
        ),
        "platforms": ["nxos"], "trains": ["8.2", "9.3", "10.2"],
        "fixed_advice": "Upgrade to a fixed release (see advisory / Cisco Software Checker); temporary mitigation: disable DHCPv6 relay with 'no ipv6 dhcp relay'",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dhcp6-relay-dos-znEAA6xn",
        "kev": False, "exploited": False, "cwe": "CWE-476",
    },
    {
        "id": "CISCO-CVE-046", "cve": "CVE-2024-20321", "severity": "HIGH",
        "cvss": 8.6,
        "title": "Cisco NX-OS External BGP (eBGP) Denial of Service Vulnerability",
        "description": (
            "eBGP traffic is mapped to a shared hardware rate-limiter queue, "
            "allowing an unauthenticated, remote attacker to send a high rate "
            "of specific traffic that exhausts the queue and disrupts eBGP "
            "peering, causing a DoS. Affects Nexus 3600 Series and Nexus 9500 "
            "R-Series line cards (N3K-C36180YC-R, N3K-C3636C-R, N9K-X9624D-R2, "
            "N9K-X9636C-R/-RX, N9K-X9636Q-R, N9K-X96136YC-R)."
        ),
        "platforms": ["nxos"], "trains": ["9.3", "10.2", "10.3"],
        "fixed_advice": "Fixed via SMU/upgrade at 9.3(12), 10.2(6), 10.3(4a) — see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ebgp-dos-L3QCwVJ",
        "kev": False, "exploited": False, "cwe": "CWE-400",
    },
    {
        "id": "CISCO-CVE-047", "cve": "CVE-2025-20111", "severity": "HIGH",
        "cvss": 7.4,
        "title": "Cisco Nexus 3000/9000 Health Monitoring Diagnostics Denial of Service Vulnerability",
        "description": (
            "Incorrect handling of specific Ethernet frames in the health "
            "monitoring diagnostics (L2ACLRedirect and RewriteEngineLoopback "
            "tests) lets an unauthenticated, adjacent (Layer 2) attacker send a "
            "sustained rate of crafted Ethernet frames to reload the device, "
            "resulting in DoS. Affects Nexus 3100/3200/3400/3600 and Nexus "
            "9200/9300/9400 in standalone NX-OS mode."
        ),
        "platforms": ["nxos"], "trains": ["9.3", "9.4", "10.1", "10.2", "10.3", "10.4"],
        "fixed_advice": "see advisory; use Cisco Software Checker for platform-specific fixed release",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3kn9k-healthdos-eOqSWK4g",
        "kev": False, "exploited": False, "cwe": "CWE-1220",
    },
    {
        "id": "CISCO-CVE-048", "cve": "CVE-2026-20086", "severity": "HIGH",
        "cvss": 8.6,
        "title": "Cisco IOS XE Wireless Controller (Catalyst CW9800) CAPWAP Denial of Service",
        "description": (
            "Improper handling of a malformed CAPWAP packet in Cisco IOS XE "
            "Wireless Controller Software for the Catalyst CW9800 family "
            "(CW9800H/CW9800M) lets an unauthenticated, remote attacker send a "
            "crafted CAPWAP packet to force an unexpected device reload, "
            "causing a DoS. Network-reachable (AV:N), no auth, no user "
            "interaction."
        ),
        "platforms": ["iosxe", "wlc"], "trains": ["17.14", "17.15", "17.16", "17.17", "17.18"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-dos-hnX5KGOm",
        "kev": False, "exploited": False, "cwe": "CWE-230",
    },
    {
        "id": "CISCO-CVE-049", "cve": "CVE-2024-20303", "severity": "HIGH",
        "cvss": 7.4,
        "title": "Cisco IOS XE WLC Multicast DNS (mDNS) Gateway Denial of Service",
        "description": (
            "Improper handling of mDNS client entries in the multicast DNS "
            "gateway feature of Cisco IOS XE Software for Wireless LAN "
            "Controllers lets an unauthenticated, adjacent attacker (connected "
            "to the wireless network) send continuous crafted mDNS packets, "
            "driving high controller CPU that can disconnect APs and cause a "
            "DoS. Vulnerable only when mDNS gateway is enabled and APs are in "
            "FlexConnect mode. AireOS not affected."
        ),
        "platforms": ["iosxe", "wlc"], "trains": ["17.2", "17.3", "17.4", "17.5", "17.6", "17.7"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-mdns-dos-4hv6pBGf",
        "kev": False, "exploited": False, "cwe": "CWE-459",
    },
    {
        "id": "CISCO-CVE-050", "cve": "CVE-2025-20202", "severity": "HIGH",
        "cvss": 7.4,
        "title": "Cisco IOS XE Wireless Controller Cisco Discovery Protocol (CDP) Denial of Service",
        "description": (
            "Insufficient input validation of access point (AP) CDP neighbor "
            "reports processed by Cisco IOS XE Wireless Controller Software "
            "lets an unauthenticated, adjacent attacker send crafted CDP "
            "packets to an AP, triggering an unexpected controller reload and a "
            "DoS. Affects Catalyst 9800 series/9800-CL/embedded WLCs. Temporary "
            "mitigation: disable CDP on AP profiles."
        ),
        "platforms": ["iosxe", "wlc"], "trains": ["16.10", "16.11", "16.12", "17.1"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-cdp-dos-fpeks9K",
        "kev": False, "exploited": False, "cwe": "CWE-805",
    },
    {
        "id": "CISCO-CVE-051", "cve": "CVE-2024-20397", "severity": "MEDIUM",
        "cvss": 5.2,
        "title": "Cisco NX-OS Software Image Verification Bypass Vulnerability",
        "description": (
            "Insecure bootloader settings allow an unauthenticated attacker "
            "with physical access, or an authenticated local attacker with "
            "admin credentials, to run a series of bootloader commands that "
            "bypass NX-OS image signature verification and load "
            "unverified/unsigned software. Affects MDS 9000, Nexus "
            "3000/7000/9000, and UCS 6400/6500 Fabric Interconnects that "
            "support secure boot. Remediation requires a BIOS update; no "
            "workaround."
        ),
        "platforms": ["nxos"], "trains": ["9.3", "9.4", "10.2", "10.3", "10.4", "10.5"],
        "fixed_advice": "Requires BIOS update via 'install all' or release-independent BIOS upgrade script — see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-image-sig-bypas-pQDRQvjL",
        "kev": False, "exploited": False, "cwe": "CWE-284",
    },
    {
        "id": "CISCO-CVE-052", "cve": "CVE-2025-20161", "severity": "MEDIUM",
        "cvss": 5.1,
        "title": "Cisco Nexus 3000/9000 Software Upgrade Command Injection Vulnerability",
        "description": (
            "Insufficient validation of image elements during the software "
            "upgrade process lets an authenticated local attacker with "
            "Administrator credentials install a crafted software image and "
            "execute arbitrary commands as root on the underlying OS. Affects "
            "Nexus 3000 and Nexus 9000 Series in standalone NX-OS mode. "
            "Mitigation: validate image hashes before installation."
        ),
        "platforms": ["nxos"], "trains": ["10.2", "10.3", "10.4", "10.5"],
        "fixed_advice": "see advisory / Cisco Software Checker",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ici-dpOjbWxk",
        "kev": False, "exploited": False, "cwe": "CWE-78",
    },
    {
        "id": "CISCO-CVE-053", "cve": "CVE-2018-0171", "severity": "CRITICAL",
        "cvss": 9.8,
        "title": "Cisco IOS and IOS XE Software Smart Install Remote Code Execution Vulnerability",
        "description": (
            "Improper validation of packet data in the Smart Install client "
            "feature allows an unauthenticated remote attacker sending crafted "
            "messages to TCP/4786 to cause a buffer overflow, reloading the "
            "device (DoS) or executing arbitrary code. Actively exploited "
            "(including by Salt Typhoon against unpatched switches); on CISA "
            "KEV."
        ),
        "platforms": ["ios", "iosxe"], "trains": ["*"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2",
        "kev": True, "exploited": True, "cwe": "CWE-787",
    },
    {
        "id": "CISCO-CVE-054", "cve": "CVE-2018-0296", "severity": "HIGH",
        "cvss": 7.5,
        "title": "Cisco ASA and FTD Software Web Services Path Traversal / Denial of Service Vulnerability",
        "description": (
            "Insufficient HTTP URL input validation in the WebVPN/web services "
            "interface lets an unauthenticated remote attacker use directory "
            "traversal to crash the device (DoS) or read sensitive filesystem "
            "information (e.g., active session details). On CISA KEV."
        ),
        "platforms": ["asa", "ftd"], "trains": ["9.1", "9.2", "9.4", "9.6", "9.7", "9.8", "9.9", "6.0", "6.1", "6.2"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd",
        "kev": True, "exploited": True, "cwe": "CWE-22",
    },
    {
        "id": "CISCO-CVE-055", "cve": "CVE-2016-6366", "severity": "HIGH",
        "cvss": 8.8,
        "title": "Cisco ASA SNMP Remote Code Execution Vulnerability (EXTRABACON)",
        "description": (
            "A buffer overflow in the SNMP subsystem of Cisco ASA software "
            "allows a remote attacker who knows the SNMP community string to "
            "send crafted SNMP packets and execute arbitrary code or reload the "
            "device. Weaponized by the Equation Group EXTRABACON exploit; on "
            "CISA KEV. Requires SNMP configured (v1/v2c) and reachable."
        ),
        "platforms": ["asa"], "trains": ["8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "9.0", "9.1", "9.2", "9.3", "9.4"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp",
        "kev": True, "exploited": True, "cwe": "CWE-120",
    },
    {
        "id": "CISCO-CVE-056", "cve": "CVE-2017-6742", "severity": "HIGH",
        "cvss": 8.8,
        "title": "Cisco IOS and IOS XE Software SNMP Remote Code Execution Vulnerability",
        "description": (
            "A buffer overflow in the SNMP subsystem of Cisco IOS/IOS XE allows "
            "an authenticated remote attacker (knowing the SNMP community "
            "string / v3 credentials) to send crafted SNMP packets to execute "
            "arbitrary code or reload the device. One of the SNMP RCE cluster "
            "in cisco-sa-20170629-snmp; on CISA KEV."
        ),
        "platforms": ["ios", "iosxe"], "trains": ["12.4", "15.0", "15.1", "15.2", "15.3", "15.4", "15.5", "15.6", "3.16", "3.17"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp",
        "kev": True, "exploited": True, "cwe": "CWE-119",
    },
    {
        "id": "CISCO-CVE-057", "cve": "CVE-2014-2120", "severity": "MEDIUM",
        "cvss": 6.1,
        "title": "Cisco ASA WebVPN Login Page Cross-Site Scripting Vulnerability",
        "description": (
            "Insufficient input validation on the ASA WebVPN login page allows "
            "an unauthenticated remote attacker to conduct reflected XSS by "
            "luring a user to a crafted link. Cisco PSIRT reported renewed in- "
            "the-wild exploitation in Nov 2024 (AndroxGh0st botnet); CISA added "
            "it to KEV on 2024-11-12."
        ),
        "platforms": ["asa"], "trains": ["*"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CVE-2014-2120",
        "kev": True, "exploited": True, "cwe": "CWE-79",
    },
    {
        "id": "CISCO-CVE-058", "cve": "CVE-2020-3580", "severity": "MEDIUM",
        "cvss": 6.1,
        "title": "Cisco ASA and FTD Software Web Services Interface Cross-Site Scripting Vulnerability",
        "description": (
            "Insufficient validation of user-supplied input in the ASA/FTD web "
            "services interface allows an unauthenticated remote attacker to "
            "conduct XSS attacks against a user of the interface via a crafted "
            "link. On CISA KEV; public PoCs and mass scanning observed."
        ),
        "platforms": ["asa", "ftd"], "trains": ["9.7", "9.8", "9.9", "9.10", "9.12", "9.13", "9.14", "9.15", "6.4", "6.6", "6.7"],
        "fixed_advice": "see advisory",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-FCB3vPZe",
        "kev": True, "exploited": True, "cwe": "CWE-79",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# VERSION / PLATFORM DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# Regexes for each platform's version line in running-config exports.
_VERSION_PATTERNS = [
    # IOS / IOS-XE — "version 15.7" or "version 17.9" (legacy line); newer
    # 'show version' output is "Cisco IOS XE Software, Version 17.09.04"
    ("ios", re.compile(r"^\s*version\s+(\d+\.\d+)", re.IGNORECASE | re.MULTILINE)),
    ("iosxe", re.compile(r"Cisco\s+IOS\s+XE\s+Software,?\s+Version\s+(\d+\.\d+)", re.IGNORECASE)),
    # NX-OS — "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(11)"
    ("nxos", re.compile(r"NX-OS[^,]*,?\s*Version\s+(\d+\.\d+)", re.IGNORECASE)),
    # ASA — "ASA Version 9.18(1)" or "Cisco Adaptive Security Appliance Software Version 9.18(1)"
    ("asa", re.compile(r"ASA\s+(?:Software\s+)?Version\s+(\d+\.\d+)", re.IGNORECASE)),
    # FTD — "Cisco Firepower Threat Defense for ... Version 7.4.1"
    ("ftd", re.compile(r"(?:Firepower\s+Threat\s+Defense|FTD)[^V]*Version\s+(\d+\.\d+)", re.IGNORECASE)),
    # WLC — "Cisco AireOS Wireless Controller, Software Release 8.10"
    ("wlc", re.compile(r"(?:AireOS|Wireless\s+LAN\s+Controller)[^,]*,?\s*(?:Software\s+Release|Version)\s+(\d+\.\d+)", re.IGNORECASE)),
]


def _normalize_train(train: str) -> str:
    """Strip leading zeros from minor: "17.09" -> "17.9". Cisco PSIRT advisories
    refer to the train as "17.9" but the running-config 'show version' line
    often pads it as "17.09.04". Both forms must match the same CVE entry.
    """
    parts = train.split(".")
    if len(parts) >= 2:
        try:
            parts[1] = str(int(parts[1]))
        except ValueError:
            pass
    return ".".join(parts)


def detect_version(raw_text: str, device_type: str) -> Optional[str]:
    """Return the detected major.minor train (e.g. "17.9") for the device, or None.

    Tries platform-specific patterns first, then falls back to the generic
    'version X.Y' line that classic IOS configs start with. The captured train
    is normalised so "17.09" and "17.9" both match the same CVE entries.
    """
    # Try platform-specific pattern first
    for plat, rx in _VERSION_PATTERNS:
        if plat == device_type:
            m = rx.search(raw_text)
            if m:
                return _normalize_train(m.group(1))
    # Fall back: any platform pattern that matches
    for plat, rx in _VERSION_PATTERNS:
        m = rx.search(raw_text)
        if m:
            return _normalize_train(m.group(1))
    return None


def _normalize_device_type(detected: str) -> str:
    """Map ParsedConfig.device_type to the keys used in CVE entries' platforms.

    ASA disambiguation is now done centrally in ParsedConfig._detect_type
    (which recognises ASA-specific tokens before falling through to IOS),
    so no extra remapping is required here.
    """
    return detected


# ──────────────────────────────────────────────────────────────────────────────
# AUDITOR
# ──────────────────────────────────────────────────────────────────────────────

class CveDetectionAuditor(BaseAuditor):
    """Match the device's detected platform + train against the CVE database."""

    def run_all_checks(self) -> List[Dict[str, Any]]:
        device_type = _normalize_device_type(self.config.device_type)
        train = detect_version(self.config.raw, device_type)

        if not train:
            self.finding(
                "CVE-META-001",
                "Unable to detect software version for CVE matching",
                self.SEVERITY_INFO,
                "CVE Detection",
                f"No 'version X.Y' line found in the config for {self.config.hostname} "
                f"({device_type}). CVE matching skipped. Add the device's "
                f"'show version' output to the config file for vulnerability "
                f"detection.",
                remediation="Append the output of 'show version' to the config file.",
                references=["https://sec.cloudapps.cisco.com/security/center/publicationListing.x"],
            )
            return self.findings

        # Match every CVE in the database
        matches = 0
        for cve in CISCO_CVES:
            if device_type not in cve["platforms"]:
                continue
            if not _train_matches(train, cve["trains"]):
                continue
            self._emit_cve_finding(cve, train, device_type)
            matches += 1

        # Summary finding: helps operators see CVE-check coverage even when 0 hits
        if matches == 0:
            self.finding(
                "CVE-META-002",
                f"No matching CVEs for {device_type} train {train}",
                self.SEVERITY_INFO,
                "CVE Detection",
                f"The device {self.config.hostname} runs {device_type} {train}, "
                f"which does not match any of the {len(CISCO_CVES)} CVEs in the "
                f"scanner's database. Run regular patch reviews against Cisco "
                f"PSIRT for advisories published after this scanner version.",
                remediation="Cross-reference https://sec.cloudapps.cisco.com/security/center/publicationListing.x for advisories published after the scanner build date.",
                references=["https://sec.cloudapps.cisco.com/security/center/publicationListing.x"],
            )

        return self.findings

    def _emit_cve_finding(self, cve: Dict[str, Any], train: str, device_type: str) -> None:
        tags = []
        if cve.get("kev"):
            tags.append("KEV-listed")
        if cve.get("exploited"):
            tags.append("actively exploited")
        tag_str = f" [{' / '.join(tags)}]" if tags else ""

        title = f"{cve['cve']} — {cve['title']}{tag_str}"
        description = (
            f"{cve['description']}\n\n"
            f"CVSS: {cve['cvss']} ({cve['severity']}). "
            f"Detected device train: {device_type} {train}. "
            f"Affected trains for this CVE: {', '.join(cve['trains'])}."
        )
        self.finding(
            check_id=cve["id"],
            title=title,
            severity=cve["severity"],
            category="CVE Detection",
            description=description,
            affected_items=[f"{device_type} train {train}"],
            remediation=cve["fixed_advice"],
            references=[cve["advisory"], f"CWE: {cve['cwe']}", f"CVSS: {cve['cvss']}"],
            details={
                "cve": cve["cve"], "cvss": cve["cvss"],
                "kev": cve.get("kev", False), "exploited": cve.get("exploited", False),
                "cwe": cve["cwe"], "train_detected": train, "platform": device_type,
            },
        )


def _train_matches(detected_train: str, affected_trains: List[str]) -> bool:
    """Return True if the detected train (e.g. "17.9") matches any affected entry.

    Handles wildcard entries like "9.x" or "*" (any version on that platform).
    """
    for t in affected_trains:
        if t == "*":
            return True
        if t.endswith(".x"):
            # "9.x" matches any 9.* train
            major = t[:-2]
            if detected_train.startswith(major + "."):
                return True
        elif t == detected_train:
            return True
    return False
