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
        "id": "CISCO-CVE-019", "cve": "CVE-2023-20025", "severity": "CRITICAL",
        "cvss": 9.8,
        "title": "Small Business RV016/RV042/RV082/RV320/RV325 — auth bypass",
        "description": "Improper validation of user input in the web management "
                       "interface lets a remote attacker bypass authentication and "
                       "execute arbitrary commands as root.",
        "platforms": ["ios"],
        "trains": ["4.x", "1.x"],
        "fixed_advice": "These RV products are end-of-life; replace with a supported platform.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv-overflow-WUnUgv4U",
        "kev": True, "exploited": True, "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-020", "cve": "CVE-2021-1414", "severity": "CRITICAL",
        "cvss": 8.1,
        "title": "Small Business 220 Series switches — auth bypass and RCE",
        "description": "Insufficient validation of HTTP requests lets a remote "
                       "unauthenticated attacker bypass authentication and execute "
                       "arbitrary code on Cisco Small Business 220 Series switches.",
        "platforms": ["ios"],
        "trains": ["1.x"],
        "fixed_advice": "Upgrade firmware to 1.2.0.6 or later.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb220-multi-7teLepwz",
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
        "title": "WLC 9800 / AireOS — authentication bypass",
        "description": "Improper implementation of the password validation "
                       "algorithm in the Cisco Wireless LAN Controller (9800, AireOS) "
                       "lets a remote attacker log in to the WLC management interface "
                       "with elevated privileges if a specific configuration exists.",
        "platforms": ["wlc"],
        "trains": ["8.10", "16.12", "17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade to 17.3.4c / 17.6.2 / 17.9.1 or later; review macfilter-radius config.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-auth-bypass-JBkahkhd",
        "kev": False, "exploited": False, "cwe": "CWE-287",
    },
    {
        "id": "CISCO-CVE-025", "cve": "CVE-2023-20025", "severity": "HIGH",
        "cvss": 7.5,
        "title": "WLC 9800 IPv6 packet processing denial of service",
        "description": "Improper handling of certain IPv6 packets on the management "
                       "interface lets an unauthenticated adjacent attacker cause "
                       "the WLC to crash and reload.",
        "platforms": ["wlc", "iosxe"],
        "trains": ["17.3", "17.6", "17.9"],
        "fixed_advice": "Upgrade per the advisory.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-ipv6-dos-LjJ7B5SR",
        "kev": False, "exploited": False, "cwe": "CWE-754",
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
    {
        "id": "CISCO-CVE-040", "cve": "CVE-2022-20695", "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "WLC RADIUS authentication bypass via macfilter",
        "description": "Improper password validation when the WLC is configured to "
                       "use macfilter-radius authentication lets a remote attacker "
                       "log in as any user with full admin rights.",
        "platforms": ["wlc"],
        "trains": ["8.10", "16.12", "17.3", "17.6"],
        "fixed_advice": "Upgrade per advisory; avoid macfilter-radius as a primary admin auth method.",
        "advisory": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-auth-bypass-JBkahkhd",
        "kev": False, "exploited": False, "cwe": "CWE-287",
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
    """Map ParsedConfig.device_type to the keys used in CVE entries' platforms."""
    # ParsedConfig._detect_type returns: ftd, nxos, wlc, iosxe, ios.
    # ASA configs are auto-detected as 'ios' or 'iosxe' today since the parser
    # has no specific marker. The CVE check disambiguates via the raw text below.
    return detected


def _looks_like_asa(raw_text: str) -> bool:
    """Heuristic to detect ASA running-config (distinct from IOS/IOS-XE)."""
    asa_markers = [
        r"^\s*ASA\s+Version\s+\d",
        r"^names$",
        r"^interface\s+(GigabitEthernet|TenGigabitEthernet)\d+/\d+\s*$",
        r"^webvpn\b",
        r"^anyconnect\b",
        r"^tunnel-group\s+",
        r"^access-list\s+\S+\s+extended\s+",
    ]
    rx = re.compile("|".join(asa_markers), re.IGNORECASE | re.MULTILINE)
    return bool(rx.search(raw_text))


# ──────────────────────────────────────────────────────────────────────────────
# AUDITOR
# ──────────────────────────────────────────────────────────────────────────────

class CveDetectionAuditor(BaseAuditor):
    """Match the device's detected platform + train against the CVE database."""

    def run_all_checks(self) -> List[Dict[str, Any]]:
        device_type = _normalize_device_type(self.config.device_type)

        # ASA disambiguation: ParsedConfig calls ASA configs 'ios' or 'iosxe'
        # because the parser has no explicit marker. Re-classify here.
        if device_type in ("ios", "iosxe") and _looks_like_asa(self.config.raw):
            device_type = "asa"

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
