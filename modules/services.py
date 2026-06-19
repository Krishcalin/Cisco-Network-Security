"""
Services & Protocols Auditor
===============================
CIS Benchmark Sections: 4.x
Checks: Disable unused services, SNMP security, DNS, BOOTP, finger, etc.
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class ServicesProtocolsAuditor(BaseAuditor):

    DANGEROUS_SERVICES = [
        ("ip finger", "Finger service — user enumeration"),
        ("ip bootp server", "BOOTP server — unnecessary in most deployments"),
        ("ip identd", "Ident service — information disclosure"),
        ("service pad", "PAD service — X.25 packet assembler/disassembler"),
        ("ip http server", "HTTP server — unencrypted web management"),
        ("service tcp-small-servers", "TCP small servers (echo, chargen, etc.)"),
        ("service udp-small-servers", "UDP small servers (echo, chargen, etc.)"),
        ("service config", "Remote config loading — network boot vector"),
        ("ip domain-lookup", "DNS lookup on typos can delay CLI operations"),
    ]

    # The "dangerous services" list (ip finger, bootp, identd, service pad,
    # tcp/udp small-servers, service config) is IOS / IOS-XE only. NX-OS uses
    # 'feature' to enable services; ASA/FTD have a fixed service set. SNMP
    # checks look for IOS-format 'snmp-server community' lines that NX-OS
    # writes differently and ASA writes as 'snmp-server host inside ... community'.
    SUPPORTED_PLATFORMS = {"ios", "iosxe", "wlc"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_platform():
            return self._emit_skip_notice("Services & Protocols")
        self.check_unused_services()
        self.check_snmp_version()
        self.check_snmp_community()
        self.check_snmp_acl()
        self.check_snmp_views()
        self.check_tcp_keepalives()
        self.check_ip_cef()
        self.check_service_timestamps()
        return self.findings

    def check_unused_services(self):
        enabled = []
        for service, desc in self.DANGEROUS_SERVICES:
            # Check if NOT disabled
            service_pattern = service.replace(" ", r"\s+")
            has_service = self.config.has_line(rf"^{service_pattern}")
            has_no = self.config.has_line(rf"^no\s+{service_pattern}")
            if has_service and not has_no:
                enabled.append(f"{service} — {desc}")
        if enabled:
            self.finding("SVC-001", f"Unnecessary services enabled ({len(enabled)})",
                self.SEVERITY_HIGH, "Services & Protocols",
                f"{len(enabled)} unnecessary service(s) are enabled, increasing attack surface.",
                enabled,
                "Disable each service with the 'no' prefix. Example: no ip finger",
                ["CIS Cisco IOS Benchmark 4.1"])

    def check_snmp_version(self):
        snmp = self.config.get_snmp_config()
        has_v1v2 = any(re.search(r"snmp-server community\s+\S+\s+(RO|RW)", l, re.I)
                      for l in snmp)
        has_v3 = any(re.search(r"snmp-server group\s+\S+\s+v3", l, re.I) for l in snmp)

        if has_v1v2 and not has_v3:
            self.finding("SVC-002", "Only SNMPv1/v2c configured (no SNMPv3)",
                self.SEVERITY_HIGH, "Services & Protocols",
                "SNMP is configured with community strings (v1/v2c) only. "
                "Community strings are transmitted in plaintext and lack "
                "authentication and encryption.",
                remediation="Migrate to SNMPv3 with authentication (auth) and "
                "encryption (priv):\nsnmp-server group <grp> v3 priv\n"
                "snmp-server user <usr> <grp> v3 auth sha <pass> priv aes 256 <key>",
                references=["CIS Cisco IOS Benchmark 4.2.1"])
        if has_v1v2:
            # Check for default communities
            for l in snmp:
                m = re.search(r"snmp-server community\s+(\S+)\s+(RO|RW)", l, re.I)
                if m:
                    comm = m.group(1).lower()
                    perm = m.group(2).upper()
                    if comm in ("public", "private", "community", "cisco", "default"):
                        self.finding("SVC-003", f"Default SNMP community string: '{m.group(1)}'",
                            self.SEVERITY_CRITICAL, "Services & Protocols",
                            f"SNMP community string '{m.group(1)}' ({perm}) is a well-known default. "
                            "Attackers will test these first.",
                            affected_items=[l],
                            remediation="Change to a complex, non-guessable community string, "
                            "or migrate to SNMPv3.",
                            references=["CIS Cisco IOS Benchmark 4.2.2"])
                    if perm == "RW":
                        self.finding("SVC-004", "SNMP Read-Write (RW) community configured",
                            self.SEVERITY_HIGH, "Services & Protocols",
                            f"SNMP RW community allows remote configuration changes. "
                            "If compromised, an attacker can modify the entire device config.",
                            affected_items=[re.sub(r'community\s+\S+', 'community ****', l)],
                            remediation="Remove RW community if not required. Use SNMPv3 with "
                            "strict ACL for write access.",
                            references=["CIS Cisco IOS Benchmark 4.2.3"])

    def check_snmp_community(self):
        pass  # Covered in check_snmp_version

    def check_snmp_acl(self):
        snmp = self.config.get_snmp_config()
        communities = [l for l in snmp if "community" in l.lower()]
        for comm_line in communities:
            # Check if ACL is applied to community
            parts = comm_line.split()
            # Format: snmp-server community <string> <RO|RW> [ACL]
            if len(parts) <= 4:
                self.finding("SVC-005", "SNMP community without access-list restriction",
                    self.SEVERITY_HIGH, "Services & Protocols",
                    "SNMP community is configured without an ACL. Any IP can query "
                    "this device via SNMP.",
                    affected_items=[re.sub(r'community\s+\S+', 'community ****', comm_line)],
                    remediation="Apply an ACL: snmp-server community <str> RO <acl-number>",
                    references=["CIS Cisco IOS Benchmark 4.2.4"])
                break

    def check_snmp_views(self):
        snmp = self.config.get_snmp_config()
        has_traps = any("snmp-server host" in l.lower() for l in snmp)
        if has_traps:
            trap_targets = [l for l in snmp if "snmp-server host" in l.lower()]
            # Check if trap destinations use v3
            for t in trap_targets:
                if "version 3" not in t.lower() and "v3" not in t.lower():
                    self.finding("SVC-006", "SNMP traps not using SNMPv3",
                        self.SEVERITY_MEDIUM, "Services & Protocols",
                        "SNMP trap destinations are not configured with SNMPv3.",
                        affected_items=[re.sub(r'community\s+\S+', 'community ****', t) for t in trap_targets[:5]],
                        remediation="Configure trap hosts with SNMPv3: "
                        "snmp-server host <ip> version 3 priv <user>",
                        references=["CIS Cisco IOS Benchmark 4.2.5"])
                    break

    def check_tcp_keepalives(self):
        if not self.config.has_line(r"^service tcp-keepalives-in"):
            self.finding("SVC-007", "TCP keepalives-in not enabled",
                self.SEVERITY_LOW, "Services & Protocols",
                "TCP keepalives for incoming connections not enabled. "
                "Stale/orphaned TCP sessions may persist.",
                remediation="Configure: service tcp-keepalives-in\nservice tcp-keepalives-out",
                references=["CIS Cisco IOS Benchmark 4.3.1"])

    def check_ip_cef(self):
        if not self.config.has_line(r"^ip cef") and not self.config.has_line(r"^ipv6 cef"):
            self.finding("SVC-008", "Cisco Express Forwarding (CEF) not enabled",
                self.SEVERITY_MEDIUM, "Services & Protocols",
                "CEF is not explicitly enabled. CEF is required for many security "
                "features including uRPF.",
                remediation="Configure: ip cef",
                references=["Cisco IOS Hardening Guide — CEF"])

    def check_service_timestamps(self):
        has_ts_log = self.config.has_line(r"^service timestamps log datetime")
        has_ts_debug = self.config.has_line(r"^service timestamps debug datetime")
        issues = []
        if not has_ts_log:
            issues.append("service timestamps log datetime — not configured")
        if not has_ts_debug:
            issues.append("service timestamps debug datetime — not configured")
        if issues:
            self.finding("SVC-009", "Service timestamps not configured with datetime",
                self.SEVERITY_MEDIUM, "Services & Protocols",
                "Log/debug timestamps are not configured with datetime format. "
                "Without proper timestamps, log correlation and forensics are impaired.",
                affected_items=issues,
                remediation="Configure: service timestamps log datetime msec localtime show-timezone\n"
                "service timestamps debug datetime msec localtime show-timezone",
                references=["CIS Cisco IOS Benchmark 4.4.1"])
