"""
NGFW Platform Security Auditor (Firepower/FTD)
=================================================
NSA Firepower Hardening Guide
Checks: User access, management security, update compliance, FXOS, certificates
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class NgfwPlatformAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_management_access()
        self.check_user_accounts()
        self.check_fxos_version()
        self.check_dns_security()
        self.check_geolocation_updates()
        self.check_snmp_on_ftd()
        self.check_management_interface()
        return self.findings

    def check_management_access(self):
        if self.config.device_type != "ftd":
            return
        has_ssh_restrict = self.config.has_line(r"ssh.*access-list")
        has_https_restrict = self.config.has_line(r"(http|https).*access-list")
        issues = []
        if not has_ssh_restrict:
            issues.append("SSH access: not restricted by ACL")
        if not has_https_restrict:
            issues.append("HTTPS management: not restricted by ACL")
        if issues:
            self.finding("NGFW-PLAT-001", "FTD management access not restricted",
                self.SEVERITY_HIGH, "NGFW Platform Security",
                "Management access (SSH/HTTPS) to the FTD is not restricted by ACL.",
                issues,
                "Configure SSH access-list to limit management to specific admin IPs. "
                "Use FMC platform settings to restrict HTTPS access.",
                ["NSA Firepower Hardening Guide — Management Access",
                 "CIS Cisco FTD Benchmark 2.1"])

    def check_user_accounts(self):
        if self.config.device_type != "ftd":
            return
        users = self.config.find_lines(r"^username\s+\S+")
        admin_users = [u for u in users if "privilege 15" in u.lower() or "admin" in u.lower()]
        if len(admin_users) > 3:
            sanitized = [re.sub(r'(secret|password)\s+\S+', r'\1 ****', u) for u in admin_users]
            self.finding("NGFW-PLAT-002", f"Excessive admin accounts on FTD ({len(admin_users)})",
                self.SEVERITY_MEDIUM, "NGFW Platform Security",
                f"{len(admin_users)} admin-level accounts configured on the FTD. "
                "Minimize local accounts; use external AAA (TACACS+/RADIUS).",
                sanitized[:10],
                "Remove unnecessary local admin accounts. Use RADIUS/TACACS+ "
                "with external AAA for user management.",
                ["NSA Firepower Hardening Guide — User Accounts"])

    def check_fxos_version(self):
        if self.config.device_type != "ftd":
            return
        version = self.config.get_value(r"(FXOS|FTD|Firepower).*version\s+(\S+)", group=2)
        if version:
            # Flag if version appears old (heuristic)
            parts = version.split(".")
            try:
                major = int(parts[0])
                if major < 7:
                    self.finding("NGFW-PLAT-003", f"FTD/FXOS version may be outdated ({version})",
                        self.SEVERITY_HIGH, "NGFW Platform Security",
                        f"FTD/FXOS version {version} detected. Older versions may contain "
                        "unpatched security vulnerabilities.",
                        [f"Detected version: {version}"],
                        "Upgrade to the latest Cisco-recommended release. Check "
                        "sec.cloudapps.cisco.com for security advisories.",
                        ["NSA Firepower Hardening Guide — Software Updates"])
            except (ValueError, IndexError):
                pass

    def check_dns_security(self):
        if self.config.device_type != "ftd":
            return
        has_dns_inspect = self.config.has_line(r"(dns|domain).*inspect")
        if not has_dns_inspect:
            self.finding("NGFW-PLAT-004", "DNS inspection not configured on FTD",
                self.SEVERITY_MEDIUM, "NGFW Platform Security",
                "DNS inspection is not configured. Malicious DNS queries and "
                "DNS tunneling attacks may pass through the firewall.",
                remediation="Enable DNS inspection in the access control policy. "
                "Configure DNS sinkholing for known malicious domains.",
                references=["CIS Cisco FTD Benchmark — DNS Inspection"])

    def check_geolocation_updates(self):
        if self.config.device_type != "ftd":
            return
        has_geo = self.config.has_line(r"geo.*location|country.*rule")
        if not has_geo:
            self.finding("NGFW-PLAT-005", "Geolocation-based rules not detected",
                self.SEVERITY_LOW, "NGFW Platform Security",
                "No geolocation-based access control rules detected. "
                "Geolocation rules can block traffic from high-risk countries.",
                remediation="Configure geolocation rules in FMC for known threat origin countries. "
                "Keep the geolocation database updated.",
                references=["NSA Firepower Hardening Guide — Geolocation"])

    def check_snmp_on_ftd(self):
        if self.config.device_type != "ftd":
            return
        snmp = self.config.get_snmp_config()
        if snmp:
            has_v3 = any("v3" in l.lower() or "version 3" in l.lower() for l in snmp)
            if not has_v3:
                self.finding("NGFW-PLAT-006", "SNMP on FTD not using SNMPv3",
                    self.SEVERITY_MEDIUM, "NGFW Platform Security",
                    "SNMP is configured on the FTD but not using SNMPv3.",
                    remediation="Migrate to SNMPv3 with auth+priv.",
                    references=["CIS Cisco FTD Benchmark — SNMP Configuration"])

    def check_management_interface(self):
        if self.config.device_type != "ftd":
            return
        mgmt_intf = self.config.get_interfaces(r"management|mgmt")
        for intf, lines in mgmt_intf.items():
            # Check if management interface has proper ACL
            has_acl = any("access-group" in l.lower() or "access-list" in l.lower()
                        for l in lines)
            if not has_acl:
                self.finding("NGFW-PLAT-007", f"Management interface without ACL: {intf}",
                    self.SEVERITY_MEDIUM, "NGFW Platform Security",
                    f"FTD management interface {intf} has no access-group applied.",
                    remediation="Apply a restrictive ACL to the management interface.",
                    references=["NSA Firepower Hardening Guide — Management Interface"])
