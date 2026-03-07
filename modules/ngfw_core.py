"""
NGFW Core Security Auditor (Firepower/FTD)
=============================================
NSA Cisco Firepower Hardening Guide + CIS FTD Benchmark
Checks: Access control policies, IPS, AMP, SI, URL filtering, SSL inspection
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class NgfwCoreAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_default_action()
        self.check_ips_policy()
        self.check_malware_protection()
        self.check_security_intelligence()
        self.check_url_filtering()
        self.check_ssl_inspection()
        self.check_rule_logging()
        self.check_any_any_rules()
        self.check_rule_order()
        return self.findings

    def check_default_action(self):
        has_deny_default = (self.config.has_line(r"default.*action.*(block|deny|drop)") or
                          self.config.has_line(r"access-control.*default.*(block|deny)"))
        has_allow_default = self.config.has_line(r"default.*action.*allow")
        if has_allow_default:
            self.finding("NGFW-001", "Access control default action is Allow",
                self.SEVERITY_CRITICAL, "NGFW Core Security",
                "The default access control policy action is set to Allow. "
                "All traffic not matching an explicit rule is permitted through the firewall.",
                remediation="Set default action to Block All Traffic or Block with Reset. "
                "Create explicit allow rules for required traffic flows.",
                references=["NSA Firepower Hardening Guide — Access Control",
                           "CIS Cisco FTD Benchmark 3.1"])
        if not has_deny_default and not has_allow_default:
            # Check for generic firewall deny statements
            if self.config.device_type == "ftd":
                self.finding("NGFW-002", "Default access control action not verified",
                    self.SEVERITY_HIGH, "NGFW Core Security",
                    "Cannot determine the default access control action from the config. "
                    "Verify it is set to Block in FMC.",
                    remediation="In FMC: Policies → Access Control → Default Action → Block All Traffic",
                    references=["NSA Firepower Hardening Guide"])

    def check_ips_policy(self):
        has_ips = (self.config.has_line(r"(intrusion|ips)\s*(policy|rule)") or
                  self.config.has_line(r"snort") or
                  self.config.has_line(r"inspect.*policy"))
        if not has_ips:
            if self.config.device_type == "ftd":
                self.finding("NGFW-003", "IPS/intrusion policy not detected",
                    self.SEVERITY_HIGH, "NGFW Core Security",
                    "No intrusion prevention policy detected in the configuration. "
                    "Without IPS, known exploits and attacks pass through the firewall.",
                    remediation="Configure an intrusion policy (Balanced Security and Connectivity "
                    "or Maximum Detection) and assign to access control rules.",
                    references=["NSA Firepower Hardening Guide — Intrusion Policy",
                               "CIS Cisco FTD Benchmark 4.1"])

    def check_malware_protection(self):
        has_amp = (self.config.has_line(r"(malware|amp|file\s*policy|threat\s*defense)") or
                  self.config.has_line(r"file.*inspect"))
        if not has_amp and self.config.device_type == "ftd":
            self.finding("NGFW-004", "Advanced Malware Protection (AMP) not configured",
                self.SEVERITY_HIGH, "NGFW Core Security",
                "AMP/file policy is not detected. Without file inspection, "
                "malware downloads and transfers are not detected or blocked.",
                remediation="Create a File Policy with malware detection enabled (Block Malware). "
                "Assign to access control rules for HTTP/SMTP/FTP traffic.",
                references=["NSA Firepower Hardening Guide — Malware Protection",
                           "CIS Cisco FTD Benchmark 5.1"])

    def check_security_intelligence(self):
        has_si = (self.config.has_line(r"security.intelligence") or
                 self.config.has_line(r"(blacklist|blocklist|threat\s*feed)"))
        if not has_si and self.config.device_type == "ftd":
            self.finding("NGFW-005", "Security Intelligence feeds not configured",
                self.SEVERITY_HIGH, "NGFW Core Security",
                "Security Intelligence (SI) is not configured. SI provides proactive "
                "blocking of known malicious IPs, URLs, and domains before rule evaluation.",
                remediation="Enable Security Intelligence in the access control policy. "
                "Subscribe to Cisco Talos threat feeds. Configure both IP and URL intelligence.",
                references=["NSA Firepower Hardening Guide — Security Intelligence",
                           "CIS Cisco FTD Benchmark 6.1"])

    def check_url_filtering(self):
        has_url = (self.config.has_line(r"url.*(filter|category|reputation)") or
                  self.config.has_line(r"http.*inspect.*url"))
        if not has_url and self.config.device_type == "ftd":
            self.finding("NGFW-006", "URL filtering not configured",
                self.SEVERITY_MEDIUM, "NGFW Core Security",
                "URL category/reputation filtering is not detected. Without URL "
                "filtering, users can access malicious or policy-violating websites.",
                remediation="Configure URL filtering rules with category and reputation blocking. "
                "At minimum, block: Malware Sites, Phishing, Botnets, Spam URLs.",
                references=["NSA Firepower Hardening Guide — URL Filtering"])

    def check_ssl_inspection(self):
        has_ssl = (self.config.has_line(r"ssl.*(policy|inspection|decrypt)") or
                  self.config.has_line(r"decrypt.*rule"))
        if not has_ssl and self.config.device_type == "ftd":
            self.finding("NGFW-007", "SSL/TLS decryption not configured",
                self.SEVERITY_MEDIUM, "NGFW Core Security",
                "SSL/TLS inspection is not configured. Encrypted traffic (HTTPS) cannot "
                "be inspected for threats, bypassing IPS, AMP, and URL filtering.",
                remediation="Configure an SSL policy with Decrypt-Resign for outbound traffic "
                "and Decrypt-Known Key for inbound to critical servers. "
                "Add exceptions for privacy-sensitive categories.",
                references=["NSA Firepower Hardening Guide — SSL Inspection",
                           "CIS Cisco FTD Benchmark 7.1"])

    def check_rule_logging(self):
        rules = self.config.find_lines(r"(access-list|access-control|rule)\s")
        if rules:
            no_log = [r for r in rules if "log" not in r.lower()]
            total = len(rules)
            if no_log and len(no_log) > total * 0.5:
                self.finding("NGFW-008", f"Many firewall rules without logging ({len(no_log)}/{total})",
                    self.SEVERITY_MEDIUM, "NGFW Core Security",
                    f"{len(no_log)} of {total} rules have no logging configured. "
                    "Without logging, traffic matching (or not matching) rules is invisible.",
                    remediation="Enable connection logging on all access control rules. "
                    "Log at minimum: Begin and End of connection.",
                    references=["NSA Firepower Hardening Guide — Logging",
                               "CIS Cisco FTD Benchmark 8.1"])

    def check_any_any_rules(self):
        any_any = self.config.find_lines(
            r"(permit|allow)\s+(ip|tcp|udp)?\s*any\s+any")
        if any_any:
            self.finding("NGFW-009", f"Overly permissive 'any any' rules ({len(any_any)})",
                self.SEVERITY_HIGH, "NGFW Core Security",
                f"{len(any_any)} rule(s) permit all traffic from any source to any destination. "
                "These effectively bypass the firewall for matched traffic.",
                any_any[:10],
                "Replace 'any any' rules with specific source/destination definitions. "
                "If temporary, set an expiry date and review schedule.",
                ["CIS Cisco Benchmark — Firewall Rule Hygiene"])

    def check_rule_order(self):
        # Check if deny rules come before permit (reversed = misconfiguration)
        rules = self.config.find_lines(r"^(access-list|ip access-list)")
        if len(rules) > 5:
            first_deny_idx = None
            first_permit_idx = None
            for i, r in enumerate(rules):
                if "deny" in r.lower() and first_deny_idx is None:
                    first_deny_idx = i
                if "permit" in r.lower() and first_permit_idx is None:
                    first_permit_idx = i
            # This is a simplistic check — just informational
