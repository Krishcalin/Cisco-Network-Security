"""
Wireless Security Auditor
============================
Checks: SSID security, WPA2/WPA3, rogue AP detection, WLC management, WIDS, MFP
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class WirelessSecurityAuditor(BaseAuditor):

    WEAK_ENCRYPTION = ["wep", "open", "tkip", "wpa "]  # WPA1 without 2

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_ssid_encryption()
        self.check_wpa_version()
        self.check_psk_strength()
        self.check_management_ssid()
        self.check_mgmt_over_wireless()
        self.check_rogue_detection()
        self.check_client_exclusion()
        self.check_wlc_ssh()
        self.check_mfp()
        return self.findings

    def check_ssid_encryption(self):
        wlans = self.config.get_section("wlan")
        if not wlans:
            return
        weak = []
        for section, lines in wlans.items():
            ssid_name = section
            encryption = [l for l in lines if re.search(r"security|encryption|auth", l, re.I)]
            all_lines = " ".join(lines).lower()
            if "open" in all_lines and "web-auth" not in all_lines:
                weak.append(f"{ssid_name} — OPEN (no encryption)")
            elif "wep" in all_lines:
                weak.append(f"{ssid_name} — WEP (broken encryption)")
        if weak:
            self.finding("WIFI-001", "WLANs with weak or no encryption",
                self.SEVERITY_CRITICAL, "Wireless Security",
                f"{len(weak)} WLAN(s) use open or WEP encryption. WEP is cryptographically "
                "broken and open networks expose all traffic.",
                weak,
                "Migrate to WPA2-Enterprise (802.1X) or WPA3-SAE at minimum.",
                ["CIS Wireless Benchmark — Encryption Requirements"])

    def check_wpa_version(self):
        wlans = self.config.get_section("wlan")
        for section, lines in wlans.items():
            all_text = " ".join(lines).lower()
            if "wpa" in all_text and "wpa2" not in all_text and "wpa3" not in all_text:
                self.finding("WIFI-002", f"WPA1 only on {section}",
                    self.SEVERITY_HIGH, "Wireless Security",
                    f"{section} uses WPA (version 1) which has known TKIP vulnerabilities.",
                    remediation="Upgrade to WPA2 (AES-CCMP) or WPA3-SAE.",
                    references=["Wi-Fi Alliance — WPA3 Specification"])
            if "tkip" in all_text and "aes" not in all_text and "ccmp" not in all_text:
                self.finding("WIFI-003", f"TKIP cipher on {section} (no AES)",
                    self.SEVERITY_HIGH, "Wireless Security",
                    f"{section} uses TKIP cipher only. TKIP has known weaknesses.",
                    remediation="Configure AES-CCMP cipher for all WLANs.",
                    references=["CIS Wireless Benchmark — Cipher Requirements"])

    def check_psk_strength(self):
        wlans = self.config.get_section("wlan")
        for section, lines in wlans.items():
            for l in lines:
                m = re.search(r"(psk|pre-shared-key|wpa-psk)\s+(\S+)", l, re.I)
                if m:
                    psk = m.group(2)
                    if len(psk) < 12:
                        self.finding("WIFI-004", f"Weak PSK on {section} (length: {len(psk)})",
                            self.SEVERITY_HIGH, "Wireless Security",
                            f"Pre-shared key on {section} is only {len(psk)} characters. "
                            "Short PSKs are vulnerable to offline brute-force attacks.",
                            remediation="Use PSK of 20+ characters or migrate to 802.1X.",
                            references=["Wi-Fi Alliance — PSK Best Practices"])

    def check_management_ssid(self):
        wlans = self.config.get_section("wlan")
        for section, lines in wlans.items():
            all_text = " ".join(lines).lower()
            name_lower = section.lower()
            if any(kw in name_lower for kw in ["mgmt", "admin", "management", "infra"]):
                if "802.1x" not in all_text and "eap" not in all_text and "dot1x" not in all_text:
                    self.finding("WIFI-005", f"Management WLAN without 802.1X: {section}",
                        self.SEVERITY_HIGH, "Wireless Security",
                        f"WLAN '{section}' appears to be a management network but does not "
                        "use 802.1X (EAP) authentication.",
                        remediation="Configure 802.1X with RADIUS for management WLANs.",
                        references=["Cisco WLC Security Best Practices"])

    def check_mgmt_over_wireless(self):
        if self.config.has_line(r"management\s+(via|over)\s+wireless.*enable"):
            self.finding("WIFI-006", "WLC management via wireless is enabled",
                self.SEVERITY_HIGH, "Wireless Security",
                "WLC management access is allowed over wireless. An attacker on the "
                "wireless network could attempt to manage the controller.",
                remediation="Disable: config network mgmt-via-wireless disable",
                references=["Cisco WLC Best Practices — Security"])
        # Also check IOS-XE WLC config
        if self.config.has_line(r"wireless management interface.*wireless"):
            pass  # Similar check for C9800

    def check_rogue_detection(self):
        has_rogue = (self.config.has_line(r"rogue.*detection") or
                    self.config.has_line(r"wps.*rogue") or
                    self.config.has_line(r"rogue ap"))
        if not has_rogue and self.config.device_type == "wlc":
            self.finding("WIFI-007", "Rogue AP detection not configured",
                self.SEVERITY_MEDIUM, "Wireless Security",
                "Rogue access point detection is not visibly configured. "
                "Rogue APs can create backdoor access to the network.",
                remediation="Enable rogue AP detection and containment in the WLC. "
                "Configure auto-containment for detected rogues on the wired network.",
                references=["Cisco WLC — Rogue AP Detection"])

    def check_client_exclusion(self):
        if self.config.device_type == "wlc":
            if not self.config.has_line(r"client.exclusion.*enable"):
                self.finding("WIFI-008", "Client exclusion policies not enabled",
                    self.SEVERITY_MEDIUM, "Wireless Security",
                    "Client exclusion is not enabled. Misbehaving clients "
                    "(failed auth, DoS) are not automatically blocked.",
                    remediation="Enable: config wps client-exclusion all enable",
                    references=["Cisco WLC Security Best Practices — Client Exclusion"])

    def check_wlc_ssh(self):
        if self.config.device_type == "wlc":
            if self.config.has_line(r"transfer.*telnet") or \
               (not self.config.has_line(r"ssh") and self.config.has_line(r"telnet")):
                self.finding("WIFI-009", "WLC management via Telnet (not SSH)",
                    self.SEVERITY_HIGH, "Wireless Security",
                    "WLC management appears to use Telnet instead of SSH.",
                    remediation="Enable SSH and disable Telnet for WLC CLI access.",
                    references=["Cisco WLC — SSH Configuration"])

    def check_mfp(self):
        if self.config.device_type == "wlc":
            if not self.config.has_line(r"(management frame protection|mfp|pmf)"):
                self.finding("WIFI-010", "Management Frame Protection (MFP/PMF) not configured",
                    self.SEVERITY_MEDIUM, "Wireless Security",
                    "802.11w Management Frame Protection is not configured. "
                    "Without MFP, deauthentication and disassociation attacks are possible.",
                    remediation="Enable PMF (802.11w) on all WLANs: "
                    "security pmf mandatory (or optional for compatibility).",
                    references=["IEEE 802.11w — Protected Management Frames"])
