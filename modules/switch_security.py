"""
Switch-Specific Security Auditor
===================================
Checks: Port security, VLAN security, trunk hardening, DTP, native VLAN, VACL
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class SwitchSecurityAuditor(BaseAuditor):
    # Switchport checks (port-security, native VLAN, DTP, BPDU guard, IP source
    # guard) are IOS / IOS-XE Catalyst syntax. NX-OS has switchports but uses
    # different feature flags; ASA/FTD/WLC aren't L2 switches.
    SUPPORTED_PLATFORMS = {"ios", "iosxe"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.supports_platform():
            return self._emit_skip_notice("Switch Security")
        self.check_port_security()
        self.check_trunk_native_vlan()
        self.check_dtp_negotiation()
        self.check_unused_ports()
        self.check_vlan1_usage()
        self.check_bpdu_guard_global()
        self.check_dhcp_rate_limiting()
        self.check_ip_source_guard()
        return self.findings

    def check_port_security(self):
        interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet|Ethernet)")
        no_portsec = []
        for intf, lines in interfaces.items():
            is_access = any("switchport mode access" in l.lower() for l in lines)
            if is_access:
                has_portsec = any("switchport port-security" in l.lower() for l in lines)
                if not has_portsec:
                    no_portsec.append(intf.split()[-1] if " " in intf else intf)
        if no_portsec:
            self.finding("SW-001", f"Port security not enabled on {len(no_portsec)} access port(s)",
                self.SEVERITY_MEDIUM, "Switch Security",
                f"{len(no_portsec)} access port(s) have no port-security. Unauthorized devices "
                "can connect and access the network.",
                no_portsec[:20],
                "Configure on access ports: switchport port-security\n"
                "switchport port-security maximum 2\n"
                "switchport port-security violation restrict\n"
                "switchport port-security mac-address sticky",
                ["CIS Cisco IOS Benchmark 5.1"],
                details={"total_count": len(no_portsec)})

    def check_trunk_native_vlan(self):
        interfaces = self.config.get_interfaces()
        trunks = []
        for intf, lines in interfaces.items():
            is_trunk = any("switchport mode trunk" in l.lower() for l in lines)
            if is_trunk:
                native = [l for l in lines if "switchport trunk native" in l.lower()]
                if not native:
                    trunks.append(f"{intf} — native VLAN: default (VLAN 1)")
                else:
                    for n in native:
                        m = re.search(r"native vlan\s+(\d+)", n, re.I)
                        if m and m.group(1) == "1":
                            trunks.append(f"{intf} — native VLAN 1 (default)")
        if trunks:
            self.finding("SW-002", "Trunk ports using default native VLAN 1",
                self.SEVERITY_HIGH, "Switch Security",
                f"{len(trunks)} trunk port(s) use native VLAN 1. VLAN hopping attacks "
                "exploit the default native VLAN.",
                trunks,
                "Change native VLAN: switchport trunk native vlan <unused-vlan-id>",
                ["CIS Cisco IOS Benchmark 5.2"])

    def check_dtp_negotiation(self):
        interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet|TenGig)")
        dtp_enabled = []
        for intf, lines in interfaces.items():
            is_access = any("switchport mode access" in l.lower() for l in lines)
            has_noneg = any("switchport nonegotiate" in l.lower() for l in lines)
            if is_access and not has_noneg:
                dtp_enabled.append(intf.split()[-1] if " " in intf else intf)
        if dtp_enabled:
            self.finding("SW-003", f"DTP negotiation not disabled on {len(dtp_enabled)} port(s)",
                self.SEVERITY_HIGH, "Switch Security",
                f"{len(dtp_enabled)} port(s) may still negotiate trunk mode via DTP. "
                "An attacker can force a trunk and access all VLANs.",
                dtp_enabled[:20],
                "Configure on access ports: switchport nonegotiate",
                ["CIS Cisco IOS Benchmark 5.3"],
                details={"total_count": len(dtp_enabled)})

    def check_unused_ports(self):
        interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet|Ethernet)")
        active_no_shutdown = []
        for intf, lines in interfaces.items():
            is_shutdown = any("shutdown" == l.lower().strip() for l in lines)
            has_config = any(l.lower().startswith("switchport") or
                           l.lower().startswith("ip address") for l in lines)
            if not is_shutdown and not has_config:
                active_no_shutdown.append(intf.split()[-1] if " " in intf else intf)
        if active_no_shutdown:
            self.finding("SW-004", f"Unused ports not shut down ({len(active_no_shutdown)})",
                self.SEVERITY_MEDIUM, "Switch Security",
                f"{len(active_no_shutdown)} port(s) appear unused but are not administratively "
                "shutdown. Unused ports should be disabled and placed in an unused VLAN.",
                active_no_shutdown[:20],
                "Configure: shutdown\nswitchport access vlan <unused-vlan>",
                ["CIS Cisco IOS Benchmark 5.4"],
                details={"total_count": len(active_no_shutdown)})

    def check_vlan1_usage(self):
        interfaces = self.config.get_interfaces()
        vlan1_usage = []
        for intf, lines in interfaces.items():
            for l in lines:
                if re.search(r"switchport access vlan\s+1\b", l, re.I):
                    vlan1_usage.append(intf.split()[-1] if " " in intf else intf)
        if vlan1_usage:
            self.finding("SW-005", f"Access ports assigned to VLAN 1 ({len(vlan1_usage)})",
                self.SEVERITY_MEDIUM, "Switch Security",
                f"{len(vlan1_usage)} access port(s) are explicitly assigned to VLAN 1. "
                "VLAN 1 should only be used for management/control traffic.",
                vlan1_usage[:10],
                "Move user ports to non-default VLANs: switchport access vlan <vlan-id>",
                ["CIS Cisco IOS Benchmark 5.5"])

    def check_bpdu_guard_global(self):
        if not self.config.has_line(r"^spanning-tree portfast (bpduguard|edge bpduguard) default"):
            self.finding("SW-006", "BPDU Guard not enabled globally as default",
                self.SEVERITY_MEDIUM, "Switch Security",
                "BPDU Guard is not enabled as the global default for portfast ports. "
                "Rogue switches on access ports can cause STP disruptions.",
                remediation="Configure: spanning-tree portfast bpduguard default",
                references=["CIS Cisco IOS Benchmark 5.6"])

    def check_dhcp_rate_limiting(self):
        if self.config.has_line(r"^ip dhcp snooping"):
            interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet)")
            no_limit = []
            for intf, lines in interfaces.items():
                is_access = any("switchport mode access" in l.lower() for l in lines)
                if is_access:
                    has_limit = any("ip dhcp snooping limit rate" in l.lower() for l in lines)
                    if not has_limit:
                        no_limit.append(intf.split()[-1] if " " in intf else intf)
            if no_limit:
                self.finding("SW-007", f"DHCP snooping rate limit not set on {len(no_limit)} port(s)",
                    self.SEVERITY_LOW, "Switch Security",
                    "DHCP snooping rate limiting not configured on access ports. "
                    "A malicious client could flood the DHCP server.",
                    no_limit[:10],
                    "Configure: ip dhcp snooping limit rate 15",
                    ["Cisco Switch Hardening — DHCP Rate Limiting"],
                    details={"total_count": len(no_limit)})

    def check_ip_source_guard(self):
        if self.config.has_line(r"^ip dhcp snooping"):
            interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet)")
            no_guard = []
            for intf, lines in interfaces.items():
                is_access = any("switchport mode access" in l.lower() for l in lines)
                if is_access:
                    has_guard = any("ip verify source" in l.lower() for l in lines)
                    if not has_guard:
                        no_guard.append(intf.split()[-1] if " " in intf else intf)
            if no_guard and len(no_guard) < 50:
                self.finding("SW-008", f"IP Source Guard not enabled on {len(no_guard)} access port(s)",
                    self.SEVERITY_MEDIUM, "Switch Security",
                    "IP Source Guard prevents IP/MAC spoofing on access ports.",
                    no_guard[:10],
                    "Configure: ip verify source",
                    ["CIS Cisco IOS Benchmark 5.7"],
                    details={"total_count": len(no_guard)})
