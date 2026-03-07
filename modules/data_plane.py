"""
Data Plane Security Auditor
==============================
CIS Benchmark Sections: 3.x (Data Plane)
Checks: uRPF, DHCP snooping, DAI, storm control, iACLs, ICMP controls
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class DataPlaneAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_urpf()
        self.check_dhcp_snooping()
        self.check_arp_inspection()
        self.check_storm_control()
        self.check_ip_directed_broadcast()
        self.check_icmp_redirects()
        self.check_icmp_unreachables()
        self.check_proxy_arp()
        self.check_ip_mask_reply()
        return self.findings

    def check_urpf(self):
        interfaces = self.config.get_interfaces(r"(Serial|GigabitEthernet|TenGig|Ethernet)")
        for intf, lines in interfaces.items():
            is_l3 = any("ip address" in l.lower() for l in lines)
            if is_l3:
                has_urpf = any("ip verify unicast source reachable-via" in l.lower() or
                              "ip verify unicast reverse-path" in l.lower()
                              for l in lines)
                if not has_urpf:
                    self.finding("DATA-001", f"uRPF not enabled on {intf}",
                        self.SEVERITY_MEDIUM, "Data Plane",
                        f"Unicast RPF is not enabled on {intf}. Without uRPF, spoofed "
                        "source IP packets are forwarded without validation.",
                        affected_items=[intf],
                        remediation="Configure: ip verify unicast source reachable-via rx (strict) "
                        "or 'any' (loose)",
                        references=["CIS Cisco IOS Benchmark 3.1.1"])

    def check_dhcp_snooping(self):
        if not self.config.has_line(r"^ip dhcp snooping$") and \
           not self.config.has_line(r"^ip dhcp snooping vlan"):
            if self.config.device_type in ("ios", "iosxe"):
                self.finding("DATA-002", "DHCP Snooping not enabled",
                    self.SEVERITY_HIGH, "Data Plane",
                    "DHCP Snooping is not enabled. Without it, rogue DHCP servers "
                    "can assign malicious configurations (gateway, DNS) to clients.",
                    remediation="Configure: ip dhcp snooping\nip dhcp snooping vlan <vlans>\n"
                    "Mark trusted uplinks: ip dhcp snooping trust",
                    references=["CIS Cisco IOS Benchmark 3.2.1"])

    def check_arp_inspection(self):
        if not self.config.has_line(r"^ip arp inspection vlan"):
            if self.config.device_type in ("ios", "iosxe"):
                self.finding("DATA-003", "Dynamic ARP Inspection (DAI) not enabled",
                    self.SEVERITY_HIGH, "Data Plane",
                    "DAI is not configured. Without it, ARP spoofing/poisoning attacks "
                    "can redirect traffic through an attacker's machine (MITM).",
                    remediation="Configure: ip arp inspection vlan <vlans>\n"
                    "Requires DHCP Snooping to be enabled first.",
                    references=["CIS Cisco IOS Benchmark 3.2.2"])

    def check_storm_control(self):
        interfaces = self.config.get_interfaces(r"(GigabitEthernet|FastEthernet|TenGig|Ethernet)")
        no_storm = []
        for intf, lines in interfaces.items():
            is_access = any("switchport" in l.lower() for l in lines)
            if is_access:
                has_storm = any("storm-control" in l.lower() for l in lines)
                if not has_storm:
                    no_storm.append(intf.split()[-1] if " " in intf else intf)
        if no_storm and len(no_storm) > 0:
            self.finding("DATA-004", f"Storm control not configured on {len(no_storm)} switchport(s)",
                self.SEVERITY_MEDIUM, "Data Plane",
                f"{len(no_storm)} switchport interface(s) have no storm control configured. "
                "Broadcast/multicast storms can cause network-wide outages.",
                affected_items=no_storm[:20],
                remediation="Configure on access ports:\nstorm-control broadcast level 10.00\n"
                "storm-control multicast level 10.00\nstorm-control action shutdown",
                references=["CIS Cisco IOS Benchmark 3.3.1"],
                details={"total_count": len(no_storm)})

    def check_ip_directed_broadcast(self):
        if not self.config.has_line(r"^no ip directed-broadcast"):
            interfaces = self.config.get_interfaces()
            for intf, lines in interfaces.items():
                is_l3 = any("ip address" in l.lower() for l in lines)
                has_no_db = any("no ip directed-broadcast" in l.lower() for l in lines)
                if is_l3 and not has_no_db:
                    # Note: disabled by default in IOS 12.0+, but verify
                    pass
        # Check if explicitly enabled anywhere
        enabled = self.config.find_lines(r"^\s*ip directed-broadcast$")
        if enabled:
            self.finding("DATA-005", "IP directed-broadcast enabled",
                self.SEVERITY_HIGH, "Data Plane",
                "IP directed-broadcast is enabled on one or more interfaces. "
                "This enables Smurf-style DDoS amplification attacks.",
                affected_items=enabled,
                remediation="Configure on all interfaces: no ip directed-broadcast",
                references=["CIS Cisco IOS Benchmark 3.4.1"])

    def check_icmp_redirects(self):
        interfaces = self.config.get_interfaces()
        for intf, lines in interfaces.items():
            is_l3 = any("ip address" in l.lower() for l in lines)
            if is_l3:
                has_no_redirect = any("no ip redirects" in l.lower() for l in lines)
                if not has_no_redirect:
                    self.finding("DATA-006", f"ICMP redirects not disabled on {intf}",
                        self.SEVERITY_MEDIUM, "Data Plane",
                        f"ICMP redirects are enabled on {intf}. An attacker can send crafted "
                        "ICMP redirects to divert traffic through a malicious gateway.",
                        affected_items=[intf],
                        remediation="Configure on interface: no ip redirects",
                        references=["CIS Cisco IOS Benchmark 3.4.2"])
                    break  # Report once, not per-interface

    def check_icmp_unreachables(self):
        # Check on external-facing interfaces
        interfaces = self.config.get_interfaces()
        for intf, lines in interfaces.items():
            is_l3 = any("ip address" in l.lower() for l in lines)
            if is_l3:
                has_no_unreach = any("no ip unreachables" in l.lower() for l in lines)
                if not has_no_unreach:
                    self.finding("DATA-007", f"ICMP unreachables not disabled on {intf}",
                        self.SEVERITY_LOW, "Data Plane",
                        f"ICMP unreachable messages enabled on {intf}. These can be used "
                        "for network reconnaissance (port scanning, mapping).",
                        affected_items=[intf],
                        remediation="Configure on external interfaces: no ip unreachables",
                        references=["CIS Cisco IOS Benchmark 3.4.3"])
                    break

    def check_proxy_arp(self):
        interfaces = self.config.get_interfaces()
        enabled_ints = []
        for intf, lines in interfaces.items():
            is_l3 = any("ip address" in l.lower() for l in lines)
            if is_l3:
                has_no_proxy = any("no ip proxy-arp" in l.lower() for l in lines)
                if not has_no_proxy:
                    enabled_ints.append(intf.split()[-1] if " " in intf else intf)
        if enabled_ints:
            self.finding("DATA-008", f"Proxy ARP enabled on {len(enabled_ints)} interface(s)",
                self.SEVERITY_MEDIUM, "Data Plane",
                f"Proxy ARP is enabled (default) on {len(enabled_ints)} L3 interface(s). "
                "This can allow ARP-based attacks across subnets.",
                affected_items=enabled_ints[:10],
                remediation="Configure on each interface: no ip proxy-arp",
                references=["CIS Cisco IOS Benchmark 3.4.4"],
                details={"total_count": len(enabled_ints)})

    def check_ip_mask_reply(self):
        interfaces = self.config.get_interfaces()
        for intf, lines in interfaces.items():
            has_mask_reply = any("ip mask-reply" in l.lower() and
                               "no ip mask-reply" not in l.lower() for l in lines)
            if has_mask_reply:
                self.finding("DATA-009", f"IP mask-reply enabled on {intf}",
                    self.SEVERITY_LOW, "Data Plane",
                    f"IP mask-reply is enabled on {intf}. This discloses subnet mask "
                    "information to potential attackers.",
                    remediation="Configure: no ip mask-reply",
                    references=["Cisco IOS Hardening Guide"])
                break
