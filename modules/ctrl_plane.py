"""
Control Plane Security Auditor
================================
CIS Benchmark Sections: 2.x (Control Plane)
Checks: CoPP, routing protocol auth, NTP security, STP protection
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class ControlPlaneAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_copp()
        self.check_routing_auth()
        self.check_ntp_authentication()
        self.check_ntp_trusted_keys()
        self.check_stp_security()
        self.check_cdp_lldp()
        self.check_ip_source_routing()
        self.check_gratuitous_arp()
        return self.findings

    def check_copp(self):
        has_copp = (self.config.has_line(r"^control-plane") or
                   self.config.has_line(r"policy-map.*control-plane") or
                   self.config.has_line(r"service-policy input.*copp"))
        if not has_copp:
            self.finding("CTRL-001", "Control Plane Policing (CoPP) not configured",
                self.SEVERITY_HIGH, "Control Plane",
                "No CoPP policy found. Without CoPP, the control plane is vulnerable "
                "to DoS attacks from excessive traffic (BGP floods, ICMP storms, etc.).",
                remediation="Configure CoPP policy-map and apply to control-plane:\n"
                "control-plane\n service-policy input CoPP-Policy",
                references=["CIS Cisco IOS Benchmark 2.1.1", "Cisco IOS-XE Hardening Guide — CoPP"])

    def check_routing_auth(self):
        routing = self.config.get_routing_protocols()
        for section, lines in routing.items():
            protocol = section.split()[1] if len(section.split()) > 1 else "unknown"
            # OSPF
            if "ospf" in protocol.lower():
                interfaces = self.config.get_interfaces()
                ospf_ints = [s for s, l in interfaces.items()
                           if any("ip ospf" in x.lower() for x in l)]
                for intf in ospf_ints:
                    intf_lines = interfaces[intf]
                    has_auth = any("ip ospf authentication" in l.lower() or
                                  "ip ospf message-digest-key" in l.lower()
                                  for l in intf_lines)
                    if not has_auth:
                        self.finding("CTRL-002", f"OSPF authentication missing on {intf}",
                            self.SEVERITY_HIGH, "Control Plane",
                            f"{intf} runs OSPF without authentication. An attacker on the "
                            "same segment can inject routes.",
                            affected_items=[intf],
                            remediation="Configure OSPF MD5 or SHA authentication on the interface.",
                            references=["CIS Cisco IOS Benchmark 2.2.1"])
            # BGP
            if "bgp" in protocol.lower():
                neighbors = [l for l in lines if "neighbor" in l.lower() and "remote-as" in l.lower()]
                for nbr in neighbors:
                    nbr_ip = re.search(r"neighbor\s+(\S+)", nbr)
                    if nbr_ip:
                        ip = nbr_ip.group(1)
                        has_pwd = any(f"neighbor {ip}" in l and "password" in l.lower()
                                    for l in lines)
                        if not has_pwd:
                            self.finding("CTRL-003", f"BGP neighbor {ip} has no MD5 authentication",
                                self.SEVERITY_HIGH, "Control Plane",
                                f"BGP peer {ip} in {section} has no password configured. "
                                "BGP sessions are vulnerable to TCP RST and route injection attacks.",
                                affected_items=[f"{section}: neighbor {ip}"],
                                remediation=f"Configure: neighbor {ip} password <shared-secret>",
                                references=["CIS Cisco IOS Benchmark 2.2.2"])
            # EIGRP
            if "eigrp" in protocol.lower():
                has_auth = any("authentication" in l.lower() for l in lines)
                if not has_auth:
                    self.finding("CTRL-004", f"EIGRP authentication not configured ({section})",
                        self.SEVERITY_HIGH, "Control Plane",
                        f"{section} does not use authentication. EIGRP is vulnerable to "
                        "route injection from rogue devices on the network.",
                        remediation="Configure EIGRP HMAC-SHA-256 authentication.",
                        references=["CIS Cisco IOS Benchmark 2.2.3"])

    def check_ntp_authentication(self):
        ntp = self.config.get_ntp_config()
        has_ntp = bool(ntp)
        if not has_ntp:
            return
        has_auth = any("authenticate" in l.lower() for l in ntp)
        if not has_auth:
            self.finding("CTRL-005", "NTP authentication not enabled",
                self.SEVERITY_MEDIUM, "Control Plane",
                "NTP is configured but authentication is not enabled. An attacker "
                "can spoof NTP responses to manipulate device time, affecting "
                "certificate validation, logging, and scheduled operations.",
                remediation="Configure: ntp authenticate\nntp authentication-key <id> md5 <key>\n"
                "ntp trusted-key <id>\nntp server <ip> key <id>",
                references=["CIS Cisco IOS Benchmark 2.3.1"])

    def check_ntp_trusted_keys(self):
        ntp = self.config.get_ntp_config()
        servers = [l for l in ntp if re.match(r"ntp server\s+\S+", l, re.I)]
        for srv in servers:
            if "key" not in srv.lower():
                ip = re.search(r"ntp server\s+(\S+)", srv)
                if ip:
                    self.finding("CTRL-006", f"NTP server {ip.group(1)} without key association",
                        self.SEVERITY_MEDIUM, "Control Plane",
                        f"NTP server {ip.group(1)} is not associated with a trusted key.",
                        affected_items=[srv],
                        remediation=f"Configure: ntp server {ip.group(1)} key <id>",
                        references=["CIS Cisco IOS Benchmark 2.3.2"])

    def check_stp_security(self):
        interfaces = self.config.get_interfaces(r"(Ethernet|GigabitEthernet|FastEthernet|TenGig)")
        for intf, lines in interfaces.items():
            is_access = any("switchport mode access" in l.lower() for l in lines)
            if is_access:
                has_bpdu = any("spanning-tree bpduguard" in l.lower() for l in lines)
                has_portfast = any("spanning-tree portfast" in l.lower() for l in lines)
                if has_portfast and not has_bpdu:
                    self.finding("CTRL-007", f"Portfast without BPDU Guard on {intf}",
                        self.SEVERITY_MEDIUM, "Control Plane",
                        f"{intf} has portfast enabled but no BPDU guard. A rogue switch "
                        "connected to this port could cause STP topology changes.",
                        affected_items=[intf],
                        remediation="Configure: spanning-tree bpduguard enable",
                        references=["CIS Cisco IOS Benchmark 2.4.1"])
        # Global STP root guard
        if not self.config.has_line(r"spanning-tree guard root"):
            # Check per-interface
            pass

    def check_cdp_lldp(self):
        if not self.config.has_line(r"^no cdp run"):
            self.finding("CTRL-008", "CDP is enabled globally",
                self.SEVERITY_MEDIUM, "Control Plane",
                "Cisco Discovery Protocol is enabled. CDP broadcasts device information "
                "(model, IOS version, IP addresses) to adjacent devices, which can aid "
                "reconnaissance.",
                remediation="Disable globally: no cdp run\n"
                "Or disable per interface on untrusted ports: no cdp enable",
                references=["CIS Cisco IOS Benchmark 2.5.1"])
        if self.config.has_line(r"^lldp run"):
            self.finding("CTRL-009", "LLDP is enabled globally",
                self.SEVERITY_LOW, "Control Plane",
                "LLDP is enabled and broadcasts device information to adjacent devices.",
                remediation="Disable if not required: no lldp run",
                references=["CIS Cisco IOS Benchmark 2.5.2"])

    def check_ip_source_routing(self):
        if not self.config.has_line(r"^no ip source-route"):
            self.finding("CTRL-010", "IP source routing not disabled",
                self.SEVERITY_HIGH, "Control Plane",
                "IP source routing allows packets to specify their own route, "
                "bypassing routing tables. This can be exploited for spoofing.",
                remediation="Configure: no ip source-route",
                references=["CIS Cisco IOS Benchmark 2.6.1"])

    def check_gratuitous_arp(self):
        if not self.config.has_line(r"^no ip gratuitous-arps"):
            self.finding("CTRL-011", "Gratuitous ARP not disabled",
                self.SEVERITY_LOW, "Control Plane",
                "Gratuitous ARP can be exploited for ARP cache poisoning attacks.",
                remediation="Configure: no ip gratuitous-arps",
                references=["Cisco IOS Hardening Guide — ARP Security"])
