"""
Management Plane Security Auditor
====================================
CIS Benchmark Sections: 1.x (Management Plane)
Cisco Hardening Guide: Management Plane

Checks:
  - Enable secret vs enable password
  - Password encryption (Type 0/7 vs Type 8/9/scrypt)
  - AAA configuration (new-model, TACACS+/RADIUS)
  - SSH version and configuration
  - VTY line security (access-class, transport, timeout)
  - Console/AUX line security
  - HTTP/HTTPS server configuration
  - Login banners (MOTD, login, exec)
  - EXEC timeout on all lines
  - Login failure rate limiting
  - Privilege levels
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class ManagementPlaneAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_enable_secret()
        self.check_password_encryption()
        self.check_type7_passwords()
        self.check_aaa_newmodel()
        self.check_aaa_authentication()
        self.check_aaa_authorization()
        self.check_ssh_version()
        self.check_ssh_timeout()
        self.check_vty_transport()
        self.check_vty_access_class()
        self.check_vty_exec_timeout()
        self.check_console_security()
        self.check_aux_port()
        self.check_http_server()
        self.check_login_banner()
        self.check_login_failure_rate()
        self.check_privilege_levels()
        return self.findings

    def check_enable_secret(self):
        has_secret = self.config.has_line(r"^enable secret")
        has_password = self.config.has_line(r"^enable password")
        if not has_secret:
            self.finding("MGMT-001", "Enable secret not configured",
                self.SEVERITY_CRITICAL, "Management Plane",
                "The 'enable secret' command is not configured. Without it, "
                "privileged EXEC access uses a weaker or no password.",
                remediation="Configure: enable secret <strong-password>",
                references=["CIS Cisco IOS Benchmark 1.1.1"])
        if has_password:
            self.finding("MGMT-002", "Weak 'enable password' command in use",
                self.SEVERITY_HIGH, "Management Plane",
                "'enable password' uses Type 7 (reversible) encryption. "
                "Use 'enable secret' with Type 5/8/9 encryption instead.",
                affected_items=self.config.find_lines(r"^enable password"),
                remediation="Remove 'enable password' and use 'enable secret' only.",
                references=["CIS Cisco IOS Benchmark 1.1.1", "Cisco Hardening Guide"])

    def check_password_encryption(self):
        if not self.config.has_line(r"^service password-encryption"):
            self.finding("MGMT-003", "Service password-encryption not enabled",
                self.SEVERITY_HIGH, "Management Plane",
                "Passwords in the config file are stored in clear text. "
                "'service password-encryption' provides basic (Type 7) obfuscation.",
                remediation="Configure: service password-encryption",
                references=["CIS Cisco IOS Benchmark 1.1.2"])

    def check_type7_passwords(self):
        # Type 7 passwords: password 7 <hex>
        type7 = self.config.find_lines(r"password\s+7\s+")
        # Also check for username with password 7
        type7 += self.config.find_lines(r"username\s+\S+\s+password\s+7\s+")
        if type7:
            # Sanitize — don't expose actual password hashes
            sanitized = [re.sub(r'(password\s+7\s+)\S+', r'\1****', l) for l in type7]
            self.finding("MGMT-004", f"Type 7 (reversible) passwords found ({len(type7)})",
                self.SEVERITY_HIGH, "Management Plane",
                f"{len(type7)} password(s) use Type 7 encoding which is trivially reversible. "
                "Use 'secret' keyword (Type 5/8/9) or TACACS+/RADIUS instead.",
                affected_items=sanitized[:20],
                remediation="Replace 'password' with 'secret' for local users. "
                "Use 'username <name> secret <pass>' instead of 'username <name> password'.",
                references=["CIS Cisco IOS Benchmark 1.1.3", "Cisco IOS-XE Hardening Guide"])

    def check_aaa_newmodel(self):
        if not self.config.has_line(r"^aaa new-model"):
            self.finding("MGMT-005", "AAA new-model not enabled",
                self.SEVERITY_CRITICAL, "Management Plane",
                "AAA framework is not enabled. Without 'aaa new-model', the device "
                "cannot use TACACS+/RADIUS for centralized authentication, authorization, "
                "and accounting.",
                remediation="Configure: aaa new-model",
                references=["CIS Cisco IOS Benchmark 1.2.1", "Cisco Hardening Guide — AAA"])

    def check_aaa_authentication(self):
        if not self.config.has_line(r"^aaa new-model"):
            return
        auth_login = self.config.find_lines(r"^aaa authentication login")
        if not auth_login:
            self.finding("MGMT-006", "AAA authentication login not configured",
                self.SEVERITY_HIGH, "Management Plane",
                "No AAA login authentication method list defined.",
                remediation="Configure: aaa authentication login default group tacacs+ local",
                references=["CIS Cisco IOS Benchmark 1.2.2"])
        # Check if 'none' is used as fallback
        none_auth = [l for l in auth_login if re.search(r'\bnone\b', l, re.I)]
        if none_auth:
            self.finding("MGMT-007", "AAA authentication allows 'none' (no authentication)",
                self.SEVERITY_CRITICAL, "Management Plane",
                "Authentication method list includes 'none', allowing unauthenticated access.",
                affected_items=none_auth,
                remediation="Remove 'none' from authentication method lists. "
                "Use 'local' as final fallback instead.",
                references=["CIS Cisco IOS Benchmark 1.2.3"])

    def check_aaa_authorization(self):
        if not self.config.has_line(r"^aaa new-model"):
            return
        if not self.config.has_line(r"^aaa authorization"):
            self.finding("MGMT-008", "AAA authorization not configured",
                self.SEVERITY_MEDIUM, "Management Plane",
                "No command authorization configured. All authenticated users "
                "can execute any command at their privilege level.",
                remediation="Configure: aaa authorization exec default group tacacs+ local\n"
                "aaa authorization commands 15 default group tacacs+ local",
                references=["CIS Cisco IOS Benchmark 1.2.4"])
        if not self.config.has_line(r"^aaa accounting"):
            self.finding("MGMT-009", "AAA accounting not configured",
                self.SEVERITY_MEDIUM, "Management Plane",
                "No AAA accounting configured. Administrative actions are not logged "
                "to TACACS+/RADIUS for audit trail.",
                remediation="Configure: aaa accounting exec default start-stop group tacacs+\n"
                "aaa accounting commands 15 default start-stop group tacacs+",
                references=["CIS Cisco IOS Benchmark 1.2.5"])

    def check_ssh_version(self):
        if self.config.has_line(r"^ip ssh version 1"):
            self.finding("MGMT-010", "SSH version 1 is enabled",
                self.SEVERITY_CRITICAL, "Management Plane",
                "SSHv1 has known cryptographic weaknesses (man-in-the-middle, "
                "key recovery). Only SSHv2 should be used.",
                remediation="Configure: ip ssh version 2",
                references=["CIS Cisco IOS Benchmark 1.3.1"])
        elif not self.config.has_line(r"^ip ssh version 2"):
            self.finding("MGMT-011", "SSH version 2 not explicitly configured",
                self.SEVERITY_HIGH, "Management Plane",
                "SSHv2 is not explicitly enforced. The device may accept SSHv1 connections.",
                remediation="Configure: ip ssh version 2",
                references=["CIS Cisco IOS Benchmark 1.3.1"])
        # Check RSA key size
        rsa_bits = self.config.get_value(r"crypto key generate rsa.*modulus\s+(\d+)", default="")
        if not rsa_bits:
            rsa_bits = self.config.get_value(r"ip ssh rsa keypair-name\s+\S+", default="")
        # Check for weak key in ssh config
        ssh_lines = self.config.find_lines(r"^ip ssh")
        if not any("version 2" in l.lower() for l in ssh_lines) and not ssh_lines:
            pass  # Already flagged above

    def check_ssh_timeout(self):
        timeout = self.config.get_value(r"^ip ssh time-out\s+(\d+)")
        if timeout:
            if int(timeout) > 60:
                self.finding("MGMT-012", f"SSH timeout too long ({timeout}s)",
                    self.SEVERITY_LOW, "Management Plane",
                    f"SSH authentication timeout is {timeout} seconds (recommended: ≤60).",
                    remediation="Configure: ip ssh time-out 60",
                    references=["CIS Cisco IOS Benchmark 1.3.2"])
        retries = self.config.get_value(r"^ip ssh authentication-retries\s+(\d+)")
        if retries and int(retries) > 3:
            self.finding("MGMT-013", f"SSH authentication retries too high ({retries})",
                self.SEVERITY_LOW, "Management Plane",
                f"SSH allows {retries} authentication retries (recommended: ≤3).",
                remediation="Configure: ip ssh authentication-retries 3",
                references=["CIS Cisco IOS Benchmark 1.3.3"])

    def check_vty_transport(self):
        vty_sections = self.config.get_vty_lines()
        for section, lines in vty_sections.items():
            transport = [l for l in lines if l.lower().startswith("transport input")]
            if not transport:
                self.finding("MGMT-014", f"No transport input restriction on {section}",
                    self.SEVERITY_HIGH, "Management Plane",
                    f"{section} has no 'transport input' configured. Telnet may be allowed.",
                    remediation=f"Configure under {section}: transport input ssh",
                    references=["CIS Cisco IOS Benchmark 1.3.4"])
            else:
                for t in transport:
                    if "telnet" in t.lower() or "all" in t.lower():
                        self.finding("MGMT-015", f"Telnet enabled on {section}",
                            self.SEVERITY_CRITICAL, "Management Plane",
                            f"{section} allows Telnet (plaintext protocol). "
                            "Credentials are transmitted unencrypted.",
                            affected_items=[f"{section}: {t}"],
                            remediation=f"Configure under {section}: transport input ssh",
                            references=["CIS Cisco IOS Benchmark 1.3.4"])

    def check_vty_access_class(self):
        vty_sections = self.config.get_vty_lines()
        for section, lines in vty_sections.items():
            has_acl = any("access-class" in l.lower() for l in lines)
            if not has_acl:
                self.finding("MGMT-016", f"No access-class ACL on {section}",
                    self.SEVERITY_HIGH, "Management Plane",
                    f"{section} has no access-class restricting which IPs can connect. "
                    "Any IP can attempt SSH/Telnet to this device.",
                    remediation=f"Configure an ACL and apply: access-class <ACL> in",
                    references=["CIS Cisco IOS Benchmark 1.3.5"])

    def check_vty_exec_timeout(self):
        for section_type in ["line vty", "line con"]:
            sections = self.config.get_section(section_type)
            for section, lines in sections.items():
                has_timeout = any("exec-timeout" in l.lower() for l in lines)
                if not has_timeout:
                    self.finding("MGMT-017", f"No exec-timeout on {section}",
                        self.SEVERITY_MEDIUM, "Management Plane",
                        f"{section} has no exec-timeout. Idle sessions remain open indefinitely.",
                        remediation=f"Configure under {section}: exec-timeout 10 0",
                        references=["CIS Cisco IOS Benchmark 1.3.6"])
                else:
                    for l in lines:
                        m = re.match(r"exec-timeout\s+(\d+)\s+(\d+)", l)
                        if m and int(m.group(1)) == 0 and int(m.group(2)) == 0:
                            self.finding("MGMT-018", f"Exec-timeout disabled on {section}",
                                self.SEVERITY_HIGH, "Management Plane",
                                f"{section} has exec-timeout 0 0 (never timeout). "
                                "Idle sessions will never disconnect.",
                                remediation=f"Configure: exec-timeout 10 0",
                                references=["CIS Cisco IOS Benchmark 1.3.6"])

    def check_console_security(self):
        console = self.config.get_console_lines()
        for section, lines in console.items():
            has_login = any("login" in l.lower() for l in lines)
            if not has_login:
                self.finding("MGMT-019", "Console line has no login configured",
                    self.SEVERITY_HIGH, "Management Plane",
                    "Console port does not require authentication. Physical access grants "
                    "full device access.",
                    remediation="Configure under line con 0: login local (or login authentication)",
                    references=["CIS Cisco IOS Benchmark 1.3.7"])

    def check_aux_port(self):
        aux = self.config.get_section("line aux")
        if aux:
            for section, lines in aux.items():
                has_no_exec = any("no exec" in l.lower() for l in lines)
                transport_none = any("transport input none" in l.lower() for l in lines)
                if not has_no_exec and not transport_none:
                    self.finding("MGMT-020", "AUX port not disabled",
                        self.SEVERITY_MEDIUM, "Management Plane",
                        "The auxiliary port is active. If not used for out-of-band management, "
                        "it should be disabled.",
                        remediation="Configure under line aux 0: no exec\ntransport input none",
                        references=["CIS Cisco IOS Benchmark 1.3.8"])

    def check_http_server(self):
        if self.config.has_line(r"^ip http server") and not self.config.has_line(r"^no ip http server"):
            self.finding("MGMT-021", "HTTP server enabled (unencrypted web management)",
                self.SEVERITY_HIGH, "Management Plane",
                "The HTTP server is enabled, allowing unencrypted web-based management. "
                "Use HTTPS (ip http secure-server) instead.",
                remediation="Configure: no ip http server\nip http secure-server",
                references=["CIS Cisco IOS Benchmark 1.4.1"])
        if self.config.has_line(r"^ip http secure-server"):
            if not self.config.has_line(r"^ip http secure-active-session-modules"):
                pass  # HTTPS is fine

    def check_login_banner(self):
        has_banner = (self.config.has_line(r"^banner motd") or
                     self.config.has_line(r"^banner login") or
                     self.config.has_line(r"^banner exec"))
        if not has_banner:
            self.finding("MGMT-022", "No login warning banner configured",
                self.SEVERITY_MEDIUM, "Management Plane",
                "No login banner is configured. A legal warning banner is required "
                "for authorized use notification and legal prosecution support.",
                remediation="Configure: banner login ^Authorized access only. "
                "Unauthorized access is prohibited and will be prosecuted.^",
                references=["CIS Cisco IOS Benchmark 1.5.1", "NIST 800-53 AC-8"])

    def check_login_failure_rate(self):
        if not self.config.has_line(r"^login block-for"):
            self.finding("MGMT-023", "Login brute-force protection not configured",
                self.SEVERITY_MEDIUM, "Management Plane",
                "No 'login block-for' configured to rate-limit failed login attempts.",
                remediation="Configure: login block-for 120 attempts 3 within 60",
                references=["Cisco IOS Hardening Guide — Login Enhancements"])
        if not self.config.has_line(r"^login on-failure log"):
            self.finding("MGMT-024", "Failed login logging not enabled",
                self.SEVERITY_LOW, "Management Plane",
                "Failed login attempts are not being logged.",
                remediation="Configure: login on-failure log\nlogin on-success log",
                references=["Cisco IOS Hardening Guide — Login Logging"])

    def check_privilege_levels(self):
        level0_users = self.config.find_lines(r"username\s+\S+\s+privilege\s+15")
        if len(level0_users) > 3:
            sanitized = [re.sub(r'(secret|password)\s+\S+\s+\S+', r'\1 ****', l) for l in level0_users]
            self.finding("MGMT-025", f"Many users with privilege level 15 ({len(level0_users)})",
                self.SEVERITY_MEDIUM, "Management Plane",
                f"{len(level0_users)} local users have privilege 15 (full admin). "
                "Use TACACS+ authorization for granular command control instead.",
                affected_items=sanitized[:10],
                remediation="Use TACACS+ with command authorization for privilege separation.",
                references=["CIS Cisco IOS Benchmark 1.2.6"])
