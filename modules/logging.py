"""
Logging & Monitoring Auditor
===============================
CIS Benchmark + Cisco Hardening Guide
Checks: Syslog, buffered logging, console logging, SNMP traps, NetFlow, archive
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class LoggingMonitoringAuditor(BaseAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_syslog_server()
        self.check_logging_level()
        self.check_buffered_logging()
        self.check_console_logging()
        self.check_logging_source()
        self.check_archive_logging()
        self.check_snmp_traps()
        self.check_netflow()
        return self.findings

    def check_syslog_server(self):
        logging = self.config.get_logging_config()
        syslog_hosts = [l for l in logging if re.match(r"logging\s+(host\s+)?\d+\.", l, re.I) or
                       re.match(r"logging\s+server\s+", l, re.I)]
        if not syslog_hosts:
            self.finding("LOG-001", "No external syslog server configured",
                self.SEVERITY_HIGH, "Logging & Monitoring",
                "No remote syslog server is configured. Device logs are only stored "
                "locally (buffer) and will be lost on reboot or buffer overflow. "
                "External syslog is essential for forensics and SIEM integration.",
                remediation="Configure: logging host <syslog-server-ip>\n"
                "logging trap informational",
                references=["CIS Cisco IOS Benchmark 6.1.1"])
        else:
            # Check if logging is via UDP (default) — TCP is more reliable
            for host in syslog_hosts:
                if "tcp" not in host.lower() and "tls" not in host.lower():
                    self.finding("LOG-002", "Syslog using UDP (not TCP/TLS)",
                        self.SEVERITY_MEDIUM, "Logging & Monitoring",
                        "Syslog is configured over UDP, which is unreliable (no delivery "
                        "guarantee) and unencrypted.",
                        affected_items=syslog_hosts[:5],
                        remediation="Use TCP or TLS transport: logging host <ip> transport tcp port 514",
                        references=["Cisco IOS-XE Hardening Guide — Secure Logging"])
                    break

    def check_logging_level(self):
        logging = self.config.get_logging_config()
        trap_level = None
        for l in logging:
            m = re.match(r"logging trap\s+(\S+)", l, re.I)
            if m:
                trap_level = m.group(1).lower()
        if trap_level is None:
            return  # No syslog configured
        level_map = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
                    "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}
        level_num = level_map.get(trap_level, -1)
        if level_num < 0:
            try:
                level_num = int(trap_level)
            except ValueError:
                return
        if level_num < 5:
            self.finding("LOG-003", f"Syslog trap level too restrictive ({trap_level})",
                self.SEVERITY_MEDIUM, "Logging & Monitoring",
                f"Syslog trap level is '{trap_level}' (level {level_num}). "
                "Important security events at notifications (5) and informational (6) "
                "levels will not be forwarded.",
                remediation="Configure: logging trap informational (level 6)",
                references=["CIS Cisco IOS Benchmark 6.1.2"])
        if level_num >= 7:
            self.finding("LOG-004", "Syslog trap level set to debugging",
                self.SEVERITY_LOW, "Logging & Monitoring",
                "Debug-level logging generates excessive output and may impact performance.",
                remediation="Configure: logging trap informational",
                references=["Cisco IOS Hardening Guide — Logging Levels"])

    def check_buffered_logging(self):
        logging = self.config.get_logging_config()
        has_buffer = any(re.match(r"logging buffered", l, re.I) for l in logging)
        if not has_buffer:
            self.finding("LOG-005", "Buffered logging not configured",
                self.SEVERITY_MEDIUM, "Logging & Monitoring",
                "Local buffered logging is not enabled. Even with syslog, local "
                "buffer provides immediate access to recent events.",
                remediation="Configure: logging buffered 64000 informational",
                references=["CIS Cisco IOS Benchmark 6.1.3"])

    def check_console_logging(self):
        logging = self.config.get_logging_config()
        console_logging = [l for l in logging if "logging console" in l.lower()]
        for cl in console_logging:
            if "debugging" in cl.lower() or "7" in cl:
                self.finding("LOG-006", "Console logging set to debug level",
                    self.SEVERITY_LOW, "Logging & Monitoring",
                    "Console logging at debug level can cause performance issues.",
                    remediation="Configure: logging console critical",
                    references=["Cisco IOS Hardening Guide"])
                break

    def check_logging_source(self):
        logging = self.config.get_logging_config()
        has_source = any("logging source-interface" in l.lower() for l in logging)
        if not has_source and self.config.find_lines(r"logging\s+(host\s+)?\d"):
            self.finding("LOG-007", "Logging source-interface not configured",
                self.SEVERITY_LOW, "Logging & Monitoring",
                "No logging source-interface set. Syslog messages may originate from "
                "unpredictable interfaces, complicating log correlation.",
                remediation="Configure: logging source-interface Loopback0",
                references=["CIS Cisco IOS Benchmark 6.1.4"])

    def check_archive_logging(self):
        if not self.config.has_line(r"^archive"):
            self.finding("LOG-008", "Configuration archive/changelog not configured",
                self.SEVERITY_MEDIUM, "Logging & Monitoring",
                "No configuration archive is configured. Configuration changes "
                "are not tracked or rollback-able.",
                remediation="Configure:\narchive\n log config\n  logging enable\n  notify syslog",
                references=["CIS Cisco IOS Benchmark 6.2.1"])

    def check_snmp_traps(self):
        snmp = self.config.get_snmp_config()
        has_traps = any("snmp-server enable traps" in l.lower() for l in snmp)
        if not has_traps and snmp:
            self.finding("LOG-009", "SNMP traps not enabled",
                self.SEVERITY_LOW, "Logging & Monitoring",
                "SNMP traps are not enabled. Network monitoring systems will not "
                "receive asynchronous event notifications.",
                remediation="Configure: snmp-server enable traps",
                references=["CIS Cisco IOS Benchmark 6.3.1"])

    def check_netflow(self):
        has_netflow = (self.config.has_line(r"flow\s+exporter") or
                      self.config.has_line(r"ip flow") or
                      self.config.has_line(r"flow record"))
        if not has_netflow:
            self.finding("LOG-010", "NetFlow/IPFIX not configured",
                self.SEVERITY_LOW, "Logging & Monitoring",
                "NetFlow is not configured. NetFlow provides traffic visibility "
                "essential for threat detection and capacity planning.",
                remediation="Configure NetFlow v9 or IPFIX with export to a collector.",
                references=["Cisco IOS Hardening Guide — Traffic Visibility"])
