"""
Base Auditor and Configuration Parser for Network Security Scanner.
Handles parsing of Cisco IOS/IOS-XE/NX-OS/FTD/WLC running configs.
"""

import re
import datetime
from typing import Dict, List, Any, Optional, Set, Tuple


class BaseAuditor:
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    def __init__(self, config: 'ParsedConfig', baseline: Dict = None):
        self.config = config
        self.baseline = baseline or {}
        self.findings: List[Dict[str, Any]] = []

    def finding(self, check_id: str, title: str, severity: str, category: str,
                description: str, affected_items: List[str] = None,
                remediation: str = "", references: List[str] = None,
                details: Dict = None) -> Dict[str, Any]:
        f = {
            "check_id": check_id, "title": title, "severity": severity,
            "category": category, "description": description,
            "affected_items": affected_items or [],
            "affected_count": len(affected_items) if affected_items else 0,
            "remediation": remediation, "references": references or [],
            "details": details or {},
            "timestamp": datetime.datetime.now().isoformat(),
        }
        self.findings.append(f)
        return f

    def run_all_checks(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_baseline(self, key: str, default: Any) -> Any:
        return self.baseline.get(key, default)


class ParsedConfig:
    """
    Parses a Cisco running-config text file into a structured format
    for security analysis. Supports IOS, IOS-XE, NX-OS, FTD, and WLC.
    """

    def __init__(self, raw_text: str, device_type: str = "auto"):
        self.raw = raw_text
        self.lines = raw_text.splitlines()
        self.device_type = device_type if device_type != "auto" else self._detect_type()
        self.hostname = self._extract_hostname()
        self._sections: Dict[str, List[str]] = {}
        self._parse_sections()

    def _detect_type(self) -> str:
        raw_upper = self.raw.upper()
        if "FIREPOWER" in raw_upper or "FTD" in raw_upper or "ACCESS-CONTROL" in raw_upper:
            return "ftd"
        if "FEATURE" in raw_upper and "NX-OS" in raw_upper:
            return "nxos"
        if "AP GROUP" in raw_upper or "WLAN" in raw_upper and "SSID" in raw_upper:
            return "wlc"
        if "IOS-XE" in raw_upper or "CATALYST" in raw_upper:
            return "iosxe"
        return "ios"

    def _extract_hostname(self) -> str:
        for line in self.lines:
            m = re.match(r'^hostname\s+(\S+)', line, re.IGNORECASE)
            if m:
                return m.group(1)
        return "unknown"

    def _parse_sections(self):
        """Parse config into interface, line, router, and other sections."""
        current_section = "__global__"
        self._sections[current_section] = []
        for line in self.lines:
            stripped = line.rstrip()
            if not stripped or stripped.startswith("!"):
                continue
            # Detect section starts
            if re.match(r'^(interface|line|router|ip access-list|crypto|snmp-server|'
                       r'ntp|logging|banner|aaa|tacacs|radius|vlan|spanning-tree|'
                       r'control-plane|wlan|ap group|policy-map|class-map)\s', stripped, re.I):
                current_section = stripped
                self._sections[current_section] = []
            elif not stripped.startswith(" ") and not stripped.startswith("\t"):
                current_section = "__global__"
                self._sections.setdefault(current_section, []).append(stripped)
            else:
                self._sections.setdefault(current_section, []).append(stripped.strip())

    # ── Query methods ───────────────────────────────────────────

    def has_line(self, pattern: str, flags=re.IGNORECASE) -> bool:
        """Check if any line matches a regex pattern."""
        rx = re.compile(pattern, flags)
        return any(rx.search(line) for line in self.lines)

    def find_lines(self, pattern: str, flags=re.IGNORECASE) -> List[str]:
        """Return all lines matching a regex pattern."""
        rx = re.compile(pattern, flags)
        return [line.strip() for line in self.lines if rx.search(line)]

    def get_value(self, pattern: str, group: int = 1, default: str = "") -> str:
        """Extract a value from the first matching line."""
        rx = re.compile(pattern, re.IGNORECASE)
        for line in self.lines:
            m = rx.search(line)
            if m and m.lastindex and m.lastindex >= group:
                return m.group(group)
        return default

    def get_interfaces(self, pattern: str = r".*") -> Dict[str, List[str]]:
        """Return interface sections matching a pattern."""
        rx = re.compile(pattern, re.IGNORECASE)
        result = {}
        for section, lines in self._sections.items():
            if section.lower().startswith("interface") and rx.search(section):
                result[section] = lines
        return result

    def get_section(self, prefix: str) -> Dict[str, List[str]]:
        """Return all sections starting with prefix."""
        result = {}
        for section, lines in self._sections.items():
            if section.lower().startswith(prefix.lower()):
                result[section] = lines
        return result

    def get_global_lines(self) -> List[str]:
        return self._sections.get("__global__", [])

    def has_no_line(self, pattern: str) -> bool:
        """Check if a 'no X' command is present (feature disabled)."""
        return self.has_line(r"^no\s+" + pattern)

    def get_vty_lines(self) -> Dict[str, List[str]]:
        return self.get_section("line vty")

    def get_console_lines(self) -> Dict[str, List[str]]:
        return self.get_section("line con")

    def get_snmp_config(self) -> List[str]:
        return self.find_lines(r"^snmp-server\s")

    def get_logging_config(self) -> List[str]:
        return self.find_lines(r"^logging\s")

    def get_ntp_config(self) -> List[str]:
        return self.find_lines(r"^ntp\s")

    def get_aaa_config(self) -> List[str]:
        return self.find_lines(r"^aaa\s")

    def get_acls(self) -> Dict[str, List[str]]:
        return self.get_section("ip access-list")

    def get_routing_protocols(self) -> Dict[str, List[str]]:
        return self.get_section("router")

    @property
    def all_sections(self) -> Dict[str, List[str]]:
        return self._sections


def load_configs(data_dir) -> List[Tuple[str, ParsedConfig]]:
    """Load all .cfg/.txt/.conf files from directory and parse them."""
    from pathlib import Path
    configs = []
    data_path = Path(data_dir)
    for ext in ("*.cfg", "*.txt", "*.conf", "*.config"):
        for f in data_path.glob(ext):
            try:
                raw = f.read_text(encoding="utf-8", errors="replace")
                if len(raw) > 100:  # Skip tiny files
                    pc = ParsedConfig(raw)
                    configs.append((f.name, pc))
                    print(f"    Parsed: {f.name} → {pc.hostname} ({pc.device_type})")
            except Exception as e:
                print(f"    [WARN] Failed to parse {f.name}: {e}")
    return configs
