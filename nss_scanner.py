#!/usr/bin/env python3
"""
Network Security Scanner (NSS)
================================
A Python-based security scanner for Cisco switches, routers,
wireless access points, and next-generation firewalls.

Parses running-config exports and evaluates against CIS Benchmarks,
Cisco Hardening Guides, and NSA NGFW guidance.

Usage:
    python nss_scanner.py --data-dir ./sample_configs --output report.html
    python nss_scanner.py --data-dir ./exports --modules mgmt ctrl data --severity HIGH
"""

import argparse
import json
import sys
import datetime
from pathlib import Path

# Reconfigure stdout/stderr to UTF-8 with errors='replace' so the banner's
# box-drawing characters (╔ ═ ║ ╚) and any non-ASCII finding text don't crash
# Windows consoles that default to cp1252.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if callable(_reconfigure):
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

from modules.base import load_configs
from modules.mgmt_plane import ManagementPlaneAuditor
from modules.ctrl_plane import ControlPlaneAuditor
from modules.data_plane import DataPlaneAuditor
from modules.services import ServicesProtocolsAuditor
from modules.switch_security import SwitchSecurityAuditor
from modules.wireless import WirelessSecurityAuditor
from modules.ngfw_core import NgfwCoreAuditor
from modules.ngfw_platform import NgfwPlatformAuditor
from modules.logging import LoggingMonitoringAuditor
from modules.crypto import CryptoPostureAuditor
from modules.cve_detection import CveDetectionAuditor
from modules.report_generator import ReportGenerator


def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════╗
  ║   Network Security Scanner (NSS) v1.0                        ║
  ║   Cisco Switches · Routers · WAP · NGFW                      ║
  ║   CIS Benchmark · Cisco Hardening Guide · NSA FTD Guide      ║
  ╚═══════════════════════════════════════════════════════════════╝
    """)


MODULE_MAP = {
    "mgmt":     ("Management Plane Security", ManagementPlaneAuditor),
    "ctrl":     ("Control Plane Security", ControlPlaneAuditor),
    "data":     ("Data Plane Security", DataPlaneAuditor),
    "services": ("Services & Protocols", ServicesProtocolsAuditor),
    "switch":   ("Switch-Specific Security", SwitchSecurityAuditor),
    "wireless": ("Wireless Security", WirelessSecurityAuditor),
    "ngfw":     ("NGFW Core Security", NgfwCoreAuditor),
    "ngfwplat": ("NGFW Platform Security", NgfwPlatformAuditor),
    "logging":  ("Logging & Monitoring", LoggingMonitoringAuditor),
    "crypto":   ("Cryptographic Posture", CryptoPostureAuditor),
    "cve":      ("CVE Detection", CveDetectionAuditor),
}


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Network Security Scanner — Cisco device config audit"
    )
    parser.add_argument("--data-dir", required=True,
        help="Directory containing device config files (.cfg/.txt/.conf)")
    parser.add_argument("--output", default="nss_security_report.html",
        help="Output HTML report filename")
    parser.add_argument("--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"], default="ALL")
    parser.add_argument("--modules", nargs="+",
        choices=list(MODULE_MAP.keys()) + ["all"], default=["all"])
    parser.add_argument("--config", default=None,
        help="Custom baseline config JSON")

    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)

    print("[*] Loading device configurations...")
    configs = load_configs(data_dir)
    if not configs:
        print("[ERROR] No config files found (.cfg/.txt/.conf)")
        sys.exit(1)
    print(f"    Loaded {len(configs)} device configuration(s)\n")

    baseline = {}
    if args.config:
        with open(args.config) as f:
            baseline = json.load(f)
        print(f"[*] Loaded baseline from {args.config}")

    run_modules = list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings = []

    for filename, parsed_config in configs:
        print(f"[*] Scanning: {filename} ({parsed_config.hostname}, {parsed_config.device_type})")
        for mod_key in run_modules:
            if mod_key not in MODULE_MAP:
                continue
            label, auditor_cls = MODULE_MAP[mod_key]
            auditor = auditor_cls(parsed_config, baseline)
            findings = auditor.run_all_checks()
            # Tag findings with device info
            for f in findings:
                f["device"] = parsed_config.hostname
                f["device_file"] = filename
                f["device_type"] = parsed_config.device_type
            all_findings.extend(findings)

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        threshold = severity_order.get(args.severity, 4)
        all_findings = [
            f for f in all_findings
            if severity_order.get(f.get("severity", "INFO"), 4) <= threshold
        ]

    scan_meta = {
        "scan_time": datetime.datetime.now().isoformat(),
        "data_directory": str(data_dir),
        "modules_run": run_modules,
        "severity_filter": args.severity,
        "devices_scanned": len(configs),
        "device_list": [f"{fn} ({pc.hostname})" for fn, pc in configs],
    }

    print(f"\n[*] Generating report: {args.output}")
    generator = ReportGenerator(all_findings, scan_meta)
    generator.generate(args.output)

    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*65}")
    print(f"  SCAN COMPLETE — {len(configs)} device(s), {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report: {args.output}")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    main()
