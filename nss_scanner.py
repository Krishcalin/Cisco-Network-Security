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
    parser.add_argument("--json", dest="json_out", default=None, metavar="FILE",
        help="Also write a machine-readable JSON findings report (feeds --verify-against, diffs, pipelines)")
    parser.add_argument("--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"], default="ALL")
    parser.add_argument("--modules", nargs="+",
        choices=list(MODULE_MAP.keys()) + ["all"], default=["all"])
    parser.add_argument("--config", default=None,
        help="Custom baseline config JSON")
    parser.add_argument("--fail-on", dest="fail_on", default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Exit non-zero (2) if any finding at or above this severity is present (CI gating). Default: always exit 0.")
    parser.add_argument("--history", default=None, metavar="FILE",
        help="Continuous posture: update a system-of-record JSON and report new/resolved/reopened/SLA per device")
    parser.add_argument("--exceptions", default=None, metavar="FILE",
        help="Risk-acceptance file (JSON) for --history: accepted findings stop nagging until they expire (fail-open)")

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

    # Capture the FULL, pre-severity-filter finding set. Benchmark scoring,
    # attestation and remediation-verification must run on this (a --severity
    # display filter must never inflate a pass rate or fabricate regressions).
    all_findings_unfiltered = list(all_findings)

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

    if args.json_out:
        _save_json(args.json_out, all_findings, scan_meta)
        print(f"[*] JSON findings report: {args.json_out}")

    # Continuous posture runs on the FULL (unfiltered) finding set so a --severity
    # display filter can never record a finding as resolved. Per device (NSS is
    # multi-device); the returned deltas are stashed for later exporters.
    posture_deltas = {}
    if args.history:
        posture_deltas = _update_posture(args.history, args.exceptions, all_findings_unfiltered)

    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*65}")
    print(f"  SCAN COMPLETE — {len(configs)} device(s), {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report: {args.output}")
    print(f"{'='*65}\n")

    # Severity-gated exit code for CI (default: always 0, unchanged behaviour).
    if args.fail_on:
        gate = severity_order.get(args.fail_on, 4)
        if any(severity_order.get(f.get("severity", "INFO"), 4) <= gate for f in all_findings):
            print(f"[!] Findings at or above {args.fail_on} present — exiting 2 (--fail-on).")
            sys.exit(2)


_SEV_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}


def _posture_host_key(findings):
    """Return a fn mapping a finding -> a stable posture host key. Uses the device
    hostname, but disambiguates with the config filename when the hostname is
    'unknown' or collides across multiple files (so two boxes can't merge in the
    system of record)."""
    from collections import defaultdict
    files_by_host = defaultdict(set)
    for f in findings:
        files_by_host[f.get("device", "unknown") or "unknown"].add(f.get("device_file", ""))

    def key(f):
        h = f.get("device", "unknown") or "unknown"
        if h == "unknown" or len(files_by_host.get(h, ())) > 1:
            return f"{h}|{f.get('device_file', '')}"
        return h
    return key


def _update_posture(history_path, exceptions_path, findings, prio_by_id=None):
    """Update the file-based posture store per device and print what changed.
    prio_by_id (id(finding)->PriorityResult) drives SLA/weaponization when the
    risk-prioritizer is available; None degrades gracefully."""
    try:
        from posture import PostureStore, Exceptions
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] posture module unavailable: {exc}")
        return {}
    from collections import defaultdict
    keyfn = _posture_host_key(findings)
    groups = defaultdict(list)
    for f in findings:
        groups[keyfn(f)].append(f)
    store = PostureStore(history_path)
    exc = Exceptions.load(exceptions_path)
    deltas = {}
    print("\n[*] Posture update (system of record):")
    for host, fs in sorted(groups.items()):
        risk = min(100, sum(_SEV_WEIGHT.get(f.get("severity", ""), 0) for f in fs))
        prio = None
        if prio_by_id:
            prio = [prio_by_id[id(f)] for f in fs if id(f) in prio_by_id] or None
        d = store.update(host, fs, prio, exc, risk_score=risk)
        deltas[host] = d
        since = f"since {d.prev_date[:10]}" if d.prev_date else "baseline recorded"
        line = (f"    {host}: +{len(d.new)} new  -{len(d.resolved)} resolved"
                f"  ~{len(d.reopened)} reopened  (carried {len(d.carried)}, {since})")
        if d.sla_breaches:
            line += f"  [!] {len(d.sla_breaches)} SLA breach(es)"
        if d.newly_weaponized:
            line += f"  [!] {len(d.newly_weaponized)} newly weaponized"
        if d.open_accepted:
            line += f"  ({d.open_accepted} accepted-risk)"
        print(line)
    try:
        store.save()
    except OSError as exc:
        print(f"    [WARN] could not write history '{history_path}': {exc}")
    return deltas


def _save_json(path, findings, scan_meta):
    """Write a machine-readable findings report. The stable base other tooling
    (remediation-verification, diffs, exporters) reads. Schema v1."""
    report = {
        "scanner": "Network Security Scanner (NSS)",
        "schema_version": 1,
        "generated": datetime.datetime.now().isoformat(),
        "scan_meta": scan_meta,
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
