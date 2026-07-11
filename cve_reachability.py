"""
Cisco NSS — CVE Reachability Assessment
=======================================
The CVE check (``modules/cve_detection``) fires on software-version math alone: if
the device runs an affected train it reports the CVE, regardless of whether the
*vulnerable feature is even turned on*. That is correct for "am I running vulnerable
code", but it over-states urgency — an IOS-XE Web UI RCE should not sit at "Fix Now"
on a switch where the HTTP server is disabled.

This module answers, from the parsed configuration only (stdlib, offline-safe), a
narrower question per CVE: *is the vulnerable component actually enabled, and is it
exposed on THIS device?* The verdict feeds the Risk-Prioritization Engine, which
**downranks** (never suppresses) findings whose vulnerable feature is disabled or
locked down, and keeps the CISA-KEV floor so a known-exploited bug is never buried.

Design principles (deliberately conservative — a wrong "disabled" verdict could hide
a real RCE, so the engine only ever downranks and the KEV floor still holds):
  * Only emit a decisive verdict when the config signal is unambiguous.
  * Anything uncertain -> INDETERMINATE (no change to the finding's priority).
  * A CVE with no confident component mapping is INDETERMINATE.
  * Every decisive verdict carries a cited config-evidence string.

Cisco exposure note: unlike a FortiGate .conf there is no ``role wan`` marker, so
"reachable" here means the vulnerable service is ENABLED and not locked down by an
access-class/ACL — the actionable, provable signal. Internet-vs-internal is not
asserted (that would require topology the config doesn't carry).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

# Verdicts (plain strings the risk_prioritizer consumes without importing this module).
CONFIRMED_REACHABLE = "CONFIRMED_REACHABLE"        # feature enabled AND not locked down
CONFIGURED_NOT_EXPOSED = "CONFIGURED_NOT_EXPOSED"  # feature enabled but access-restricted / internal
FEATURE_DISABLED = "FEATURE_DISABLED"              # vulnerable feature not enabled on this device
INDETERMINATE = "INDETERMINATE"                    # cannot tell from config -> do not change priority


# --------------------------------------------------------------------------- #
#  CVE -> vulnerable-component map (curated, conservative)                      #
# --------------------------------------------------------------------------- #
# Only CVEs whose config gate is UNAMBIGUOUS are mapped; everything else stays
# INDETERMINATE (no priority change). A wrong "disabled" would downrank a real bug,
# so we map only the flagship, well-understood gates. New CVEs carry their own
# reachability_component from research; fold confident ones in here.
CVE_COMPONENT: Dict[str, str] = {
    # IOS-XE Web UI (must have the HTTP server on) — the flagship, actively exploited.
    "CVE-2023-20198": "web-ui",
    "CVE-2023-20273": "web-ui",
    # ASA/FTD VPN web server / WebVPN / AnyConnect (ArcaneDoor + web-services family).
    "CVE-2025-20333": "webvpn-ssl",
    "CVE-2025-20362": "webvpn-ssl",
    "CVE-2025-20363": "webvpn-ssl",
    "CVE-2024-20359": "webvpn-ssl",
    "CVE-2024-20353": "webvpn-ssl",
    "CVE-2025-20336": "webvpn-ssl",
    "CVE-2018-0101": "webvpn-ssl",
    # IOS/IOS-XE SNMP stack (SNMP must be configured).
    "CVE-2025-20352": "snmp",
}


# --------------------------------------------------------------------------- #
#  config view — one parse of the raw config into the signals predicates need  #
# --------------------------------------------------------------------------- #

_EXTERNAL_HINT = re.compile(r"\b(outside|wan|internet|public|untrust)\b", re.IGNORECASE)


def _raw(parsed_config: Any) -> str:
    if isinstance(parsed_config, str):
        return parsed_config
    return str(getattr(parsed_config, "raw", "") or "")


def _has_line(raw: str, pattern: str) -> bool:
    return re.search(pattern, raw, re.IGNORECASE | re.MULTILINE) is not None


def build_view(parsed_config: Any) -> Dict[str, Any]:
    """Parse the handful of feature signals the predicates need from a ParsedConfig
    (or raw text). Returns a plain dict so the predicates stay pure and testable."""
    raw = _raw(parsed_config)
    device_type = ""
    if not isinstance(parsed_config, str):
        device_type = str(getattr(parsed_config, "device_type", "") or "")

    # HTTP server (IOS/IOS-XE web management). 'ip http server' / 'ip http secure-server'
    # are present when ON; 'no ip http ...' when explicitly OFF.
    http_server_on = _has_line(raw, r"^\s*ip http server\b")
    http_secure_on = _has_line(raw, r"^\s*ip http secure-server\b")
    http_server_off = _has_line(raw, r"^\s*no ip http server\b")
    http_secure_off = _has_line(raw, r"^\s*no ip http secure-server\b")
    http_access_class = _has_line(raw, r"^\s*ip http access-class\b")

    # ASA/FTD WebVPN / AnyConnect. The 'webvpn' block + an 'enable <intf>' line means the
    # SSL web server is listening; the interface name hints at external exposure.
    webvpn_present = _has_line(raw, r"^\s*webvpn\b")
    enable_intfs = re.findall(r"^\s*enable\s+(\S+)", raw, re.IGNORECASE | re.MULTILINE)
    anyconnect_enable = _has_line(raw, r"^\s*anyconnect enable\b") or _has_line(raw, r"^\s*enable\s+\S+")
    webvpn_external = any(_EXTERNAL_HINT.search(i) for i in enable_intfs)

    # SNMP configured at all.
    snmp_present = _has_line(raw, r"^\s*snmp-server\b")

    # Smart Install (vstack) — historically remote-exploited on TCP/4786.
    vstack_on = _has_line(raw, r"^\s*vstack\b") and not _has_line(raw, r"^\s*no vstack\b")

    # NX-API (feature nxapi).
    nxapi_on = _has_line(raw, r"^\s*feature nxapi\b")

    return {
        "device_type": device_type,
        "http_on": bool(http_server_on or http_secure_on),
        "http_off_explicit": bool((http_server_off or not http_server_on)
                                  and (http_secure_off or not http_secure_on)
                                  and (http_server_off or http_secure_off)),
        "http_access_class": http_access_class,
        "webvpn_present": webvpn_present,
        "webvpn_enabled": bool(webvpn_present and anyconnect_enable),
        "webvpn_external": webvpn_external,
        "snmp_present": snmp_present,
        "vstack_on": vstack_on,
        "nxapi_on": nxapi_on,
    }


# --------------------------------------------------------------------------- #
#  per-component predicates                                                    #
# --------------------------------------------------------------------------- #

def _web_ui(v):
    if v["http_on"]:
        if v["http_access_class"]:
            return CONFIGURED_NOT_EXPOSED, "HTTP server enabled but restricted by 'ip http access-class'"
        return CONFIRMED_REACHABLE, "HTTP(S) server enabled (ip http server/secure-server) with no access-class"
    if v["http_off_explicit"]:
        return FEATURE_DISABLED, "HTTP server disabled (no ip http server / no ip http secure-server)"
    return INDETERMINATE, "no explicit 'ip http server' state in config — cannot determine web UI exposure"


def _webvpn(v):
    if not v["webvpn_present"]:
        return FEATURE_DISABLED, "no 'webvpn' configuration block present"
    if v["webvpn_enabled"]:
        if v["webvpn_external"]:
            return CONFIRMED_REACHABLE, "webvpn enabled on an external-named interface (SSL VPN web server listening)"
        return CONFIRMED_REACHABLE, "webvpn enabled (SSL VPN web server listening)"
    return CONFIGURED_NOT_EXPOSED, "webvpn block present but no 'enable <interface>' — not actively listening"


def _snmp(v):
    if v["snmp_present"]:
        return CONFIGURED_NOT_EXPOSED, "SNMP configured (snmp-server) — typically management-network reachable"
    return FEATURE_DISABLED, "no snmp-server configuration present"


def _smart_install(v):
    if v["vstack_on"]:
        return CONFIRMED_REACHABLE, "Smart Install (vstack) enabled — listens on TCP/4786"
    return FEATURE_DISABLED, "Smart Install (vstack) not enabled"


def _nxapi(v):
    if v["nxapi_on"]:
        return CONFIGURED_NOT_EXPOSED, "NX-API enabled (feature nxapi)"
    return FEATURE_DISABLED, "NX-API not enabled (no 'feature nxapi')"


def _indeterminate(reason):
    def _p(v):
        return INDETERMINATE, reason
    return _p


PREDICATES: Dict[str, Callable[[dict], Tuple[str, str]]] = {
    "web-ui": _web_ui,
    "webvpn-ssl": _webvpn,
    "snmp": _snmp,
    "smart-install": _smart_install,
    "nxapi": _nxapi,
    "mgmt-plane": _indeterminate("management-plane exposure is not decisively determinable from config"),
    "indeterminate": _indeterminate("no confident config gate for this CVE"),
}


def assess(component: Optional[str], view: dict) -> Tuple[str, str]:
    """Return (verdict, evidence) for a component against a prebuilt config view.
    Unknown/None components -> INDETERMINATE (no priority change)."""
    pred = PREDICATES.get(component or "")
    if pred is None:
        return INDETERMINATE, ""
    try:
        return pred(view)
    except Exception:  # pragma: no cover - defensive
        return INDETERMINATE, ""


# --------------------------------------------------------------------------- #
#  multi-device stamping                                                        #
# --------------------------------------------------------------------------- #

def _cve_of(finding: Any) -> str:
    try:
        from finding_view import fv_cve
        return str(fv_cve(finding) or "")
    except Exception:  # pragma: no cover
        return str((finding or {}).get("cve", "") if isinstance(finding, dict) else "")


def stamp_reachability(configs, findings) -> int:
    """Stamp a per-finding CVE reachability verdict onto every CVE finding, using
    THAT finding's device config. NSS is multi-device, so the same CVE on two boxes
    can get different verdicts — hence per-finding, not a flat CVE->verdict map.

    ``configs`` = the scanner's [(filename, ParsedConfig), ...]; findings are matched
    to their device via ``device_file``. Writes ``f["_cve_reach"] = {verdict, evidence,
    component}`` on each CVE finding that maps to a known component. Returns the count
    of decisive (non-INDETERMINATE) verdicts stamped."""
    views: Dict[str, dict] = {}
    for fn, pc in (configs or []):
        try:
            views[fn] = build_view(pc)
        except Exception:  # pragma: no cover
            continue
    decisive = 0
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        cve = _cve_of(f)
        component = CVE_COMPONENT.get(cve)
        if not cve or not component:
            continue
        view = views.get(f.get("device_file", ""))
        if view is None:
            continue
        verdict, evidence = assess(component, view)
        f["_cve_reach"] = {"verdict": verdict, "evidence": evidence, "component": component}
        if verdict != INDETERMINATE:
            decisive += 1
    return decisive
