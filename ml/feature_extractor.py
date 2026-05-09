"""Extract a fixed-length numeric feature vector from an extension's manifest and findings.

The feature vector captures permissions, code patterns, dynamic confirmations,
and derived interaction signals.  Every extension is reduced to exactly 30 floats
before the ML model (or heuristic fallback) scores it.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, List

from core.engine import Finding

# Canonical ordered list of feature names — NEVER reorder or remove entries
# without bumping the model version in threshold.json.
FEATURE_NAMES: list[str] = [
    "has_all_urls",
    "has_tabs",
    "has_history",
    "has_cookies",
    "has_web_request",
    "has_native_messaging",
    "has_debugger",
    "has_management",
    "has_proxy",
    "num_host_permissions",
    "ext_connectable_breadth",
    "has_web_accessible_broad",
    "num_eval_sinks",
    "num_innerHTML_sinks",
    "num_postmessage_listeners",
    "has_origin_validation",
    "num_secrets_found",
    "max_secret_entropy",
    "num_dynamic_script_creates",
    "dynamic_xss_confirmed",
    "dynamic_cors_confirmed",
    "dynamic_injection_confirmed",
    "dynamic_postmessage_confirmed",
    "high_perms_with_ext_connectable",
    "eval_without_origin_check",
    "secrets_with_broad_host_perms",
    "static_critical_count",
    "static_high_count",
    "static_medium_count",
    "num_postmessage_senders",
    "findings_from_minified_only",
]

assert len(FEATURE_NAMES) == 31, f"Expected 31 features, got {len(FEATURE_NAMES)}"


@dataclass
class ExtensionFeatureVector:
    """Typed container for the 31-element feature vector."""

    # Permission features (0 or 1)
    has_all_urls: int = 0
    has_tabs: int = 0
    has_history: int = 0
    has_cookies: int = 0
    has_web_request: int = 0
    has_native_messaging: int = 0
    has_debugger: int = 0
    has_management: int = 0
    has_proxy: int = 0

    # Scope features
    num_host_permissions: int = 0
    ext_connectable_breadth: float = 0.0
    has_web_accessible_broad: int = 0

    # Code analysis features
    num_eval_sinks: int = 0
    num_innerHTML_sinks: int = 0
    num_postmessage_listeners: int = 0
    has_origin_validation: int = 0
    num_secrets_found: int = 0
    max_secret_entropy: float = 0.0
    num_dynamic_script_creates: int = 0

    # Dynamic confirmation features
    dynamic_xss_confirmed: int = 0
    dynamic_cors_confirmed: int = 0
    dynamic_injection_confirmed: int = 0
    dynamic_postmessage_confirmed: int = 0

    # Derived / interaction features
    high_perms_with_ext_connectable: int = 0
    eval_without_origin_check: int = 0
    secrets_with_broad_host_perms: int = 0

    # Severity distribution
    static_critical_count: int = 0
    static_high_count: int = 0
    static_medium_count: int = 0

    # Additional code analysis
    num_postmessage_senders: int = 0

    # Minified file indicator
    findings_from_minified_only: int = 0


def to_vector(fv: ExtensionFeatureVector) -> List[float]:
    """Convert an ``ExtensionFeatureVector`` to an ordered list of 31 floats."""
    return [float(getattr(fv, name)) for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------

def _collect_all_permissions(manifest: dict[str, Any]) -> list[str]:
    """Flatten permissions + optional_permissions + host_permissions."""
    out: list[str] = []
    for key in ("permissions", "optional_permissions"):
        val = manifest.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    out.append(item)
    host = manifest.get("host_permissions")
    if isinstance(host, list):
        for item in host:
            if isinstance(item, str):
                out.append(item)
    return out


def _has_permission(perms: list[str], name: str) -> int:
    """Return 1 if ``name`` appears in the permission list."""
    return 1 if name in perms else 0


def _has_all_urls(perms: list[str]) -> int:
    """Return 1 if any permission is effectively <all_urls>."""
    for p in perms:
        if p in ("<all_urls>", "*://*/*"):
            return 1
    return 0


def _count_host_permissions(manifest: dict[str, Any], perms: list[str]) -> int:
    """Count explicit host permission entries."""
    count = len(manifest.get("host_permissions", []) or [])
    for p in perms:
        if p.startswith("http://") or p.startswith("https://"):
            count += 1
    return count


def _ext_connectable_breadth(manifest: dict[str, Any]) -> float:
    """Measure how broadly externally_connectable is configured."""
    ec = manifest.get("externally_connectable")
    if not isinstance(ec, dict):
        return 0.0
    matches = ec.get("matches")
    if not isinstance(matches, list) or not matches:
        return 0.0
    for m in matches:
        if isinstance(m, str) and m.strip() in ("*://*/*", "<all_urls>"):
            return 1.0
    for m in matches:
        if isinstance(m, str) and "*." in m:
            return 0.5
    return 0.3


def _has_web_accessible_broad(manifest: dict[str, Any]) -> int:
    """Return 1 if web_accessible_resources contains broad glob patterns."""
    war = manifest.get("web_accessible_resources")
    if not isinstance(war, list):
        return 0
    for entry in war:
        if isinstance(entry, str):
            if entry in ("*", "*.js", "*.html") or "*" in entry:
                return 1
        elif isinstance(entry, dict):
            resources = entry.get("resources", [])
            if isinstance(resources, list):
                for r in resources:
                    if isinstance(r, str) and ("*" in r):
                        return 1
    return 0


# ---------------------------------------------------------------------------
# Code feature extraction from findings
# ---------------------------------------------------------------------------

def _count_eval_sinks(findings: list[Finding]) -> int:
    """Count eval/new-Function findings from ast_scanner."""
    count = 0
    for f in findings:
        if f.module != "ast_scanner":
            continue
        title_low = f.title.lower()
        evidence_low = f.evidence.lower()
        if "eval" in title_low or "eval" in evidence_low:
            count += 1
        elif "new function" in title_low or "new function" in evidence_low:
            count += 1
    return count


def _count_innerHTML_sinks(findings: list[Finding]) -> int:
    """Count innerHTML / outerHTML / document.write findings from ast_scanner."""
    count = 0
    for f in findings:
        if f.module != "ast_scanner":
            continue
        title_low = f.title.lower()
        evidence_low = f.evidence.lower()
        if ("innerhtml" in title_low or "innerhtml" in evidence_low
                or "outerhtml" in title_low or "outerhtml" in evidence_low
                or "document.write" in title_low or "document.write" in evidence_low
                or "insertadjacenthtml" in title_low):
            count += 1
    return count


def _count_postmessage_listeners(findings: list[Finding]) -> int:
    """Count postMessage-related listener findings from ast_scanner."""
    count = 0
    for f in findings:
        if f.module != "ast_scanner":
            continue
        title_low = f.title.lower()
        if "message listener" in title_low or "onmessage" in title_low:
            count += 1
    return count


def _count_postmessage_senders(findings: list[Finding]) -> int:
    """Count postMessage send findings from ast_scanner."""
    count = 0
    for f in findings:
        if f.module != "ast_scanner":
            continue
        title_low = f.title.lower()
        if "postmessage send" in title_low:
            count += 1
    return count


def _has_origin_validation(findings: list[Finding]) -> int:
    """Determine if origin validation is present.

    Returns 1 if:
      - The ast_scanner found origin guards (reflected in lower severity for listeners), OR
      - No postMessage listener findings exist at all (nothing to validate).
    Returns 0 if postMessage listeners exist but no origin check was detected.

    The ast_scanner already detects ``event.origin`` / ``sender.origin`` guards
    and sets guarded listeners to severity ``medium`` instead of ``high``.
    """
    has_pm_listener = False
    has_guarded_listener = False

    for f in findings:
        if f.module != "ast_scanner":
            continue
        title_low = f.title.lower()

        # Is this a message listener finding?
        if "message listener" in title_low or "onmessage" in title_low:
            has_pm_listener = True
            # ast_scanner sets severity=medium when origin guard detected
            # vs severity=high when no guard
            if f.severity == "medium":
                has_guarded_listener = True

    if not has_pm_listener:
        return 1  # No listeners = nothing to validate, considered safe
    return 1 if has_guarded_listener else 0


def _count_secrets(findings: list[Finding]) -> int:
    """Count secrets_scanner findings."""
    return sum(1 for f in findings if f.module == "secrets_scanner")


def _max_secret_entropy(findings: list[Finding]) -> float:
    """Get maximum confidence across secrets_scanner findings (proxy for entropy)."""
    vals = [f.confidence for f in findings if f.module == "secrets_scanner"]
    return max(vals) if vals else 0.0


def _count_dynamic_script_creates(findings: list[Finding]) -> int:
    """Count createElement('script') findings."""
    count = 0
    for f in findings:
        evidence_low = f.evidence.lower()
        if "script" in evidence_low and "createelement" in evidence_low:
            count += 1
    return count


def _dynamic_confirmed(findings: list[Finding], keyword: str) -> int:
    """Return 1 if any dynamic-module finding mentions the keyword."""
    for f in findings:
        if f.module.startswith("dynamic"):
            combined = (f.title + " " + f.description + " " + f.evidence).lower()
            if keyword in combined:
                return 1
    return 0


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def _all_findings_minified(findings: list[Finding]) -> int:
    """Return 1 if ALL ast_scanner findings are from minified files, 0 otherwise."""
    ast_findings = [f for f in findings if f.module == 'ast_scanner']
    if not ast_findings:
        return 0
    # A finding is from minified code if its description contains
    # the minified file notice added in Fix 1
    minified_marker = 'minified/bundled file'
    all_minified = all(
        minified_marker in (f.description or '')
        for f in ast_findings
    )
    return 1 if all_minified else 0


def extract_features(
    manifest: dict[str, Any],
    findings: list[Finding],
) -> ExtensionFeatureVector:
    """Build an ``ExtensionFeatureVector`` from a manifest dict and finding list."""
    perms = _collect_all_permissions(manifest)

    # Permission features
    has_all = _has_all_urls(perms)
    has_dbg = _has_permission(perms, "debugger")
    has_cook = _has_permission(perms, "cookies")
    ecb = _ext_connectable_breadth(manifest)

    # Code features
    n_eval = _count_eval_sinks(findings)
    n_inner = _count_innerHTML_sinks(findings)
    n_pm = _count_postmessage_listeners(findings)
    origin_val = _has_origin_validation(findings)
    n_secrets = _count_secrets(findings)
    max_ent = _max_secret_entropy(findings)

    # Derived features
    high_perms_ext = 1 if (has_dbg or has_cook) and ecb > 0.5 else 0
    eval_no_origin = 1 if n_eval > 0 and origin_val == 0 else 0
    secrets_broad = 1 if n_secrets > 0 and has_all == 1 else 0

    # Severity counts
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")

    return ExtensionFeatureVector(
        has_all_urls=has_all,
        has_tabs=_has_permission(perms, "tabs"),
        has_history=_has_permission(perms, "history"),
        has_cookies=has_cook,
        has_web_request=_has_permission(perms, "webRequest"),
        has_native_messaging=_has_permission(perms, "nativeMessaging"),
        has_debugger=has_dbg,
        has_management=_has_permission(perms, "management"),
        has_proxy=_has_permission(perms, "proxy"),
        num_host_permissions=_count_host_permissions(manifest, perms),
        ext_connectable_breadth=ecb,
        has_web_accessible_broad=_has_web_accessible_broad(manifest),
        num_eval_sinks=n_eval,
        num_innerHTML_sinks=n_inner,
        num_postmessage_listeners=n_pm,
        has_origin_validation=origin_val,
        num_secrets_found=n_secrets,
        max_secret_entropy=max_ent,
        num_dynamic_script_creates=_count_dynamic_script_creates(findings),
        dynamic_xss_confirmed=_dynamic_confirmed(findings, "xss"),
        dynamic_cors_confirmed=_dynamic_confirmed(findings, "cors"),
        dynamic_injection_confirmed=_dynamic_confirmed(findings, "inject"),
        dynamic_postmessage_confirmed=_dynamic_confirmed(findings, "postmessage"),
        high_perms_with_ext_connectable=high_perms_ext,
        eval_without_origin_check=eval_no_origin,
        secrets_with_broad_host_perms=secrets_broad,
        static_critical_count=crit,
        static_high_count=high,
        static_medium_count=med,
        num_postmessage_senders=_count_postmessage_senders(findings),
        findings_from_minified_only=_all_findings_minified(findings),
    )

