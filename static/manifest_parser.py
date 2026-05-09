"""Analyze ``manifest.json`` for risky permissions, CSP, and exposure settings."""

from __future__ import annotations

import json
import re
from typing import Any

from core.engine import Finding

DANGEROUS_PERMISSIONS: dict[str, tuple[str, str, str]] = {
    "tabs": ("high", "CWE-359", "Can read tab URLs and titles across sites"),
    "history": ("high", "CWE-359", "Full browsing history access"),
    "webRequest": ("high", "CWE-359", "Observes HTTP(S) traffic"),
    "webRequestBlocking": ("critical", "CWE-353", "Can block or modify HTTP traffic"),
    "cookies": ("high", "CWE-522", "Access to cookies across permitted origins"),
    "nativeMessaging": ("high", "CWE-749", "Can communicate with native binaries"),
    "clipboardRead": ("medium", "CWE-200", "Clipboard contents may include secrets"),
    "geolocation": ("medium", "CWE-359", "User location access"),
    "downloads": ("medium", "CWE-494", "Can initiate downloads"),
    "management": ("high", "CWE-284", "Can manage or install other extensions"),
    "debugger": ("critical", "CWE-749", "Full debugger control over pages"),
    "proxy": ("high", "CWE-441", "Can reroute browser traffic"),
    "privacy": ("medium", "CWE-284", "Can alter privacy-sensitive settings"),
}

SENSITIVE_DOMAIN_SUBSTRINGS = (
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazonaws.com",
    "facebook.com",
    "login.microsoftonline.com",
    "okta.com",
    "auth0.com",
)

WEBREQUEST_BLOCKING_ALIASES = frozenset({"webRequestBlocking", "blocking"})


def _manifest_path_label(manifest_path: str) -> str:
    """Return a display path for the manifest file."""
    return manifest_path or "manifest.json"


def _collect_permission_strings(manifest: dict[str, Any]) -> list[str]:
    """Flatten permission-related string entries for MV2/MV3."""
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


def _has_webrequest_blocking(manifest: dict[str, Any]) -> bool:
    """Return True if manifest requests blocking webRequest behavior (MV2 style)."""
    perms = manifest.get("permissions")
    if not isinstance(perms, list):
        return False
    has_wr = False
    has_block = False
    for p in perms:
        if not isinstance(p, str):
            continue
        if p == "webRequest":
            has_wr = True
        if p in WEBREQUEST_BLOCKING_ALIASES:
            has_block = True
    return has_wr and has_block


def _webrequest_blocking_effective(perms: list[str], manifest: dict[str, Any]) -> bool:
    """Return True if blocking webRequest is requested."""
    if "webRequestBlocking" in perms:
        return True
    return _has_webrequest_blocking(manifest)


def _is_broad_host_pattern(pat: str) -> bool:
    """Return True for patterns that effectively cover all origins."""
    p = pat.strip()
    return p in ("<all_urls>", "*://*/*")


def _wildcard_covers_multiple_domains(pat: str) -> bool:
    """
    Heuristic: ``*`` in host part covering TLD-wide or multi-site patterns.

    Examples: ``*://*.com/*``, ``http://*/*``.
    """
    if _is_broad_host_pattern(pat):
        return False  # handled as critical separately
    if "*" not in pat:
        return False
    # scheme://host/path style
    if "://" not in pat:
        return "*" in pat
    try:
        _, rest = pat.split("://", 1)
        host = rest.split("/")[0]
    except ValueError:
        return False
    if host == "*":
        return True
    if host.startswith("*."):
        return True
    if "*" in host and any(host.endswith(tld) for tld in (".com", ".net", ".org", ".*")):
        return True
    return "*" in host


def _matches_sensitive_domain(pat: str) -> bool:
    """Return True if pattern text mentions a commonly sensitive domain."""
    lower = pat.lower()
    return any(s in lower for s in SENSITIVE_DOMAIN_SUBSTRINGS)


def _csp_strings(manifest: dict[str, Any]) -> list[str]:
    """Extract CSP policy strings from MV2/MV3 manifests."""
    policies: list[str] = []
    csp = manifest.get("content_security_policy")
    if isinstance(csp, str):
        policies.append(csp)
    elif isinstance(csp, dict):
        for key in ("extension_pages", "sandbox", "default_src"):
            v = csp.get(key)
            if isinstance(v, str):
                policies.append(v)
    return policies


def _web_accessible_entries(manifest: dict[str, Any]) -> list[Any]:
    """Normalize ``web_accessible_resources`` to a list of entries."""
    war = manifest.get("web_accessible_resources")
    if war is None:
        return []
    if isinstance(war, list):
        return war
    return []


def _war_is_broad(entry: Any) -> bool:
    """Return True if a web_accessible_resources entry uses very broad matches."""
    if isinstance(entry, str):
        return "*" in entry or "?" in entry
    if not isinstance(entry, dict):
        return False
    matches = entry.get("matches")
    if isinstance(matches, list):
        for m in matches:
            if isinstance(m, str) and (_is_broad_host_pattern(m) or m == "<all_urls>"):
                return True
    resources = entry.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if isinstance(r, str) and ("*" in r or "?" in r):
                return True
    return False


def analyze_manifest(manifest: dict[str, Any], manifest_path: str) -> list[Finding]:
    """
    Parse manifest fields and emit :class:`core.engine.Finding` objects.

    Handles Manifest V2 and V3 where practical; skips unknown shapes safely.
    """
    findings: list[Finding] = []
    label = _manifest_path_label(manifest_path)

    if not manifest:
        findings.append(
            Finding(
                module="manifest_parser",
                severity="medium",
                title="Missing or unreadable manifest.json",
                description="The extension manifest could not be parsed or is empty.",
                evidence="(no manifest data)",
                file=label,
                line=None,
                remediation="Ensure manifest.json exists and is valid JSON.",
                cwe="CWE-754",
                confidence=0.9,
            )
        )
        return findings

    perms = _collect_permission_strings(manifest)
    seen_perm_finding: set[str] = set()
    blocking_wr = _webrequest_blocking_effective(perms, manifest)

    for perm in perms:
        if perm == "webRequest" and blocking_wr:
            # Covered by a single critical webRequest+blocking finding below.
            continue
        if perm == "webRequestBlocking" and blocking_wr:
            continue
        if _is_broad_host_pattern(perm):
            if f"host:{perm}" not in seen_perm_finding:
                seen_perm_finding.add(f"host:{perm}")
                findings.append(
                    Finding(
                        module="manifest_parser",
                        severity="critical",
                        title="Broad host permission",
                        description="Host pattern grants access to all websites.",
                        evidence=perm,
                        file=label,
                        line=None,
                        remediation="Replace with explicit origin lists and optional_activeTab patterns.",
                        cwe="CWE-269",
                        confidence=1.0,
                    )
                )
            continue
        if perm in DANGEROUS_PERMISSIONS:
            sev, cwe, why = DANGEROUS_PERMISSIONS[perm]
            key = f"perm:{perm}"
            if key not in seen_perm_finding:
                seen_perm_finding.add(key)
                findings.append(
                    Finding(
                        module="manifest_parser",
                        severity=sev,  # type: ignore[arg-type]
                        title=f"Permission: {perm}",
                        description=why,
                        evidence=perm,
                        file=label,
                        line=None,
                        remediation="Remove the permission if not strictly required; scope host access.",
                        cwe=cwe,
                        confidence=1.0,
                    )
                )
        elif _wildcard_covers_multiple_domains(perm):
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity="high",
                    title="Wildcard host permission",
                    description="Pattern uses wildcards that may cover many unrelated origins.",
                    evidence=perm,
                    file=label,
                    line=None,
                    remediation="Prefer explicit origins; avoid TLD-wide wildcards.",
                    cwe="CWE-20",
                    confidence=0.85,
                )
            )
        elif _matches_sensitive_domain(perm):
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity="medium",
                    title="Sensitive domain in host permission",
                    description="Extension can interact with sites users commonly trust with credentials.",
                    evidence=perm,
                    file=label,
                    line=None,
                    remediation="Validate least privilege; document why access is needed.",
                    cwe="CWE-284",
                    confidence=0.7,
                )
            )

    if blocking_wr:
        findings.append(
            Finding(
                module="manifest_parser",
                severity="critical",
                title="webRequest with blocking",
                description="Blocking webRequest can intercept and alter all HTTP traffic allowed by host permissions.",
                evidence=json.dumps(manifest.get("permissions", []), ensure_ascii=False),
                file=label,
                line=None,
                remediation="Avoid blocking webRequest; use declarativeNetRequest where possible.",
                cwe="CWE-353",
                confidence=1.0,
            )
        )
    elif "webRequest" in perms:
        already = any(f.title == "Permission: webRequest" for f in findings)
        if not already:
            sev, cwe, why = DANGEROUS_PERMISSIONS["webRequest"]
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity=sev,  # type: ignore[arg-type]
                    title="Permission: webRequest",
                    description=why,
                    evidence="webRequest",
                    file=label,
                    line=None,
                    remediation="Minimize listeners; avoid collecting sensitive payloads.",
                    cwe=cwe,
                    confidence=1.0,
                )
            )

    # CSP
    policies = _csp_strings(manifest)
    if not policies:
        findings.append(
            Finding(
                module="manifest_parser",
                severity="medium",
                title="Missing explicit extension CSP",
                description="No content_security_policy string found; defaults may allow risky patterns.",
                evidence="(no CSP field)",
                file=label,
                line=None,
                remediation="Define a strict CSP for extension pages and sandboxed documents.",
                cwe="CWE-693",
                confidence=0.6,
            )
        )
    for pol in policies:
        if "unsafe-inline" in pol:
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity="medium",
                    title="CSP allows unsafe-inline",
                    description="Inline scripts/styles weaken XSS mitigations for extension pages.",
                    evidence=pol[:500],
                    file=label,
                    line=None,
                    remediation="Remove unsafe-inline; use nonces or external bundles.",
                    cwe="CWE-79",
                    confidence=0.9,
                )
            )
        if "unsafe-eval" in pol:
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity="high",
                    title="CSP allows unsafe-eval",
                    description="Dynamic code execution is permitted in extension contexts.",
                    evidence=pol[:500],
                    file=label,
                    line=None,
                    remediation="Remove unsafe-eval; avoid eval/new Function in extension code.",
                    cwe="CWE-94",
                    confidence=0.95,
                )
            )

    # web_accessible_resources
    broad_war: list[str] = []
    for entry in _web_accessible_entries(manifest):
        if _war_is_broad(entry):
            ev = json.dumps(entry, ensure_ascii=False) if not isinstance(entry, str) else entry
            broad_war.append(ev)
    if broad_war:
        findings.append(
            Finding(
                module="manifest_parser",
                severity="medium",
                title="Broad web_accessible_resources exposure",
                description="Resources may be reachable from web origins with loose match patterns.",
                evidence="; ".join(broad_war)[:800],
                file=label,
                line=None,
                remediation="Tighten matches/resources; expose only non-sensitive assets.",
                cwe="CWE-200",
                confidence=0.75,
            )
        )

    # MV2 persistent background
    bg = manifest.get("background")
    if isinstance(bg, dict) and manifest.get("manifest_version") == 2:
        if bg.get("persistent") is True:
            findings.append(
                Finding(
                    module="manifest_parser",
                    severity="info",
                    title="Persistent background page (MV2)",
                    description="A persistent background page increases always-on attack surface.",
                    evidence=json.dumps(bg, ensure_ascii=False),
                    file=label,
                    line=None,
                    remediation="Prefer event pages or MV3 service workers when possible.",
                    cwe="CWE-400",
                    confidence=0.8,
                )
            )

    return findings
