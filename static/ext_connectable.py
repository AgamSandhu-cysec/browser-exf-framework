"""Deep analysis of ``externally_connectable`` and external message handlers."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from core.engine import Finding

logger = logging.getLogger(__name__)

SUBDOMAIN_TAKEOVER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("*.github.io", "GitHub Pages"),
    ("*.herokuapp.com", "Heroku"),
    ("*.netlify.app", "Netlify"),
    ("*.vercel.app", "Vercel"),
    ("*.glitch.me", "Glitch"),
)

HIGH_PRIVILEGE_PERMISSIONS = frozenset(
    {
        "tabs",
        "cookies",
        "webRequest",
        "webRequestBlocking",
        "history",
        "debugger",
        "management",
        "nativeMessaging",
        "proxy",
    }
)

ONMESSAGE_EXTERNAL_START = re.compile(
    r"chrome\.runtime\.onMessageExternal\.addListener\s*\(",
    re.MULTILINE,
)


def _manifest_label(path: str) -> str:
    """Return display path for manifest references."""
    return path or "manifest.json"


def _collect_permission_strings(manifest: dict[str, Any]) -> set[str]:
    """Collect permission-like strings from MV2/MV3 manifests."""
    out: set[str] = set()
    for key in ("permissions", "optional_permissions"):
        val = manifest.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    out.add(item)
    host = manifest.get("host_permissions")
    if isinstance(host, list):
        for item in host:
            if isinstance(item, str):
                out.add(item)
    return out


def _is_all_urls(pat: str) -> bool:
    """Return True for patterns equivalent to all URLs."""
    p = pat.strip()
    return p in ("*://*/*", "<all_urls>")


def _is_broad_tld_wildcard(pat: str) -> bool:
    """Detect ``*://*.tld/*`` style overly broad patterns."""
    if "://" not in pat:
        return False
    try:
        _, rest = pat.split("://", 1)
        host = rest.split("/")[0]
    except ValueError:
        return False
    return host.startswith("*.") and "*" not in host[2:]


def _describe_external_handlers(js_files: list[str]) -> list[tuple[str, str]]:
    """
    Scan JS files for ``onMessageExternal`` listeners.

    Returns list of (file, excerpt) tuples with a short code excerpt after each match.
    """
    hits: list[tuple[str, str]] = []
    slice_len = 1200
    for path in sorted(set(js_files)):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("Cannot read JS for external handler scan: %s (%s)", path, exc)
            continue
        for m in ONMESSAGE_EXTERNAL_START.finditer(text):
            excerpt = text[m.start() : m.start() + slice_len].strip()
            hits.append((path, excerpt))
    return hits


def analyze_externally_connectable(
    manifest: dict[str, Any],
    js_files: list[str],
    manifest_path: str,
) -> list[Finding]:
    """
    Analyze ``externally_connectable`` and correlate with permissions and JS handlers.

    Emits informational findings when the field is absent.
    """
    findings: list[Finding] = []
    label = _manifest_label(manifest_path)
    extcon = manifest.get("externally_connectable")

    if extcon is None:
        findings.append(
            Finding(
                module="ext_connectable",
                severity="info",
                title="No externally_connectable manifest field",
                description="Websites cannot directly use chrome.runtime.sendMessage to this extension.",
                evidence="(field not defined)",
                file=label,
                line=None,
                remediation="If external messaging is never required, keep this field absent.",
                cwe="CWE-1061",
                confidence=0.9,
            )
        )
        return findings

    if not isinstance(extcon, dict):
        findings.append(
            Finding(
                module="ext_connectable",
                severity="low",
                title="externally_connectable has unexpected shape",
                description="Manifest field is not an object; external messaging may be misconfigured.",
                evidence=json.dumps(extcon, ensure_ascii=False)[:500],
                file=label,
                line=None,
                remediation="Use an object with a matches array per Chrome documentation.",
                cwe="CWE-754",
                confidence=0.5,
            )
        )
        return findings

    matches = extcon.get("matches")
    if not isinstance(matches, list) or not matches:
        findings.append(
            Finding(
                module="ext_connectable",
                severity="info",
                title="externally_connectable with empty matches",
                description="External messaging is declared but no match patterns are listed.",
                evidence=json.dumps(extcon, ensure_ascii=False),
                file=label,
                line=None,
                remediation="Populate matches with explicit trusted HTTPS origins.",
                cwe="CWE-1061",
                confidence=0.7,
            )
        )
        return findings

    perms = _collect_permission_strings(manifest)
    has_high_priv = bool(perms & HIGH_PRIVILEGE_PERMISSIONS)

    broad_critical = False

    for raw in matches:
        if not isinstance(raw, str):
            continue
        pat = raw.strip()
        lower = pat.lower()

        for suffix, platform in SUBDOMAIN_TAKEOVER_PATTERNS:
            core = suffix[2:].lower()
            if core in lower and ("*." in pat or "*://" in pat):
                findings.append(
                    Finding(
                        module="ext_connectable",
                        severity="high",
                        title=f"Subdomain takeover risk ({platform})",
                        description=(
                            f"Pattern `{pat}` may allow an attacker to register a matching "
                            f"subdomain on {platform} and call extension APIs."
                        ),
                        evidence=pat,
                        file=label,
                        line=None,
                        remediation="Avoid shared-hosting wildcards; pin to origins you control.",
                        cwe="CWE-350",
                        confidence=0.85,
                    )
                )
                break

        if _is_all_urls(pat):
            broad_critical = True
            findings.append(
                Finding(
                    module="ext_connectable",
                    severity="critical",
                    title="externally_connectable allows all origins",
                    description="Any website can attempt to message this extension.",
                    evidence=pat,
                    file=label,
                    line=None,
                    remediation="Restrict to explicit https:// origins under your control.",
                    cwe="CWE-284",
                    confidence=1.0,
                    poc_type="ext_connectable_abuse",
                    poc_payload='{"type":"probe"}',
                )
            )
        elif _is_broad_tld_wildcard(pat):
            findings.append(
                Finding(
                    module="ext_connectable",
                    severity="high",
                    title="Broad externally_connectable host pattern",
                    description="Wildcard host patterns can cover many unrelated sites.",
                    evidence=pat,
                    file=label,
                    line=None,
                    remediation="Replace wildcards with fixed hostnames where possible.",
                    cwe="CWE-20",
                    confidence=0.8,
                )
            )
        else:
            findings.append(
                Finding(
                    module="ext_connectable",
                    severity="medium",
                    title="externally_connectable pattern",
                    description="Review whether this origin pattern is minimal and HTTPS-only.",
                    evidence=pat,
                    file=label,
                    line=None,
                    remediation="Validate senders inside the external message handler.",
                    cwe="CWE-284",
                    confidence=0.65,
                )
            )

    if broad_critical and has_high_priv:
        findings.append(
            Finding(
                module="ext_connectable",
                severity="critical",
                title="Broad external messaging combined with high-privilege permissions",
                description="Untrusted web origins may drive APIs backed by sensitive browser permissions.",
                evidence=f"permissions sample: {sorted(perms)[:20]}",
                file=label,
                line=None,
                remediation="Narrow externally_connectable and drop unnecessary powerful permissions.",
                cwe="CWE-272",
                confidence=0.9,
            )
        )

    handlers = _describe_external_handlers(js_files)
    if not handlers:
        findings.append(
            Finding(
                module="ext_connectable",
                severity="medium",
                title="No onMessageExternal listener found in JS scan",
                description="externally_connectable is declared but no obvious listener was detected; verify MV3 service worker bundles.",
                evidence=json.dumps(matches, ensure_ascii=False),
                file=label,
                line=None,
                remediation="Ensure listeners validate sender.origin before acting.",
                cwe="CWE-345",
                confidence=0.4,
            )
        )
    else:
        for path, excerpt in handlers:
            action_hints: list[str] = []
            low = excerpt.lower()
            if "eval(" in low:
                action_hints.append("eval of external-controlled data")
            if "chrome.tabs" in low:
                action_hints.append("tab APIs")
            if "chrome.cookies" in low:
                action_hints.append("cookie APIs")
            if "fetch(" in low or "xmlhttprequest" in low:
                action_hints.append("network requests")
            hint = ", ".join(action_hints) if action_hints else "generic handler logic"
            findings.append(
                Finding(
                    module="ext_connectable",
                    severity="high",
                    title="External message handler capabilities",
                    description=f"onMessageExternal handler may perform: {hint}.",
                    evidence=f"{path}: {excerpt[:600]}",
                    file=path,
                    line=None,
                    remediation="Validate sender.origin/url; reject unexpected senders before any side effect.",
                    cwe="CWE-345",
                    confidence=0.75,
                )
            )

    return findings
