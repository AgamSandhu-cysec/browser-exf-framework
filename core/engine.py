"""Orchestrate static analysis modules and aggregate ``Finding`` results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    """Single security-relevant observation from a scanner module."""

    module: str
    severity: Severity
    title: str
    description: str
    evidence: str
    file: str
    line: int | None
    remediation: str
    cwe: str
    confidence: float = 1.0
    likely_fp: bool = field(default=False)
    poc_type: str | None = None
    poc_payload: str | None = None
    poc_description: str | None = None


def finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialize a ``Finding`` to a JSON-friendly dict."""
    return asdict(f)


def _severity_meets_minimum(severity: str, minimum: str) -> bool:
    """Return True if ``severity`` is at least as serious as ``minimum``."""
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(minimum, 99)


def filter_findings(
    findings: list[Finding],
    minimum_severity: str = "info",
    module_filter: str = "all",
) -> list[Finding]:
    """Filter findings by severity floor and optional module name."""
    mod = module_filter.lower().strip()
    out: list[Finding] = []
    for f in findings:
        if not _severity_meets_minimum(f.severity, minimum_severity):
            continue
        if mod != "all":
            if mod == "manifest" and f.module not in ("manifest_parser", "ext_connectable"):
                continue
            if mod == "ast" and f.module != "ast_scanner":
                continue
            if mod == "secrets" and f.module != "secrets_scanner":
                continue
            if mod == "dynamic" and not f.module.startswith("dynamic_"):
                continue
        out.append(f)
    return out


def run_static_scan(
    extension_root: Path,
    layout: dict[str, Any],
    manifest: dict[str, Any],
    modules: str = "all",
) -> list[Finding]:
    """
    Run enabled static scanners against an unpacked extension.

    ``layout`` and ``manifest`` come from :func:`core.extractor.extract`.
    ``modules`` is one of: ``all``, ``manifest``, ``ast``, ``secrets``.
    """
    # Lazy imports avoid circular dependencies with static scanners.
    from static.ast_scanner import scan_javascript_files
    from static.ext_connectable import analyze_externally_connectable
    from static.manifest_parser import analyze_manifest
    from static.secrets_scanner import scan_for_secrets

    findings: list[Finding] = []
    mod = modules.lower().strip()
    root = extension_root.resolve()

    if mod in ("all", "manifest"):
        findings.extend(analyze_manifest(manifest, str(root / "manifest.json")))
        findings.extend(
            analyze_externally_connectable(
                manifest,
                layout.get("js_files", []),
                str(root / "manifest.json"),
            )
        )

    if mod in ("all", "ast"):
        js_files: list[str] = list(layout.get("js_files", []))
        findings.extend(scan_javascript_files(js_files))

    if mod in ("all", "secrets"):
        secret_paths = (
            list(layout.get("js_files", []))
            + list(layout.get("html_files", []))
            + list(layout.get("json_files", []))
        )
        findings.extend(scan_for_secrets(secret_paths))

    return findings


def apply_dynamic_confirmations(static_findings: list[Finding], dynamic_findings: list[Finding]) -> None:
    """
    Elevate matching static findings when dynamic harness confirms exploitability.

    If a dynamic finding has ``confidence >= 0.95`` and indicates ``content_script_xss``,
    upgrade ``ast_scanner`` DOM-XSS-style static findings to ``critical`` when not already.
    """
    strong_xss = any(
        getattr(d, "confidence", 0) >= 0.95
        and getattr(d, "poc_type", None) == "content_script_xss"
        and d.severity == "critical"
        and d.module == "dynamic_xss"
        for d in dynamic_findings
    )
    if not strong_xss:
        return
    for s in static_findings:
        if s.module != "ast_scanner":
            continue
        if "innerHTML" not in s.title and "DOM XSS" not in s.title:
            continue
        if s.severity == "critical":
            s.description = (s.description + " [Confirmed by dynamic harness]").strip()
            continue
        s.severity = "critical"
        s.description = (s.description + " [Confirmed by dynamic harness]").strip()


def has_critical_or_high(findings: list[Finding]) -> bool:
    """Return True if any finding is critical or high severity."""
    return any(f.severity in ("critical", "high") for f in findings)
