from __future__ import annotations

import json
from pathlib import Path


def test_html_report_generates(tmp_path: Path) -> None:
    from report.engine import generate_html_report
    from core.engine import Finding

    manifest = json.load(open("tests/fixtures/vulnerable_ext/manifest.json", encoding="utf-8"))
    finding = Finding(
        module="manifest_parser",
        severity="critical",
        title="Dangerous permission: debugger",
        description="The debugger permission grants full DevTools access.",
        evidence='"debugger"',
        file="manifest.json",
        line=None,
        remediation="Remove debugger permission.",
        cwe="CWE-250",
        confidence=0.91,
        likely_fp=False,
    )
    out = generate_html_report(
        [finding],
        manifest,
        "tests/fixtures/vulnerable_ext",
        tmp_path,
        generate_pocs=False,
        version="0.1.0",
    )
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "debugger" in content
    assert "CRITICAL" in content.upper()
    assert "91%" in content or "91" in content


def test_html_report_all_severities(tmp_path: Path) -> None:
    from report.engine import generate_html_report
    from core.engine import Finding

    manifest = {"name": "TestExt", "version": "1.0", "permissions": ["<all_urls>"]}
    findings = [
        Finding(
            module="m",
            severity="critical",
            title="crit",
            description="",
            evidence="",
            file="x",
            line=None,
            remediation="",
            cwe="CWE-79",
            confidence=0.9,
        ),
        Finding(
            module="m",
            severity="high",
            title="high",
            description="",
            evidence="",
            file="x",
            line=None,
            remediation="",
            cwe="CWE-201",
            confidence=0.8,
        ),
        Finding(
            module="m",
            severity="medium",
            title="med",
            description="",
            evidence="",
            file="x",
            line=None,
            remediation="",
            cwe="CWE-346",
            confidence=0.6,
        ),
        Finding(
            module="m",
            severity="low",
            title="low",
            description="",
            evidence="",
            file="x",
            line=None,
            remediation="",
            cwe="CWE-798",
            confidence=0.4,
        ),
        Finding(
            module="m",
            severity="info",
            title="info",
            description="",
            evidence="",
            file="x",
            line=None,
            remediation="",
            cwe="CWE-1061",
            confidence=0.2,
        ),
    ]
    out = generate_html_report(findings, manifest, "TestExt", tmp_path, generate_pocs=False)
    content = out.read_text(encoding="utf-8")
    for t in ("crit", "high", "med", "low", "info"):
        assert t in content


def test_executive_summary_mentions_extension_name() -> None:
    from report.engine import _build_executive_summary

    manifest = {"name": "TestExt", "version": "1.0", "permissions": ["<all_urls>"]}
    counts = {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0}
    findings = []
    summary = _build_executive_summary(manifest, findings, counts)
    assert "TestExt" in summary


def test_poc_generated_for_high_confidence(tmp_path: Path) -> None:
    from report.poc_generator import generate_poc_for_finding
    from core.engine import Finding

    f = Finding(
        module="dynamic",
        severity="critical",
        title="postMessage injection",
        description="",
        evidence="eval(event.data.code)",
        file="[runtime]",
        line=None,
        remediation="",
        cwe="CWE-95",
        confidence=0.95,
        likely_fp=False,
        poc_type="postmessage_injection",
    )
    path = generate_poc_for_finding(f, "testextid123456789012345678901234", tmp_path)
    assert path is not None
    assert path.exists()
    assert "testextid" in path.read_text(encoding="utf-8")


def test_poc_not_generated_low_confidence(tmp_path: Path) -> None:
    from report.poc_generator import generate_poc_for_finding
    from core.engine import Finding

    f = Finding(
        module="ast_scanner",
        severity="high",
        title="innerHTML sink",
        description="",
        evidence="el.innerHTML = x",
        file="content.js",
        line=42,
        remediation="",
        cwe="CWE-79",
        confidence=0.45,
        likely_fp=True,
        poc_type="postmessage_injection",
    )
    path = generate_poc_for_finding(f, "abc", tmp_path)
    assert path is None

