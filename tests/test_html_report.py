"""Tests for HTML report rendering."""

from __future__ import annotations

from pathlib import Path

from core.engine import Finding
from report.engine import render_html_report


def test_render_html_includes_poc_block(tmp_path: Path) -> None:
    """Jinja report should include PoC sections when findings carry payloads."""
    f = Finding(
        module="xss_tester",
        severity="high",
        title="Test XSS",
        description="Desc",
        evidence="ev",
        file="f.js",
        line=10,
        remediation="Fix it",
        cwe="CWE-79",
        confidence=0.9,
        poc_payload="javascript:alert(1)",
        poc_description="Open this URL with the extension loaded.",
    )
    out = tmp_path / "out.html"
    render_html_report([f], "fixture/path", out)
    html = out.read_text(encoding="utf-8")
    assert "ext-attack-framework" in html
    assert "Proof-of-concept" in html
    assert "javascript:alert(1)" in html
