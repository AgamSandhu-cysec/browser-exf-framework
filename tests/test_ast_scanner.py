"""Tests for ``static.ast_scanner``."""

from __future__ import annotations

from pathlib import Path

from static.ast_scanner import scan_javascript_files


def test_innerhtml_detection(tmp_path: Path) -> None:
    """innerHTML assignment should be reported."""
    p = tmp_path / "x.js"
    p.write_text("document.body.innerHTML = userInput;\n", encoding="utf-8")
    hits = scan_javascript_files([str(p)])
    assert any("innerHTML" in h.title for h in hits)


def test_eval_detection(tmp_path: Path) -> None:
    """eval( should be flagged as critical dynamic execution."""
    p = tmp_path / "e.js"
    p.write_text("eval(untrusted);\n", encoding="utf-8")
    hits = scan_javascript_files([str(p)])
    assert any(h.title.startswith("Dynamic code execution: eval") for h in hits)


def test_message_listener_missing_origin_check(tmp_path: Path) -> None:
    """Message listener without nearby origin guard should be higher severity."""
    p = tmp_path / "m.js"
    p.write_text(
        "window.addEventListener('message', function(ev) { console.log(ev.data); });\n",
        encoding="utf-8",
    )
    hits = scan_javascript_files([str(p)])
    assert hits
    assert any("Message listener" in h.title for h in hits)
    assert any(h.severity == "medium" for h in hits if "addEventListener" in h.title)


def test_safe_code_has_no_eval_or_innerhtml_findings(tmp_path: Path) -> None:
    """Benign code should not match eval/innerHTML sinks."""
    p = tmp_path / "safe.js"
    p.write_text(
        "function greet(name) { return 'Hello ' + name; }\n"
        "document.body.textContent = greet('world');\n",
        encoding="utf-8",
    )
    hits = scan_javascript_files([str(p)])
    assert not any("eval" in h.title.lower() for h in hits)
    assert not any("innerHTML" in h.title for h in hits)


def test_is_minified_long_line(tmp_path: Path) -> None:
    f = tmp_path / "bundle.js"
    f.write_text("var x=" + "a" * 600 + ";")
    from static.ast_scanner import is_minified
    assert is_minified(str(f)) is True


def test_is_minified_normal_file(tmp_path: Path) -> None:
    f = tmp_path / "normal.js"
    f.write_text("function foo() {\n  return 1;\n}\n")
    from static.ast_scanner import is_minified
    assert is_minified(str(f)) is False


def test_minified_finding_has_reduced_severity(tmp_path: Path) -> None:
    """Create a temp minified JS file with innerHTML. Scan it, verify
    finding severity is at most medium and confidence <= 0.4."""
    p = tmp_path / "minified_bundle.js"
    # Create a minified-looking file: one long line with innerHTML
    p.write_text("var x=" + "a" * 600 + ";document.body.innerHTML=userInput;")
    hits = scan_javascript_files([str(p)])
    assert hits
    for h in hits:
        if "innerHTML" in h.title:
            assert h.severity in ("medium", "low", "info")
            assert h.confidence <= 0.4
            assert "minified/bundled file" in h.description


def test_deduplication_removes_same_file_title_line() -> None:
    from static.ast_scanner import deduplicate_findings
    from core.engine import Finding
    f1 = Finding(module='ast_scanner', severity='high',
                 title='innerHTML sink', description='',
                 evidence='x', file='bundle.js', line=1,
                 remediation='', cwe='CWE-79', confidence=0.4)
    f2 = Finding(module='ast_scanner', severity='high',
                 title='innerHTML sink', description='',
                 evidence='y', file='bundle.js', line=1,
                 remediation='', cwe='CWE-79', confidence=0.4)
    f3 = Finding(module='ast_scanner', severity='high',
                 title='innerHTML sink', description='',
                 evidence='z', file='bundle.js', line=2,
                 remediation='', cwe='CWE-79', confidence=0.4)
    result = deduplicate_findings([f1, f2, f3])
    assert len(result) == 2   # f1 kept, f2 deduplicated, f3 kept (diff line)


def test_deduplication_keeps_different_titles() -> None:
    from static.ast_scanner import deduplicate_findings
    from core.engine import Finding
    def make(title):
        return Finding(module='ast_scanner', severity='high',
                       title=title, description='', evidence='x',
                       file='bundle.js', line=1, remediation='',
                       cwe='CWE-79', confidence=0.4)
    result = deduplicate_findings([make('innerHTML sink'),
                                   make('eval sink'),
                                   make('innerHTML sink')])
    assert len(result) == 2

