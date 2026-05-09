"""Tests for :mod:`dynamic.orchestrator`."""

from __future__ import annotations

import os
import sys
from subprocess import CompletedProcess
from pathlib import Path
from unittest.mock import patch

import pytest

from dynamic import orchestrator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "dynamic_vuln_ext"


def test_node_not_found_returns_empty() -> None:
    """When ``node`` is absent, dynamic analysis returns an empty list."""
    with patch("dynamic.orchestrator.shutil.which", return_value=None):
        out = orchestrator.run_dynamic_analysis(str(DYNAMIC_FIXTURE))
    assert out == []


def test_harness_timeout_returns_empty() -> None:
    """Subprocess timeout must yield an empty list without raising."""
    with patch("dynamic.orchestrator.shutil.which", return_value="/usr/bin/node"):
        with patch("dynamic.orchestrator._run_harness_subprocess", return_value=None):
            out = orchestrator.run_dynamic_analysis(str(DYNAMIC_FIXTURE), timeout=1)
    assert out == []


def test_bad_json_output_returns_empty(tmp_path: Path) -> None:
    """Invalid JSON on stdout must be swallowed."""
    (tmp_path / "runner.js").write_text("// stub\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    bad = CompletedProcess(["node", "runner.js"], 0, "not json", "")
    with patch("dynamic.orchestrator.shutil.which", return_value="/usr/bin/node"):
        with patch("dynamic.orchestrator._run_harness_subprocess", return_value=bad):
            with patch("dynamic.orchestrator._get_harness_dir", return_value=tmp_path):
                out = orchestrator.run_dynamic_analysis(str(DYNAMIC_FIXTURE))
    assert out == []


@pytest.mark.slow
def test_dynamic_vuln_ext_finds_critical_or_high() -> None:
    """End-to-end harness against the intentionally vulnerable fixture extension."""
    import shutil

    if not shutil.which("node"):
        pytest.skip("node not installed")
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        pytest.skip("DISPLAY not set — headed Chrome needs a display (e.g. xvfb-run -a pytest … -m slow)")

    findings = orchestrator.run_dynamic_analysis(str(DYNAMIC_FIXTURE), timeout=180)
    assert findings
    assert any(
        "dynamic" in f.module and f.severity in ("critical", "high") for f in findings
    )
