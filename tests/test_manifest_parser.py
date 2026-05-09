"""Tests for ``static.manifest_parser``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from static.manifest_parser import analyze_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULN_MANIFEST = PROJECT_ROOT / "tests/fixtures/vulnerable_ext/manifest.json"


def _load(p: Path) -> dict:
    """Load JSON manifest from path."""
    return json.loads(p.read_text(encoding="utf-8"))


def test_dangerous_permissions_generate_findings() -> None:
    """Vulnerable fixture manifest should surface multiple permission-related issues."""
    manifest = _load(VULN_MANIFEST)
    findings = analyze_manifest(manifest, str(VULN_MANIFEST))
    titles = {f.title for f in findings}
    assert any("Permission: debugger" in t for t in titles)
    assert any("Broad host permission" in t for t in titles)
    assert any("Permission: tabs" in t for t in titles)
    assert any("webRequest with blocking" in t for t in titles)


def test_safe_permissions_generate_no_dangerous_findings() -> None:
    """A minimal manifest with only benign API permissions should not flag dangerous items."""
    manifest = {
        "manifest_version": 3,
        "name": "Safe",
        "version": "1.0",
        "permissions": ["storage", "alarms"],
    }
    findings = analyze_manifest(manifest, "manifest.json")
    assert not any("Permission: debugger" in f.title for f in findings)
    assert not any("Broad host permission" in f.title for f in findings)


def test_manifest_v2_vs_v3_host_permissions() -> None:
    """MV3 ``host_permissions`` should be analyzed like MV2 permission strings."""
    mv2 = _load(VULN_MANIFEST)
    mv2_findings = analyze_manifest(mv2, "m.json")
    mv3 = {
        "manifest_version": 3,
        "name": "MV3",
        "version": "2.0",
        "permissions": ["storage"],
        "host_permissions": ["https://api.github.com/*"],
    }
    mv3_findings = analyze_manifest(mv3, "m.json")
    assert any("Sensitive domain" in f.title for f in mv3_findings)
    assert any(f.severity == "critical" for f in mv2_findings)


def test_externally_connectable_analyzed_by_ext_module_not_manifest() -> None:
    """Manifest parser focuses on permissions/CSP/WAR; external exposure is ext_connectable."""
    manifest = _load(VULN_MANIFEST)
    findings = analyze_manifest(manifest, str(VULN_MANIFEST))
    assert not any("externally_connectable" in f.title.lower() for f in findings)
