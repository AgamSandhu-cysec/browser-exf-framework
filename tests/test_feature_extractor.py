"""Tests for ml.feature_extractor — vector shape, permission detection, derived features."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.engine import Finding
from ml.feature_extractor import (
    FEATURE_NAMES,
    ExtensionFeatureVector,
    extract_features,
    to_vector,
)


def _finding(**kwargs) -> Finding:
    """Helper to build a Finding with sensible defaults."""
    defaults = dict(
        module="ast_scanner",
        severity="high",
        title="test",
        description="",
        evidence="",
        file="test.js",
        line=1,
        remediation="",
        cwe="CWE-0",
        confidence=0.0,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── Vector shape ──────────────────────────────────────────────────

def test_feature_names_count():
    assert len(FEATURE_NAMES) == 31


def test_vector_length():
    fv = ExtensionFeatureVector()
    vec = to_vector(fv)
    assert len(vec) == 31


def test_vector_all_floats():
    fv = ExtensionFeatureVector()
    vec = to_vector(fv)
    assert all(isinstance(v, float) for v in vec)


# ── Permission detection ─────────────────────────────────────────

def test_all_urls_detected():
    manifest = {"permissions": ["<all_urls>"], "manifest_version": 2}
    fv = extract_features(manifest, [])
    assert fv.has_all_urls == 1


def test_star_url_pattern_detected():
    manifest = {"permissions": ["*://*/*"], "manifest_version": 2}
    fv = extract_features(manifest, [])
    assert fv.has_all_urls == 1


def test_tabs_detected():
    manifest = {"permissions": ["tabs"], "manifest_version": 2}
    fv = extract_features(manifest, [])
    assert fv.has_tabs == 1


def test_no_perms_all_zero():
    manifest = {"permissions": [], "manifest_version": 2}
    fv = extract_features(manifest, [])
    assert fv.has_all_urls == 0
    assert fv.has_tabs == 0
    assert fv.has_debugger == 0
    assert fv.has_cookies == 0


def test_host_permissions_mv3():
    manifest = {
        "permissions": ["tabs"],
        "host_permissions": ["https://example.com/*", "https://other.com/*"],
        "manifest_version": 3,
    }
    fv = extract_features(manifest, [])
    assert fv.num_host_permissions >= 2


# ── Externally connectable ───────────────────────────────────────

def test_ext_connectable_breadth_all():
    manifest = {
        "externally_connectable": {"matches": ["*://*/*"]},
        "manifest_version": 2,
    }
    fv = extract_features(manifest, [])
    assert fv.ext_connectable_breadth == 1.0


def test_ext_connectable_breadth_narrow():
    manifest = {
        "externally_connectable": {"matches": ["*://*.example.com/*"]},
        "manifest_version": 2,
    }
    fv = extract_features(manifest, [])
    assert fv.ext_connectable_breadth == 0.5


def test_ext_connectable_breadth_none():
    fv = extract_features({"manifest_version": 2}, [])
    assert fv.ext_connectable_breadth == 0.0


# ── Code features from findings ──────────────────────────────────

def test_eval_sink_counted():
    finding = _finding(
        module="ast_scanner",
        severity="critical",
        title="Dynamic code execution: eval",
        evidence="eval(msg.code)",
    )
    fv = extract_features({}, [finding])
    assert fv.num_eval_sinks == 1


def test_innerHTML_sink_counted():
    finding = _finding(
        module="ast_scanner",
        severity="high",
        title="DOM XSS sink: innerHTML",
        evidence="el.innerHTML = data",
    )
    fv = extract_features({}, [finding])
    assert fv.num_innerHTML_sinks == 1


def test_non_ast_findings_not_counted_as_eval():
    finding = _finding(
        module="secrets_scanner",
        severity="critical",
        title="eval stuff in title",
        evidence="eval(x)",
    )
    fv = extract_features({}, [finding])
    assert fv.num_eval_sinks == 0


def test_secrets_counted():
    finding = _finding(
        module="secrets_scanner",
        severity="critical",
        title="Hardcoded secret: Google API key",
        evidence="AIzaSy...",
        confidence=0.95,
    )
    fv = extract_features({}, [finding])
    assert fv.num_secrets_found == 1
    assert fv.max_secret_entropy == 0.95


def test_dynamic_script_creates():
    finding = _finding(
        module="ast_scanner",
        severity="medium",
        title="Dynamic script element creation",
        evidence='document.createElement("script")',
    )
    fv = extract_features({}, [finding])
    assert fv.num_dynamic_script_creates == 1


# ── Derived features ─────────────────────────────────────────────

def test_eval_without_origin_check_derived():
    finding = _finding(
        module="ast_scanner",
        severity="critical",
        title="Dynamic code execution: eval",
        evidence="eval(x)",
    )
    manifest = {"permissions": [], "manifest_version": 2}
    fv = extract_features(manifest, [finding])
    # No postMessage listener findings → has_origin_validation=1
    # So eval_without_origin_check should be 0 (no listeners to worry about)
    assert fv.has_origin_validation == 1


def test_eval_without_origin_when_listener_present():
    findings = [
        _finding(
            module="ast_scanner",
            severity="high",
            title="Message listener without origin validation (addEventListener('message'))",
            evidence="addEventListener('message', ...)",
        ),
        _finding(
            module="ast_scanner",
            severity="critical",
            title="Dynamic code execution: eval",
            evidence="eval(x)",
        ),
    ]
    manifest = {"permissions": [], "manifest_version": 2}
    fv = extract_features(manifest, findings)
    assert fv.eval_without_origin_check == 1
    assert fv.has_origin_validation == 0


def test_secrets_with_broad_perms_derived():
    finding = _finding(
        module="secrets_scanner",
        severity="critical",
        title="Hardcoded secret: Google API key",
        evidence="AIzaSy...",
        confidence=0.95,
    )
    manifest = {"permissions": ["<all_urls>"], "manifest_version": 2}
    fv = extract_features(manifest, [finding])
    assert fv.secrets_with_broad_host_perms == 1


def test_secrets_without_broad_perms():
    finding = _finding(
        module="secrets_scanner",
        severity="critical",
        title="Hardcoded secret: Google API key",
        evidence="AIzaSy...",
        confidence=0.95,
    )
    manifest = {"permissions": ["storage"], "manifest_version": 2}
    fv = extract_features(manifest, [finding])
    assert fv.secrets_with_broad_host_perms == 0


def test_high_perms_with_ext_connectable():
    manifest = {
        "permissions": ["debugger"],
        "externally_connectable": {"matches": ["*://*/*"]},
        "manifest_version": 2,
    }
    fv = extract_features(manifest, [])
    assert fv.high_perms_with_ext_connectable == 1


# ── Severity counts ──────────────────────────────────────────────

def test_severity_counts():
    findings = [
        _finding(severity="critical", title="a"),
        _finding(severity="critical", title="b"),
        _finding(severity="high", title="c"),
        _finding(severity="medium", title="d"),
        _finding(severity="info", title="e"),
    ]
    fv = extract_features({}, findings)
    assert fv.static_critical_count == 2
    assert fv.static_high_count == 1
    assert fv.static_medium_count == 1


# ── Real fixture test ────────────────────────────────────────────

def test_vulnerable_ext_fixture():
    """Smoke-test against the real vulnerable_ext fixture."""
    from core.engine import run_static_scan
    from core.extractor import extract

    root = Path(__file__).resolve().parent / "fixtures" / "vulnerable_ext"
    if not root.is_dir():
        pytest.skip("vulnerable_ext fixture not found")

    layout, manifest = extract(root)
    findings = run_static_scan(root, layout, manifest, modules="all")
    fv = extract_features(manifest, findings)
    vec = to_vector(fv)

    assert len(vec) == 31
    assert fv.has_all_urls == 1
    assert fv.has_debugger == 1
    assert fv.num_eval_sinks > 0
    assert fv.static_critical_count > 0
    assert fv.num_secrets_found > 0
