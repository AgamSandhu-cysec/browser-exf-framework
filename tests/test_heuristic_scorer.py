"""Tests for ml.heuristic — scoring logic and false-positive detection."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.engine import Finding
from ml.feature_extractor import ExtensionFeatureVector
from ml.heuristic import heuristic_score, mark_likely_fp


def _finding(**kwargs) -> Finding:
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


def _fv(**kwargs) -> ExtensionFeatureVector:
    return ExtensionFeatureVector(**kwargs)


# ── Severity base scores ─────────────────────────────────────────

def test_critical_base_score():
    f = _finding(severity="critical")
    score = heuristic_score(f, _fv())
    assert score >= 0.70


def test_info_base_score():
    f = _finding(severity="info")
    score = heuristic_score(f, _fv())
    assert score <= 0.15


# ── Boost: eval without origin check + all_urls ──────────────────

def test_boost_eval_no_origin_all_urls():
    f = _finding(severity="high")
    fv = _fv(eval_without_origin_check=1, has_all_urls=1)
    score = heuristic_score(f, fv)
    assert score >= 0.90


# ── Boost: high perms + ext connectable ──────────────────────────

def test_boost_high_perms_ext_connectable():
    f = _finding(severity="high")
    fv = _fv(high_perms_with_ext_connectable=1)
    score = heuristic_score(f, fv)
    assert score >= 0.85


# ── Boost: dynamic confirmation ──────────────────────────────────

def test_boost_dynamic_xss():
    f = _finding(severity="high", module="dynamic_xss")
    fv = _fv(dynamic_xss_confirmed=1)
    score = heuristic_score(f, fv)
    assert score >= 0.90


# ── Reduction: origin validation reduces ast_scanner ─────────────

def test_reduction_origin_validated():
    f = _finding(severity="high", module="ast_scanner")
    fv = _fv(has_origin_validation=1)
    score = heuristic_score(f, fv)
    # Base is 0.60 * 0.55 = 0.33 - significantly reduced
    assert score < 0.40


# ── Reduction: example credentials ───────────────────────────────

def test_reduction_example_secret():
    f = _finding(
        severity="critical",
        module="secrets_scanner",
        evidence="YOUR_API_KEY_HERE example",
    )
    score = heuristic_score(f, _fv())
    assert score < 0.25


# ── Reduction: low entropy secret ────────────────────────────────

def test_reduction_low_entropy():
    f = _finding(severity="critical", module="secrets_scanner")
    fv = _fv(max_secret_entropy=2.0)
    score = heuristic_score(f, fv)
    assert score < 0.30


# ── False positive detection ─────────────────────────────────────

def test_low_score_is_fp():
    f = _finding(severity="info")
    assert mark_likely_fp(f, 0.15) is True


def test_high_score_not_fp():
    f = _finding(severity="critical")
    assert mark_likely_fp(f, 0.85) is False


def test_example_evidence_is_fp():
    f = _finding(evidence="placeholder API key")
    assert mark_likely_fp(f, 0.50) is True


# ── Score bounds ─────────────────────────────────────────────────

def test_score_never_exceeds_1():
    f = _finding(severity="critical", module="dynamic_xss")
    fv = _fv(
        dynamic_xss_confirmed=1,
        eval_without_origin_check=1,
        has_all_urls=1,
        high_perms_with_ext_connectable=1,
    )
    score = heuristic_score(f, fv)
    assert 0.0 <= score <= 1.0


def test_score_never_below_0():
    f = _finding(severity="info", module="secrets_scanner", evidence="dummy example placeholder")
    fv = _fv(max_secret_entropy=1.0)
    score = heuristic_score(f, fv)
    assert 0.0 <= score <= 1.0
