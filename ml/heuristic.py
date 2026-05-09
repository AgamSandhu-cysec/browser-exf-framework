"""Heuristic (rule-based) exploitability scoring using feature combinations.

Used as a fallback when ``model.pkl`` is not available.  Unlike a naive
severity-echo approach, this scorer examines *combinations* of features
to judge whether a finding represents a real exploitation path.
"""

from __future__ import annotations

from core.engine import Finding
from ml.feature_extractor import ExtensionFeatureVector


def heuristic_score(finding: Finding, fv: ExtensionFeatureVector) -> float:
    """Score a single finding using feature-combination heuristics.

    Returns a float in [0.0, 1.0] representing exploitability confidence.
    """
    # Base from severity
    base_map = {
        "critical": 0.75,
        "high": 0.60,
        "medium": 0.40,
        "low": 0.25,
        "info": 0.10,
    }
    score = base_map.get(finding.severity, 0.40)

    # ── BOOSTS — combinations that are genuinely exploitable ──────────

    # eval with no origin check + reachable from any page
    if fv.eval_without_origin_check and fv.has_all_urls:
        score = max(score, 0.92)

    # Externally connectable + high privilege permission
    if fv.high_perms_with_ext_connectable:
        score = max(score, 0.88)

    # Live secret + broad access
    if fv.secrets_with_broad_host_perms and fv.max_secret_entropy > 4.5:
        score = max(score, 0.87)

    # postMessage no origin check + cookie access
    if (fv.num_postmessage_listeners > 0
            and not fv.has_origin_validation
            and fv.has_cookies):
        score = max(score, 0.85)

    # Dynamic confirmation always boosts to at least 0.90
    if (fv.dynamic_xss_confirmed or fv.dynamic_injection_confirmed
            or fv.dynamic_cors_confirmed):
        score = max(score, 0.90)
        if finding.module.startswith("dynamic"):
            score = max(score, 0.95)

    # ── REDUCTIONS — things that reduce exploitability ────────────────

    # Origin validation present: postMessage/eval findings less exploitable
    if fv.has_origin_validation and finding.module == "ast_scanner":
        score *= 0.55

    # Finding is about a test/example credential
    evidence_lower = finding.evidence.lower()
    if any(w in evidence_lower for w in
           ("example", "placeholder", "your_api", "test_key", "dummy")):
        score *= 0.25

    # Low entropy secret (not a real credential)
    if finding.module == "secrets_scanner" and fv.max_secret_entropy < 3.5:
        score *= 0.30

    # Info severity permission finding with no dangerous code
    if (finding.severity == "info"
            and fv.num_eval_sinks == 0
            and fv.num_innerHTML_sinks == 0):
        score *= 0.50

    # All AST findings from minified files — unverifiable
    if fv.findings_from_minified_only == 1:
        score *= 0.50

    return max(0.0, min(1.0, score))


def mark_likely_fp(finding: Finding, score: float, threshold: float = 0.30) -> bool:
    """Determine whether a finding should be flagged as a likely false positive.

    Returns ``True`` when the finding should be hidden from default reports.
    """
    if score < threshold:
        return True
    if finding.severity == "info" and score < 0.35:
        return True
    evidence_lower = finding.evidence.lower()
    if any(w in evidence_lower for w in ("example", "placeholder", "dummy")):
        return True
    if (finding.module == "secrets_scanner"
            and hasattr(finding, "confidence")
            and finding.confidence < 0.3):
        return True
    return False
