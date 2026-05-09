"""Score extension findings using the trained ML model with heuristic fallback.

Loads ``model.pkl`` and ``threshold.json`` at import time.  If either is
missing or incompatible the heuristic scorer is used transparently.  The
scorer **never** crashes — all failures degrade gracefully.
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Any, List

from core.engine import Finding
from ml.feature_extractor import (
    FEATURE_NAMES,
    ExtensionFeatureVector,
    extract_features,
    to_vector,
)
from ml.heuristic import heuristic_score, mark_likely_fp

logger = logging.getLogger(__name__)

_ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = _ML_DIR / "model.pkl"
THRESHOLD_PATH = _ML_DIR / "threshold.json"

EXPECTED_FEATURES = len(FEATURE_NAMES)  # 30


def _load_threshold() -> tuple[float, int]:
    """Load threshold and feature count from ``threshold.json``.

    Returns ``(threshold, feature_count)``.  Defaults to ``(0.30, 30)``
    if file is missing or malformed.
    """
    try:
        data = json.loads(THRESHOLD_PATH.read_text())
        thresh = float(data.get("threshold", 0.30))
        feat = int(data.get("features", EXPECTED_FEATURES))
        return thresh, feat
    except Exception:
        return 0.30, EXPECTED_FEATURES


def _load_model():
    """Try loading the pickled model; return ``None`` on any failure."""
    if not MODEL_PATH.exists():
        logger.info("No model.pkl found — using heuristic scorer.")
        return None
    try:
        with open(MODEL_PATH, "rb") as fh:
            model = pickle.load(fh)
        return model
    except Exception as exc:
        logger.warning("Failed to load model.pkl: %s — falling back to heuristic.", exc)
        return None


def score_all_findings(
    findings: list[Finding],
    manifest: dict[str, Any],
) -> list[Finding]:
    """Score every finding in-place and return the same list.

    Attempts ML model scoring; falls back to heuristic on any error.
    Never raises — sets ``confidence=0.5`` on total failure.
    """
    try:
        return _score_impl(findings, manifest)
    except Exception as exc:
        logger.error("Scorer crashed: %s — setting all confidence to 0.5", exc)
        for f in findings:
            f.confidence = 0.5
        return findings


def _score_impl(
    findings: list[Finding],
    manifest: dict[str, Any],
) -> list[Finding]:
    """Internal scoring implementation."""
    threshold, feat_count = _load_threshold()

    # Extract features from manifest + findings
    fv = extract_features(manifest, findings)
    vec = to_vector(fv)

    model = None
    if feat_count == EXPECTED_FEATURES:
        model = _load_model()
    else:
        logger.warning(
            "Feature count mismatch (threshold.json says %d, we have %d) — heuristic mode.",
            feat_count,
            EXPECTED_FEATURES,
        )

    use_model = model is not None

    if use_model:
        try:
            base_score = float(model.predict_proba([vec])[0][1])
        except Exception as exc:
            logger.warning("Model prediction failed: %s — falling back to heuristic.", exc)
            use_model = False

    for f in findings:
        if use_model:
            adjusted = base_score
        else:
            adjusted = heuristic_score(f, fv)

        # Per-finding adjustments
        if f.severity == "critical" and f.module.startswith("dynamic"):
            adjusted = min(adjusted + 0.15, 1.0)
        if f.severity == "info":
            adjusted *= 0.6
        if "example" in f.evidence.lower():
            adjusted *= 0.4

        f.confidence = max(0.0, min(1.0, adjusted))

        # Mark likely false positives
        if use_model:
            f_likely_fp = f.confidence < threshold
        else:
            # When using heuristic fallback, use the heuristic's own default
            # threshold (0.30), not the ML model's threshold which was
            # calibrated for model probability outputs.
            f_likely_fp = mark_likely_fp(f, f.confidence)

        # Store likely_fp as a custom attribute since Finding doesn't have it
        # We'll set it via object attribute
        try:
            f.likely_fp = f_likely_fp  # type: ignore[attr-defined]
        except Exception:
            pass

    return findings
