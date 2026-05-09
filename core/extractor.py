"""Enumerate extension files and load ``manifest.json``."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
HTML_SUFFIXES = frozenset({".html", ".htm"})
CSS_SUFFIXES = frozenset({".css"})
JSON_SUFFIXES = frozenset({".json"})


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    """Parse JSON from ``path`` or return None on failure."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None
    return data


def extract(extension_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Walk ``extension_root`` and return ``(layout, manifest_dict)``.

    ``layout`` contains categorized paths, total size in KB, and ``all_files``.
    ``manifest_dict`` is the parsed ``manifest.json`` or ``{}`` if missing/invalid.
    """
    root = extension_root.resolve()
    if not root.is_dir():
        raise ValueError(f"Extension root is not a directory: {root}")

    manifest_path = root / MANIFEST_NAME
    manifest: dict[str, Any] = _safe_read_json(manifest_path) or {}

    js_files: list[str] = []
    html_files: list[str] = []
    css_files: list[str] = []
    json_files: list[str] = []
    all_files: list[str] = []
    total_bytes = 0

    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        # Skip hidden control dirs if any
        if any(part.startswith(".") for part in rel.parts):
            continue
        try:
            total_bytes += p.stat().st_size
        except OSError:
            pass
        sp = str(p)
        all_files.append(sp)
        suf = p.suffix.lower()
        if suf in JS_SUFFIXES:
            js_files.append(sp)
        elif suf in HTML_SUFFIXES:
            html_files.append(sp)
        elif suf in CSS_SUFFIXES:
            css_files.append(sp)
        elif suf in JSON_SUFFIXES:
            json_files.append(sp)

    layout: dict[str, Any] = {
        "manifest": str(manifest_path) if manifest_path.is_file() else "",
        "js_files": js_files,
        "html_files": html_files,
        "css_files": css_files,
        "json_files": json_files,
        "all_files": all_files,
        "total_size_kb": round(total_bytes / 1024.0, 3),
    }
    return layout, manifest
