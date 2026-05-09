"""Regex-oriented JavaScript scanning for dangerous sinks and weak message handling."""

from __future__ import annotations

import logging
import os
import re
from typing import Iterable

from core.engine import Finding

logger = logging.getLogger(__name__)


def is_minified(file_path: str) -> bool:
    """
    Returns True if a JS file appears to be minified.
    Criteria: any single line is longer than 500 characters,
    OR the file has fewer than 10 lines but is larger than 5KB.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        lines = content.splitlines()
        if any(len(line) > 500 for line in lines):
            return True
        size_kb = os.path.getsize(file_path) / 1024
        if len(lines) < 10 and size_kb > 5:
            return True
        return False
    except OSError:
        return False


_SEVERITY_DEMOTION = {
    'critical': 'high',
    'high': 'medium',
}


def _apply_minified_adjustments(findings: list[Finding]) -> list[Finding]:
    """Cap confidence and demote severity for findings from minified files."""
    minified_note = (" [found in minified/bundled file — manual deobfuscation required"
                     " to confirm exploitability]")
    for f in findings:
        f.confidence = min(f.confidence, 0.4)
        f.description = f.description + minified_note
        f.severity = _SEVERITY_DEMOTION.get(f.severity, f.severity)
    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    For findings from the same file with the same title and same line
    number, keep only the first occurrence.
    This prevents minified files from generating 20 identical findings
    for the same pattern match.
    """
    seen: set[tuple[str, str, int | None]] = set()
    result: list[Finding] = []
    for f in findings:
        key = (f.file, f.title, f.line)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result

CONTEXT_LINES = 2

DOM_SINK_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"\binnerHTML\s*=", "DOM XSS sink: innerHTML", "high", "CWE-79"),
    (r"\bouterHTML\s*=", "DOM XSS sink: outerHTML", "high", "CWE-79"),
    (r"\binsertAdjacentHTML\s*\(", "DOM XSS sink: insertAdjacentHTML", "high", "CWE-79"),
    (r"\bdocument\.write\s*\(", "DOM XSS sink: document.write", "high", "CWE-79"),
    (r"\bdocument\.writeln\s*\(", "DOM XSS sink: document.writeln", "high", "CWE-79"),
    (r"\.\s*(?:src|href)\s*=", "DOM sink: dynamic src/href assignment", "medium", "CWE-79"),
    (
        r"\bdocument\.title\s*=[^;\n]*\blocation\b",
        "DOM XSS: document.title from location",
        "medium",
        "CWE-79",
    ),
]

EVAL_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"\beval\s*\(", "Dynamic code execution: eval", "critical", "CWE-94"),
    (r"\bnew\s+Function\s*\(", "Dynamic code execution: new Function", "critical", "CWE-94"),
    (r"\bsetTimeout\s*\(\s*['\"]", "setTimeout with string code argument", "high", "CWE-94"),
    (r"\bsetInterval\s*\(\s*['\"]", "setInterval with string code argument", "high", "CWE-94"),
]

POSTMESSAGE_SEND_PATTERNS: list[tuple[str, str]] = [
    (r"\bwindow\.postMessage\s*\(", "window.postMessage"),
    (r"\bport\.postMessage\s*\(", "port.postMessage"),
]

POSTMESSAGE_RECV_PATTERNS: list[tuple[str, str]] = [
    (r"addEventListener\s*\(\s*['\"]message['\"]", "addEventListener('message')"),
    (r"addEventListener\s*\(\s*[\"']message[\"']", 'addEventListener("message")'),
    (r"\bonmessage\s*=", "onmessage handler"),
    (r"chrome\.runtime\.onMessage\.addListener\s*\(", "chrome.runtime.onMessage listener"),
    (r"chrome\.runtime\.onMessageExternal\.addListener\s*\(", "chrome.runtime.onMessageExternal listener"),
]

SCRIPT_CREATE = (
    r"document\.createElement\s*\(\s*['\"]script['\"]\s*\)",
    "Dynamic script element creation",
    "medium",
    "CWE-94",
)

STORAGE_SENSITIVE = re.compile(
    r"chrome\.storage\.(?:local|sync)\.set\s*\([^)]*\b(password|token|secret|apikey|api_key|auth)\b",
    re.IGNORECASE | re.DOTALL,
)

LOCALSTORAGE_SENSITIVE = re.compile(
    r"localStorage\.setItem\s*\(\s*['\"]([^'\"]*(?:password|token|secret|key|auth)[^'\"]*)['\"]",
    re.IGNORECASE,
)

ORIGIN_GUARD_RE = re.compile(
    r"(?:event|e|msg)\.origin|sender\.(?:url|origin)",
    re.IGNORECASE,
)


def _line_from_offset(text: str, offset: int) -> int:
    """Return 1-based line number for byte offset in ``text``."""
    return text.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int, width: int = CONTEXT_LINES) -> str:
    """Build a small multi-line context snippet around ``line_no`` (1-based)."""
    if line_no < 1 or line_no > len(lines):
        return ""
    start = max(1, line_no - width)
    end = min(len(lines), line_no + width)
    parts: list[str] = []
    for i in range(start, end + 1):
        prefix = ">" if i == line_no else " "
        parts.append(f"{prefix} {i:4d}: {lines[i - 1]}")
    return "\n".join(parts)


def _nearby_has_origin_guard(text: str, match_start: int, window: int = 400) -> bool:
    """Heuristic: search a nearby window for origin validation patterns."""
    lo = max(0, match_start - window // 2)
    hi = min(len(text), match_start + window)
    window_text = text[lo:hi]
    return bool(ORIGIN_GUARD_RE.search(window_text))


def scan_javascript_files(js_paths: Iterable[str]) -> list[Finding]:
    """
    Scan JavaScript paths for dangerous sinks and weak messaging patterns.

    Uses multiline regex heuristics (not a full JS parser).
    """
    findings: list[Finding] = []
    for path in sorted(set(js_paths)):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("Skipping unreadable JS: %s (%s)", path, exc)
            continue
        lines = text.splitlines()
        file_minified = is_minified(path)
        file_findings: list[Finding] = []

        for pattern, title, sev, cwe in DOM_SINK_PATTERNS:
            for m in re.finditer(pattern, text, flags=re.MULTILINE):
                line_no = _line_from_offset(text, m.start())
                file_findings.append(
                    Finding(
                        module="ast_scanner",
                        severity=sev,  # type: ignore[arg-type]
                        title=title,
                        description="User-controlled data may reach a DOM XSS sink without sufficient encoding.",
                        evidence=_snippet(lines, line_no),
                        file=path,
                        line=line_no,
                        remediation="Avoid assigning untrusted HTML/URLs; use textContent and safe URL APIs.",
                        cwe=cwe,
                        confidence=0.75,
                    )
                )

        for pattern, title, sev, cwe in EVAL_PATTERNS:
            for m in re.finditer(pattern, text, flags=re.MULTILINE):
                line_no = _line_from_offset(text, m.start())
                file_findings.append(
                    Finding(
                        module="ast_scanner",
                        severity=sev,  # type: ignore[arg-type]
                        title=title,
                        description="Dynamic evaluation allows attacker-controlled code execution.",
                        evidence=_snippet(lines, line_no),
                        file=path,
                        line=line_no,
                        remediation="Remove eval/Function; parse structured messages and use static logic.",
                        cwe=cwe,
                        confidence=0.85,
                    )
                )

        for pattern, label in POSTMESSAGE_SEND_PATTERNS:
            for m in re.finditer(pattern, text, flags=re.MULTILINE):
                line_no = _line_from_offset(text, m.start())
                guarded = _nearby_has_origin_guard(text, m.start())
                sev = "medium" if guarded else "high"
                file_findings.append(
                    Finding(
                        module="ast_scanner",
                        severity=sev,  # type: ignore[arg-type]
                        title=f"postMessage send ({label})",
                        description="Cross-context messaging without strict target origin validation can leak data.",
                        evidence=_snippet(lines, line_no),
                        file=path,
                        line=line_no,
                        remediation="Always pass an explicit targetOrigin; validate recipient trust.",
                        cwe="CWE-345",
                        confidence=0.65 if guarded else 0.8,
                    )
                )

        for pattern, label in POSTMESSAGE_RECV_PATTERNS:
            for m in re.finditer(pattern, text, flags=re.MULTILINE):
                line_no = _line_from_offset(text, m.start())
                guarded = _nearby_has_origin_guard(text, m.start())
                is_ext = "onMessageExternal" in label
                base_sev = "high" if is_ext else "medium"
                sev = "medium" if guarded else base_sev
                file_findings.append(
                    Finding(
                        module="ast_scanner",
                        severity=sev,  # type: ignore[arg-type]
                        title=f"Message listener without origin validation ({label})",
                        description="Handlers that do not verify event.origin/sender may process untrusted data.",
                        evidence=_snippet(lines, line_no),
                        file=path,
                        line=line_no,
                        remediation="Reject messages unless origin/sender matches an allowlist.",
                        cwe="CWE-345",
                        confidence=0.7 if guarded else 0.85,
                    )
                )

        pat, title, sev, cwe = SCRIPT_CREATE
        for m in re.finditer(pat, text, flags=re.MULTILINE):
            line_no = _line_from_offset(text, m.start())
            file_findings.append(
                Finding(
                    module="ast_scanner",
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    description="Creating script tags from extension code can load remote code.",
                    evidence=_snippet(lines, line_no),
                    file=path,
                    line=line_no,
                    remediation="Avoid dynamic script injection; bundle known-good scripts.",
                    cwe=cwe,
                    confidence=0.7,
                )
            )

        for m in STORAGE_SENSITIVE.finditer(text):
            line_no = _line_from_offset(text, m.start())
            file_findings.append(
                Finding(
                    module="ast_scanner",
                    severity="medium",
                    title="Sensitive chrome.storage key",
                    description="Storage keys suggest passwords/tokens may be persisted in plaintext.",
                    evidence=_snippet(lines, line_no),
                    file=path,
                    line=line_no,
                    remediation="Do not store secrets in extension storage; use secure remote auth.",
                    cwe="CWE-522",
                    confidence=0.55,
                )
            )

        for m in LOCALSTORAGE_SENSITIVE.finditer(text):
            line_no = _line_from_offset(text, m.start())
            file_findings.append(
                Finding(
                    module="ast_scanner",
                    severity="medium",
                    title="localStorage.setItem with sensitive key name",
                    description="Web accessible storage may retain credentials or session material.",
                    evidence=_snippet(lines, line_no),
                    file=path,
                    line=line_no,
                    remediation="Avoid localStorage for secrets; prefer session cookies with HttpOnly (web pages).",
                    cwe="CWE-522",
                    confidence=0.55,
                )
            )

        # Deduplicate findings for this file (FIX 2)
        file_findings = deduplicate_findings(file_findings)

        # Apply minified file adjustments (FIX 1)
        if file_minified:
            file_findings = _apply_minified_adjustments(file_findings)

        findings.extend(file_findings)

    return findings
