"""Detect hardcoded secrets via regex heuristics and entropy analysis."""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path

from core.engine import Finding

logger = logging.getLogger(__name__)

EXCLUDED_PATHS = [
    '_metadata/',
    '_metadata/verified_contents.json',
    'node_modules/',
    '.LICENSE.txt',
    'vendors-react.js',      # React source, not extension code
    'vendors-node_modules',
]


def should_skip_file(file_path: str) -> bool:
    """Returns True if this file should be excluded from secrets scanning."""
    normalized = file_path.replace('\\', '/')
    return any(excl in normalized for excl in EXCLUDED_PATHS)


CSS_IN_JS_HASH_PATTERN = re.compile(
    r'^[a-z][a-z0-9]{5,11}$'   # e.g. ewxqhom6, e1nihd4910, ed4cshv0
)


def is_css_in_js_hash(s: str) -> bool:
    """
    Returns True if string looks like an emotion/styled-components
    generated class name hash. These are not secrets.
    Pattern: starts with lowercase letter, followed by 5-11 alphanumeric chars.
    Total length 6-12 chars. Must contain at least one digit.
    """
    if len(s) > 12 or len(s) < 6:
        return False
    if not CSS_IN_JS_HASH_PATTERN.match(s):
        return False
    # Must have at least one digit to distinguish from normal words
    return any(c.isdigit() for c in s)

MIN_ENTROPY_STRING_LEN = 21
ENTROPY_THRESHOLD = 4.5

COMPILED_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical", "CWE-798"),
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{48}"), "critical", "CWE-798"),
    ("OpenAI project key", re.compile(r"sk-proj-[a-zA-Z0-9_\-]{50,}"), "critical", "CWE-798"),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "critical", "CWE-798"),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "CWE-798"),
    ("Stripe live secret", re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "critical", "CWE-798"),
    ("Stripe test secret", re.compile(r"sk_test_[0-9a-zA-Z]{24}"), "medium", "CWE-798"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+"), "high", "CWE-798"),
    ("Twilio API key", re.compile(r"SK[0-9a-fA-F]{32}"), "high", "CWE-798"),
    ("SendGrid API key", re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43}"), "high", "CWE-798"),
    ("Firebase server key", re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "high", "CWE-798"),
    (
        "PEM private key",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "high",
        "CWE-798",
    ),
]

AWS_SECRET_INLINE = re.compile(
    r"aws[_\-]?(?:secret|secret_access|secretkey)\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]",
    re.I,
)
GENERIC_ASSIGN = re.compile(
    r"\b(?:password|passwd|api_key|apikey|secret)\s*=\s*['\"]([^'\"]{9,})['\"]",
    re.IGNORECASE,
)

GENERIC_ASSIGN_FULL_LINE = re.compile(
    r"\b(?:password|passwd|api_key|apikey|secret)\s*=\s*(?P<value>[^;\n]+)",
    re.IGNORECASE,
)

LONG_STRING_LITERAL_RE = re.compile(r"'([^']{21,})'|\"([^\"]{21,})\"")


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits per symbol for ``data``."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def _looks_like_secret_material(s: str) -> bool:
    """Heuristic: base64-ish or hex-ish high-entropy blobs."""
    if len(s) < MIN_ENTROPY_STRING_LEN:
        return False
    hexish = sum(1 for c in s if c in "0123456789abcdefABCDEF") / len(s)
    b64ish = sum(1 for c in s if c.isalnum() or c in "+/=") / len(s)
    return hexish > 0.85 or b64ish > 0.9


def redact_secret(value: str) -> str:
    """Return a redacted representation showing first and last four characters."""
    v = value.strip()
    if len(v) <= 8:
        return "[REDACTED]"
    return f"{v[:4]}...{v[-4:]} (redacted)"


def _line_from_offset(text: str, offset: int) -> int:
    """Return 1-based line number for byte offset in ``text``."""
    return text.count("\n", 0, offset) + 1


def _snippet_for_line(text: str, line_no: int, width: int = 1, redact_value: str | None = None) -> str:
    """Return a short snippet around ``line_no`` (1-based), optionally masking ``redact_value``."""
    lines = text.splitlines()
    if line_no < 1 or line_no > len(lines):
        return ""
    start = max(1, line_no - width)
    end = min(len(lines), line_no + width)
    out: list[str] = []
    for i in range(start, end + 1):
        prefix = ">" if i == line_no else " "
        line_text = lines[i - 1]
        if redact_value and redact_value in line_text:
            line_text = line_text.replace(redact_value, redact_secret(redact_value))
        out.append(f"{prefix} {i:4d}: {line_text}")
    return "\n".join(out)


def _credential_note(severity: str, name: str) -> str:
    """Human-readable note on live vs test style credentials."""
    if "test" in name.lower() or severity == "medium":
        return "appears test or lower-risk material; verify intent"
    return "treat as live credential material until proven otherwise"


def scan_for_secrets(paths: list[str]) -> list[Finding]:
    """
    Scan text-like files for known secret formats and suspicious literals.

    Secrets are redacted in ``Finding.evidence`` and descriptions.
    """
    findings: list[Finding] = []
    seen_spans: set[tuple[str, int, int]] = set()

    for file_path in sorted(set(paths)):
        if should_skip_file(file_path):
            continue
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Skipping unreadable file for secrets: %s (%s)", file_path, exc)
            continue

        # Detect if file is minified (for raised entropy threshold)
        from static.ast_scanner import is_minified
        file_is_minified = is_minified(file_path)
        effective_entropy_threshold = 5.5 if file_is_minified else ENTROPY_THRESHOLD

        def mark(line_no: int, start: int, end: int) -> bool:
            """Return True if this span is new."""
            key = (file_path, start, end)
            if key in seen_spans:
                return False
            seen_spans.add(key)
            return True

        # Regex catalog
        for name, rx, sev, cwe in COMPILED_PATTERNS:
            for m in rx.finditer(text):
                raw = m.group(0)
                line_no = _line_from_offset(text, m.start())
                if not mark(line_no, m.start(), m.end()):
                    continue
                note = _credential_note(sev, name)
                findings.append(
                    Finding(
                        module="secrets_scanner",
                        severity=sev,  # type: ignore[arg-type]
                        title=f"Hardcoded secret: {name}",
                        description=f"Pattern matched a value resembling {name}. {note.capitalize()}.",
                        evidence=f"{redact_secret(raw)}\n{_snippet_for_line(text, line_no, redact_value=raw)}",
                        file=file_path,
                        line=line_no,
                        remediation="Rotate the credential, remove it from source, and load secrets securely at runtime.",
                        cwe=cwe,
                        confidence=0.9 if sev == "critical" else 0.75,
                    )
                )

        for m in AWS_SECRET_INLINE.finditer(text):
            raw = m.group(1)
            line_no = _line_from_offset(text, m.start())
            if not mark(line_no, m.start(1), m.end(1)):
                continue
            findings.append(
                Finding(
                    module="secrets_scanner",
                    severity="critical",
                    title="Hardcoded secret: AWS secret access key",
                    description="An AWS secret-like value appears next to an aws_secret keyword.",
                    evidence=f"{redact_secret(raw)}\n{_snippet_for_line(text, line_no, redact_value=raw)}",
                    file=file_path,
                    line=line_no,
                    remediation="Remove static AWS secrets; use IAM roles or a secrets manager.",
                    cwe="CWE-798",
                    confidence=0.65,
                )
            )

        for m in GENERIC_ASSIGN.finditer(text):
            raw = m.group(1)
            line_no = _line_from_offset(text, m.start())
            if not mark(line_no, m.start(1), m.end(1)):
                continue
            # Verify the full assignment is a string literal, not a variable/function call
            full_match = GENERIC_ASSIGN_FULL_LINE.search(text[m.start():m.end() + 50])
            if full_match:
                val = full_match.group('value').strip()
                # Must start and end with quotes — reject variable references
                if not (val.startswith("'") or val.startswith('"')):
                    continue
            findings.append(
                Finding(
                    module="secrets_scanner",
                    severity="high",
                    title="Hardcoded sensitive assignment",
                    description="A variable named like a secret is assigned a long string literal.",
                    evidence=f"{redact_secret(raw)}\n{_snippet_for_line(text, line_no, redact_value=raw)}",
                    file=file_path,
                    line=line_no,
                    remediation="Do not embed secrets in extension code; fetch short-lived tokens remotely.",
                    cwe="CWE-798",
                    confidence=0.55,
                )
            )

        # Entropy scan on string literals (length > 20 inside quotes)
        for m in LONG_STRING_LITERAL_RE.finditer(text):
            inner = m.group(1) or m.group(2) or ""
            if len(inner) <= 20:
                continue
            # Skip CSS-in-JS hashes
            if is_css_in_js_hash(inner):
                continue
            ent = shannon_entropy(inner)
            if ent <= effective_entropy_threshold:
                continue
            if not _looks_like_secret_material(inner):
                continue
            line_no = _line_from_offset(text, m.start())
            if not mark(line_no, m.start(), m.end()):
                continue
            findings.append(
                Finding(
                    module="secrets_scanner",
                    severity="medium",
                    title="High-entropy string literal",
                    description="Long literal with high entropy resembles encoded key material.",
                    evidence=(
                        f"{redact_secret(inner)}\nentropy={ent:.2f}\n"
                        f"{_snippet_for_line(text, line_no, redact_value=inner)}"
                    ),
                    file=file_path,
                    line=line_no,
                    remediation="Verify this is not a secret; if benign, refactor to configuration.",
                    cwe="CWE-200",
                    confidence=0.45,
                )
            )

    return findings


def scan_file(file_path: str) -> list[Finding]:
    """Convenience wrapper: scan a single file for secrets."""
    return scan_for_secrets([file_path])

