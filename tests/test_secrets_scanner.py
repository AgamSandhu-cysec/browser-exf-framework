"""Tests for ``static.secrets_scanner``."""

from __future__ import annotations

from pathlib import Path

from static.secrets_scanner import redact_secret, scan_for_secrets, shannon_entropy


def test_google_api_key_detection(tmp_path: Path) -> None:
    """Google API key format should be detected."""
    p = tmp_path / "k.js"
    p.write_text('const k = "AIzaSyD-example-google-api-key-here1234";\n', encoding="utf-8")
    hits = scan_for_secrets([str(p)])
    assert any("Google API" in h.title for h in hits)


def test_entropy_based_detection(tmp_path: Path) -> None:
    """High-entropy hex-like literals should be flagged as suspicious."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    blob = (alphabet * 3)[:88]
    p = tmp_path / "ent.js"
    p.write_text(f"const x = '{blob}';\n", encoding="utf-8")
    hits = scan_for_secrets([str(p)])
    assert any("High-entropy" in h.title for h in hits)


def test_low_entropy_long_string_not_flagged(tmp_path: Path) -> None:
    """Repeated characters produce low entropy and should not match entropy rule."""
    p = tmp_path / "low.js"
    p.write_text("const y = '" + ("a" * 80) + "';\n", encoding="utf-8")
    hits = scan_for_secrets([str(p)])
    assert not any("High-entropy" in h.title for h in hits)


def test_shannon_entropy_monotonic_repetition() -> None:
    """Uniform single-character strings have ~0 entropy."""
    assert shannon_entropy("a" * 50) == 0.0


def test_secret_redaction_in_output(tmp_path: Path) -> None:
    """Evidence must not include full secret value."""
    p = tmp_path / "r.js"
    secret = "AIzaSyD-example-google-api-key-here1234"
    p.write_text(f'const k = "{secret}";\n', encoding="utf-8")
    hits = scan_for_secrets([str(p)])
    assert hits
    for h in hits:
        assert secret not in h.evidence
    assert "redacted" in redact_secret(secret).lower() or "..." in redact_secret(secret)


def test_metadata_file_skipped() -> None:
    from static.secrets_scanner import should_skip_file
    assert should_skip_file('_metadata/verified_contents.json') is True
    assert should_skip_file('/path/to/ext/_metadata/verified_contents.json') is True


def test_normal_file_not_skipped() -> None:
    from static.secrets_scanner import should_skip_file
    assert should_skip_file('background.js') is False
    assert should_skip_file('static/js/main.js') is False


def test_css_in_js_hash_not_flagged() -> None:
    from static.secrets_scanner import is_css_in_js_hash
    assert is_css_in_js_hash('ewxqhom6') is True
    assert is_css_in_js_hash('e1nihd4910') is True
    assert is_css_in_js_hash('ed4cshv0') is True


def test_real_secret_not_excluded_by_css_hash() -> None:
    from static.secrets_scanner import is_css_in_js_hash
    assert is_css_in_js_hash('AIzaSyDabcdefghijk') is False
    assert is_css_in_js_hash('sk-proj-abc') is False


def test_password_variable_name_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / 'content.js'
    f.write_text('var passwordInput = document.querySelector("#pw");')
    from static.secrets_scanner import scan_file
    findings = scan_file(str(f))
    assert len(findings) == 0


def test_real_hardcoded_password_still_flagged(tmp_path: Path) -> None:
    f = tmp_path / 'config.js'
    f.write_text('var password = "SuperSecret123!";')
    from static.secrets_scanner import scan_file
    findings = scan_file(str(f))
    assert len(findings) == 1

