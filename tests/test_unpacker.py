"""Tests for ``core.unpacker``."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.unpacker import unpack

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULN_DIR = PROJECT_ROOT / "tests/fixtures/vulnerable_ext"


def test_folder_input_returns_unpacked_path() -> None:
    """Passing an unpacked extension directory should resolve to that tree."""
    out = unpack(str(VULN_DIR), work_dir=None)
    assert out.is_dir()
    assert (out / "manifest.json").is_file()


def test_folder_with_work_dir_copies_extension() -> None:
    """When ``work_dir`` is set, folder input is copied under workspace/extension."""
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        ext = unpack(str(VULN_DIR), work_dir=tmp)
        assert ext.name == "extension"
        assert (ext / "manifest.json").is_file()
    finally:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)


def test_invalid_input_raises_value_error() -> None:
    """Garbage input that is not ID, folder, or .crx must raise ``ValueError``."""
    with pytest.raises(ValueError):
        unpack("not-a-valid-extension-id-or-path-zzzzzzzz")
