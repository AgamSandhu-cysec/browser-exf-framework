"""Download and unpack Chrome extensions from ID, .crx, or unpacked folders."""

from __future__ import annotations

import io
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

import requests

CRX_MAGIC = b"Cr24"
ZIP_SIGNATURE = b"PK\x03\x04"
CHROME_UPDATE_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=120.0.0.0&acceptformat=crx3"
    "&x=id%3D{id}%26installsource%3Dondemand%26uc"
)
EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")
REQUEST_TIMEOUT_SEC = 120
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _is_extension_id(value: str) -> bool:
    """Return True if ``value`` matches Chrome's 32-char extension ID alphabet (a-p)."""
    return bool(EXTENSION_ID_PATTERN.match(value))


def _find_zip_offset(crx_bytes: bytes) -> int:
    """Return byte offset of the embedded ZIP (PK\\x03\\x04) inside a CRX blob."""
    idx = crx_bytes.find(ZIP_SIGNATURE)
    if idx == -1:
        raise ValueError("CRX file does not contain a ZIP archive (PK signature not found)")
    return idx


def _unpack_crx_bytes(crx_bytes: bytes, dest_dir: Path) -> Path:
    """
    Extract a CRX3 (or CRX with ZIP tail) into ``dest_dir``.

    CRX3 files prepend a binary header; everything from the first PK\\x03\\x04
    onward is treated as a ZIP archive.
    """
    offset = _find_zip_offset(crx_bytes)
    zip_bytes = crx_bytes[offset:]
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(dest_dir)
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid CRX/ZIP payload") from exc
    return dest_dir


def download_crx(extension_id: str, session: requests.Session | None = None) -> bytes:
    """
    Download a ``.crx`` from Google's update service for the given extension ID.

    Follows redirects to the actual CRX payload.
    """
    if not _is_extension_id(extension_id):
        raise ValueError(
            f"Invalid extension ID (expected 32 chars from a-p): {extension_id!r}"
        )
    url = CHROME_UPDATE_URL.format(id=extension_id)
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}
    try:
        response = sess.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SEC, allow_redirects=True)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise ValueError(f"Failed to download extension: {exc}") from exc
    return response.content


def unpack_crx_file(crx_path: Path, dest_dir: Path | None = None) -> Path:
    """
    Read a local ``.crx`` file and extract it to ``dest_dir`` (or a new temp directory).
    """
    path = crx_path.resolve()
    if not path.is_file():
        raise ValueError(f"CRX path is not a file: {path}")
    if path.suffix.lower() != ".crx":
        raise ValueError(f"Expected a .crx file, got: {path}")
    try:
        crx_bytes = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Cannot read CRX file: {exc}") from exc
    target = dest_dir if dest_dir is not None else Path(tempfile.mkdtemp(prefix="ext_attack_crx_"))
    return _unpack_crx_bytes(crx_bytes, target)


def unpack(
    input_value: str,
    work_dir: Path | None = None,
    session: requests.Session | None = None,
) -> Path:
    """
    Resolve ``input_value`` to an unpacked extension directory.

    Accepts:
      - A filesystem path to an unpacked extension folder (used as-is, copied if work_dir set)
      - A filesystem path to a ``.crx`` file (extracted)
      - A 32-character Chrome Web Store extension ID (downloaded then extracted)

    Returns the absolute path to the unpacked extension root.
    """
    raw = input_value.strip()
    path_candidate = Path(raw).expanduser()

    if path_candidate.exists() and path_candidate.is_dir():
        resolved = path_candidate.resolve()
        if work_dir is not None:
            dest = work_dir.resolve()
            dest.mkdir(parents=True, exist_ok=True)
            # Copy tree so callers can mutate/output without touching original
            ext_root = dest / "extension"
            if ext_root.exists():
                shutil.rmtree(ext_root)
            shutil.copytree(resolved, ext_root, symlinks=False)
            return ext_root
        return resolved

    if path_candidate.is_file() and path_candidate.suffix.lower() == ".crx":
        out = work_dir if work_dir is not None else Path(tempfile.mkdtemp(prefix="ext_attack_unpack_"))
        out = out.resolve()
        out.mkdir(parents=True, exist_ok=True)
        ext_root = out / "extension"
        if ext_root.exists():
            shutil.rmtree(ext_root)
        return unpack_crx_file(path_candidate, ext_root)

    if _is_extension_id(raw.lower()):
        ext_id = raw.lower()
        tmp_base = work_dir if work_dir is not None else Path(tempfile.mkdtemp(prefix="ext_attack_dl_"))
        tmp_base = tmp_base.resolve()
        tmp_base.mkdir(parents=True, exist_ok=True)
        ext_root = tmp_base / "extension"
        if ext_root.exists():
            shutil.rmtree(ext_root)
        crx_bytes = download_crx(ext_id, session=session)
        return _unpack_crx_bytes(crx_bytes, ext_root)

    raise ValueError(
        "Input must be an unpacked extension folder, a .crx file path, "
        "or a 32-character extension ID (a-p only)"
    )
