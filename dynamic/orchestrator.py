"""Spawn the Node.js Puppeteer harness and convert JSON findings into ``Finding`` objects."""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from core.engine import Finding

logger = logging.getLogger(__name__)

HARNESS_REL = Path("harness")
RUNNER_SCRIPT = "runner.js"


def _get_harness_dir() -> Path:
    """Return the absolute path to the Node harness directory."""
    return (Path(__file__).resolve().parent / HARNESS_REL).resolve()


def _kill_harness_process_tree(proc: subprocess.Popen[str]) -> None:
    """
    Terminate the Node harness and any child Chrome processes.

    On POSIX, Chrome is typically in the same process group as ``node`` when
    ``start_new_session=True`` was used on :class:`~subprocess.Popen`.
    """
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            proc.kill()
        except ProcessLookupError:
            return
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _run_harness_subprocess(
    harness_dir: Path,
    ext_resolved: str,
    timeout: int,
) -> subprocess.CompletedProcess[str] | None:
    """
    Run ``node runner.js`` and return a completed result, or ``None`` on timeout.

    Uses a new POSIX session so a timeout can ``killpg`` Puppeteer’s Chrome child.
    """
    cmd = ["node", RUNNER_SCRIPT, "--ext-path", ext_resolved]
    popen_kw: dict[str, Any] = {
        "args": cmd,
        "cwd": str(harness_dir),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name != "nt":
        popen_kw["start_new_session"] = True
    proc = subprocess.Popen(**popen_kw)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Dynamic harness subprocess timed out after %ss", timeout)
        _kill_harness_process_tree(proc)
        try:
            proc.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            pass
        return None
    rc = proc.returncode if proc.returncode is not None else -1
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)
POC_CWE_MAP: dict[str, str] = {
    "content_script_xss": "CWE-79",
    "postmessage_leak": "CWE-201",
    "cors_proxy": "CWE-346",
    "background_inject": "CWE-94",
    "ext_connectable": "CWE-346",
}

def _raw_to_finding(raw: dict[str, Any]) -> Finding:
    """Convert a harness JSON object into a :class:`core.engine.Finding`."""
    sev = raw.get("severity", "info")
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "info"
    poc_type = raw.get("poc_type")
    cwe_val = raw.get("cwe") or ""
    if isinstance(poc_type, str) and not cwe_val:
        cwe_val = POC_CWE_MAP.get(poc_type, "CWE-693")
    line_val = raw.get("line")
    if line_val is not None and isinstance(line_val, str) and line_val.isdigit():
        line_val = int(line_val)
    elif line_val is not None and not isinstance(line_val, int):
        line_val = None
    try:
        conf = float(raw.get("confidence", 1.0))
    except (TypeError, ValueError):
        conf = 1.0
    return Finding(
        module=str(raw.get("module", "dynamic_unknown")),
        severity=sev,  # type: ignore[arg-type]
        title=str(raw.get("title", "Dynamic finding")),
        description=str(raw.get("description", "")),
        evidence=str(raw.get("evidence", "")),
        file=str(raw.get("file", "[runtime]")),
        line=line_val,
        remediation=str(raw.get("remediation", "")),
        cwe=str(cwe_val or "CWE-693"),
        confidence=conf,
        poc_type=str(poc_type) if poc_type is not None else None,
        poc_payload=str(raw["poc_payload"]) if raw.get("poc_payload") is not None else None,
        poc_description=str(raw["poc_description"]) if raw.get("poc_description") is not None else None,
    )


def run_dynamic_analysis(
    ext_path: str,
    *,
    timeout: int = 180,
    console: Console | None = None,
) -> list[Finding]:
    """
    Spawn ``node harness/runner.js`` and parse JSON findings from stdout.

    Returns an empty list if Node is missing, npm install fails, subprocess times out,
    or JSON parsing fails. Failures are non-fatal for callers running static analysis first.
    """
    out = console or Console(stderr=True)
    harness_dir = _get_harness_dir()
    ext_resolved = str(Path(ext_path).resolve())

    if not shutil.which("node"):
        out.print("[yellow]node not found — skipping dynamic analysis[/yellow]")
        return []

    if not (harness_dir / "node_modules").exists():
        out.print("[yellow]Running npm install for dynamic harness...[/yellow]")
        try:
            subprocess.run(
                ["npm", "install"],
                cwd=str(harness_dir),
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning("npm install failed for harness: %s", exc)
            out.print("[yellow]npm install failed — skipping dynamic analysis[/yellow]")
            return []

    runner_path = harness_dir / RUNNER_SCRIPT
    if not runner_path.is_file():
        logger.warning("Harness runner missing at %s", runner_path)
        return []

    try:
        result = _run_harness_subprocess(harness_dir, ext_resolved, timeout)
    except (OSError, ValueError) as exc:
        logger.warning("Could not execute harness: %s", exc)
        return []

    if result is None:
        return []

    if result.stderr:
        for line in result.stderr.strip().splitlines()[:200]:
            logger.info("harness stderr: %s", line)

    if result.returncode != 0:
        logger.warning(
            "Dynamic harness exited %s: %s",
            result.returncode,
            (result.stderr or "")[:500],
        )
        return []

    raw_stdout = (result.stdout or "").strip()
    if not raw_stdout:
        return []

    parsed: Any = None
    try:
        parsed = json.loads(raw_stdout)
    except json.JSONDecodeError:
        for line in reversed(raw_stdout.splitlines()):
            line = line.strip()
            if line.startswith("[") or line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
    if parsed is None:
        logger.warning("Harness stdout was not valid JSON")
        return []

    if not isinstance(parsed, list):
        logger.warning("Harness JSON root is not an array")
        return []

    findings: list[Finding] = []
    for item in parsed:
        if isinstance(item, dict):
            try:
                findings.append(_raw_to_finding(item))
            except (TypeError, KeyError, ValueError) as exc:
                logger.info("Skipping malformed harness finding: %s (%s)", item, exc)
    return findings
