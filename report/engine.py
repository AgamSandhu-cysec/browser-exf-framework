"""Build Rich terminal summaries and JSON reports from findings."""

from __future__ import annotations

import json
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from core.engine import Finding

TOOL_NAME = "ext-attack-framework"
TOOL_VERSION = "0.2.0"

SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

ATTACK_SCENARIOS: dict[str, str] = {
    "CWE-79": "inject arbitrary HTML/JS into the extension UI context",
    "CWE-95": "execute arbitrary code in the extension background context",
    "CWE-201": "receive sensitive data broadcast by the extension",
    "CWE-346": "trigger the extension to fetch any cross-origin URL",
    "CWE-798": "use this credential to access the associated service",
}


def _get_jinja_env():
    """Return a Jinja environment for report templates."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    template_dir = Path(__file__).resolve().parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(("html", "xml")),
    )


def _infer_ext_id(ext_path: str) -> str:
    """
    Return extension ID if ext_path looks like one, else folder name slug.
    """
    p = Path(ext_path).name
    if len(p) == 32 and all(c in "abcdefghijklmnop" for c in p):
        return p
    return p.lower().replace(" ", "-")[:32]


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _highest_severity(findings: list[Finding]) -> str:
    """Return the highest severity label present, else 'none'."""
    order = ["critical", "high", "medium", "low", "info"]
    severities = {f.severity for f in findings}
    for s in order:
        if s in severities:
            return s
    return "none"


def _build_executive_summary(
    manifest: dict,
    findings: list[Finding],
    counts: dict[str, int],
) -> str:
    """
    Build a plain-English one-paragraph summary.
    """
    name = manifest.get("name", "This extension")
    version = manifest.get("version", "")
    ver_str = f" (v{version})" if version else ""

    perms = (manifest.get("permissions", []) + manifest.get("host_permissions", [])) or []

    DANGEROUS = [
        "<all_urls>",
        "*://*/*",
        "tabs",
        "history",
        "cookies",
        "webRequest",
        "nativeMessaging",
        "debugger",
        "management",
        "proxy",
        "clipboardRead",
    ]
    dangerous = [p for p in perms if p in DANGEROUS]

    total = sum(counts.values())
    if total == 0:
        return f"{name}{ver_str} passed all checks with no findings."

    perm_str = ""
    if dangerous:
        shown = dangerous[:3]
        rest = len(dangerous) - 3
        perm_str = (
            f" requests {len(dangerous)} sensitive permission"
            f"{'s' if len(dangerous) > 1 else ''} including "
            f"{', '.join(shown)}"
            f"{' and ' + str(rest) + ' more' if rest > 0 else ''}"
        )

    sev_parts: list[str] = []
    for s in ("critical", "high", "medium"):
        if counts.get(s, 0) > 0:
            sev_parts.append(f"{counts[s]} {s}")
    sev_str = ", ".join(sev_parts) if sev_parts else "no high-severity"

    critical_findings = [f for f in findings if f.severity == "critical"]
    highlight = ""
    if critical_findings:
        titles = [f.title for f in critical_findings[:2]]
        highlight = f" Critical issues include: {'; '.join(titles)}."

    return (
        f"{name}{ver_str}{perm_str}. "
        f"The scanner identified {total} finding{'s' if total > 1 else ''}: "
        f"{sev_str} severity.{highlight}"
    )


def generate_html_report(
    findings: list[Finding],
    manifest: dict,
    ext_path: str,
    output_dir: Path,
    generate_pocs: bool = False,
    version: str = "0.1.0",
) -> Path:
    """
    Render ``report.html.j2`` and optionally generate PoC files.
    """
    ext_id = _infer_ext_id(ext_path)
    counts = _count_by_severity(findings)
    highest = _highest_severity(findings)
    summary = _build_executive_summary(manifest, findings, counts)

    poc_paths: dict[int, str] = {}
    if generate_pocs:
        from report.poc_generator import generate_poc_for_finding

        for f in findings:
            path = generate_poc_for_finding(f, ext_id, output_dir)
            if path:
                poc_paths[id(f)] = path.name

    permissions = (manifest.get("permissions", []) + manifest.get("host_permissions", [])) or []

    env = _get_jinja_env()
    template = env.get_template("report.html.j2")

    # attach stable IDs for template lookup
    for f in findings:
        setattr(f, "_fid", id(f))

    html = template.render(
        findings=findings,
        manifest=manifest,
        ext_name=manifest.get("name", "Unknown Extension"),
        ext_version=manifest.get("version", "?"),
        ext_id=ext_id,
        counts=counts,
        total_findings=len(findings),
        highest_severity=highest,
        executive_summary=summary,
        permissions=permissions,
        severity_colors=SEVERITY_COLORS,
        attack_scenarios=ATTACK_SCENARIOS,
        poc_paths=poc_paths,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        version=version,
    )

    out_path = output_dir / "report.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path

def _severity_summary(findings: Sequence[object]) -> dict[str, int]:
    """Count findings by severity label."""
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        sev = getattr(f, "severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def render_terminal_report(
    findings: Sequence[object],
    target: str,
    *,
    verbose: bool = False,
    no_color: bool = False,
) -> None:
    """
    Print a Rich banner, severity summary, findings table, and optional details.

    ``findings`` may be :class:`dataclasses.dataclass` instances with Finding fields.
    """
    console = Console(force_terminal=not no_color, no_color=no_color, highlight=False)
    header = Text()
    header.append(f"{TOOL_NAME}  •  v{TOOL_VERSION}\n", style="bold")
    header.append(f"Target: {target}", style="cyan")
    console.print(
        Panel.fit(header, box=box.DOUBLE, border_style="cyan", title="[bold]scan[/bold]")
    )

    counts = _severity_summary(findings)
    summary_line = Text()
    for label, sym in (
        ("critical", "● CRITICAL"),
        ("high", "● HIGH"),
        ("medium", "● MEDIUM"),
        ("low", "● LOW"),
        ("info", "● INFO"),
    ):
        summary_line.append(
            f"{sym}  {counts[label]:<3}  ",
            style=SEVERITY_STYLES[label],
        )
    console.print("\nSeverity summary:\n")
    console.print(summary_line)
    console.print()

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        title="Findings",
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=10)
    table.add_column("Module", width=18)
    table.add_column("Title", overflow="fold")

    for idx, f in enumerate(findings, start=1):
        sev = getattr(f, "severity", "info")
        style = SEVERITY_STYLES.get(sev, "white")
        conf_val = getattr(f, "confidence", 0.0)
        try:
            conf = float(conf_val)
        except (TypeError, ValueError):
            conf = 0.0
        pct = int(round(conf * 100))
        if pct >= 70:
            conf_style = "green"
        elif pct >= 40:
            conf_style = "yellow"
        else:
            conf_style = "red"
        table.add_row(
            str(idx),
            Text(sev.upper(), style=style),
            Text(f"{pct}%", style=conf_style),
            getattr(f, "module", ""),
            getattr(f, "title", ""),
        )
    console.print(table)

    console.print("\n[bold]Details[/bold]\n")
    for idx, f in enumerate(findings, start=1):
        sev = getattr(f, "severity", "info")
        title = getattr(f, "title", "")
        if not verbose:
            loc = f"{getattr(f, 'file', '')}"
            line = getattr(f, "line", None)
            if line is not None:
                loc += f":{line}"
            console.print(
                f"  [{idx}] [{sev.upper()}] {title} — {loc}",
                style=SEVERITY_STYLES.get(sev, ""),
            )
            continue
        console.print(
            Panel(
                Text.assemble(
                    (f"#{idx} ", "bold"),
                    (f"[{sev.upper()}] ", SEVERITY_STYLES.get(sev, "")),
                    (title, "bold white"),
                    "\n",
                    (getattr(f, "description", ""), ""),
                    "\n\n",
                    ("Evidence:\n", "bold"),
                    (getattr(f, "evidence", ""), "dim"),
                    "\n\n",
                    ("File: ", "bold"),
                    (str(getattr(f, "file", "")), "cyan"),
                    "  ",
                    ("Line: ", "bold"),
                    (str(getattr(f, "line", "")), "cyan"),
                    "\n",
                    ("CWE: ", "bold"),
                    (getattr(f, "cwe", ""), ""),
                    "  ",
                    ("Confidence: ", "bold"),
                    (str(getattr(f, "confidence", "")), ""),
                    "\n\n",
                    ("Remediation: ", "bold"),
                    (getattr(f, "remediation", ""), "green"),
                ),
                title=f"[{idx}] {getattr(f, 'module', '')}",
                border_style=SEVERITY_STYLES.get(sev, "white"),
            )
        )


def write_json_report(findings: Sequence[object], output_path: Path) -> None:
    """Write all findings as JSON to ``output_path``."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(f) if hasattr(f, "__dataclass_fields__") else dict(f) for f in findings]
    meta = {"tool": TOOL_NAME, "version": TOOL_VERSION, "findings_count": len(payload)}
    out = {"meta": meta, "findings": payload}
    output_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def render_html_report(
    findings: Sequence[object],
    target: str,
    output_path: Path,
) -> None:
    """
    Render a Jinja2 HTML report with severity styling and optional per-finding PoC blocks.

    ``findings`` should be ``Finding`` dataclass instances (or dicts with the same keys).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Back-compat wrapper for older callers/tests: render the same HTML template
    # with minimal context derived from the provided findings + target string.
    env = _get_jinja_env()
    tpl = env.get_template("report.html.j2")

    typed: list[Finding] = []
    for f in findings:
        if isinstance(f, Finding):
            typed.append(f)

    counts = _count_by_severity(typed) if typed else {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    highest = _highest_severity(typed) if typed else "none"
    summary = _build_executive_summary({"name": target, "version": ""}, typed, counts)

    for f in typed:
        setattr(f, "_fid", id(f))

    html = tpl.render(
        findings=typed,
        manifest={},
        ext_name=target,
        ext_version="?",
        ext_id=_infer_ext_id(target),
        counts=counts,
        total_findings=len(typed),
        highest_severity=highest,
        executive_summary=summary,
        permissions=[],
        severity_colors=SEVERITY_COLORS,
        attack_scenarios=ATTACK_SCENARIOS,
        poc_paths={},
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        version=TOOL_VERSION,
    )
    output_path.write_text(html, encoding="utf-8")


def run_with_progress(console: Console, task_labels: list[str], runner) -> None:
    """
    Display a Rich progress bar while executing ``runner(progress, task_id_map)``.

    ``runner`` receives the Progress instance and a dict of task_name -> task_id.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        ids: dict[str, int] = {}
        for label in task_labels:
            ids[label] = progress.add_task(label, total=1)
        runner(progress, ids)
