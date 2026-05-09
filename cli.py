#!/usr/bin/env python3
"""
ext-attack-framework — Browser Extension Attack Framework.

Static and optional Puppeteer-based dynamic analysis for Chrome extensions
(ID, .crx, or unpacked folder).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.engine import (
    apply_dynamic_confirmations,
    filter_findings,
    has_critical_or_high,
    run_static_scan,
)
from core.extractor import extract
from core.unpacker import unpack
from dynamic.orchestrator import run_dynamic_analysis
from report.engine import (
    TOOL_NAME,
    TOOL_VERSION,
    generate_html_report,
    render_html_report,
    render_terminal_report,
    run_with_progress,
    write_json_report,
)

app = typer.Typer(
    name="ext-attack-framework",
    add_completion=False,
    help=(
        "Static and dynamic (Puppeteer harness) analysis for Chrome extensions. "
        "Use --dynamic with --module all, or --module dynamic for Node-driven runtime tests."
    ),
    rich_markup_mode="rich",
)
console = Console()


def _slugify(s: str) -> str:
    """Create a filesystem-safe slug for report directories."""
    out = []
    for ch in s.strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "_", "-", "."):
            out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return (slug or "extension")[:48]


def _scan_modules_order(module: str, *, include_dynamic: bool) -> list[str]:
    """Return ordered progress labels for the selected module scope."""
    mod = module.lower().strip()
    if mod == "manifest":
        return ["Unpack / resolve", "Extract files", "Manifest + external exposure"]
    if mod == "ast":
        return ["Unpack / resolve", "Extract files", "AST pattern scan"]
    if mod == "secrets":
        return ["Unpack / resolve", "Extract files", "Secrets scan"]
    if mod == "dynamic":
        return ["Unpack / resolve", "Extract files", "Dynamic analysis (Puppeteer harness)"]
    base = ["Unpack / resolve", "Extract files", "Static analysis (all modules)"]
    if include_dynamic:
        base.append("Dynamic analysis (Puppeteer harness)")
    return base


@app.command("scan")
def scan_command(
    input_path: str = typer.Option(
        ...,
        "--input",
        help="Extension ID (32 a-p chars), path to .crx, or unpacked extension folder",
    ),
    output: Path = typer.Option(
        Path("output"),
        "--output",
        help="Directory for JSON/HTML report files",
    ),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        help="Output: terminal, json, html, or all",
    ),
    poc: bool = typer.Option(
        False,
        "--poc",
        help="Generate PoC HTML files (only meaningful with --format html or all)",
    ),
    severity: str = typer.Option(
        "info",
        "--severity",
        help="Minimum severity: critical, high, medium, low, info",
    ),
    module: str = typer.Option(
        "all",
        "--module",
        help="Run only: manifest, ast, secrets, dynamic, or all",
    ),
    dynamic: bool = typer.Option(
        False,
        "--dynamic",
        help="Run Puppeteer harness (Node) for XSS / postMessage / CORS / background tests",
    ),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help="Hide findings below this score",
    ),
    show_fp: bool = typer.Option(
        False,
        "--show-fp",
        help="Include likely-false-positive findings",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors"),
    verbose: bool = typer.Option(False, "--verbose", help="Show full evidence panels"),
) -> None:
    """
    Run static scanners (and optional Puppeteer harness probes) against an extension.

    Exits with code 1 when any critical or high severity finding is present
    (before severity filtering), for CI integration.
    """
    fmt = output_format.lower().strip()
    if fmt not in {"terminal", "json", "html", "all"}:
        console.print(f"[red]Invalid --format: {output_format}[/red]")
        raise typer.Exit(code=2)

    sev = severity.lower().strip()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        console.print(f"[red]Invalid --severity: {severity}[/red]")
        raise typer.Exit(code=2)

    mod = module.lower().strip()
    if mod not in {"all", "manifest", "ast", "secrets", "dynamic"}:
        console.print(f"[red]Invalid --module: {module}[/red]")
        raise typer.Exit(code=2)

    run_dynamic = (mod == "dynamic") or (dynamic and mod == "all")

    start = time.time()

    base_out_dir = output.resolve()
    base_out_dir.mkdir(parents=True, exist_ok=True)
    if fmt in {"html", "all"}:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name_hint = _slugify(Path(input_path).name)
        out_dir = base_out_dir / f"scan_{stamp}_{name_hint}"
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        stamp = ""
        out_dir = base_out_dir

    ext_root: Path | None = None
    layout: dict | None = None
    manifest: dict | None = None
    raw_findings: list = []

    labels = _scan_modules_order(mod, include_dynamic=(mod == "all" and dynamic))

    out_console = Console(force_terminal=not no_color, no_color=no_color, stderr=False)
    static_results: list = []

    def runner(progress, task_ids: dict[str, int]) -> None:
        """Execute scan stages and update the Rich progress bar."""
        nonlocal ext_root, layout, manifest, raw_findings, out_dir

        def complete(name: str) -> None:
            tid = task_ids.get(name)
            if tid is not None:
                progress.update(tid, completed=1)

        unpack_label = labels[0]
        progress.update(task_ids[unpack_label], description=unpack_label)
        ext_root = unpack(input_path, work_dir=out_dir / "workspace")
        complete(unpack_label)

        extract_label = labels[1]
        progress.update(task_ids[extract_label], description=extract_label)
        layout, manifest = extract(ext_root)
        complete(extract_label)

        if fmt in {"html", "all"}:
            desired_slug = _slugify(str(manifest.get("name", "")))
            desired = base_out_dir / f"scan_{stamp}_{desired_slug}"
            if desired != out_dir and not desired.exists():
                try:
                    out_dir.rename(desired)
                    out_dir = desired
                    ext_root = out_dir / "workspace" / "extension"
                    layout, manifest = extract(ext_root)
                except OSError:
                    pass

        scan_label = labels[2]
        progress.update(task_ids[scan_label], description=scan_label)
        raw_findings = []
        static_results.clear()
        if mod == "dynamic":
            raw_findings.extend(
                run_dynamic_analysis(str(ext_root), timeout=180, console=out_console)
            )
        else:
            static_batch = run_static_scan(ext_root, layout, manifest, modules=mod)
            static_results.extend(static_batch)
            raw_findings.extend(static_batch)
        complete(scan_label)

        if len(labels) > 3:
            dyn_label = labels[3]
            progress.update(task_ids[dyn_label], description=dyn_label)
            dyn_batch = run_dynamic_analysis(str(ext_root), timeout=180, console=out_console)
            apply_dynamic_confirmations(static_results, dyn_batch)
            raw_findings.extend(dyn_batch)
            complete(dyn_label)

    run_with_progress(out_console, labels, runner)

    assert ext_root is not None and layout is not None and manifest is not None

    manifest_dict = manifest
    all_findings = raw_findings

    from ml.scorer import score_all_findings
    from ml.feature_extractor import extract_features

    try:
        fv = extract_features(manifest_dict, all_findings)
        all_findings = score_all_findings(all_findings, manifest_dict)
    except Exception as e:
        console.print(f"[yellow]ML scorer skipped: {e}[/]")

    if not show_fp:
        all_findings = [f for f in all_findings if not f.likely_fp]
    if min_confidence > 0.0:
        all_findings = [f for f in all_findings if f.confidence >= min_confidence]

    exit_alarming = any(f.severity in ("critical", "high") for f in all_findings)
    displayed = filter_findings(all_findings, minimum_severity=sev, module_filter=mod)

    json_path = out_dir / "scan_results.json"

    if fmt in ("terminal", "all"):
        render_terminal_report(
            displayed,
            input_path,
            verbose=verbose,
            no_color=no_color,
        )

    write_json_report(displayed, json_path)
    out_console.print(f"\n[cyan]JSON report written to {json_path}[/cyan]")

    if fmt in ("html", "all"):
        report_path = generate_html_report(
            displayed,
            manifest_dict,
            input_path,
            out_dir,
            generate_pocs=poc,
            version=TOOL_VERSION,
        )
        out_console.print(f"[green]Report saved: {report_path}[/green]")
        if poc:
            poc_dir = out_dir / "poc"
            if poc_dir.exists():
                for f in sorted(poc_dir.iterdir()):
                    if f.is_file():
                        out_console.print(f"  [cyan]PoC:[/] {f.name}")

    elapsed = time.time() - start
    out_console.print(f"[dim]Scan completed in {elapsed:.2f}s[/dim]")

    if exit_alarming:
        raise typer.Exit(code=1)


@app.command("info")
def info_command(
    input_path: str = typer.Option(
        ...,
        "--input",
        help="Extension ID or path to unpacked extension / .crx",
    ),
) -> None:
    """
    Show extension name, version, and permission list without running scanners.

    Downloads CRX when given a Web Store ID.
    """
    work = Path("output") / "info_workspace"
    work.mkdir(parents=True, exist_ok=True)
    try:
        root = unpack(input_path, work_dir=work)
        _, manifest = extract(root)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    name = manifest.get("name", "(unknown)")
    version = manifest.get("version", "(unknown)")
    perms = manifest.get("permissions", [])
    if not isinstance(perms, list):
        perms = []
    optional = manifest.get("optional_permissions", [])
    if not isinstance(optional, list):
        optional = []
    host = manifest.get("host_permissions", [])
    if not isinstance(host, list):
        host = []

    console.print(f"[bold]{TOOL_NAME}[/bold] v{TOOL_VERSION} — [cyan]info[/cyan]\n")
    console.print(f"Name: [green]{name}[/green]")
    console.print(f"Version: [green]{version}[/green]")
    console.print("\n[bold]permissions[/bold]:")
    for p in perms:
        if isinstance(p, str):
            console.print(f"  • {p}")
    if host:
        console.print("\n[bold]host_permissions[/bold]:")
        for p in host:
            if isinstance(p, str):
                console.print(f"  • {p}")
    if optional:
        console.print("\n[bold]optional_permissions[/bold]:")
        for p in optional:
            if isinstance(p, str):
                console.print(f"  • {p}")


@app.command("list-modules")
def list_modules_command() -> None:
    """List scan modules."""
    table = Table(title="Available scan modules")
    table.add_column("Module")
    table.add_column("Phase")
    table.add_column("Finds")
    table.add_column("Default")
    table.add_row("manifest_parser", "1–2", "Dangerous permissions", "yes")
    table.add_row("ast_scanner", "1–2", "eval/innerHTML sinks", "yes")
    table.add_row("secrets_scanner", "1–2", "Hardcoded secrets", "yes")
    table.add_row("ext_connectable", "1–2", "External API surface", "yes")
    table.add_row("dynamic", "3", "Live exploitation", "--dynamic flag")
    console.print(table)


@app.command("version")
def version_command() -> None:
    """Print tool version."""
    console.print(f"{TOOL_NAME} {TOOL_VERSION}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
