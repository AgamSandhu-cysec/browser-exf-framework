"""Generate standalone HTML Proof-of-Concept files for findings."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from core.engine import Finding

TEMPLATE_DIR = Path(__file__).parent / "templates" / "poc"

POC_TYPE_TO_TEMPLATE: dict[str, str] = {
    "postmessage_injection": "postmessage_injection.html.j2",
    "cors_proxy": "cors_proxy.html.j2",
    "ext_connectable_abuse": "ext_connectable_abuse.html.j2",
    "background_injection": "background_injection.html.j2",
}


def generate_poc_for_finding(
    finding: Finding,
    ext_id: str,
    output_dir: Path,
) -> Path | None:
    """
    Generate a standalone PoC HTML file for a finding.

    Returns the output path, or None if:
      - finding.poc_type not in POC_TYPE_TO_TEMPLATE
      - finding.confidence < 0.7
    """
    if not finding.poc_type:
        return None
    if finding.poc_type not in POC_TYPE_TO_TEMPLATE:
        return None
    if finding.confidence < 0.7:
        return None

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=False)
    template = env.get_template(POC_TYPE_TO_TEMPLATE[finding.poc_type])

    html = template.render(
        ext_id=ext_id,
        finding=finding,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
    )

    out_dir = output_dir / "poc"
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = finding.poc_type.replace("/", "_")
    cwe_slug = finding.cwe.replace("-", "_").lower()
    filename = f"poc_{safe_name}_{cwe_slug}.html"
    out_path = out_dir / filename
    out_path.write_text(html, encoding="utf-8")
    return out_path

