from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .intelligence import build_report_context
from .models import AnalysisResult


def write_json_report(results: Iterable[AnalysisResult], destination: Path) -> Path:
    payload = [result.model_dump(mode="json") for result in results]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination


def write_html_report(results: list[AnalysisResult], destination: Path) -> Path:
    templates = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(templates),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    context = build_report_context(results)
    rendered = template.render(title="BLACKTERM // MITRE MAPPER", results=results, **context)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding="utf-8")
    return destination
