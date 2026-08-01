from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .attack_data import AttackCatalog, download_enterprise_stix
from .engine import MitreMapper
from .loaders import discover_rule_paths, load_events, load_rules
from .models import AnalysisResult
from .reporting import write_html_report, write_json_report
from .sigma import convert_sigma_file, write_blackterm_rules

app = typer.Typer(
    name="mitre-mapper",
    help="BLACKTERM // MITRE MAPPER — map security activity to ATT&CK.",
    no_args_is_help=True,
)
console = Console()


def _mapper(custom_rules: Path | None = None) -> MitreMapper:
    return MitreMapper(load_rules(discover_rule_paths(custom_rules)))


@app.command()
def analyze(
    command: Annotated[str, typer.Argument(help="Command line or free-form event text")],
    rules: Annotated[Path | None, typer.Option(help="Additional YAML rule file/directory")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print machine-readable JSON")] = False,
) -> None:
    """Analyze a command line or free-form security event."""
    result = _mapper(rules).analyze_command(command)
    if json_output:
        console.print_json(result.model_dump_json(indent=2))
        return
    _print_result(result)


@app.command("analyze-event")
def analyze_event(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    rules: Annotated[Path | None, typer.Option(help="Additional YAML rule file/directory")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Analyze one JSON event."""
    events = load_events(path)
    if len(events) != 1:
        raise typer.BadParameter("Input must contain exactly one event")
    result = _mapper(rules).analyze_event(events[0], source=str(path))
    if json_output:
        console.print_json(result.model_dump_json(indent=2))
        return
    _print_result(result)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    rules: Annotated[Path | None, typer.Option(help="Additional YAML rule file/directory")] = None,
    format: Annotated[str, typer.Option(help="Output format: console, json, or html")] = "console",
    output: Annotated[Path | None, typer.Option(help="Report destination")] = None,
) -> None:
    """Scan JSON, JSONL, or Windows EVTX security events."""
    events = load_events(path)
    mapper = _mapper(rules)
    results = [mapper.analyze_event(event, source=str(path)) for event in events]

    selected_format = format.lower()
    if selected_format == "console":
        for index, result in enumerate(results, start=1):
            console.rule(f"Event {index}/{len(results)}")
            _print_result(result)
        return

    if selected_format == "json":
        destination = output or Path("mitre-mapper-report.json")
        write_json_report(results, destination)
    elif selected_format == "html":
        destination = output or Path("mitre-mapper-report.html")
        write_html_report(results, destination)
    else:
        raise typer.BadParameter("Format must be console, json, or html")

    console.print(f"[bold green]Report written:[/] {destination.resolve()}")


@app.command("import-sigma")
def import_sigma(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Sigma YAML rule")],
    output: Annotated[Path, typer.Option(help="BLACKTERM YAML output")] = Path("rules/imported-sigma.yml"),
) -> None:
    """Convert a supported Sigma rule into BLACKTERM's transparent rule format."""
    try:
        rules = convert_sigma_file(path)
        destination = write_blackterm_rules(rules, output)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Sigma import failed:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[bold green]Imported {len(rules)} Sigma rule(s):[/] {destination.resolve()}")


@app.command("inspect-telemetry")
def inspect_telemetry(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    limit: Annotated[int, typer.Option(help="Maximum events to preview")] = 5,
) -> None:
    """Normalize and preview JSON, JSONL, or EVTX telemetry without mapping it."""
    try:
        events = load_events(path)
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]Telemetry load failed:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[bold cyan]{len(events)} event(s) loaded[/]")
    for event in events[:max(1, limit)]:
        console.print_json(json.dumps(event, default=str))


@app.command()
def techniques(
    query: Annotated[str | None, typer.Option(help="Search ID, name, or description")] = None,
    data: Annotated[Path | None, typer.Option(help="Downloaded Enterprise STIX JSON")] = None,
) -> None:
    """List or search ATT&CK techniques."""
    catalog = AttackCatalog.from_stix_file(data) if data else AttackCatalog.bundled()
    matches = catalog.search(query) if query else catalog.techniques

    table = Table(title="ATT&CK Technique Catalog")
    table.add_column("ID", style="bold cyan")
    table.add_column("Technique")
    table.add_column("Tactics")
    table.add_column("Platforms")

    for item in matches[:100]:
        table.add_row(
            item["external_id"],
            item["name"],
            ", ".join(item.get("tactics", [])),
            ", ".join(item.get("platforms", [])),
        )

    console.print(table)
    if len(matches) > 100:
        console.print(f"[dim]Showing 100 of {len(matches)} results.[/]")


@app.command()
def technique(
    technique_id: Annotated[str, typer.Argument(help="ATT&CK ID, e.g. T1059.001")],
    data: Annotated[Path | None, typer.Option(help="Downloaded Enterprise STIX JSON")] = None,
) -> None:
    """Show details for one ATT&CK technique."""
    catalog = AttackCatalog.from_stix_file(data) if data else AttackCatalog.bundled()
    item = catalog.get(technique_id)
    if not item:
        console.print(f"[red]Technique not found:[/] {technique_id}")
        raise typer.Exit(code=1)

    body = (
        f"[bold]{item['name']}[/]\n\n"
        f"[cyan]Tactics:[/] {', '.join(item.get('tactics', [])) or 'Unknown'}\n"
        f"[cyan]Platforms:[/] {', '.join(item.get('platforms', [])) or 'Unknown'}\n"
        f"[cyan]Sub-technique:[/] {item.get('is_subtechnique', False)}\n\n"
        f"{item.get('description', 'No description available.')}"
    )
    console.print(Panel(body, title=item["external_id"], border_style="cyan"))


@app.command("validate-rules")
def validate_rules(
    rules: Annotated[Path, typer.Argument(exists=True)],
) -> None:
    """Validate custom YAML rules."""
    loaded = load_rules([rules])
    console.print(f"[bold green]Valid rules:[/] {len(loaded)}")
    for rule in loaded:
        console.print(f"  [cyan]{rule.id}[/]  {rule.technique_id}  {rule.name}")


@app.command("update-attack-data")
def update_attack_data(
    output: Annotated[Path, typer.Option(help="Destination STIX JSON file")] = Path(
        "data/enterprise-attack.json"
    ),
) -> None:
    """Download the official Enterprise ATT&CK STIX 2.1 bundle."""
    with console.status("Downloading Enterprise ATT&CK STIX data..."):
        destination = download_enterprise_stix(output)
    console.print(f"[bold green]ATT&CK data updated:[/] {destination.resolve()}")


@app.command()
def dashboard(
    host: Annotated[str, typer.Option(help="Dashboard bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Dashboard TCP port")] = 8080,
    rules: Annotated[Path | None, typer.Option(help="Additional YAML rule file/directory")] = None,
    open_browser: Annotated[bool, typer.Option("--open/--no-open", help="Open the dashboard in a browser")] = True,
) -> None:
    """Launch the local investigation dashboard."""
    import threading
    import webbrowser

    import uvicorn

    from .web import create_app

    url = f"http://{host}:{port}"
    console.print(Panel(f"[bold cyan]{url}[/]\nPress Ctrl+C to stop.", title="BLACKTERM // DASHBOARD"))
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(rules), host=host, port=port, log_level="warning")


def _print_result(result: AnalysisResult) -> None:
    header = (
        f"[bold]Risk score:[/] {result.risk_score}/100\n"
        f"[bold]Highest severity:[/] {result.highest_severity}\n"
        f"[bold]Mappings:[/] {len(result.mappings)}"
    )
    border = "red" if result.risk_score >= 70 else "yellow" if result.risk_score >= 40 else "cyan"
    console.print(Panel(header, title="BLACKTERM // MITRE MAPPER", border_style=border))

    if not result.mappings:
        console.print("[green]No ATT&CK mappings matched the current rule set.[/]")
        return

    for mapping in result.mappings:
        evidence = "\n".join(
            f"• {item.field} {item.operator} {json.dumps(item.expected)}"
            for item in mapping.evidence
            if item.matched
        )
        body = (
            f"[bold]{mapping.technique_name}[/]\n"
            f"[cyan]Tactics:[/] {', '.join(mapping.tactics)}\n"
            f"[cyan]Severity:[/] {mapping.severity}\n"
            f"[cyan]Confidence:[/] {mapping.confidence:.0%}\n\n"
            f"{mapping.description}\n\n"
            f"[bold]Evidence[/]\n{evidence}"
        )
        console.print(Panel(body, title=mapping.technique_id, border_style="magenta"))


if __name__ == "__main__":
    app()
