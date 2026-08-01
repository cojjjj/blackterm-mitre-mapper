from pathlib import Path

from fastapi.testclient import TestClient

from blackterm_mitre_mapper.web import create_app, parse_events


def test_health_endpoint(tmp_path: Path):
    client = TestClient(create_app(case_directory=tmp_path))
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "1.0.0"


def test_analyze_and_save_case(tmp_path: Path):
    client = TestClient(create_app(case_directory=tmp_path))
    response = client.post("/api/analyze-command", data={"command": "powershell.exe -enc SQBFAFgA"})
    assert response.status_code == 200
    body = response.json()
    case_id = body["investigation_id"]
    assert body["view"]["mapping_count"] >= 1
    assert body["view"]["recommendations"]
    saved = client.post(f"/api/cases/{case_id}", json={"title": "Encoded PowerShell", "notes": "Review host"})
    assert saved.status_code == 200
    listed = client.get("/api/cases").json()["cases"]
    assert listed[0]["title"] == "Encoded PowerShell"
    opened = client.get(f"/api/cases/{case_id}")
    assert opened.status_code == 200
    assert opened.json()["view"]["event_count"] == 1


def test_parse_jsonl():
    events = parse_events('{"message":"one"}\n{"message":"two"}\n', "events.jsonl")
    assert len(events) == 2


def test_platform_summary_endpoint(tmp_path: Path):
    client = TestClient(create_app(case_directory=tmp_path))
    response = client.get("/api/platform")
    assert response.status_code == 200
    body = response.json()
    assert body["case_count"] == 0
    assert any(module["id"] == "mitre" and module["status"] == "online" for module in body["modules"])


def test_demo_investigation(tmp_path: Path):
    client = TestClient(create_app(case_directory=tmp_path))
    response = client.post("/api/demo")
    assert response.status_code == 200
    view = response.json()["view"]
    assert view["event_count"] == 5
    assert view["mapping_count"] >= 4
    assert view["max_risk"] >= 80

