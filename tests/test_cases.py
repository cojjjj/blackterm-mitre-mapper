from pathlib import Path

from blackterm_mitre_mapper.cases import CaseStore


def test_case_store_round_trip(tmp_path: Path):
    store = CaseStore(tmp_path)
    saved = store.save("abc123", {"title": "Demo", "view": {"max_risk": 86}})
    assert saved["case_id"] == "abc123"
    assert store.get("abc123")["title"] == "Demo"
    assert len(store.list()) == 1
    assert store.delete("abc123") is True
