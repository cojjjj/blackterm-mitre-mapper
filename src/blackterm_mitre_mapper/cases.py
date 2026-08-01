from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseStore:
    """Small local JSON case store. No database or external service required."""

    def __init__(self, directory: Path | None = None):
        self.directory = directory or (Path.home() / ".blackterm" / "mitre-mapper" / "cases")
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get(case_id)
        now = datetime.now(timezone.utc).isoformat()
        record = {
            **payload,
            "case_id": case_id,
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
        }
        self._path(case_id).write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def get(self, case_id: str) -> dict[str, Any] | None:
        path = self._path(case_id)
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def list(self) -> list[dict[str, Any]]:
        records = []
        for path in self.directory.glob("*.json"):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                records.append(item)
        return sorted(records, key=lambda item: item.get("updated_at", ""), reverse=True)

    def delete(self, case_id: str) -> bool:
        path = self._path(case_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _path(self, case_id: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "", case_id)
        if not safe:
            raise ValueError("Invalid case ID")
        return self.directory / f"{safe}.json"
