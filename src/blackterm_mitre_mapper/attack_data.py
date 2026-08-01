from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx


ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


class AttackCatalog:
    def __init__(self, techniques: list[dict[str, Any]]):
        self.techniques = techniques
        self.by_id = {item["external_id"]: item for item in techniques}

    @classmethod
    def from_stix_file(cls, path: Path) -> "AttackCatalog":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(_extract_techniques(data))

    @classmethod
    def bundled(cls) -> "AttackCatalog":
        path = Path(__file__).parent / "data" / "techniques_seed.json"
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def get(self, technique_id: str) -> dict[str, Any] | None:
        return self.by_id.get(technique_id.upper())

    def search(self, query: str) -> list[dict[str, Any]]:
        needle = query.casefold()
        return [
            item
            for item in self.techniques
            if needle in item["external_id"].casefold()
            or needle in item["name"].casefold()
            or needle in item.get("description", "").casefold()
        ]


def download_enterprise_stix(destination: Path, timeout: float = 30.0) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", ENTERPRISE_STIX_URL, follow_redirects=True, timeout=timeout) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
    return destination


def _extract_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        external = next(
            (
                ref
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )
        if not external:
            continue

        kill_chain_phases = [
            item.get("phase_name", "")
            for item in obj.get("kill_chain_phases", [])
            if item.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            {
                "external_id": external["external_id"],
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "tactics": kill_chain_phases,
                "url": external.get("url"),
                "modified": obj.get("modified"),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
        )

    return sorted(techniques, key=lambda item: item["external_id"])
