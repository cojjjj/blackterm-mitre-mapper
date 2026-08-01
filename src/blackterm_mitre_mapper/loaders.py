from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml

from .models import MappingRule
from .telemetry import load_telemetry


class RuleLoadError(RuntimeError):
    pass


def load_rules(paths: Iterable[Path]) -> list[MappingRule]:
    rules: list[MappingRule] = []
    seen_ids: set[str] = set()

    for path in paths:
        for document in _iter_rule_documents(path):
            rule = MappingRule.model_validate(document)
            if not rule.enabled:
                continue
            if rule.id in seen_ids:
                raise RuleLoadError(f"Duplicate rule ID: {rule.id}")
            rules.append(rule)
            seen_ids.add(rule.id)

    return rules


def discover_rule_paths(custom_path: Path | None = None) -> list[Path]:
    package_rules = Path(__file__).parent / "rules"
    paths = [package_rules]
    if custom_path:
        paths.append(custom_path)
    return paths


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load JSON, JSONL, or EVTX telemetry."""
    return load_telemetry(path)


def _iter_rule_documents(path: Path):
    if not path.exists():
        raise RuleLoadError(f"Rule path does not exist: {path}")

    candidates = sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml")) if path.is_dir() else [path]

    for candidate in candidates:
        try:
            parsed = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleLoadError(f"Could not load {candidate}: {exc}") from exc

        if parsed is None:
            continue
        documents = parsed if isinstance(parsed, list) else [parsed]
        for document in documents:
            if not isinstance(document, dict):
                raise RuleLoadError(f"Rule in {candidate} must be a mapping")
            yield document
