from __future__ import annotations

import hashlib
from typing import Any

from .models import AnalysisResult, Evidence, MappingResult, MappingRule
from .normalize import flatten_event, normalize_command
from .operators import evaluate_condition

SEVERITY_SCORE = {
    "informational": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class MitreMapper:
    def __init__(self, rules: list[MappingRule]):
        self.rules = rules

    def analyze_command(self, command: str, source: str | None = "command-line") -> AnalysisResult:
        event = {
            "process": {
                "name": command.strip().split(maxsplit=1)[0] if command.strip() else "",
                "command_line": command,
            },
            "raw": command,
        }
        return self.analyze_event(event, source=source, normalized=normalize_command(command))

    def analyze_event(
        self,
        event: dict[str, Any],
        source: str | None = None,
        normalized: dict[str, Any] | None = None,
    ) -> AnalysisResult:
        flat_event = normalized or flatten_event(event)
        matches: list[MappingResult] = []

        for rule in self.rules:
            result = self._evaluate_rule(flat_event, rule)
            if result is not None:
                matches.append(result)

        matches = self._deduplicate(matches)
        highest = self._highest_severity(matches)
        risk_score = self._risk_score(matches)
        event_id = self._event_id(event)

        return AnalysisResult(
            event_id=event_id,
            source=source,
            event=event,
            mappings=matches,
            risk_score=risk_score,
            highest_severity=highest,
        )

    def _evaluate_rule(
        self, event: dict[str, Any], rule: MappingRule
    ) -> MappingResult | None:
        all_evidence = [evaluate_condition(event, item) for item in rule.match.all]
        any_evidence = [evaluate_condition(event, item) for item in rule.match.any]
        none_evidence = [evaluate_condition(event, item) for item in rule.match.none]

        all_pass = all(item.matched for item in all_evidence)
        any_pass = not any_evidence or any(item.matched for item in any_evidence)
        none_pass = not any(item.matched for item in none_evidence)

        if not (all_pass and any_pass and none_pass):
            return None

        evidence = all_evidence + [item for item in any_evidence if item.matched] + none_evidence
        confidence = self._confidence(rule, evidence)

        return MappingResult(
            rule_id=rule.id,
            rule_name=rule.name,
            technique_id=rule.technique_id,
            technique_name=rule.technique_name,
            tactics=rule.tactics,
            severity=rule.severity,
            confidence=confidence,
            description=rule.description,
            platforms=rule.platforms,
            evidence=evidence,
            references=rule.references,
            tags=rule.tags,
        )

    @staticmethod
    def _confidence(rule: MappingRule, evidence: list[Evidence]) -> float:
        positive = [item for item in evidence if item.matched]
        if not positive:
            return round(rule.confidence, 3)

        total_weight = sum(item.weight for item in positive)
        specificity_bonus = min(0.08, max(0.0, (total_weight - 1.0) * 0.02))
        return round(min(0.99, rule.confidence + specificity_bonus), 3)

    @staticmethod
    def _deduplicate(matches: list[MappingResult]) -> list[MappingResult]:
        best: dict[str, MappingResult] = {}
        for match in matches:
            current = best.get(match.technique_id)
            if current is None:
                best[match.technique_id] = match
                continue
            candidate_key = (SEVERITY_ORDER[match.severity], match.confidence)
            current_key = (SEVERITY_ORDER[current.severity], current.confidence)
            if candidate_key > current_key:
                best[match.technique_id] = match

        return sorted(
            best.values(),
            key=lambda item: (SEVERITY_ORDER[item.severity], item.confidence),
            reverse=True,
        )

    @staticmethod
    def _risk_score(matches: list[MappingResult]) -> int:
        if not matches:
            return 0

        weighted = [
            SEVERITY_SCORE[item.severity] * item.confidence
            for item in matches
        ]
        base = max(weighted)
        breadth_bonus = min(15, max(0, len(matches) - 1) * 4)
        return min(100, round(base + breadth_bonus))

    @staticmethod
    def _highest_severity(matches: list[MappingResult]) -> str:
        if not matches:
            return "informational"
        return max(matches, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    @staticmethod
    def _event_id(event: dict[str, Any]) -> str:
        encoded = repr(sorted(flatten_event(event).items())).encode("utf-8", errors="replace")
        return hashlib.sha256(encoded).hexdigest()[:16]
