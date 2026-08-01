from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Condition(BaseModel):
    field: str = "*"
    operator: Literal[
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "startswith",
        "endswith",
        "regex",
        "in",
        "exists",
        "cidr",
        "greater_than",
        "less_than",
    ]
    value: Any = None
    case_sensitive: bool = False
    weight: float = Field(default=1.0, ge=0.0)

    @field_validator("field")
    @classmethod
    def normalize_field(cls, value: str) -> str:
        return value.strip().lower()


class MatchExpression(BaseModel):
    all: list[Condition] = Field(default_factory=list)
    any: list[Condition] = Field(default_factory=list)
    none: list[Condition] = Field(default_factory=list)

    @field_validator("all", "any", "none")
    @classmethod
    def require_conditions(cls, value: list[Condition]) -> list[Condition]:
        return value


class MappingRule(BaseModel):
    id: str
    name: str
    technique_id: str
    technique_name: str
    tactics: list[str]
    severity: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    match: MatchExpression
    references: list[str] = Field(default_factory=list)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)

    @field_validator("technique_id")
    @classmethod
    def normalize_technique_id(cls, value: str) -> str:
        return value.upper().strip()

    @field_validator("tactics")
    @classmethod
    def normalize_tactics(cls, value: list[str]) -> list[str]:
        return [item.lower().replace(" ", "-") for item in value]


class Evidence(BaseModel):
    field: str
    operator: str
    expected: Any = None
    observed: Any = None
    matched: bool
    weight: float = 1.0


class MappingResult(BaseModel):
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    tactics: list[str]
    severity: str
    confidence: float
    description: str
    platforms: list[str]
    evidence: list[Evidence]
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    event_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str | None = None
    event: dict[str, Any]
    mappings: list[MappingResult]
    risk_score: int
    highest_severity: str
