from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from datetime import datetime
from typing import Any

from .models import AnalysisResult
from .normalize import flatten_event

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

IOC_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "emails": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domains": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "registry_keys": re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+", re.IGNORECASE),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\(?:[^\s\"'<>|]+\\)*[^\s\"'<>|]*"),
    "unix_paths": re.compile(r"(?<![\w.])/(?:[\w.@+-]+/)*[\w.@+-]+"),
}


def build_report_context(results: list[AnalysisResult]) -> dict[str, Any]:
    enriched = [enrich_result(result, index + 1) for index, result in enumerate(results)]
    all_mappings = [mapping for result in results for mapping in result.mappings]
    tactic_counts = Counter(tactic for mapping in all_mappings for tactic in mapping.tactics)
    technique_counts = Counter(mapping.technique_id for mapping in all_mappings)
    all_iocs = merge_iocs(item["iocs"] for item in enriched)
    platforms = sorted({platform for mapping in all_mappings for platform in mapping.platforms})
    max_risk = max((result.risk_score for result in results), default=0)

    return {
        "results_view": enriched,
        "tactics": [
            {
                "id": tactic,
                "label": tactic.replace("-", " ").title(),
                "count": tactic_counts.get(tactic, 0),
                "active": tactic_counts.get(tactic, 0) > 0,
            }
            for tactic in TACTIC_ORDER
        ],
        "technique_counts": technique_counts.most_common(),
        "all_iocs": all_iocs,
        "platforms": platforms,
        "summary": investigation_summary(results),
        "relationship_graph": build_relationship_graph(results, all_iocs),
        "max_risk": max_risk,
        "overall_severity": severity_for_score(max_risk),
        "mapping_count": len(all_mappings),
        "event_count": len(results),
        "ioc_count": sum(len(values) for values in all_iocs.values()),
    }


def enrich_result(result: AnalysisResult, sequence: int) -> dict[str, Any]:
    flat = flatten_event(result.event)
    timestamp = event_timestamp(flat, result.timestamp)
    iocs = extract_iocs(result.event)
    evidence_quality = round(
        max((mapping.confidence for mapping in result.mappings), default=0.0) * 100
    )
    matched_evidence = sum(
        1 for mapping in result.mappings for evidence in mapping.evidence if evidence.matched
    )
    entities = extract_entities(flat)

    return {
        "result": result,
        "sequence": sequence,
        "timestamp": timestamp,
        "timestamp_label": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if timestamp else "Unknown time",
        "time_short": timestamp.strftime("%H:%M:%S") if timestamp else f"Event {sequence}",
        "iocs": iocs,
        "evidence_quality": evidence_quality,
        "matched_evidence": matched_evidence,
        "entities": entities,
        "primary_action": primary_action(result, flat),
        "score_rotation": min(360, round(result.risk_score * 3.6)),
    }


def event_timestamp(flat: dict[str, Any], fallback: datetime) -> datetime | None:
    candidates = [
        flat.get("@timestamp"), flat.get("timestamp"), flat.get("event.created"),
        flat.get("event.ingested"), flat.get("timecreated"), flat.get("datetime"),
    ]
    for value in candidates:
        if not value:
            continue
        text = str(value).strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            continue
    return fallback


def extract_iocs(event: dict[str, Any]) -> dict[str, list[str]]:
    flat = flatten_event(event)
    text = " ".join(str(value) for key, value in flat.items() if key != "*" and value is not None)
    found: dict[str, set[str]] = {key: set() for key in IOC_PATTERNS}
    found.update({"ipv4": set(), "ipv6": set(), "processes": set(), "users": set(), "ports": set()})

    for key, pattern in IOC_PATTERNS.items():
        found[key].update(match.rstrip(".,);]") for match in pattern.findall(text))

    for token in re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", text):
        try:
            found["ipv4"].add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass

    for key, value in flat.items():
        if value is None:
            continue
        lower = key.lower()
        values = value if isinstance(value, list) else [value]
        for item in values:
            item_text = str(item)
            if lower.endswith(("process.name", "image", "process_name")):
                found["processes"].add(item_text)
            elif lower.endswith(("user.name", "username", "subjectusername")):
                found["users"].add(item_text)
            elif lower.endswith("port") and item_text.isdigit():
                found["ports"].add(item_text)

    # Domains inside URLs are redundant in the domain card.
    url_domains = set()
    for url in found["urls"]:
        match = re.match(r"https?://([^/:]+)", url, re.IGNORECASE)
        if match:
            url_domains.add(match.group(1).lower())
    found["domains"] = {value for value in found["domains"] if value.lower() not in url_domains}

    return {key: sorted(values) for key, values in found.items() if values}


def merge_iocs(collection: Any) -> dict[str, list[str]]:
    merged: dict[str, set[str]] = {}
    for item in collection:
        for key, values in item.items():
            merged.setdefault(key, set()).update(values)
    return {key: sorted(values) for key, values in sorted(merged.items()) if values}


def extract_entities(flat: dict[str, Any]) -> list[dict[str, str]]:
    entity_fields = {
        "user.name": "user", "process.name": "process", "parent_process.name": "process",
        "source.ip": "ip", "destination.ip": "ip", "destination.port": "port",
        "dns.question.name": "domain", "file.path": "file", "registry.path": "registry",
        "host.name": "host",
    }
    entities = []
    seen = set()
    for field, kind in entity_fields.items():
        value = flat.get(field)
        if value is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            key = (kind, str(item))
            if key not in seen:
                entities.append({"type": kind, "value": str(item), "field": field})
                seen.add(key)
    return entities


def primary_action(result: AnalysisResult, flat: dict[str, Any]) -> str:
    if result.mappings:
        return result.mappings[0].technique_name
    process = flat.get("process.name")
    if process:
        return f"Process activity: {process}"
    return "Unmapped security event"


def investigation_summary(results: list[AnalysisResult]) -> str:
    mappings = [mapping for result in results for mapping in result.mappings]
    if not mappings:
        return "No ATT&CK-mapped behavior was identified in the supplied telemetry. Review the raw events and expand the rule set if the activity is expected to be covered."

    ordered = sorted(mappings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.confidence), reverse=True)
    unique = []
    seen = set()
    for mapping in ordered:
        if mapping.technique_id not in seen:
            unique.append(mapping)
            seen.add(mapping.technique_id)

    names = [f"{item.technique_name} ({item.technique_id})" for item in unique[:4]]
    tactics = sorted({tactic.replace("-", " ") for item in unique for tactic in item.tactics})
    max_risk = max(result.risk_score for result in results)
    severity = severity_for_score(max_risk)
    sentence = ", ".join(names[:-1]) + (" and " + names[-1] if len(names) > 1 else names[0])
    return (
        f"The telemetry contains {severity} activity mapped to {sentence}. "
        f"Observed behavior spans {', '.join(tactics)}. The highest event risk score is {max_risk}/100. "
        "Validate the affected user and host, preserve surrounding telemetry, and investigate the sequence as a connected incident rather than isolated alerts."
    )


def build_relationship_graph(results: list[AnalysisResult], iocs: dict[str, list[str]]) -> dict[str, Any]:
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    seen_nodes: set[str] = set()

    def add_node(node_id: str, label: str, kind: str) -> None:
        if node_id not in seen_nodes and len(nodes) < 28:
            nodes.append({"id": node_id, "label": label, "kind": kind})
            seen_nodes.add(node_id)

    add_node("incident", "Investigation", "incident")
    for index, result in enumerate(results, start=1):
        event_id = f"event-{index}"
        add_node(event_id, f"Event {index}", "event")
        edges.append({"source": "incident", "target": event_id, "label": "contains"})
        flat = flatten_event(result.event)
        for entity in extract_entities(flat)[:6]:
            digest = hashlib.sha1(f"{entity['type']}:{entity['value']}".encode()).hexdigest()[:10]
            node_id = f"entity-{digest}"
            add_node(node_id, entity["value"], entity["type"])
            edges.append({"source": event_id, "target": node_id, "label": entity["field"]})
        for mapping in result.mappings[:3]:
            node_id = f"tech-{mapping.technique_id.replace('.', '-')}"
            add_node(node_id, mapping.technique_id, "technique")
            edges.append({"source": event_id, "target": node_id, "label": mapping.technique_name})

    return {"nodes": nodes, "edges": edges}


def severity_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "informational"
