from pathlib import Path

from blackterm_mitre_mapper.engine import MitreMapper
from blackterm_mitre_mapper.loaders import load_rules

RULES = Path(__file__).parents[1] / "src" / "blackterm_mitre_mapper" / "rules"


def mapper() -> MitreMapper:
    return MitreMapper(load_rules([RULES]))


def test_encoded_powershell_maps_to_subtechnique():
    result = mapper().analyze_command("powershell.exe -NoProfile -enc SQBFAFgA")
    ids = {item.technique_id for item in result.mappings}
    assert "T1059.001" in ids
    assert result.risk_score >= 60


def test_clear_event_log_is_critical():
    result = mapper().analyze_command("wevtutil.exe cl Security")
    mapping = next(item for item in result.mappings if item.technique_id == "T1070.001")
    assert mapping.severity == "critical"
    assert mapping.confidence >= 0.94


def test_no_match_returns_zero_risk():
    result = mapper().analyze_event({"message": "normal application startup"})
    assert result.mappings == []
    assert result.risk_score == 0


def test_nested_fields_are_normalized():
    result = mapper().analyze_event(
        {
            "process": {
                "name": "schtasks.exe",
                "command_line": "schtasks /create /tn Update /tr calc.exe /sc onlogon",
            }
        }
    )
    assert any(item.technique_id == "T1053.005" for item in result.mappings)
