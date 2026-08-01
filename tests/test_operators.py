from blackterm_mitre_mapper.models import Condition
from blackterm_mitre_mapper.operators import evaluate_condition


def test_contains_is_case_insensitive():
    event = {"process.command_line": "PowerShell.EXE -ENC ABC"}
    condition = Condition(
        field="process.command_line",
        operator="contains",
        value="powershell",
    )
    assert evaluate_condition(event, condition).matched


def test_cidr_operator():
    event = {"source.ip": "10.10.5.22"}
    condition = Condition(field="source.ip", operator="cidr", value="10.10.0.0/16")
    assert evaluate_condition(event, condition).matched
