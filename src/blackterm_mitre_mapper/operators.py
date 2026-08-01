from __future__ import annotations

import ipaddress
import re
from typing import Any

from .models import Condition, Evidence


def evaluate_condition(event: dict[str, Any], condition: Condition) -> Evidence:
    exists = condition.field in event and event.get(condition.field) is not None
    observed = event.get(condition.field)

    if condition.operator == "exists":
        expected = True if condition.value is None else bool(condition.value)
        matched = exists is expected
        return Evidence(
            field=condition.field,
            operator=condition.operator,
            expected=expected,
            observed=observed,
            matched=matched,
            weight=condition.weight,
        )

    if not exists:
        return Evidence(
            field=condition.field,
            operator=condition.operator,
            expected=condition.value,
            observed=None,
            matched=False,
            weight=condition.weight,
        )

    matched = _evaluate_value(observed, condition)
    return Evidence(
        field=condition.field,
        operator=condition.operator,
        expected=condition.value,
        observed=observed,
        matched=matched,
        weight=condition.weight,
    )


def _evaluate_value(observed: Any, condition: Condition) -> bool:
    if isinstance(observed, list):
        if condition.operator == "in":
            expected_values = _to_list(condition.value)
            return any(_normalize(item, condition) in expected_values for item in observed)
        return any(_evaluate_scalar(item, condition) for item in observed)

    return _evaluate_scalar(observed, condition)


def _evaluate_scalar(observed: Any, condition: Condition) -> bool:
    operator = condition.operator
    expected = condition.value

    if operator in {"greater_than", "less_than"}:
        try:
            left = float(observed)
            right = float(expected)
        except (TypeError, ValueError):
            return False
        return left > right if operator == "greater_than" else left < right

    if operator == "cidr":
        try:
            return ipaddress.ip_address(str(observed)) in ipaddress.ip_network(
                str(expected), strict=False
            )
        except ValueError:
            return False

    left = str(observed)
    right = "" if expected is None else str(expected)

    if not condition.case_sensitive:
        left = left.casefold()
        right = right.casefold()

    if operator == "equals":
        return left == right
    if operator == "not_equals":
        return left != right
    if operator == "contains":
        return right in left
    if operator == "not_contains":
        return right not in left
    if operator == "startswith":
        return left.startswith(right)
    if operator == "endswith":
        return left.endswith(right)
    if operator == "regex":
        flags = 0 if condition.case_sensitive else re.IGNORECASE
        try:
            return re.search(str(expected), str(observed), flags=flags) is not None
        except re.error:
            return False
    if operator == "in":
        return left in _to_list(expected, condition.case_sensitive)

    return False


def _normalize(value: Any, condition: Condition) -> str:
    text = str(value)
    return text if condition.case_sensitive else text.casefold()


def _to_list(value: Any, case_sensitive: bool = False) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [str(item) if case_sensitive else str(item).casefold() for item in values]
