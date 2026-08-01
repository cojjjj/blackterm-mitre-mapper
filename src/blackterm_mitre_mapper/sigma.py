from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import Condition, MappingRule, MatchExpression

FIELD_ALIASES = {
    'image': 'process.name',
    'commandline': 'process.command_line',
    'parentimage': 'parent_process.name',
    'parentcommandline': 'parent_process.command_line',
    'user': 'user.name',
    'sourceip': 'source.ip',
    'destinationip': 'destination.ip',
    'destinationport': 'destination.port',
    'targetfilename': 'file.path',
    'targetobject': 'registry.path',
    'queryname': 'dns.question.name',
    'eventid': 'event.id',
}


def convert_sigma_file(path: Path) -> list[MappingRule]:
    documents = list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
    rules: list[MappingRule] = []
    for index, document in enumerate(documents, start=1):
        if not document:
            continue
        rules.append(convert_sigma_rule(document, source=f'{path.name}:{index}'))
    return rules


def convert_sigma_rule(document: dict[str, Any], source: str = 'sigma') -> MappingRule:
    detection = document.get('detection')
    if not isinstance(detection, dict):
        raise ValueError(f'{source}: missing detection section')

    selections = {key: value for key, value in detection.items() if key != 'condition'}
    condition_text = str(detection.get('condition', '')).strip()
    if not selections:
        raise ValueError(f'{source}: no selections found')

    selected_names, mode = _parse_condition(condition_text, list(selections))
    conditions_by_selection = {
        name: _selection_to_conditions(selections[name], source, name)
        for name in selected_names
    }

    all_conditions: list[Condition] = []
    any_conditions: list[Condition] = []
    if mode == 'all':
        for conditions in conditions_by_selection.values():
            all_conditions.extend(conditions)
    else:
        for conditions in conditions_by_selection.values():
            if len(conditions) == 1:
                any_conditions.extend(conditions)
            else:
                # A multi-field Sigma selection means AND. Preserve it by creating
                # one searchable regex across the flattened event only when needed.
                combined = '.*'.join(re.escape(str(item.value)) for item in conditions)
                any_conditions.append(Condition(field='*', operator='regex', value=combined))

    tags = [str(tag) for tag in document.get('tags', [])]
    technique_id = next((tag.split('.', 1)[1].upper() for tag in tags if tag.lower().startswith('attack.t')), 'T0000')
    tactics = [tag.split('.', 1)[1].replace('_', '-') for tag in tags if tag.lower().startswith('attack.') and not tag.lower().startswith('attack.t')]
    level = str(document.get('level', 'medium')).lower()
    severity = level if level in {'informational', 'low', 'medium', 'high', 'critical'} else 'medium'
    status = str(document.get('status', 'experimental')).lower()
    confidence = {'stable': 0.86, 'test': 0.78, 'experimental': 0.68}.get(status, 0.72)

    return MappingRule(
        id=f"SIGMA-{document.get('id') or _slug(document.get('title', source))}",
        name=str(document.get('title', 'Imported Sigma rule')),
        technique_id=technique_id,
        technique_name=str(document.get('title', 'Sigma detection')),
        tactics=tactics or ['unknown'],
        severity=severity,
        confidence=confidence,
        description=str(document.get('description', 'Imported from Sigma.')),
        platforms=_platforms(document),
        match=MatchExpression(all=all_conditions, any=any_conditions),
        references=[str(item) for item in document.get('references', [])],
        tags=['sigma', *tags],
    )


def write_blackterm_rules(rules: list[MappingRule], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = [rule.model_dump(mode='json', exclude_none=True) for rule in rules]
    destination.write_text(yaml.safe_dump(payload, sort_keys=False), encoding='utf-8')
    return destination


def _parse_condition(condition: str, available: list[str]) -> tuple[list[str], str]:
    lowered = condition.casefold()
    if not condition or condition == 'selection':
        return [available[0]], 'all'
    if lowered.startswith('all of '):
        target = condition[7:].strip()
        return _expand_names(target, available), 'all'
    if lowered.startswith('1 of ') or lowered.startswith('any of '):
        target = condition.split('of', 1)[1].strip()
        return _expand_names(target, available), 'any'
    if ' or ' in lowered:
        return [name.strip() for name in re.split(r'\s+or\s+', condition, flags=re.I) if name.strip() in available], 'any'
    if ' and ' in lowered:
        return [name.strip() for name in re.split(r'\s+and\s+', condition, flags=re.I) if name.strip() in available], 'all'
    if condition in available:
        return [condition], 'all'
    raise ValueError(f'Unsupported Sigma condition: {condition}')


def _expand_names(target: str, available: list[str]) -> list[str]:
    if target == 'them':
        return available
    if target.endswith('*'):
        prefix = target[:-1]
        return [name for name in available if name.startswith(prefix)]
    return [target] if target in available else []


def _selection_to_conditions(selection: Any, source: str, name: str) -> list[Condition]:
    if not isinstance(selection, dict):
        raise ValueError(f'{source}: selection {name} must be a mapping')
    conditions: list[Condition] = []
    for raw_field, expected in selection.items():
        field, modifiers = _parse_field(str(raw_field))
        values = expected if isinstance(expected, list) else [expected]
        converted = [_modifier_operator(modifiers, value) for value in values]
        if len(converted) == 1:
            operator, normalized = converted[0]
            conditions.append(Condition(field=field, operator=operator, value=normalized))
            continue
        # Sigma lists are OR values for one field. Collapse them into one regex so
        # BLACKTERM's all-of selection semantics remain correct.
        alternatives = []
        for operator, normalized in converted:
            escaped = re.escape(str(normalized))
            if operator == 'contains':
                alternatives.append(escaped)
            elif operator == 'startswith':
                alternatives.append(f'^{escaped}')
            elif operator == 'endswith':
                alternatives.append(f'{escaped}$')
            elif operator == 'regex':
                alternatives.append(f'(?:{normalized})')
            else:
                alternatives.append(f'^{escaped}$')
        conditions.append(Condition(field=field, operator='regex', value='(?:' + '|'.join(alternatives) + ')'))
    return conditions


def _parse_field(raw_field: str) -> tuple[str, list[str]]:
    parts = raw_field.split('|')
    field = FIELD_ALIASES.get(parts[0].casefold(), parts[0].strip().lower())
    return field, [part.casefold() for part in parts[1:]]


def _modifier_operator(modifiers: list[str], value: Any) -> tuple[str, Any]:
    if 're' in modifiers:
        return 'regex', value
    if 'startswith' in modifiers:
        return 'startswith', value
    if 'endswith' in modifiers:
        return 'endswith', value
    if 'contains' in modifiers or 'containsall' in modifiers:
        return 'contains', value
    if isinstance(value, str) and ('*' in value or '?' in value):
        pattern = re.escape(value).replace(r'\*', '.*').replace(r'\?', '.')
        return 'regex', f'^{pattern}$'
    return 'equals', value


def _platforms(document: dict[str, Any]) -> list[str]:
    product = str((document.get('logsource') or {}).get('product', '')).lower()
    return {'windows': ['Windows'], 'linux': ['Linux'], 'macos': ['macOS']}.get(product, [])


def _slug(value: Any) -> str:
    return re.sub(r'[^A-Za-z0-9]+', '-', str(value)).strip('-').upper() or 'IMPORTED'
