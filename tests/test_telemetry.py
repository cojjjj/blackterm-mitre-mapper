import json
from pathlib import Path

import pytest

from blackterm_mitre_mapper.telemetry import parse_json_events


def test_parse_jsonl_events():
    events = parse_json_events('{"event":{"id":1}}\n{"event":{"id":2}}', 'events.jsonl')
    assert [item['event']['id'] for item in events] == [1, 2]


def test_json_array_requires_objects():
    with pytest.raises(ValueError):
        parse_json_events(json.dumps([1, 2]), 'events.json')
