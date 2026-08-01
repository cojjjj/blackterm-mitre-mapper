from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

ALIASES = {
    "image": "process.name",
    "imagename": "process.name",
    "process_name": "process.name",
    "processname": "process.name",
    "newprocessname": "process.name",
    "commandline": "process.command_line",
    "command_line": "process.command_line",
    "processcommandline": "process.command_line",
    "parentimage": "parent_process.name",
    "parentprocessname": "parent_process.name",
    "parentcommandline": "parent_process.command_line",
    "user": "user.name",
    "username": "user.name",
    "subjectusername": "user.name",
    "src_ip": "source.ip",
    "sourceip": "source.ip",
    "source_ip": "source.ip",
    "dst_ip": "destination.ip",
    "destinationip": "destination.ip",
    "destination_ip": "destination.ip",
    "dst_port": "destination.port",
    "destinationport": "destination.port",
    "eventid": "event.id",
    "event_id": "event.id",
    "targetfilename": "file.path",
    "queryname": "dns.question.name",
}


def flatten_event(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}

    for raw_key, value in data.items():
        key = str(raw_key).strip().lower().replace(" ", "_")
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, Mapping):
            flattened.update(flatten_event(value, full_key))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            flattened[full_key] = list(value)
        else:
            flattened[full_key] = value

    aliases_to_add: dict[str, Any] = {}
    for key, value in flattened.items():
        leaf = key.rsplit(".", 1)[-1]
        normalized_leaf = leaf.replace("-", "_")
        alias = ALIASES.get(key) or ALIASES.get(normalized_leaf)
        if alias and alias not in flattened:
            aliases_to_add[alias] = value

    flattened.update(aliases_to_add)

    searchable = []
    for key, value in flattened.items():
        if value is not None:
            searchable.append(f"{key}={_stringify(value)}")
    flattened["*"] = " ".join(searchable)

    return flattened


def normalize_command(command: str) -> dict[str, Any]:
    return flatten_event(
        {
            "process": {
                "command_line": command,
                "name": command.strip().split(maxsplit=1)[0] if command.strip() else "",
            },
            "raw": command,
        }
    )


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)
