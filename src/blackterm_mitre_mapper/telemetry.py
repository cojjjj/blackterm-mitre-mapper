from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any


def load_telemetry(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {'.json', '.jsonl'}:
        return _load_json(path)
    if suffix == '.evtx':
        return load_evtx(path)
    raise ValueError(f'Unsupported telemetry format: {suffix or "unknown"}')


def load_telemetry_bytes(raw: bytes, filename: str) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    if suffix in {'.json', '.jsonl'}:
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError as exc:
            raise ValueError('JSON telemetry must be UTF-8 encoded') from exc
        return parse_json_events(text, filename)
    if suffix == '.evtx':
        with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as handle:
            handle.write(raw)
            temp_path = Path(handle.name)
        try:
            return load_evtx(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)
    raise ValueError('Upload a .json, .jsonl, or .evtx file')


def _load_json(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON telemetry must be UTF-8 encoded") from exc
    return parse_json_events(text, path.name)


def parse_json_events(text: str, filename: str = 'events.json') -> list[dict[str, Any]]:
    if filename.lower().endswith('.jsonl'):
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'Invalid JSONL on line {line_number}: {exc}') from exc
            if not isinstance(item, dict):
                raise ValueError(f'JSONL line {line_number} must contain an object')
            events.append(item)
        return events

    parsed = json.loads(text)
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    raise ValueError('JSON input must be an object or an array of objects')


def load_evtx(path: Path) -> list[dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise RuntimeError(
            'EVTX support requires python-evtx. Install with: pip install -e ".[evtx]"'
        ) from exc

    try:
        import xml.etree.ElementTree as ET

        events: list[dict[str, Any]] = []
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    events.append(_normalize_evtx_xml(root, record.record_num()))
                except (ET.ParseError, ValueError):
                    continue
        return events
    except OSError as exc:
        raise ValueError(f'Unable to read EVTX file: {exc}') from exc


def _normalize_evtx_xml(root: Any, record_number: int) -> dict[str, Any]:
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    system = root.find('e:System', ns)
    event_data = root.find('e:EventData', ns)
    user_data = root.find('e:UserData', ns)

    def text(path: str) -> str | None:
        node = system.find(path, ns) if system is not None else None
        return node.text if node is not None else None

    provider_node = system.find('e:Provider', ns) if system is not None else None
    time_node = system.find('e:TimeCreated', ns) if system is not None else None
    execution_node = system.find('e:Execution', ns) if system is not None else None

    event: dict[str, Any] = {
        '@timestamp': time_node.attrib.get('SystemTime') if time_node is not None else None,
        'event': {
            'id': _safe_int(text('e:EventID')),
            'record_id': _safe_int(text('e:EventRecordID')) or record_number,
            'provider': provider_node.attrib.get('Name') if provider_node is not None else None,
            'channel': text('e:Channel'),
            'computer': text('e:Computer'),
            'level': _safe_int(text('e:Level')),
            'task': _safe_int(text('e:Task')),
            'opcode': _safe_int(text('e:Opcode')),
        },
        'host': {'name': text('e:Computer')},
        'process': {},
        'user': {},
        'source': {},
        'destination': {},
        'file': {},
        'registry': {},
        'dns': {'question': {}},
        'winlog': {'record_id': record_number},
    }

    if execution_node is not None:
        event['process']['pid'] = _safe_int(execution_node.attrib.get('ProcessID'))
        event['thread'] = {'id': _safe_int(execution_node.attrib.get('ThreadID'))}

    data: dict[str, Any] = {}
    if event_data is not None:
        unnamed = 0
        for node in event_data:
            name = node.attrib.get('Name') or f'field_{unnamed}'
            unnamed += 1
            data[name] = node.text or ''
    elif user_data is not None:
        for child in user_data.iter():
            if child is user_data:
                continue
            data[_local_name(child.tag)] = child.text or ''

    event['winlog']['event_data'] = data
    _apply_windows_aliases(event, data)
    return _remove_empty(event)


def _apply_windows_aliases(event: dict[str, Any], data: dict[str, Any]) -> None:
    aliases = {key.casefold(): value for key, value in data.items()}

    def first(*names: str) -> Any:
        for name in names:
            value = aliases.get(name.casefold())
            if value not in (None, ''):
                return value
        return None

    process_name = first('Image', 'NewProcessName', 'ProcessName', 'Application')
    command_line = first('CommandLine', 'ProcessCommandLine')
    parent_name = first('ParentImage', 'ParentProcessName')
    parent_command = first('ParentCommandLine')
    user_name = first('User', 'UserName', 'SubjectUserName', 'TargetUserName')
    source_ip = first('SourceIp', 'IpAddress', 'ClientAddress')
    destination_ip = first('DestinationIp', 'DestAddress')
    destination_port = first('DestinationPort', 'DestPort')
    target_file = first('TargetFilename', 'FileName')
    registry_path = first('TargetObject', 'ObjectName')
    query_name = first('QueryName')
    hashes = first('Hashes', 'Hash')

    if process_name:
        event['process']['name'] = process_name
    if command_line:
        event['process']['command_line'] = command_line
    if parent_name or parent_command:
        event['parent_process'] = {'name': parent_name, 'command_line': parent_command}
    if user_name:
        event['user']['name'] = user_name
    if source_ip and source_ip not in {'-', '::1', '127.0.0.1'}:
        event['source']['ip'] = source_ip
    if destination_ip:
        event['destination']['ip'] = destination_ip
    if destination_port:
        event['destination']['port'] = _safe_int(destination_port) or destination_port
    if target_file:
        event['file']['path'] = target_file
    if registry_path:
        event['registry']['path'] = registry_path
    if query_name:
        event['dns']['question']['name'] = query_name
    if hashes:
        event['file']['hashes'] = _parse_hashes(str(hashes))


def _parse_hashes(value: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for part in value.replace(';', ',').split(','):
        if '=' not in part:
            continue
        algorithm, digest = part.split('=', 1)
        algorithm = algorithm.strip().lower().replace('sha256', 'sha256').replace('sha1', 'sha1')
        digest = digest.strip()
        if digest:
            hashes[algorithm] = digest
    return hashes


def _remove_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {key: _remove_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, '', {}, [])}
    if isinstance(value, list):
        return [_remove_empty(item) for item in value if item not in (None, '')]
    return value


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, '') else None
    except (TypeError, ValueError):
        return None


def _local_name(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]
