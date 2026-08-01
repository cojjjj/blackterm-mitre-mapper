# BLACKTERM // Investigation Platform

An offline-first defensive investigation workspace for mapping security telemetry to MITRE ATT&CK, reviewing evidence, visualizing entities, and preserving analyst cases.

## v1.0 capabilities

- Analyze command lines and structured security events
- Import JSON, JSONL, and Windows EVTX telemetry
- Normalize common Sysmon and Windows Event Log fields
- Map behavior to ATT&CK using transparent YAML rules
- Import a practical subset of Sigma rules
- Extract entities and indicators from telemetry
- Generate risk, confidence, tactic, timeline, graph, and recommendation views
- Save investigations locally and reopen them later
- Export JSON and standalone HTML reports
- Run a local FastAPI dashboard without sending telemetry off the machine

## Install

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

For EVTX support:

```powershell
pip install -e ".[evtx]"
```

For development:

```powershell
pip install -e ".[dev,evtx]"
pytest -q
```

## Launch the platform

```powershell
mitre-mapper dashboard
```

Open `http://127.0.0.1:8080` if the browser does not open automatically.

## CLI examples

```powershell
mitre-mapper analyze "powershell.exe -NoProfile -enc SQBFAFgA"
mitre-mapper scan examples\events\sample_events.jsonl --format html --output report.html
mitre-mapper inspect-telemetry Security.evtx --limit 3
mitre-mapper scan Security.evtx --format json --output security-results.json
```

## Sigma import

BLACKTERM supports a focused Sigma subset designed for common process, network, registry, DNS, file, and Windows event fields.

```powershell
mitre-mapper import-sigma examples\custom_rules\sigma_encoded_powershell.yml --output rules\sigma.yml
mitre-mapper validate-rules rules\sigma.yml
mitre-mapper scan events.jsonl --rules rules\sigma.yml
```

Supported Sigma condition patterns include:

- A named selection
- `all of them`
- `1 of them` / `any of them`
- `all of selection_*`
- `1 of selection_*`
- Simple `selection_a and selection_b`
- Simple `selection_a or selection_b`

Supported field modifiers include `contains`, `startswith`, `endswith`, `re`, and wildcard string values.

## EVTX normalization

EVTX records are converted into a consistent JSON event model. Common aliases include:

- `Image` → `process.name`
- `CommandLine` → `process.command_line`
- `ParentImage` → `parent_process.name`
- `User` / `TargetUserName` → `user.name`
- `SourceIp` / `IpAddress` → `source.ip`
- `DestinationIp` / `DestinationPort` → destination fields
- `TargetFilename` → `file.path`
- `TargetObject` → `registry.path`
- `QueryName` → `dns.question.name`
- Sysmon hash strings → `file.hashes`

## Custom BLACKTERM rule

```yaml
id: BT-T1059-001
name: Encoded PowerShell
technique_id: T1059.001
technique_name: PowerShell
tactics: [execution]
severity: high
confidence: 0.90
description: Detects PowerShell using encoded command arguments.
platforms: [Windows]
match:
  all:
    - field: process.command_line
      operator: contains
      value: powershell
    - field: process.command_line
      operator: regex
      value: '(?i)(?:^|\s)(?:-|/)(?:enc|encodedcommand)\b'
```

## Local storage

Saved cases are stored under:

```text
%USERPROFILE%\.blackterm\mitre-mapper\cases
```

## Safety and scope

BLACKTERM is intended for defensive analysis of telemetry you are authorized to inspect. ATT&CK mappings are investigative context, not proof of malicious activity. Review surrounding events, host context, user behavior, and supporting evidence before drawing conclusions.

This project is not affiliated with or endorsed by MITRE. MITRE ATT&CK is a registered trademark of The MITRE Corporation.
