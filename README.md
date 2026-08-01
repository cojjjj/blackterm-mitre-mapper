# BLACKTERM // MITRE Mapper

<p align="center">
  <strong>Offline-first defensive investigation workspace for telemetry, Sigma rules, and MITRE ATT&CK context.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-c66bff">
  <img alt="Status" src="https://img.shields.io/badge/Status-Active%20Development-44e5ff">
  <img alt="Processing" src="https://img.shields.io/badge/Processing-Local-55e6a5">
</p>

BLACKTERM // MITRE Mapper analyzes command lines and security telemetry, maps behavior to MITRE ATT&CK using transparent rules, extracts investigation context, and presents the result through a CLI, local dashboard, and standalone reports.

Telemetry remains on the analyst's machine.

## Capabilities

- Analyze command lines and structured security events
- Import JSON, JSONL, and Windows EVTX telemetry
- Normalize common Sysmon and Windows Event Log fields
- Map behavior to ATT&CK using reviewable YAML rules
- Import a practical subset of Sigma rules
- Extract entities and indicators from telemetry
- Generate risk, confidence, tactic, timeline, graph, and recommendation views
- Save investigations locally and reopen them later
- Export JSON and standalone HTML reports
- Run a local FastAPI dashboard without sending telemetry off the machine

## Quick start

```powershell
git clone https://github.com/cojjjj/blackterm-mitre-mapper.git
cd blackterm-mitre-mapper

python -m venv .venv
.venv\Scripts\activate
python -m pip install -e .
```

For EVTX support:

```powershell
python -m pip install -e ".[evtx]"
```

Launch the platform:

```powershell
mitre-mapper dashboard
```

The dashboard binds to:

```text
http://127.0.0.1:8080
```

## CLI examples

Analyze a command:

```powershell
mitre-mapper analyze "powershell.exe -NoProfile -enc SQBFAFgA"
```

Scan sample telemetry:

```powershell
mitre-mapper scan examples\events\sample_events.jsonl
```

Generate an HTML report:

```powershell
mitre-mapper scan examples\events\sample_events.jsonl --format html --output report.html
```

Inspect normalized EVTX telemetry:

```powershell
mitre-mapper inspect-telemetry Security.evtx --limit 3
```

Scan EVTX and export JSON:

```powershell
mitre-mapper scan Security.evtx --format json --output security-results.json
```

## Sigma import

BLACKTERM supports a focused Sigma subset designed for common process, network, registry, DNS, file, and Windows event fields.

```powershell
mitre-mapper import-sigma examples\custom_rules\sigma_encoded_powershell.yml --output rules\sigma.yml
mitre-mapper validate-rules rules\sigma.yml
mitre-mapper scan events.jsonl --rules rules\sigma.yml
```

Supported condition patterns include:

- A named selection
- `all of them`
- `1 of them` and `any of them`
- `all of selection_*`
- `1 of selection_*`
- Simple `selection_a and selection_b`
- Simple `selection_a or selection_b`

Supported field modifiers include `contains`, `startswith`, `endswith`, `re`, and wildcard string values.

## EVTX normalization

Common aliases include:

| Source field | Normalized field |
| --- | --- |
| `Image` | `process.name` |
| `CommandLine` | `process.command_line` |
| `ParentImage` | `parent_process.name` |
| `User` / `TargetUserName` | `user.name` |
| `SourceIp` / `IpAddress` | `source.ip` |
| `DestinationIp` | `destination.ip` |
| `DestinationPort` | `destination.port` |
| `TargetFilename` | `file.path` |
| `TargetObject` | `registry.path` |
| `QueryName` | `dns.question.name` |
| Sysmon hash strings | `file.hashes` |

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

## Development

```powershell
python -m pip install -e ".[dev,evtx]"
ruff check .
pytest -q
```

The GitHub Actions workflow runs quality checks across Python 3.10, 3.11, and 3.12.

## Repository structure

```text
blackterm-mitre-mapper/
├── .github/
├── data/
├── examples/
├── rules/
├── src/blackterm_mitre_mapper/
├── tests/
├── CHANGELOG.md
├── CONTRIBUTING.md
├── ROADMAP.md
├── SECURITY.md
├── LICENSE
├── README.md
└── pyproject.toml
```

## Local storage

Saved cases are stored under:

```text
%USERPROFILE%\.blackterm\mitre-mapper\cases
```

## Project documents

- [Roadmap](ROADMAP.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Safety and scope

BLACKTERM is intended for defensive analysis of telemetry you are authorized to inspect. ATT&CK mappings are investigative context, not proof of malicious activity. Review surrounding events, host context, user behavior, and supporting evidence before drawing conclusions.

This project is not affiliated with or endorsed by MITRE. MITRE ATT&CK is a registered trademark of The MITRE Corporation.
