# BLACKTERM // MITRE Mapper Roadmap

The roadmap prioritizes a reliable end-to-end defensive investigation workflow over placeholder modules or disconnected features.

## v1.0 — Functional foundation

- [x] CLI analysis
- [x] JSON and JSONL telemetry
- [x] EVTX ingestion
- [x] Sysmon and Windows field normalization
- [x] YAML detection engine
- [x] Focused Sigma import
- [x] ATT&CK mapping
- [x] IOC and entity extraction
- [x] Local dashboard
- [x] Saved investigations
- [x] HTML and JSON reports

## v1.1 — Reliability and coverage

- [ ] Expand parser and normalization tests
- [ ] Add real EVTX fixture validation
- [ ] Improve malformed-input error messages
- [ ] Add rule schema documentation
- [ ] Add report snapshot tests
- [ ] Add pagination and limits for large telemetry sets
- [ ] Add structured application logging

## v1.2 — Analyst workflow

- [ ] Case tags and status
- [ ] Investigation notes with timestamps
- [ ] Event filtering by tactic, technique, severity, user, and host
- [ ] IOC export
- [ ] Case archive and import
- [ ] Better graph navigation and entity details

## v1.3 — Detection engineering

- [ ] Broader Sigma condition support
- [ ] Sigma conversion diagnostics
- [ ] Rule test command
- [ ] Rule metadata linting
- [ ] Detection coverage summary
- [ ] Rule packs with version metadata

## Future BLACKTERM modules

These remain separate projects until each has a functioning engine:

- TRACEGRID — event correlation and attack-chain reconstruction
- SENTINEL — authorized network inventory and change detection
- IOCForge — local indicator management and enrichment
- RuleForge — detection-rule authoring and validation
- PHISHSCAN — phishing and URL investigation

Roadmap items may change based on testing, contributor feedback, and project stability.
