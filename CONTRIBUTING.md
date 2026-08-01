# Contributing to BLACKTERM // MITRE Mapper

Thank you for helping improve the project. Contributions should remain focused on authorized defensive analysis, transparent detections, reliable telemetry handling, and analyst-friendly investigation workflows.

## Development setup

```powershell
git clone https://github.com/cojjjj/blackterm-mitre-mapper.git
cd blackterm-mitre-mapper

python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev,evtx]"
```

Linux and macOS:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,evtx]"
```

## Before opening a pull request

Run:

```bash
ruff check .
pytest -q
```

Also verify any interface affected by the change:

```bash
mitre-mapper --help
mitre-mapper dashboard --no-open
```

## Branch naming

Use a clear prefix:

```text
feat/short-description
fix/short-description
docs/short-description
chore/short-description
test/short-description
```

## Commit style

Prefer conventional, focused commit messages:

```text
feat: add registry event normalization
fix: handle empty Sigma selections
docs: document EVTX import workflow
test: cover nested event aliases
chore: add CI quality checks
```

## Pull requests

A pull request should:

- Solve one focused problem
- Explain the behavior before and after the change
- Include tests for new or corrected logic
- Update documentation when commands or behavior change
- Avoid unrelated formatting or refactoring
- Never include real credentials or sensitive telemetry

## Detection rules

Detection contributions should include:

- A stable rule ID
- ATT&CK technique and tactic context
- A clear description
- Appropriate severity and confidence
- Evidence conditions that can be reviewed
- Positive and negative test cases when practical

Mappings provide investigative context. They should not claim that one matching condition proves malicious activity.

## Security scope

Do not submit features designed for unauthorized access, persistence, credential theft, evasion, destructive activity, or exploitation. Defensive parsing, detection, investigation, reporting, and authorized validation are welcome.

By contributing, you agree that your contribution may be distributed under the repository license.
