# Agent cost audit

`agent-cost-audit` validates a frozen project-usage snapshot and turns it into a concise, self-contained cost and efficiency audit. The implementation uses only the Python standard library and does not query live billing systems.

> Cost figures are API-equivalent estimates, not provider invoices. Activity attribution, Agent-hours, and proxy ceilings are derived metrics and must be read separately from observed usage facts.

## Install the skill

Clone the repository into the Codex skills directory, then restart Codex so it can discover `SKILL.md`:

```bash
git clone https://github.com/cabinw/agent-cost-audit-skill.git "$HOME/.codex/skills/agent-cost-audit"
```

No package installation is required. Python 3.11 or newer is recommended.

## Audit a project

From the project you want to review, invoke the skill with:

```text
使用 $agent-cost-audit 审计当前项目
```

The skill discovers eligible local evidence, freezes a sanitized snapshot, validates reconciliation rules, and builds the report. To exercise the validator and renderer with the committed synthetic fixture:

```bash
python3 scripts/audit_report.py validate \
  --input tests/fixtures/minimal-audit-snapshot.json

python3 scripts/audit_report.py build \
  --input tests/fixtures/minimal-audit-snapshot.json \
  --output-dir /tmp/agent-cost-audit
```

Pass `--project-name <name>` to `build` when the snapshot does not contain the desired display name.

For a real audit, pass the exact frozen source evidence (or canonical multi-source manifest) to both commands:

```bash
python3 scripts/audit_report.py validate --input audit-input.json --source-file frozen-evidence.json
python3 scripts/audit_report.py build --input audit-input.json --source-file frozen-evidence.json --output-dir /tmp/agent-cost-audit
```

The CLI computes the source file's SHA-256 and requires it to match `source_snapshot_sha256`; a 64-hex self-declaration alone is insufficient.

## Read the outputs

Each successful build writes four files to the output directory:

| File | Purpose |
| --- | --- |
| `audit-snapshot.json` | Frozen, sanitized audit input used for the build. |
| `artifact.json` | Canonical report data and presentation contract. |
| `report.html` | Self-contained HTML report with summary metrics, simple charts, and detailed analysis. |
| `qa.json` | Machine-readable validation and reconciliation results. |

Use a dedicated output directory. A rebuild atomically replaces an existing directory only when it contains this exact output set; unrelated files or symlinks cause the build to stop without changes. `qa.json` records SHA-256 hashes for the snapshot, Artifact, and HTML.

Observed totals, requests, model usage, and supplied engineering evidence remain facts from the snapshot. Prices are frozen estimates; unknown prices stay explicit. Category attribution and active-time calculations are rule-based estimates. The public outputs must not contain raw prompts, account identifiers, API keys, private paths, or the underlying per-event ledger.

A real audit snapshot uses `status: frozen_real_aggregate` and includes the SHA-256 of its authentic source ledger. The committed fixture uses `status: fixture` plus explicit synthetic provenance and is never evidence for a real audit.

## Develop and verify

Run the same checks used by CI:

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -v
python3 scripts/audit_report.py validate --input tests/fixtures/minimal-audit-snapshot.json
python3 scripts/audit_report.py build --input tests/fixtures/minimal-audit-snapshot.json --output-dir /tmp/agent-cost-audit
```

See [`SKILL.md`](SKILL.md) for the agent workflow and safety requirements.
