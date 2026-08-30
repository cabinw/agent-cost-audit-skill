---
name: agent-cost-audit
description: Audit a local AI-agent project's token usage, API-equivalent cost, execution efficiency, lineage, and Git evidence, then generate reconciled JSON and a concise self-contained HTML report. Use for project-level agent cost or efficiency audits; do not use it as a substitute for a provider invoice.
metadata:
  short-description: Audit agent runtime cost and efficiency
---

# Agent Cost Audit

Produce an evidence-backed audit for the current project. Discover the project, usage ledger, lineage metadata, pricing evidence, and Git history automatically when they are locally available. Ask for a path only when discovery is genuinely ambiguous.

## Default workflow

1. Resolve the current Git root and project identity.
2. Discover authentic usage, lineage, model, pricing, and Git sources as described in [source discovery](references/source-discovery.md).
3. Freeze the authentic source evidence (or a canonical manifest for multiple sources), compute its SHA-256, and normalize it into a snapshot that follows [the snapshot contract](references/snapshot-schema.md). Use temporary working paths until validation succeeds.
4. Validate the snapshot:

   ```bash
   python3 scripts/audit_report.py validate --input <snapshot.json> --source-file <frozen-evidence>
   ```

5. Build the deliverables:

   ```bash
   python3 scripts/audit_report.py build --input <snapshot.json> --source-file <frozen-evidence> --output-dir <dir> [--project-name <name>]
   ```

6. Deliver only after `qa.json` reports success. Do not manually edit generated files to bypass a failed check.

Omit `--source-file` only when deliberately validating the committed synthetic test fixture. A real aggregate fails closed unless the supplied file's SHA-256 matches `source_snapshot_sha256`.

The build command creates exactly:

- `audit-snapshot.json`: sanitized frozen audit input;
- `artifact.json`: canonical derived report data and provenance;
- `report.html`: self-contained data-first report;
- `qa.json`: reconciliation, privacy, and rendering checks.

## Hard evidence boundaries

- A real usage ledger is required. If none is discoverable, stop and report what was searched and what evidence is missing.
- Never use `samples/`, an existing `handoff/` report, generated HTML, or a prior Artifact as the input for a new audit. They may be used only for tests or historical comparison.
- Treat ledger and Git counts as facts; label activity attribution, lineage inference, Agent-hours, recommendations, and other rule-derived values as estimates.
- Keep API-equivalent cost separate from invoices and proxy ceilings. Unknown model prices remain `null`, not zero and not a substituted price from another model.
- Preserve partial-day and incomplete-evidence states. Put unresolved usage into explicit `unknown` or `unattributed` buckets.
- Remove raw prompts, event payloads, direct session/account identifiers, secrets, and absolute filesystem paths from every deliverable.

Read [methodology](references/methodology.md) before changing deduplication, attribution, time, pricing, or reconciliation rules. Read [the report contract](references/report-contract.md) before changing report structure or visual output.

## Delivery

Summarize the audit window, headline usage and cost, unpriced coverage, attribution gap, and QA result. Link all four generated files. State important limitations without claiming that API-equivalent cost is a billed amount.
