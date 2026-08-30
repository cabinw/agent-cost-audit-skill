# Source discovery

Read this file when locating evidence for a new audit or adding a source adapter.

## Resolve the project

Start from the current working directory and resolve the Git root when one exists. Use repository metadata and runtime project bindings to establish project identity; do not infer membership from a similar directory name alone. The default audit window is the full continuous span of eligible usage mapped to the project unless the user supplies a window. Record the exact start, end, timezone, and whether the last calendar day is partial.

## Discover evidence automatically

Look for locally available sources in this order:

1. A genuine normalized snapshot emitted by a supported collector for this project and window.
2. A canonical usage ledger containing timestamp, model, request or event identity, input, cached input, output, and project/thread association.
3. Runtime state or rollout metadata that provides root, parent, fork, subagent, and automated-review relationships.
4. Git history for commits, change counts, and commit-type evidence in the same window.
5. A dated model-price snapshot or cost records attached to the ledger.

Routine paths should be discovered without asking the user. Source adapters must accept configurable roots and must not encode one user's home directory, database path, account identifier, or collector brand into the public snapshot.

## Reject report-derived inputs

An input is not a real ledger merely because it contains plausible totals. Reject:

- files under `samples/`;
- files explicitly marked `design_only`, `fixture`, `template`, or synthetic;
- `handoff/artifact.json`, generated HTML, chart data copied from a report, or any report-derived JSON;
- the repository's frozen handoff snapshot when performing a new audit;
- snapshots without project/window provenance or with a source hash that cannot be tied to discovered evidence.

Prior sanitized snapshots may be used only for regression tests or an explicitly requested historical comparison. Never silently present them as a current audit.

## Minimum viable ledger

Usage cannot be reconstructed from Git history or prose. Stop the audit when no trustworthy source can provide, at minimum:

- event or request timestamps;
- model identity;
- input, cached-input, and output token counts;
- request counts or stable event identities;
- enough project/thread association to exclude unrelated usage.

Lineage, Git, test, and pricing evidence may be unavailable without invalidating usage totals. Represent each missing dimension explicitly, reduce the relevant coverage metric, and omit unsupported conclusions.

## Safe staging

Normalize raw evidence in a temporary or ignored location. Raw prompts and payloads are unnecessary for cost aggregation and should not be copied. Freeze the exact source file used for a single source; for multiple sources, create a deterministic manifest containing their safe identifiers and content hashes, then freeze that manifest. Put its SHA-256 in `source_snapshot_sha256` and pass the same frozen file or manifest with `--source-file`. Retain only safe provenance in public output, and run validation before writing the final output directory.
