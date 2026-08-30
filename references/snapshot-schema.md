# Snapshot and Artifact contract

Read this file when implementing an adapter, changing fields, or diagnosing reconciliation failures.

## Frozen snapshot

The normalized input represents one project and one immutable audit window. Its top-level data should include:

- status, generation timestamp, project identity, window, source provenance, and sanitization state;
- total input, cached-input, output and total tokens, requests, identifiable cost, and any proxy ceiling;
- breakdowns by model, day, activity, lineage/root, context bucket, and tool group when available;
- Git and quality evidence, efficiency signals, reconciliation results, methodology, and limitations.

Use `snake_case` JSON keys, ISO 8601 timestamps, an explicit IANA timezone, integer counts, USD decimal numbers, and ratios in the `0`–`1` range. Use `null` for unavailable values; absence must never be encoded as zero. Anonymous aliases must be stable only within the audit.

The public `audit-snapshot.json` is sanitized. Version 1 requires `agent-cost-audit/v1` (or integer `1`) and retains the source window, safe source hash, and evidence status needed to audit the derivation. A real aggregate uses `status: frozen_real_aggregate` with a 64-hex `source_snapshot_sha256`; the CLI recomputes that hash from `--source-file`. A test-only snapshot uses `status: fixture` with `provenance.kind: synthetic_test_fixture`; reports visibly identify it as synthetic.

## V1 required shape

For a new real audit, emit these fields before validation:

- root: `schema_version`, `status`, `source_snapshot_sha256`, `generated_at`, `window`, `sanitization`, `totals`, `models`, `daily`, `transaction_categories`, `ui_attribution`, `context_buckets`, and `quality_output`; `project`, `tool_calls`, `efficiency_signals`, `methodology`, and `reconciliation` are optional;
- `window`: `start`, `end`, IANA `timezone`, and `partial_end_day`; use a local-midnight start and a half-open midnight end for complete days;
- every token row: `input_tokens`, `cached_tokens`, `output_tokens`, `total_tokens`, and `requests`;
- model rows: token fields plus `model` and nullable `api_equivalent_base_usd`;
- daily rows: token fields plus `day` and `identifiable_cost_usd`;
- activity rows: token fields plus `category`, `active_hours`, and `sessions`;
- UI rows: token fields plus a schema-approved anonymous `id`, `active_hours`, and `sessions`; include explicit `unattributed` and `audit-self` rows even when zero, while the renderer derives generic labels and rejects user-supplied session names;
- context rows: all four standard buckets with `requests` and `raw_tokens`, including explicit zero rows;
- quality: `commits`, `insertions`, `deletions`, and `commit_types` rows containing `type` and `count`.

The CLI rejects unknown public fields. Update the schema, validator, fixture, and tests together when adding one.

## Required invariants

Validation must fail when any applicable invariant fails:

- `total_tokens = input_tokens + output_tokens`;
- `0 <= cached_tokens <= input_tokens`;
- non-negative token, request, time, and cost values;
- model totals and requests reconcile exactly to headline totals;
- daily totals and requests reconcile exactly to headline totals;
- identifiable cost equals the sum of non-null model costs within declared decimal tolerance;
- activity total tokens and requests reconcile to the ledger totals;
- lineage total tokens and requests reconcile, including explicit `unattributed` usage;
- context-bucket requests reconcile and bucket boundaries are mutually exclusive;
- commit-type counts equal the total commit count when both are available.

Component rows rounded for presentation may retain a small residual only when the precise total, residual, reason, and validation status are recorded. Request-grain context volume must not be asserted to add to a canonical, deduplicated token total.

## Cost fields

A priced model row records the price date/source or a cost already frozen by the genuine source. An unpriced model has a `null` cost and an explicit unknown-price status. Headline output must include both identifiable cost and pricing coverage. A proxy ceiling is optional and must include its versioned formula; a legacy frozen value whose formula is unavailable may be displayed only as such and must not be recomputed.

## Canonical Artifact

`artifact.json` is derived only from the validated snapshot. It contains:

- report metadata and audit window;
- named datasets used by metrics, charts, and tables;
- narrative findings with fact/estimate/proxy labels;
- source references and derivation metadata;
- report block order and display formats;
- snapshot and QA hashes when available.

Every displayed number must resolve to the same validated snapshot used for the Artifact. The CLI creates the Artifact and HTML in one deterministic build, records their hashes in `qa.json`, and never maintains a second manual dataset. Derived values must identify their numerator, denominator, unit, and rule.

## QA output

`qa.json` records overall status plus individual reconciliation, provenance, sanitization, and HTML checks. Include errors and warnings separately. An unknown price or missing optional evidence is a visible limitation, not a validation error; arithmetic conflicts, unsafe content, missing real-ledger provenance, or report-derived input are errors.
