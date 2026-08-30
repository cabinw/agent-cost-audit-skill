# Audit methodology

Read this file before changing ledger deduplication, attribution, elapsed-time, pricing, or reconciliation behavior.

## Evidence classes

Keep four classes visually and structurally distinct:

1. **Observed facts:** canonical usage events and Git counts.
2. **Deterministic derivations:** sums, ratios, coverage, and bucket assignments.
3. **Rule estimates:** activity attribution, inferred lineage, Agent-hours, and recommendations.
4. **Cost proxies:** API-equivalent estimates and optional budget ceilings, never invoices.

Do not turn a missing fact into an estimate without labeling it.

## Canonical usage ledger

Normalize all sources before aggregation. Prefer a stable provider event or request ID as the canonical key. When one is unavailable, use a documented composite key built from safe stable fields and report the collision risk. A fork may repeat inherited history; count a canonical usage event once even when it appears in a parent, child, worktree, or exported rollout. Preserve source-to-canonical mappings privately for QA, but do not expose direct IDs.

Aggregate input, cached input, output, requests, model, and timestamps from the deduplicated ledger. Never derive token usage from transcript text, HTML, Git activity, or a previous aggregate report.

## Lineage and activity attribution

Use explicit root and parent relationships first. Apply deterministic fallback rules only when documented. Missing or conflicting parents remain `unattributed`; do not force them into the largest session.

Use mutually exclusive activities that cover 100% of the canonical ledger. A recommended baseline taxonomy is:

- development and implementation;
- testing and validation;
- deployment and operations;
- agent orchestration;
- documentation and research.

Adapters may merge, split, or rename this baseline when project evidence requires it, but must document the taxonomy and preserve mutual exclusivity. Automated review and the audit's own consumption are separate overhead layers when present. Record rule version, confidence, and residuals. Token and request partitions must reconcile to the canonical totals.

## Time

Wall-clock time is the difference between the frozen window boundaries. Agent-hours are an estimate: within each canonical agent stream, sort events by timestamp and sum non-negative gaps capped at five minutes. The first event contributes no invented duration. Parallel streams are additive, so Agent-hours may exceed wall-clock time. Average concurrency is `Agent-hours / wall-clock hours` when wall-clock time is positive.

## Pricing

Freeze the price table used by each run with its effective date and source. When input includes cached tokens, calculate non-cached input as `input_tokens - cached_tokens`; apply the model's non-cached input, cached-input, and output rates to their respective components. Do not substitute a related model's rate.

If any required rate is unknown, keep that model's cost `null` unless the source provides a trustworthy already-frozen total. Identifiable cost is the sum of known model costs; always report its token/request coverage. Keep currency conversion, API-equivalent cost, vendor invoice values, and proxy ceilings as separate fields and labels.

## Engineering evidence

Restrict Git counts to the audit window and resolved project. Commits, insertions, deletions, test records, and accepted-task records are activity evidence, not direct measures of quality, productivity, or ROI. When standardized test or acceptance evidence is missing, say so and avoid pass-rate claims.

## Reconciliation and privacy

Reconcile headline totals independently against model, day, activity, and lineage partitions. Explain tolerated presentation rounding; never tolerate unexplained canonical differences. Scan every public file for secrets, raw prompts, direct identifiers, absolute paths, and report-derived provenance. A failed arithmetic, provenance, or privacy check blocks delivery.
