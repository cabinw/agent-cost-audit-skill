# Report contract

Read this file when implementing or changing `artifact.json` or `report.html`.

## Data-first reading order

The report must answer “how large, how costly, and where concentrated?” before presenting narrative:

1. Title, project, exact audit window, timezone, partial-day state, and evidence status.
2. Overall metrics: total tokens, requests, identifiable cost and coverage, unpriced/proxy amount, cache share, Agent-hours, wall-clock time, and attribution gap when available.
3. Three initial charts, in this order: activity/overhead distribution, context distribution, and daily usage.
4. `Executive Summary` with the few findings that materially affect a decision.
5. Detailed analysis of activity, models and pricing, lineage, context/tools, time/concurrency, Git and quality evidence, and prioritized recommendations.
6. Methodology, reconciliation, limitations, audit self-cost, and sources.

Do not put a long methodology preamble, schema explorer, template explanation, or design commentary before the overall data.

## Minimal visual language

Render a plain single-column document with system fonts, high-contrast text, simple borders, compact metric rows, native tables, and restrained inline SVG or CSS charts. Use one accent color plus neutral grays. Avoid hero treatments, gradients, decorative grids, glass effects, oversized cards, animation, and dashboard chrome.

The HTML must be self-contained and work from `file://`: no CDN, remote font, external script, analytics, server, or sidecar data request. Keep CSS and JavaScript small; prefer static markup. The document body must not overflow at 390px. Tables may scroll locally. Support keyboard navigation, print, reduced motion, and readable chart-data fallbacks.

## Chart rules

- Activity and overhead: descending horizontal bars; the adapter's documented categories, including explicit overhead layers when present, form a mutually exclusive 100% partition.
- Context: the four ordered, mutually exclusive buckets `≤32K`, `32K–128K`, `128K–272K`, and `>272K`; denominator is all requests and zero rows remain explicit in v1.
- Daily usage: discrete bars; never imply a trend from a few days, and mark the partial day in the label.
- Lineage: descending bars with explicit attributed, unattributed, and audit-self status.
- Git evidence: simple bars or table; do not label commit volume as quality or productivity.

Each chart needs a direct question/title, unit, denominator, adjacent interpretation, source reference, and accessible data table or textual fallback. Use compact values for scanning and retain exact values in tables or tooltips.

## Narrative and trust labels

Keep prose short and specific to observed data. Clearly label facts, deterministic derivations, rule estimates, and cost proxies. Use neutral language: state what the evidence supports, what it does not support, and which missing data would change the conclusion. Do not present an API-equivalent estimate as a bill, a proxy ceiling as spend, an attribution rule as fact, or Git activity as outcome quality.

Recommendations should cite the metric that motivates them and be ordered by expected impact and implementation difficulty. Missing prices, unmatched lineage, unavailable tests, and partial windows remain visible near affected conclusions and in the limitations section.

## Determinism

Generate `artifact.json` and the HTML together from the validated frozen snapshot. Stable input, project name, and renderer version must produce byte-identical outputs. Record the renderer version and output hashes in QA. Never patch values directly into either generated file after the build.

The build must also verify that every Artifact block and dataset reference has a matching HTML section in the same order. A mismatch blocks publication.
