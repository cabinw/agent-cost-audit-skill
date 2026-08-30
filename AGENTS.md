# Repository Guidelines

## Project structure and module organization

Keep the installable entry point in `SKILL.md` and user instructions in `README.md`. The standard-library CLI lives at `scripts/audit_report.py`; reusable schema and methodology notes belong in `references/`. Put automated checks in `tests/` and sanitized inputs in `tests/fixtures/`. `handoff/`, `design/`, and `samples/` contain migration or report materials, not runtime dependencies unless explicitly referenced. Generated local reports belong outside the repository or in an ignored output directory.

## Build, test, and development commands

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -v
python3 scripts/audit_report.py validate --input tests/fixtures/minimal-audit-snapshot.json
python3 scripts/audit_report.py build --input tests/fixtures/minimal-audit-snapshot.json --output-dir /tmp/agent-cost-audit
```

Compilation catches syntax errors; unit tests cover behavior; `validate` checks the synthetic fixture; `build` exercises all four outputs. The project has no third-party runtime dependencies.

## Coding style and naming conventions

Use UTF-8, LF line endings, four-space Python indentation, and sentence-case Markdown headings. Prefer `snake_case` for modules, functions, and variables; `PascalCase` for classes; and `UPPER_SNAKE_CASE` for constants. Keep CLI behavior deterministic, use `pathlib`, and avoid third-party packages. Wrap commands, paths, JSON keys, and identifiers in backticks.

## Testing guidelines

Use `unittest`; name files `test_*.py` and methods `test_*`. Every behavioral change should cover a successful case plus malformed input or reconciliation boundaries. Fixtures must be minimal and sanitized. Tests may not depend on network access, live billing accounts, mutable prices, clock time, or user-specific filesystem paths.

## Commit and pull request guidelines

Use focused, imperative Conventional Commits, for example `feat(audit): add snapshot validation` or `docs: clarify pricing boundaries`. Pull requests should state purpose, affected paths, validation performed, and assumptions about currency or pricing dates. Link related issues and include screenshots only when report presentation changes.

## Security and agent instructions

Never commit API keys, raw billing exports, account identifiers, customer prompts, private paths, or per-event ledgers. Preserve the report's distinction between observed facts and estimated cost, attribution, and Agent-hours. Use ignored local files and sanitized fixtures. Before invoking GrokGo MCP tools, read `/Users/wukaibing/.grok-go/agents-guide.md`.
