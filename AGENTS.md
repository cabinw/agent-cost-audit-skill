# Repository Guidelines

## Project structure and module organization

This repository is currently an empty scaffold. As the agent cost-audit skill is implemented, keep the root limited to entry-point and governance files such as `SKILL.md`, `README.md`, and `AGENTS.md`. Put deterministic helpers in `scripts/`, detailed provider or pricing notes in `references/`, reusable report templates in `assets/`, and automated checks in `tests/`. Mirror implementation names in tests where practical; for example, `scripts/calculate_costs.py` should have `tests/test_calculate_costs.py`.

## Build, test, and development commands

No dependency manifest, build system, linter, or test runner is committed yet. After Git initialization, use these checks for documentation-only changes:

```bash
git diff --check
rg -n "TODO|FIXME" --glob '!AGENTS.md' .
```

The first executable-code change must add reproducible setup, lint, and test commands to `README.md` and CI. Commit the relevant tool configuration; do not rely on globally installed dependencies or undocumented local state.

## Coding style and naming conventions

Use UTF-8, LF line endings, and sentence-case Markdown headings. Keep instructions task-oriented and wrap commands, paths, configuration keys, and model identifiers in backticks. Prefer `snake_case` for Python modules and functions, `PascalCase` for classes, and kebab-case for Markdown reference files. Format code with the language's standard formatter, introduced and pinned with the code that requires it.

## Testing guidelines

No testing framework or coverage threshold exists yet. Every behavioral change must include automated tests under `tests/`, including normal, malformed-input, and pricing-boundary cases. Use sanitized, minimal fixtures; tests must not depend on live billing accounts or mutable provider prices. Document the exact test command when the framework is introduced.

## Commit and pull request guidelines

There is no Git history from which to infer an established convention. Use focused, imperative Conventional Commits, for example `feat(audit): add token-cost parser` or `docs: explain pricing snapshots`. Pull requests should state the purpose, affected paths, validation performed, and any assumptions about currency or pricing dates. Link related issues and include screenshots only for visual output changes.

## Security and agent instructions

Never commit API keys, raw billing exports, account identifiers, or customer prompts. Use ignored local environment files and sanitized examples. Before invoking GrokGo MCP tools, read `/Users/wukaibing/.grok-go/agents-guide.md`.
