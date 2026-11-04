# Contributing

Thanks for helping! This is an early project, so issues and small PRs are very welcome.

## Setup

```bash
uv sync
./scripts/dev-up.sh && uv run python scripts/seed_dev.py   # optional: local Elastic
```

## Before you open a PR

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src
```

## Ground rules

* **The MCP server must never be able to change alerting.** Don't add tools that enable,
  disable or edit rules. `tests/test_server.py::test_no_tool_can_enable_or_approve`
  guards this; changing that test needs a maintainer's sign-off.
* Return aggregates, not raw log text. Pass identifiers through `safe_identifier` and
  free text through `untrusted_text`.
* Keep the approver credential out of anything the server imports.
