from __future__ import annotations

from typing import Any

import pytest

from detection_enabler_mcp.approvals import ApprovalStore
from detection_enabler_mcp.config import ReaderSettings
from detection_enabler_mcp.elastic import ReadOnlyElastic


class FakeElastic(ReadOnlyElastic):
    """In-memory stand-in for the Elastic APIs used by the readiness check."""

    def __init__(
        self,
        *,
        rules: dict[str, dict[str, Any]] | None = None,
        indices: list[str] | None = None,
        docs_in_window: int = 100,
        field_types: dict[str, str] | None = None,
        field_counts: dict[str, int] | None = None,
        preview_alerts: int = 2,
    ):
        self.space = "default"
        self.rules = rules or {}
        self.indices = indices if indices is not None else ["logs-test-default"]
        self.docs_in_window = docs_in_window
        self.field_types = field_types or {}
        self.field_counts = field_counts or {}
        self.preview_alerts = preview_alerts
        self.count_queries: list[dict[str, Any]] = []
        self.preview_calls: list[dict[str, Any]] = []

    async def aclose(self) -> None:
        pass

    async def get_rule(self, rule_id: str) -> dict[str, Any]:
        return self.rules[rule_id]

    async def find_rules(
        self, search: str | None = None, page: int = 1, per_page: int = 20
    ) -> dict[str, Any]:
        return {"total": len(self.rules), "page": page, "data": list(self.rules.values())}

    async def resolve_index(self, patterns: list[str]) -> list[str]:
        return self.indices

    async def count(self, patterns: list[str], query: dict[str, Any]) -> int:
        self.count_queries.append(query)
        if "bool" in query:  # exists-query for a field
            field = query["bool"]["filter"][1]["exists"]["field"]
            return self.field_counts.get(field, self.docs_in_window)
        return self.docs_in_window

    async def field_caps(self, patterns: list[str], fields: list[str]) -> dict[str, dict[str, Any]]:
        return {f: {self.field_types[f]: {}} for f in fields if f in self.field_types}

    async def preview_rule(
        self, rule: dict[str, Any], invocation_count: int, timeframe_end: str
    ) -> dict[str, Any]:
        self.preview_calls.append({"invocation_count": invocation_count, "timeframe_end": timeframe_end})
        return {"previewId": "p1", "logs": []}

    async def count_preview_alerts(self, preview_id: str) -> int:
        return self.preview_alerts


def make_rule(**overrides: Any) -> dict[str, Any]:
    rule = {
        "id": "so-1",
        "rule_id": "r1",
        "name": "Test rule",
        "type": "query",
        "language": "kuery",
        "query": 'process.name: "evil.exe"',
        "index": ["logs-test-*"],
        "interval": "5m",
        "enabled": False,
        "revision": 3,
        "updated_at": "2026-11-01T00:00:00Z",
    }
    rule.update(overrides)
    return rule


@pytest.fixture
def settings() -> ReaderSettings:
    return ReaderSettings(api_key="test-key")


@pytest.fixture
def store(tmp_path: Any) -> ApprovalStore:
    return ApprovalStore(tmp_path)
