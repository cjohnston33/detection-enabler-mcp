"""End-to-end tests through a real MCP client, against a fake Elastic backend."""

from __future__ import annotations

import pytest
from conftest import FakeElastic, make_rule
from mcp import Client

from detection_enabler_mcp.approvals import ApprovalStore
from detection_enabler_mcp.config import ReaderSettings
from detection_enabler_mcp.server import build_server


def server(settings: ReaderSettings, store: ApprovalStore, **kw):  # type: ignore[no-untyped-def]
    es = FakeElastic(rules={"r1": make_rule()}, field_types={"process.name": "keyword"}, **kw)
    return build_server(settings, es=es, store=store)


async def test_no_tool_can_enable_or_approve(settings: ReaderSettings, store: ApprovalStore) -> None:
    """Security invariant: the agent-facing surface has no way to change alerting."""
    async with Client(server(settings, store)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == {"list_rules", "check_rule_readiness", "request_rule_enable", "get_enable_request"}


async def test_request_flow_creates_pending_request(settings: ReaderSettings, store: ApprovalStore) -> None:
    async with Client(server(settings, store)) as c:
        r = await c.call_tool("request_rule_enable", {"rule_id": "r1", "justification": "good rule"})
        assert r.structured_content is not None
        assert r.structured_content["status"] == "pending_human_approval"
        req_id = r.structured_content["request_id"]

        again = await c.call_tool("request_rule_enable", {"rule_id": "r1", "justification": "again"})
        assert again.structured_content == {"status": "already_pending", "request_id": req_id}

        status = await c.call_tool("get_enable_request", {"request_id": req_id})
        assert status.structured_content is not None
        assert status.structured_content["status"] == "pending"
        assert status.structured_content["justification"]["untrusted"] is True


@pytest.mark.parametrize("kw", [{"preview_alerts": 1000}, {"docs_in_window": 0}, {"indices": []}])
async def test_request_refused_unless_ready(settings: ReaderSettings, store: ApprovalStore, kw: dict) -> None:
    async with Client(server(settings, store, **kw)) as c:
        r = await c.call_tool("request_rule_enable", {"rule_id": "r1", "justification": "x"})
    assert r.structured_content is not None
    assert r.structured_content["status"] == "refused"
    assert store.list() == []


async def test_list_rules_marks_names_untrusted(settings: ReaderSettings, store: ApprovalStore) -> None:
    async with Client(server(settings, store)) as c:
        r = await c.call_tool("list_rules", {})
    assert r.structured_content is not None
    assert r.structured_content["rules"][0]["name"]["untrusted"] is True
