"""Thin async clients for the Kibana detection engine and Elasticsearch APIs.

``ReadOnlyElastic`` only exposes calls that do not change what alerts. The one
call that does (enabling a rule) lives on ``RuleEnabler``, which is only built by
the approval CLI with approver credentials.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import _Credentials

KIBANA_HEADERS = {
    "kbn-xsrf": "detection-enabler-mcp",
    "elastic-api-version": "2023-10-31",
    "Content-Type": "application/json",
}


class ElasticError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def _raise_for(resp: httpx.Response) -> None:
    if resp.is_success:
        return
    try:
        body = resp.json()
        msg = body.get("message") or body.get("error", {}).get("reason") or resp.text
    except ValueError:
        msg = resp.text
    raise ElasticError(resp.status_code, str(msg)[:500])


class _Base:
    def __init__(self, creds: _Credentials, transport: httpx.AsyncBaseTransport | None = None):
        space = creds.kibana_space
        prefix = "" if space == "default" else f"/s/{space}"
        self.space = space
        common: dict[str, Any] = {
            "headers": creds.auth_header(),
            "timeout": 60.0,
            "verify": creds.verify_tls,
            "transport": transport,
        }
        self._kb = httpx.AsyncClient(base_url=creds.kibana_url.rstrip("/") + prefix, **common)
        self._kb.headers.update(KIBANA_HEADERS)
        self._es = httpx.AsyncClient(base_url=creds.es_url.rstrip("/"), **common)

    async def aclose(self) -> None:
        await self._kb.aclose()
        await self._es.aclose()

    async def _kibana(self, method: str, path: str, **kw: Any) -> Any:
        resp = await self._kb.request(method, path, **kw)
        _raise_for(resp)
        return resp.json() if resp.content else None

    async def _elastic(self, method: str, path: str, **kw: Any) -> Any:
        resp = await self._es.request(method, path, **kw)
        _raise_for(resp)
        return resp.json() if resp.content else None

    async def get_rule(self, rule_id: str) -> dict[str, Any]:
        """Fetch a rule by its ``rule_id`` (the stable id), falling back to the saved-object ``id``."""
        try:
            return await self._kibana("GET", "/api/detection_engine/rules", params={"rule_id": rule_id})
        except ElasticError as e:
            if e.status != 404:
                raise
            return await self._kibana("GET", "/api/detection_engine/rules", params={"id": rule_id})


class ReadOnlyElastic(_Base):
    async def find_rules(
        self, search: str | None = None, page: int = 1, per_page: int = 20
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "sort_field": "name",
            "sort_order": "asc",
        }
        if search:
            # KQL over saved-object attributes; quote to keep it a literal phrase.
            escaped = search.replace("\\", "\\\\").replace('"', '\\"')
            params["filter"] = f'alert.attributes.name: "{escaped}"'
        return await self._kibana("GET", "/api/detection_engine/rules/_find", params=params)

    async def data_view_pattern(self, data_view_id: str) -> str:
        body = await self._kibana("GET", f"/api/data_views/data_view/{data_view_id}")
        return body["data_view"]["title"]

    async def resolve_index(self, patterns: list[str]) -> list[str]:
        """Concrete indices / data streams matching the patterns (empty if none)."""
        expr = ",".join(patterns)
        body = await self._elastic(
            "GET",
            f"/_resolve/index/{expr}",
            params={"expand_wildcards": "open", "ignore_unavailable": "true"},
        )
        names = [i["name"] for i in body.get("indices", []) if not i.get("data_stream")]
        names += [d["name"] for d in body.get("data_streams", [])]
        names += [a["name"] for a in body.get("aliases", [])]
        return sorted(set(names))

    async def count(self, patterns: list[str], query: dict[str, Any]) -> int:
        body = await self._elastic(
            "POST",
            f"/{','.join(patterns)}/_count",
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            json={"query": query},
        )
        return int(body["count"])

    async def field_caps(self, patterns: list[str], fields: list[str]) -> dict[str, dict[str, Any]]:
        body = await self._elastic(
            "GET",
            f"/{','.join(patterns)}/_field_caps",
            params={"fields": ",".join(fields), "ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        return body.get("fields", {})

    async def preview_rule(
        self, rule: dict[str, Any], invocation_count: int, timeframe_end: str
    ) -> dict[str, Any]:
        """Run Kibana's rule preview. Writes only to the isolated ``.preview.alerts-*`` index."""
        return await self._kibana(
            "POST",
            "/api/detection_engine/rules/preview",
            json={**rule, "invocationCount": invocation_count, "timeframeEnd": timeframe_end},
        )

    async def count_preview_alerts(self, preview_id: str) -> int:
        return await self.count(
            [f".preview.alerts-security.alerts-{self.space}"],
            {"term": {"kibana.alert.rule.uuid": preview_id}},
        )


class RuleEnabler(_Base):
    """Write client. Only constructed by the approval CLI, never by the MCP server."""

    async def enable_rule(self, rule_id: str) -> dict[str, Any]:
        return await self._kibana(
            "PATCH", "/api/detection_engine/rules", json={"rule_id": rule_id, "enabled": True}
        )
