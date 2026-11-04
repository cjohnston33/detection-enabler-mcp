"""Call the MCP server's tools in-process against your local stack and print the results.

    uv run python scripts/try_tools.py                 # readiness for every rule
    uv run python scripts/try_tools.py --request RULE  # also file an enable request

This goes through a real MCP client session, so it exercises the same code path an
agent would. It uses the read-only credentials in .env.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from mcp import Client

from detection_enabler_mcp.config import ReaderSettings
from detection_enabler_mcp.server import build_server


async def main(request: str | None) -> None:
    async with Client(build_server(ReaderSettings()), raise_exceptions=True) as c:
        rules = (await c.call_tool("list_rules", {"per_page": 100})).structured_content or {}
        for r in rules.get("rules", []):
            rep = (
                await c.call_tool("check_rule_readiness", {"rule_id": r["rule_id"]})
            ).structured_content or {}
            print(f"{r['rule_id']:<32} {rep.get('verdict', 'error'):<15} {'; '.join(rep.get('reasons', []))}")
        if request:
            res = await c.call_tool(
                "request_rule_enable", {"rule_id": request, "justification": "try_tools.py"}
            )
            print(json.dumps(res.structured_content, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--request", metavar="RULE_ID", help="File an enable request for this rule.")
    asyncio.run(main(p.parse_args().request))
