"""Command line entry point.

detection-enabler serve              # run the MCP server (stdio)
detection-enabler requests [--all]   # list enable requests
detection-enabler show <id>          # show one request with its readiness report
detection-enabler approve <id>       # HUMAN ONLY: enable the rule
detection-enabler deny <id> [-m ...] # HUMAN ONLY: reject the request
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from typing import Any

from .approvals import ApprovalStore, Status
from .config import ApproverSettings, ReaderSettings, state_dir
from .elastic import ElasticError, RuleEnabler


def _store(args: argparse.Namespace) -> ApprovalStore:
    # Reading/listing requests needs no credentials.
    return ApprovalStore(args.state_dir or state_dir())


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import build_server

    build_server(ReaderSettings()).run(args.transport)
    return 0


def cmd_requests(args: argparse.Namespace) -> int:
    reqs = _store(args).list(include_closed=args.all)
    if not reqs:
        print("No requests." if args.all else "No pending requests.")
    for r in reqs:
        name = (r.readiness.get("rule_name") or {}).get("text", "?")
        print(f"{r.id}  {r.status.value:<9} {r.created_at}  {r.rule_id}  {name!r}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    print(_store(args).get(args.id).model_dump_json(indent=2))
    return 0


def _require_human() -> None:
    if not sys.stdin.isatty():
        sys.exit("Refusing: approve/deny must be run interactively by a human (stdin is not a TTY).")


def _summarize(req_json: dict[str, Any]) -> str:
    rd = req_json["readiness"]
    lines = [
        f"Request:   {req_json['id']}  (created {req_json['created_at']})",
        f"Rule:      {rd.get('rule_name', {}).get('text')!r}  [{req_json['rule_id']}] type={rd['rule_type']}",
        f"Verdict:   {rd['verdict']} at {rd['checked_at']}",
        f"Indices:   {', '.join(rd['index_patterns'])}  ({rd['docs_in_window']} docs in last {rd['lookback_hours']}h)",
    ]
    if vol := rd.get("volume"):
        lines.append(f"Volume:    ~{vol.get('alerts_per_day')} alerts/day (preview)")
    for f in rd.get("fields", []):
        lines.append(f"  field {f['name']}: {f['coverage_pct']}% populated")
    just = (req_json.get("justification") or {}).get("text")
    lines.append("Agent's justification (untrusted, written by the agent):")
    lines.append("  " + json.dumps(just))
    return "\n".join(lines)


async def _enable(settings: ApproverSettings, store: ApprovalStore, request_id: str, who: str) -> int:
    req = store.get(request_id)
    if req.status != Status.PENDING:
        sys.exit(f"Request is {req.status.value}, not pending.")
    print(_summarize(req.model_dump(mode="json")))
    print()
    answer = input(f"Type the rule_id ({req.rule_id}) to enable it, anything else to cancel: ")
    if answer.strip() != req.rule_id:
        print("Cancelled.")
        return 1

    client = RuleEnabler(settings)
    try:
        current = await client.get_rule(req.rule_id)
        if current.get("revision") != req.rule_revision or current.get("updated_at") != req.rule_updated_at:
            store.decide(req, Status.DENIED, who, "rule changed after the readiness check")
            sys.exit("Refusing: the rule was modified after it was checked. Ask the agent to re-check.")
        store.decide(req, Status.APPROVED, who)
        await client.enable_rule(req.rule_id)
    except ElasticError as e:
        store.decide(req, Status.FAILED, who, str(e))
        sys.exit(f"Enable failed: {e}")
    finally:
        await client.aclose()
    store.decide(req, Status.ENABLED, who)
    print(f"Enabled rule {req.rule_id}.")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    _require_human()
    settings = ApproverSettings()
    store = _store(args)
    return asyncio.run(_enable(settings, store, args.id, getpass.getuser()))


def cmd_deny(args: argparse.Namespace) -> int:
    _require_human()
    store = _store(args)
    req = store.get(args.id)
    if req.status != Status.PENDING:
        sys.exit(f"Request is {req.status.value}, not pending.")
    store.decide(req, Status.DENIED, getpass.getuser(), args.message)
    print(f"Denied {req.id}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="detection-enabler", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--state-dir", default=None, help="Where requests and the audit log live.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Run the MCP server.")
    s.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("requests", help="List enable requests.")
    s.add_argument("--all", action="store_true", help="Include closed requests.")
    s.set_defaults(fn=cmd_requests)

    s = sub.add_parser("show", help="Show a request.")
    s.add_argument("id")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("approve", help="Approve a request and enable the rule (human only).")
    s.add_argument("id")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("deny", help="Deny a request (human only).")
    s.add_argument("id")
    s.add_argument("-m", "--message", default=None)
    s.set_defaults(fn=cmd_deny)

    args = p.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
