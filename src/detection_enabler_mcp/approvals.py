"""File-backed store of enable requests, plus an append-only audit log.

Lifecycle::

    agent: request_enable  ->  PENDING
    human: approve         ->  APPROVED -> ENABLED | FAILED
    human: deny            ->  DENIED
    (24h without decision) ->  EXPIRED

The agent can create requests and read their status. Nothing reachable from the
MCP server can move a request out of PENDING.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

REQUEST_TTL = timedelta(hours=24)


class Status(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ENABLED = "enabled"
    FAILED = "failed"
    EXPIRED = "expired"


class EnableRequest(BaseModel):
    id: str
    rule_id: str
    rule_revision: int | None
    rule_updated_at: str | None
    status: Status
    justification: dict[str, Any] | None  # untrusted_text envelope: written by the agent
    readiness: dict[str, Any]
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    decision_note: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


class ApprovalStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.requests_dir = self.dir / "requests"
        self.requests_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.audit_path = self.dir / "audit.log"

    def _path(self, request_id: str) -> Path:
        if not request_id.isalnum():
            raise ValueError("Invalid request id.")
        return self.requests_dir / f"{request_id}.json"

    def audit(self, event: str, **data: Any) -> None:
        line = json.dumps({"ts": _now().isoformat(timespec="seconds"), "event": event, **data})
        with self.audit_path.open("a") as f:
            f.write(line + "\n")

    def save(self, req: EnableRequest) -> None:
        tmp = self._path(req.id).with_suffix(".tmp")
        tmp.write_text(req.model_dump_json(indent=2))
        os.replace(tmp, self._path(req.id))

    def create(
        self, *, rule: dict[str, Any], justification: dict[str, Any] | None, readiness: dict[str, Any]
    ) -> EnableRequest:
        req = EnableRequest(
            id=secrets.token_hex(6),
            rule_id=rule["rule_id"],
            rule_revision=rule.get("revision"),
            rule_updated_at=rule.get("updated_at"),
            status=Status.PENDING,
            justification=justification,
            readiness=readiness,
            created_at=_now().isoformat(timespec="seconds"),
        )
        self.save(req)
        self.audit(
            "request_created", request_id=req.id, rule_id=req.rule_id, verdict=readiness.get("verdict")
        )
        return req

    def get(self, request_id: str) -> EnableRequest:
        path = self._path(request_id)
        if not path.exists():
            raise KeyError(request_id)
        req = EnableRequest.model_validate_json(path.read_text())
        if req.status == Status.PENDING and _now() - datetime.fromisoformat(req.created_at) > REQUEST_TTL:
            req.status = Status.EXPIRED
            self.save(req)
            self.audit("request_expired", request_id=req.id)
        return req

    def list(self, include_closed: bool = False) -> list[EnableRequest]:
        reqs = [self.get(p.stem) for p in sorted(self.requests_dir.glob("*.json"))]
        if not include_closed:
            reqs = [r for r in reqs if r.status == Status.PENDING]
        return sorted(reqs, key=lambda r: r.created_at)

    def pending_for_rule(self, rule_id: str) -> EnableRequest | None:
        return next((r for r in self.list() if r.rule_id == rule_id), None)

    def decide(self, req: EnableRequest, status: Status, by: str, note: str | None = None) -> EnableRequest:
        req.status = status
        req.decided_at = _now().isoformat(timespec="seconds")
        req.decided_by = by
        req.decision_note = note
        self.save(req)
        self.audit(f"request_{status.value}", request_id=req.id, rule_id=req.rule_id, by=by, note=note)
        return req
