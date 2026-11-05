"""Decide whether a detection rule will actually work in this environment.

A rule is checked against four questions:

1. **Source exists** - do its index patterns / data view resolve to any index?
2. **Data is flowing** - were any documents written in the lookback window?
3. **Fields are populated** - are the fields the rule depends on mapped *and*
   present in recent documents?
4. **Volume is sane** - when previewed over the lookback window, how many alerts
   would it raise per day?

Only aggregates are returned. Raw log content never leaves this module.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .elastic import ElasticError, ReadOnlyElastic
from .untrusted import safe_identifier, untrusted_text

SUPPORTED_TYPES = {"query", "saved_query", "eql", "esql", "threshold", "new_terms", "threat_match"}
MAX_PREVIEW_INVOCATIONS = 300

# Fields on the rule response that the preview (create) schema does not accept.
_READ_ONLY_RULE_FIELDS = {
    "id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "revision",
    "immutable",
    "rule_source",
    "execution_summary",
    "output_index",
}


# Field types that behave the same for detection queries.
_TYPE_FAMILIES = [
    {"keyword", "constant_keyword", "wildcard"},
    {"text", "match_only_text"},
    {"long", "integer", "short", "byte", "unsigned_long"},
    {"double", "float", "half_float", "scaled_float"},
    {"date", "date_nanos"},
]


def types_compatible(expected: str, actual: list[str]) -> bool:
    family = next((f for f in _TYPE_FAMILIES if expected in f), {expected})
    return any(t in family for t in actual)


class Verdict(StrEnum):
    READY = "ready"
    NO_SOURCE = "no_source"  # index patterns match nothing
    NO_RECENT_DATA = "no_recent_data"  # indices exist but nothing new in the window
    MISSING_FIELDS = "missing_fields"  # data flows, but fields the rule needs are absent
    NOISY = "noisy"  # would alert above the configured daily threshold
    UNSUPPORTED = "unsupported"  # rule type we can't evaluate yet
    ERROR = "error"


class FieldCheck(BaseModel):
    name: str
    source: str = Field(description="'required_fields' or 'query'")
    mapped: bool
    types: list[str] = []
    expected_type: str | None = None
    type_mismatch: bool = False
    docs_with_field: int = 0
    coverage_pct: float = 0.0


class VolumeCheck(BaseModel):
    """Result of Kibana's rule preview.

    The preview window is a little longer than ``lookback_hours``: the first simulated run
    also searches the rule's extra lookback (``from`` minus ``interval``, e.g. 6m - 5m = 1m).
    ``source_docs_in_window`` is counted over exactly the same window, so for a simple query
    rule ``alerts_in_window`` can never exceed it.
    """

    ran: bool
    alerts_in_window: int | None = None
    alerts_per_day: float | None = None
    invocations: int | None = None
    window_start: str | None = None
    window_end: str | None = None
    window_hours: float | None = None
    source_docs_in_window: int | None = None
    errors: list[dict[str, Any]] = []


class ReadinessReport(BaseModel):
    rule_id: str
    rule_name: dict[str, Any] | None
    rule_type: str
    rule_revision: int | None
    enabled: bool
    verdict: Verdict
    reasons: list[str]
    index_patterns: list[str]
    matched_indices: list[str]
    lookback_hours: int
    docs_in_window: int = 0
    fields: list[FieldCheck] = []
    volume: VolumeCheck | None = None
    checked_at: str


_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_interval_seconds(value: str | None, default: int = 300) -> int:
    if not value:
        return default
    m = _DURATION.match(value.strip())
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)] if m else default


_RELATIVE_FROM = re.compile(r"^now-(\d+)([smhd])$")


def parse_from_seconds(value: str | None, default: int) -> int:
    """How far back each rule run searches, from the rule's ``from`` (e.g. ``now-6m`` -> 360)."""
    m = _RELATIVE_FROM.match((value or "").strip())
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)] if m else default


def es_time(dt: datetime) -> str:
    """Millisecond-precision UTC timestamp in the format Kibana and Elasticsearch accept."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def time_range(start: datetime, end: datetime) -> dict[str, Any]:
    return {"range": {"@timestamp": {"gte": es_time(start), "lte": es_time(end)}}}


_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'")
_KQL_FIELD = re.compile(r"(?<![\w.@])([A-Za-z_@][\w.@-]*)\s*:")
_DOTTED = re.compile(r"(?<![\w.@])([A-Za-z_@][\w@-]*(?:\.[\w@-]+)+)")
_ESQL_FROM = re.compile(r"^\s*FROM\s+([^\s|]+)", re.IGNORECASE)


def extract_query_fields(query: str | None, language: str | None) -> list[str]:
    """Best-effort list of field names referenced by a rule query (heuristic)."""
    if not query:
        return []
    stripped = _QUOTED.sub('""', query)
    if language in (None, "kuery", "lucene"):
        found = _KQL_FIELD.findall(stripped)
    else:  # eql / esql: rely on dotted ECS-style names
        found = _DOTTED.findall(stripped)
    return sorted({f for f in found if f not in {"_id", "_index"}})


def esql_indices(query: str | None) -> list[str]:
    m = _ESQL_FROM.match(query or "")
    return [p.strip() for p in m.group(1).split(",")] if m else []


def preview_body(rule: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rule.items() if k not in _READ_ONLY_RULE_FIELDS}


async def check_readiness(
    es: ReadOnlyElastic,
    rule: dict[str, Any],
    *,
    lookback_hours: int,
    noisy_alerts_per_day: int,
    min_field_coverage_pct: float,
    estimate_volume: bool = True,
) -> ReadinessReport:
    rule_type = rule.get("type", "unknown")
    # One fixed "now" for every query, so the count and the preview can't drift apart.
    end = datetime.now(UTC).replace(microsecond=0)
    patterns: list[str] = list(rule.get("index") or [])
    if not patterns and rule.get("data_view_id"):
        patterns = [p.strip() for p in (await es.data_view_pattern(rule["data_view_id"])).split(",")]
    if not patterns and rule_type == "esql":
        patterns = esql_indices(rule.get("query"))

    report = ReadinessReport(
        rule_id=rule.get("rule_id") or rule.get("id", ""),
        rule_name=untrusted_text(rule.get("name"), 200),
        rule_type=rule_type,
        rule_revision=rule.get("revision"),
        enabled=bool(rule.get("enabled")),
        verdict=Verdict.READY,
        reasons=[],
        index_patterns=[safe_identifier(p) for p in patterns],
        matched_indices=[],
        lookback_hours=lookback_hours,
        checked_at=end.isoformat(timespec="seconds"),
    )
    reasons = report.reasons

    if rule_type not in SUPPORTED_TYPES:
        report.verdict = Verdict.UNSUPPORTED
        reasons.append(f"Rule type '{safe_identifier(rule_type)}' is not supported yet.")
        return report
    if not patterns:
        report.verdict = Verdict.NO_SOURCE
        reasons.append("Rule has no index patterns or data view.")
        return report

    # 1. Source exists
    matched = await es.resolve_index(patterns)
    report.matched_indices = [safe_identifier(i) for i in matched[:50]]
    if not matched:
        report.verdict = Verdict.NO_SOURCE
        reasons.append("None of the rule's index patterns match an existing index or data stream.")
        return report

    # 2. Data is flowing
    window = time_range(end - timedelta(hours=lookback_hours), end)
    report.docs_in_window = await es.count(patterns, window)
    if report.docs_in_window == 0:
        report.verdict = Verdict.NO_RECENT_DATA
        reasons.append(f"Indices exist but no documents were written in the last {lookback_hours}h.")
        return report

    # 3. Fields are populated
    required = {f["name"]: f.get("type") for f in rule.get("required_fields") or [] if f.get("name")}
    from_query = [
        f for f in extract_query_fields(rule.get("query"), rule.get("language")) if f not in required
    ]
    wanted = [(n, "required_fields", t) for n, t in required.items()] + [
        (n, "query", None) for n in from_query
    ]
    if wanted:
        caps = await es.field_caps(patterns, [n for n, _, _ in wanted])
        for name, source, expected in wanted:
            types = sorted(caps.get(name, {}).keys())
            fc = FieldCheck(
                name=safe_identifier(name),
                source=source,
                mapped=bool(types),
                types=[safe_identifier(t) for t in types],
                expected_type=expected,
            )
            if expected and types and not types_compatible(expected, types):
                fc.type_mismatch = True
            if fc.mapped:
                fc.docs_with_field = await es.count(
                    patterns, {"bool": {"filter": [window, {"exists": {"field": name}}]}}
                )
                fc.coverage_pct = round(100 * fc.docs_with_field / report.docs_in_window, 2)
            report.fields.append(fc)

        missing = [f for f in report.fields if f.coverage_pct < min_field_coverage_pct]
        mismatched = [f for f in report.fields if f.type_mismatch]
        if missing:
            report.verdict = Verdict.MISSING_FIELDS
            reasons.append(
                "Fields missing or rarely populated (<"
                f"{min_field_coverage_pct}% of recent docs): " + ", ".join(f.name for f in missing)
            )
        if mismatched:
            report.verdict = Verdict.MISSING_FIELDS
            reasons.append(
                "Field type mismatch: "
                + ", ".join(
                    f"{f.name} (expected {f.expected_type}, got {'/'.join(f.types)})" for f in mismatched
                )
            )

    # 4. Volume is sane
    if estimate_volume:
        report.volume = await _estimate_volume(es, rule, patterns, lookback_hours, end)
        if report.volume.ran and report.volume.alerts_per_day is not None:
            if report.volume.alerts_per_day > noisy_alerts_per_day and report.verdict == Verdict.READY:
                report.verdict = Verdict.NOISY
            if report.volume.alerts_per_day > noisy_alerts_per_day:
                reasons.append(
                    f"Preview projects ~{report.volume.alerts_per_day:g} alerts/day "
                    f"(threshold {noisy_alerts_per_day})."
                )
        elif report.volume.errors:
            reasons.append("Volume preview failed; see volume.errors.")

    if report.verdict == Verdict.READY:
        reasons.append("Source exists, data is recent, fields are populated, and volume is within threshold.")
    return report


async def _estimate_volume(
    es: ReadOnlyElastic, rule: dict[str, Any], patterns: list[str], lookback_hours: int, end: datetime
) -> VolumeCheck:
    interval = parse_interval_seconds(rule.get("interval"))
    invocations = max(1, min(MAX_PREVIEW_INVOCATIONS, (lookback_hours * 3600) // interval))
    # Each run searches `from` seconds back, which is usually a bit more than `interval`
    # (Kibana's default is now-6m on a 5m schedule). Overlap between runs is de-duplicated,
    # so the only extra coverage is the first run's look-back before the scheduled window.
    extra = max(0, parse_from_seconds(rule.get("from"), default=interval) - interval)
    start = end - timedelta(seconds=invocations * interval + extra)
    window_hours = (end - start).total_seconds() / 3600
    try:
        result = await es.preview_rule(preview_body(rule), invocations, es_time(end))
    except ElasticError as e:
        return VolumeCheck(ran=False, errors=[{"status": e.status, "message": untrusted_text(str(e))}])

    errors = []
    for log in result.get("logs", []):
        for msg in log.get("errors", []):
            errors.append({"message": untrusted_text(msg)})
    preview_id = result.get("previewId")
    if not preview_id:
        return VolumeCheck(ran=False, invocations=invocations, errors=errors)

    alerts = await es.count_preview_alerts(preview_id)
    return VolumeCheck(
        ran=True,
        alerts_in_window=alerts,
        alerts_per_day=round(alerts * 24 / window_hours, 1),
        invocations=invocations,
        window_start=es_time(start),
        window_end=es_time(end),
        window_hours=round(window_hours, 3),
        source_docs_in_window=await es.count(patterns, time_range(start, end)),
        errors=errors[:10],
    )
