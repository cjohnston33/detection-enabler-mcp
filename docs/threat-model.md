# Threat model

## Assets

* **What alerts in production.** Enabling a broken or noisy rule causes alert fatigue,
  and an attacker who can enable rules can flood analysts. *Disabling* rules is worse,
  and this project never does it.
* **Log contents.** They may hold sensitive data and must not leak to the model needlessly.

## Actors

| Actor | Trust |
|---|---|
| Human approver | Trusted. Holds the approver credential. |
| AI agent / MCP client | **Semi-trusted.** It may be confused or manipulated by its inputs. |
| Log data, field names, rule names/descriptions, error messages | **Untrusted.** Attackers can influence them. |

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Prompt injection in log data makes the agent enable or disable rules | No tool can change alerting. The server's credential is read-only (Kibana `read`), and a test asserts the tool list. | The agent could still *file* misleading requests. The human sees the readiness data and the agent's justification, which is labeled untrusted. |
| T2 | The agent reaches the approver credential (for example via shell access) | It lives in a separate file, loaded only by the CLI. The CLI requires a TTY and a typed rule id. `.claude/settings.json` blocks reads. | **Not a hard boundary** if the agent runs as the same OS user with an unrestricted shell. In production, keep the approver credential on a different machine or account, or behind a ticketing / ChatOps flow (roadmap). |
| T3 | The rule is modified between check and approval (TOCTOU) | The request stores `revision` + `updated_at`, and approval is refused if either changed. | Data could change in that window. Requests expire after 24h. |
| T4 | Injected text in tool output | Reports are aggregates. Identifiers must match `[A-Za-z0-9_@.*-]{1,200}`. Free text is stripped of control/format characters, truncated, and wrapped as `untrusted`. Server instructions tell the model to treat it as data. | Labeling reduces risk but cannot eliminate it. The real control is that no tool can change alerting. |
| T5 | Volume preview causes side effects | Kibana preview writes only to `.preview.alerts-security.alerts-<space>`, never to real alerts, and triggers no actions. | The reader needs write on the preview index. |
| T6 | Tampering with requests on disk | The state dir is created `0700`. Request ids are validated against path traversal. Writes are atomic. | Anyone with filesystem access as the user can edit requests. The approver re-checks the rule live before enabling. |
| T7 | Reader key over-privileged on indices | Docs recommend scoping index read to log patterns. | `_count` / `_field_caps` need read on the source indices. |

## Out of scope for the MVP

* Disabling, editing or deleting rules (deliberately never supported).
* Returning sample events to the agent. If added, they must be opt-in, field-limited and
  wrapped as untrusted.
* Multi-user approval (two-person rule) and signed approvals.
