# Permissions

Feature privilege ids change between Kibana versions. The names below are for **9.5**.
List yours with `GET /api/features`. `scripts/seed_dev.py` creates both roles for the
local stack.

## Reader (MCP server)

Kibana role `dem_reader`:

```json
{
  "elasticsearch": {
    "cluster": [],
    "indices": [
      { "names": ["logs-*"], "privileges": ["read", "view_index_metadata"] },
      { "names": [".preview.alerts-security.alerts-*", ".internal.preview.alerts-security.alerts-*"],
        "privileges": ["read", "write", "maintenance", "view_index_metadata"] }
    ]
  },
  "kibana": [{ "base": [], "feature": { "siemV5": ["read"], "securitySolutionRulesV4": ["read"] }, "spaces": ["*"] }]
}
```

* Widen `logs-*` to cover every index pattern your rules use.
* The preview-index write is needed for volume estimates (Kibana's rule preview).
  Without it, `request_rule_enable` refuses, because volume is unknown.
* Verified: this key gets **403** on `PATCH /api/detection_engine/rules`.

## Approver (CLI only)

Kibana role `dem_approver`: `siemV5: all`, `securitySolutionRulesV4: all`, plus `read` on
the source indices. Rules run with the API key of whoever last enabled them, so this key
must be able to read the rule's data.
