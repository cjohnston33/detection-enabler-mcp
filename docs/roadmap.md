# Roadmap: public MVP in 3 weeks

## Week 1: foundation ✅ (scaffolded)

- [x] Local Elastic Stack (Docker) + seed script with one demo rule per verdict
- [x] MCP server: `list_rules`, `check_rule_readiness`, `request_rule_enable`, `get_enable_request`
- [x] Readiness: source, freshness, field mapping/coverage/type, preview-based volume
- [x] Human approval CLI with separate credential, TTY check, tamper check, audit log
- [x] Untrusted-content handling, unit tests, CI

## Week 2: make it trustworthy

- [ ] Integration tests in CI against a real Elastic container (`docker compose` in Actions)
- [ ] Better field extraction: KQL/EQL parsing instead of regex. Handle `saved_query`, `threshold.field`, `new_terms_fields`, `threat_mapping`
- [ ] Data view rules, multiple spaces, rules with exceptions lists
- [ ] Bulk mode: `check_rules_readiness(tag=...)` with a summary table
- [ ] Prebuilt Elastic rules (install package, check `related_integrations`)
- [ ] Prompt-injection regression tests (malicious field names, rule names, preview errors)

## Week 3: ship it

- [ ] Approval via something other than a local CLI (Slack / GitHub issue / webhook) so the approver can live off the agent's machine
- [ ] Publish to PyPI (`uvx detection-enabler-mcp`) + MCP registry listing
- [ ] Docs: demo GIF, architecture diagram, "connect to Elastic Cloud" guide
- [ ] Tag `v0.1.0`, announce

## Later

- Other SIEMs (Splunk, Sentinel) behind a backend interface
- Two-person approval, signed approval records
- Suggest fixes for `missing_fields` (field aliases, ingest pipeline gaps)
