# Security policy

This project sits between an AI agent and a production SIEM, so security reports matter.

Please **do not open a public issue** for vulnerabilities. Use GitHub's
[private vulnerability reporting](https://github.com/cjohnston33/detection-enabler-mcp/security/advisories/new)
instead. Expect a first response within 7 days.

Of particular interest:

* Any way for the MCP server (agent side) to enable, disable or modify a rule
* Prompt-injection paths where attacker-controlled text reaches the agent unwrapped
* Bypasses of the approval tamper check or request-id validation

See [docs/threat-model.md](docs/threat-model.md) for the current model and known gaps.
