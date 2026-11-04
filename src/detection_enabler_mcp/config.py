"""Configuration.

There are deliberately two settings classes with two different credential sources:

* ``ReaderSettings`` is what the MCP server loads. It must hold a *read-only*
  credential. The agent talks to this process.
* ``ApproverSettings`` is only loaded by the human-run ``detection-enabler approve``
  command. It holds the credential that can actually enable a rule. The MCP server
  never imports or reads it, so even a fully compromised agent session cannot
  enable a rule by itself.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "detection-enabler-mcp"


def state_dir() -> Path:
    """Shared by the server and the approval CLI. Override with ``DEM_STATE_DIR``."""
    return Path(os.environ.get("DEM_STATE_DIR") or DEFAULT_STATE_DIR).expanduser()


class _Credentials(BaseSettings):
    kibana_url: str = "http://localhost:5601"
    es_url: str = "http://localhost:9200"
    kibana_space: str = "default"
    api_key: SecretStr | None = None
    username: str | None = None
    password: SecretStr | None = None
    verify_tls: bool = True

    @model_validator(mode="after")
    def _need_auth(self) -> _Credentials:
        if not self.api_key and not (self.username and self.password):
            raise ValueError("Set either an API key or a username + password.")
        return self

    def auth_header(self) -> dict[str, str]:
        if self.api_key:
            return {"Authorization": f"ApiKey {self.api_key.get_secret_value()}"}
        assert self.username and self.password
        raw = f"{self.username}:{self.password.get_secret_value()}".encode()
        return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


class ReaderSettings(_Credentials):
    """Read-only credentials used by the MCP server (env prefix ``DEM_``)."""

    model_config = SettingsConfigDict(env_prefix="DEM_", env_file=".env", extra="ignore")

    # Readiness thresholds (can be overridden per call).
    default_lookback_hours: int = Field(default=24, ge=1, le=24 * 30)
    noisy_alerts_per_day: int = Field(default=50, ge=1)
    min_field_coverage_pct: float = Field(default=1.0, ge=0, le=100)


class ApproverSettings(_Credentials):
    """Write credentials used only by the human approval CLI (env prefix ``DEM_APPROVER_``)."""

    model_config = SettingsConfigDict(env_prefix="DEM_APPROVER_", env_file=".env.approver", extra="ignore")
