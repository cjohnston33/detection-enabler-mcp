from __future__ import annotations

import pytest

from detection_enabler_mcp import cli


def test_approve_refuses_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(SystemExit, match="interactively"):
        cli.main(["approve", "abc123"])


def test_requests_empty(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:  # type: ignore[no-untyped-def]
    assert cli.main(["--state-dir", str(tmp_path), "requests"]) == 0
    assert "No pending requests" in capsys.readouterr().out
