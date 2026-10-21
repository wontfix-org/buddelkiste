"""which() searches extra directories that a user PATH omits."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from buddelkiste.which import log_cmdline, which


def test_which_finds_extra_dir_when_path_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path_dir = tmp_path / "path"
    extra_dir = tmp_path / "extra"
    path_dir.mkdir()
    extra_dir.mkdir()
    tool = extra_dir / "iptables"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", (str(extra_dir),))
    assert which("iptables") == str(tool)
    assert which("iptables", path=str(path_dir)) == str(tool)


def test_which_prefers_path_over_extra_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path_dir = tmp_path / "path"
    extra_dir = tmp_path / "extra"
    path_dir.mkdir()
    extra_dir.mkdir()
    for directory in (path_dir, extra_dir):
        tool = directory / "iptables"
        tool.write_text("#!/bin/sh\n", encoding="utf-8")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", (str(extra_dir),))
    assert which("iptables") == str(path_dir / "iptables")
    assert which("missing-tool") is None


def test_log_cmdline_groups_options(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        log_cmdline(
            ["pasta", "--ipv4-only", "--dns", "none", "--", "/bin/sh"],
            label="pasta",
        )
    assert "Running pasta:" in caplog.text
    assert "--ipv4-only" in caplog.text
    assert "--dns none" in caplog.text
    assert "-- /bin/sh" in caplog.text
