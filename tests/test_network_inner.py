from __future__ import annotations

import json
import logging
from pathlib import Path

import click
import pytest

from buddelkiste import network_inner


def test_network_inner_main_usage() -> None:
    with pytest.raises(SystemExit, match="usage:"):
        network_inner.main([])


def test_network_inner_main_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    net_file = tmp_path / "net.json"
    bwrap_file = tmp_path / "bwrap.json"
    net_file.write_text(
        json.dumps(
            {
                "mode": "filter",
                "policy": "deny",
                "allow": ["1.1.1.1/32"],
                "deny": [],
                "allow_hosts": ["example.com"],
                "deny_hosts": [],
                "deny_presets": [],
            }
        ),
        encoding="utf-8",
    )
    bwrap_file.write_text(json.dumps(["bwrap", "--", "true"]), encoding="utf-8")

    captured: dict = {}

    def fake_inner(net, bwrap_args, *, start_slirp):
        captured["net"] = net
        captured["bwrap"] = bwrap_args
        captured["start_slirp"] = start_slirp
        return 0

    monkeypatch.setattr(network_inner, "run_network_inner", fake_inner)
    with pytest.raises(SystemExit) as exc:
        network_inner.main([str(net_file), str(bwrap_file)])
    assert exc.value.code == 0
    assert captured["start_slirp"] is False
    assert captured["net"].allow == ["1.1.1.1/32"]
    assert captured["bwrap"] == ["bwrap", "--", "true"]


def test_network_inner_main_start_slirp_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    net_file = tmp_path / "net.json"
    bwrap_file = tmp_path / "bwrap.json"
    net_file.write_text(
        json.dumps(
            {
                "mode": "filter",
                "policy": "deny",
                "allow": [],
                "deny": [],
                "allow_hosts": [],
                "deny_hosts": [],
                "deny_presets": [],
            }
        ),
        encoding="utf-8",
    )
    bwrap_file.write_text("[]", encoding="utf-8")

    seen: dict = {}

    def fake_inner(net, args, *, start_slirp):
        seen["start_slirp"] = start_slirp
        return 0

    monkeypatch.setattr(network_inner, "run_network_inner", fake_inner)
    with pytest.raises(SystemExit) as exc:
        network_inner.main([str(net_file), str(bwrap_file), "--start-slirp"])
    assert exc.value.code == 0
    assert seen["start_slirp"] is True


def test_network_inner_main_click_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    net_file = tmp_path / "net.json"
    bwrap_file = tmp_path / "bwrap.json"
    net_file.write_text(
        json.dumps(
            {
                "mode": "filter",
                "policy": "deny",
                "allow": [],
                "deny": [],
                "allow_hosts": [],
                "deny_hosts": [],
                "deny_presets": [],
            }
        ),
        encoding="utf-8",
    )
    bwrap_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        network_inner,
        "run_network_inner",
        lambda *a, **k: (_ for _ in ()).throw(click.ClickException("no nft")),
    )
    with pytest.raises(SystemExit) as exc:
        network_inner.main([str(net_file), str(bwrap_file)])
    assert exc.value.code == 1
    assert "no nft" in capsys.readouterr().err


def test_network_inner_appends_debug_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    net_file = tmp_path / "net.json"
    bwrap_file = tmp_path / "bwrap.json"
    net_file.write_text(
        json.dumps(
            {
                "mode": "none",
                "policy": "allow",
                "allow": [],
                "deny": [],
                "allow_hosts": [],
                "deny_hosts": [],
            }
        ),
        encoding="utf-8",
    )
    bwrap_file.write_text(json.dumps(["bwrap", "--", "true"]), encoding="utf-8")
    log_path = tmp_path / "debug.log"
    log_path.write_text("DEBUG buddelkiste: already here\n", encoding="utf-8")
    monkeypatch.setenv("BUDDELKISTE_DEBUG", "1")
    monkeypatch.setenv("BUDDELKISTE_DEBUG_FILE", str(log_path))
    monkeypatch.setenv("BUDDELKISTE_DEBUG_STDERR", "0")

    def fake_inner(net, bwrap_args, *, start_slirp):
        logging.getLogger("buddelkiste.network").debug("from inner")
        return 0

    monkeypatch.setattr(network_inner, "run_network_inner", fake_inner)
    with pytest.raises(SystemExit) as exc:
        network_inner.main([str(net_file), str(bwrap_file)])
    assert exc.value.code == 0
    text = log_path.read_text(encoding="utf-8")
    assert "already here" in text
    assert "DEBUG buddelkiste.network [netns]: from inner" in text
    assert "from inner" not in capsys.readouterr().err
