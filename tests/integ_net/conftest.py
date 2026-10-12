from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from buddelkiste.network import NET_HELPER_ENV
from tests.probes import (
    can_nested_net,
    has_bwrap,
    has_net_helper,
    has_nft,
    has_outbound_network,
    has_pasta,
    has_setpriv,
    has_slirp4netns,
    has_tun,
)


@pytest.fixture(params=["pasta", "slirp4netns"])
def filter_backend(request: pytest.FixtureRequest) -> str:
    """Run each filter-mode test once per userspace backend."""
    backend = request.param
    if backend == "pasta" and not has_pasta():
        pytest.skip("pasta not installed")
    if backend == "slirp4netns" and not has_slirp4netns():
        pytest.skip("slirp4netns not installed")
    return backend


@pytest.fixture
def run_bk(integ_workspace: dict[str, Path], filter_backend: str):
    """Run ``bk run`` with ``BUDDELKISTE_NET_HELPER`` pinned to this param."""
    import subprocess

    def _run(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HOME"] = str(integ_workspace["home"])
        env["XDG_RUNTIME_DIR"] = str(integ_workspace["runtime"])
        env[NET_HELPER_ENV] = filter_backend
        return subprocess.run(
            [sys.executable, "-m", "buddelkiste", "run", *args],
            cwd=integ_workspace["work"],
            env=env,
            check=check,
            capture_output=True,
            text=True,
        )

    return _run


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_tun"):
        missing = []
        if not has_tun():
            missing.append("/dev/net/tun")
        if not has_bwrap():
            missing.append("bwrap")
        if not has_nft():
            missing.append("nft")
        if not has_setpriv():
            missing.append("setpriv")
        if not has_net_helper():
            missing.append("pasta|slirp4netns")
        if not can_nested_net():
            missing.append("unshare --user --net")
        if missing:
            pytest.skip("filter e2e unavailable (missing: " + ", ".join(missing) + ")")
    if item.get_closest_marker("requires_outbound") and not has_outbound_network():
        pytest.skip("no outbound network to 1.1.1.1:443")
