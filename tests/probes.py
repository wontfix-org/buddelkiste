"""Runtime capability probes for integration tests."""

from __future__ import annotations

import os
import subprocess
from functools import cache
from pathlib import Path

from buddelkiste.which import path_with_tools


@cache
def has_tun() -> bool:
    return Path("/dev/net/tun").exists()


@cache
def can_nested_user() -> bool:
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "true"],
        check=False,
        capture_output=True,
    )
    return proc.returncode == 0


@cache
def can_nested_net() -> bool:
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "true"],
        check=False,
        capture_output=True,
    )
    return proc.returncode == 0


def env_with_host_tools() -> dict[str, str]:
    """Environment whose PATH can exec host tools that live in sbin."""
    env = os.environ.copy()
    env["PATH"] = path_with_tools(("nft", "ip", "setpriv"), env.get("PATH"))
    return env


@cache
def in_bwrap_sandbox() -> bool:
    """True when PID 1 is bubblewrap (nested / agent sandbox)."""
    try:
        cmdline = Path("/proc/1/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    if not cmdline or not cmdline[0]:
        return False
    return Path(os.fsdecode(cmdline[0])).name == "bwrap"
