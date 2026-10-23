from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(params=["pasta", "slirp4netns"])
def filter_backend(request: pytest.FixtureRequest) -> str:
    """Run each filter-mode test once per userspace backend."""
    return request.param


@pytest.fixture
def run_bk(integ_workspace: dict[str, Path], filter_backend: str):
    """Run ``bk run`` with ``--net-backend`` pinned to this param."""
    import subprocess

    def _run(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HOME"] = str(integ_workspace["home"])
        env["XDG_RUNTIME_DIR"] = str(integ_workspace["runtime"])
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "buddelkiste",
                "run",
                "--net-backend",
                filter_backend,
                *args,
            ],
            cwd=integ_workspace["work"],
            env=env,
            check=check,
            capture_output=True,
            text=True,
        )

    return _run
