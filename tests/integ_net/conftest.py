from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


@pytest.fixture
def run_bk(integ_workspace: dict[str, Path]):
    """Run ``bk run`` in filter mode (pasta)."""
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
                *args,
            ],
            cwd=integ_workspace["work"],
            env=env,
            check=check,
            capture_output=True,
            text=True,
        )

    return _run
