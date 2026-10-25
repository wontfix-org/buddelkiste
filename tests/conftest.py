from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

_GIT_OVERRIDE_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")


def git_on_path() -> bool:
    return shutil.which("git") is not None


needs_git = pytest.mark.skipif(not git_on_path(), reason="git is not installed")


def init_git_index(root: Path, files: Mapping[str, str] | None = None) -> Path:
    """Create a git work tree at ``root`` with ``files`` added to the index."""
    if not git_on_path():
        pytest.skip("git is not installed")
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in _GIT_OVERRIDE_VARS:
        env.pop(name, None)
    subprocess.run(
        ["git", "init"],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )
    for rel, content in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        subprocess.run(
            ["git", "add", "--", rel],
            cwd=root,
            check=True,
            capture_output=True,
            env=env,
        )
    return root


@pytest.fixture
def tmp_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config.toml"
    monkeypatch.setattr("buddelkiste.cli.CONFIG_PATH", config)
    return config


@pytest.fixture(autouse=True)
def _disable_docker_proxy_desktop_notifications(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep notify-send popups off the host desktop during the test suite."""
    import buddelkiste.docker_proxy as dp
    from buddelkiste.which import which as real_which

    def which(cmd: str, mode: int = os.F_OK | os.X_OK, path: str | None = None) -> str | None:
        if cmd == "notify-send":
            return None
        return real_which(cmd, mode=mode, path=path)

    monkeypatch.setattr(dp, "which", which)


@pytest.fixture
def runtime_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    return runtime


@pytest.fixture
def integ_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Path]]:
    """Isolated HOME/runtime/workdir with an empty feature allowlist."""
    home = tmp_path / "home"
    runtime = tmp_path / "runtime"
    work = tmp_path / "work"
    home.mkdir()
    runtime.mkdir()
    work.mkdir()

    cfg_dir = home / ".config" / "buddelkiste"
    cfg_dir.mkdir(parents=True)
    config = cfg_dir / "config.toml"
    config.write_text(
        "features = []\n"
        "\n"
        "[[projects]]\n"
        f'path = "{work}"\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.chdir(work)
    yield {"home": home, "runtime": runtime, "work": work, "config": config}

    # Overlayfs leaves ``.<upper>.work/work`` as mode 000; unlock so pytest
    # can remove the basetemp without PytestWarning (rm_rf / ENOTEMPTY).
    from buddelkiste.binds import force_rmtree

    for path in tmp_path.rglob("*.work"):
        if path.is_dir() and path.name.startswith("."):
            force_rmtree(path)


@pytest.fixture
def run_bk(integ_workspace: dict[str, Path]):
    """Run ``python -m buddelkiste`` as a real subprocess."""
    import subprocess

    def _run(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HOME"] = str(integ_workspace["home"])
        env["XDG_RUNTIME_DIR"] = str(integ_workspace["runtime"])
        return subprocess.run(
            [sys.executable, "-m", "buddelkiste", "run", *args],
            cwd=integ_workspace["work"],
            env=env,
            check=check,
            capture_output=True,
            text=True,
        )

    return _run


def pytest_configure(config: pytest.Config) -> None:
    _configure_agent_pytest_defaults(config)
    config.addinivalue_line(
        "markers", "integration: nested-safe integration tests (real bwrap host/none)"
    )
    config.addinivalue_line(
        "markers",
        "e2e: host-only tests (TUN, nested user/net ns, Docker); exclude in bwrap",
    )


def _configure_agent_pytest_defaults(config: pytest.Config) -> None:
    """Agent-only pytest tweaks (quiet progress, missing-line coverage).

    Interactive runs keep normal verbosity so file names are visible, and a
    compact coverage table without per-line Missing indicators.
    """
    if not os.environ.get("CURSOR_AGENT"):
        return

    # ``-q`` / verbose=-1; leave alone if the user passed ``-v`` / ``--verbosity``.
    if getattr(config.option, "verbose", 0) == 0:
        config.option.verbose = -1

    cov_report = getattr(config.option, "cov_report", None)
    if not isinstance(cov_report, dict):
        return
    if "term-missing" in cov_report:
        return
    if "term" in cov_report:
        cov_report["term-missing"] = cov_report.pop("term")
    else:
        cov_report["term-missing"] = None
