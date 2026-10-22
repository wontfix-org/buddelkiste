"""Destinations for ``bk run`` debug logging."""

from __future__ import annotations

import logging
import os
from pathlib import Path

_FILE_ATTR = "_buddelkiste_debug_file"
_STREAM_ATTR = "_buddelkiste_debug_stream"

HOST_LOG_FORMAT = "%(levelname)s %(name)s: %(message)s"
NETNS_LOG_FORMAT = "%(levelname)s %(name)s [netns]: %(message)s"


def configure_debug_logging(
    *,
    enabled: bool,
    stream: bool,
    path: Path | None,
    log_format: str,
    truncate: bool = False,
) -> None:
    """Send log records to stderr, ``path``, or both.

    ``enabled`` selects DEBUG; otherwise the root level is WARNING. ``stream``
    keeps a stderr handler. ``path`` receives a file handler. ``truncate``
    replaces the file first; child processes should append instead.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if enabled else logging.WARNING)
    formatter = logging.Formatter(log_format)

    for handler in list(root.handlers):
        if getattr(handler, _FILE_ATTR, None) is not None:
            root.removeHandler(handler)
            handler.close()

    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if truncate:
            path.write_text("", encoding="utf-8")
        file_handler = logging.FileHandler(path, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        setattr(file_handler, _FILE_ATTR, str(path))
        root.addHandler(file_handler)

    if stream:
        if not any(getattr(handler, _FILE_ATTR, None) is None for handler in root.handlers):
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            setattr(stream_handler, _STREAM_ATTR, True)
            root.addHandler(stream_handler)
        return

    for handler in list(root.handlers):
        if getattr(handler, _STREAM_ATTR, False):
            root.removeHandler(handler)
            handler.close()


def apply_debug_log_env(*, debug: bool, debug_file: Path | None) -> Path | None:
    """Publish the debug destination for child processes and return the file path.

    ``--debug`` logs to stderr. ``--debug-file`` logs to that file. Both
    together log to each. The returned path is absolute so a later ``chdir``
    still appends to the same file.
    """
    path: Path | None = None
    if debug_file is not None:
        path = Path(debug_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path = path.resolve()

    debug_on = debug or path is not None
    configure_debug_logging(
        enabled=debug_on,
        stream=debug or path is None,
        path=path,
        log_format=HOST_LOG_FORMAT,
        truncate=path is not None,
    )
    if debug_on:
        os.environ["BUDDELKISTE_DEBUG"] = "1"
    if path is not None:
        os.environ["BUDDELKISTE_DEBUG_FILE"] = str(path)
        os.environ["BUDDELKISTE_DEBUG_STDERR"] = "1" if debug else "0"
    else:
        os.environ.pop("BUDDELKISTE_DEBUG_FILE", None)
        os.environ.pop("BUDDELKISTE_DEBUG_STDERR", None)
    return path


def configure_debug_logging_from_env(*, log_format: str) -> None:
    """Apply :func:`apply_debug_log_env` settings inside a child process."""
    raw = os.environ.get("BUDDELKISTE_DEBUG_FILE")
    path = Path(raw).expanduser() if raw else None
    enabled = bool(os.environ.get("BUDDELKISTE_DEBUG")) or path is not None
    file_only = os.environ.get("BUDDELKISTE_DEBUG_STDERR") == "0"
    configure_debug_logging(
        enabled=enabled,
        stream=not file_only,
        path=path,
        log_format=log_format,
        truncate=False,
    )
