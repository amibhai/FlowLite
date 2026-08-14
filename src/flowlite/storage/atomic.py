"""Atomic file replacement.

State files (checkpoints, health reports) must never be observed half-written,
including when the process is killed mid-write. Every writer here goes through a
temporary file in the *same directory* -- so ``os.replace`` stays atomic on the
same filesystem -- followed by an ``fsync`` before the rename.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

__all__ = ["atomic_write_bytes", "atomic_write_text", "atomic_write_json", "read_json"]


def atomic_write_bytes(path: str | Path, data: bytes, fsync: bool = True) -> None:
    """Replace ``path`` with ``data`` atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            if fsync:
                os.fsync(handle.fileno())
        os.replace(tmp_name, str(target))
        tmp_name = ""
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def atomic_write_text(
    path: str | Path, text: str, encoding: str = "utf-8", fsync: bool = True
) -> None:
    atomic_write_bytes(path, text.encode(encoding), fsync=fsync)


def atomic_write_json(path: str | Path, payload: Any, indent: int = 2, fsync: bool = True) -> None:
    atomic_write_text(
        path, json.dumps(payload, indent=indent, default=str, sort_keys=True) + "\n", fsync=fsync
    )


def read_json(path: str | Path, default: Optional[Any] = None) -> Any:
    """Read JSON, returning ``default`` for any missing or corrupt file.

    Checkpoint files are read on startup after a possibly unclean shutdown, so a
    truncated file must degrade to "start fresh" rather than abort the process.
    """
    target = Path(path)
    try:
        if not target.exists() or target.stat().st_size == 0:
            return default
        with target.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default
