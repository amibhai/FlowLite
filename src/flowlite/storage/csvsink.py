"""Append-only CSV output with a locked schema.

The sink this replaces read the entire destination file into memory and rewrote
it on *every* append. At one write every 30 seconds that is quadratic in both
time and memory, and it silently retyped every value on the way through. This
one appends.

Guarantees:

* **True append.** Cost is proportional to the rows being written, never to the
  file already on disk.
* **Locked schema.** The header is written once. If a later write presents a
  different set of columns, the sink refuses to interleave incompatible rows:
  new columns are added by rotating the old file aside and starting a fresh one,
  which keeps every CSV on disk parseable by a single header.
* **Thread safe.** One lock per resolved path, shared process-wide, so several
  producers may target the same file.
* **Crash safe.** Rows are flushed on every write; a kill mid-run costs at most
  the rows still in the OS buffer, and never corrupts earlier rows.
* **Self-healing.** If the file is deleted or replaced underneath a running
  process (log rotation, an operator with ``rm``), the next write reopens it and
  rewrites the header.
"""

from __future__ import annotations

import csv
import os
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["CsvSink", "SchemaMismatch", "read_csv_rows", "iter_csv_rows"]

_LOCKS: Dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()

# Windows keeps handles briefly after close (indexers, AV). Retry rather than die.
_RETRY_DELAYS = (0.05, 0.15, 0.4, 1.0)


class SchemaMismatch(Exception):
    """The on-disk header does not match the sink's field names."""


def _lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve()) if path.parent.exists() else str(path.absolute())
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def _sanitize(value: Any) -> Any:
    """Neutralise spreadsheet formula injection and stray newlines.

    Flow data contains attacker-influenced strings (hostnames, interface
    descriptions). A cell beginning ``=``/``+``/``-``/``@`` is executed as a
    formula by Excel and LibreOffice when the CSV is opened, so those cells are
    prefixed with an apostrophe. Values are unchanged for every normal input.
    """
    if value is None:
        return ""
    if isinstance(value, float):
        # Keep CSVs free of 'nan'/'inf' tokens that break downstream parsers.
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        return value
    if isinstance(value, str):
        if value[:1] in ("=", "+", "-", "@", "\t", "\r") and len(value) > 1:
            return "'" + value
        return value
    return value


class CsvSink:
    """A durable, append-only CSV writer with a fixed column set."""

    def __init__(
        self,
        path: str | Path,
        fieldnames: Sequence[str],
        *,
        max_bytes: int = 0,
        backups: int = 0,
        sanitize: bool = True,
        on_schema_change: str = "rotate",
    ) -> None:
        """
        Args:
            path: Destination CSV.
            fieldnames: The complete, ordered column set.
            max_bytes: Rotate once the file exceeds this size (0 disables).
            backups: How many rotated generations to keep (0 keeps all).
            sanitize: Apply CSV-injection and NaN neutralisation.
            on_schema_change: ``rotate`` (default) moves a file with a different
                header aside; ``error`` raises :class:`SchemaMismatch`.
        """
        if not fieldnames:
            raise ValueError("CsvSink requires at least one field name")
        duplicates = [f for f in fieldnames if list(fieldnames).count(f) > 1]
        if duplicates:
            raise ValueError(
                f"CsvSink field names must be unique; duplicated: {sorted(set(duplicates))}"
            )
        if on_schema_change not in ("rotate", "error"):
            raise ValueError("on_schema_change must be 'rotate' or 'error'")

        self.path = Path(path)
        self.fieldnames: List[str] = list(fieldnames)
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self.sanitize = bool(sanitize)
        self.on_schema_change = on_schema_change

        self._lock = _lock_for(self.path)
        self._handle = None
        self._writer: Optional[csv.DictWriter] = None
        self._inode: Optional[tuple] = None
        self.rows_written = 0

    # -- lifecycle -------------------------------------------------------- #

    def __enter__(self) -> CsvSink:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._close_handle()

    def _close_handle(self) -> None:
        if self._handle is not None:
            try:
                self._handle.flush()
                self._handle.close()
            except OSError:
                pass
        self._handle = None
        self._writer = None
        self._inode = None

    # -- internals -------------------------------------------------------- #

    def _existing_header(self) -> Optional[List[str]]:
        try:
            if not self.path.exists() or self.path.stat().st_size == 0:
                return None
            with self.path.open("r", encoding="utf-8", newline="") as handle:
                first = handle.readline()
            if not first.strip():
                return None
            return next(csv.reader([first]), None)
        except OSError:
            return None

    def _rotate(self, reason: str) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.path.with_name(f"{self.path.stem}.{stamp}{self.path.suffix}")
        counter = 1
        while target.exists():
            target = self.path.with_name(f"{self.path.stem}.{stamp}-{counter}{self.path.suffix}")
            counter += 1
        self._close_handle()
        for delay in _RETRY_DELAYS + (0,):
            try:
                os.replace(str(self.path), str(target))
                break
            except OSError:
                if delay:
                    time.sleep(delay)
        self._prune_backups()
        return target

    def _prune_backups(self) -> None:
        if self.backups <= 0:
            return
        pattern = f"{self.path.stem}.*{self.path.suffix}"
        try:
            rotated = sorted(
                (p for p in self.path.parent.glob(pattern) if p != self.path),
                key=lambda p: p.name,
            )
        except OSError:
            return
        for stale in rotated[: max(0, len(rotated) - self.backups)]:
            try:
                stale.unlink()
            except OSError:
                pass

    def _ensure_open(self) -> None:
        if self._handle is not None:
            # Detect the file being deleted or swapped underneath us.
            try:
                stat = self.path.stat()
                if self._inode is not None and (stat.st_ino, stat.st_dev) != self._inode:
                    self._close_handle()
                elif stat.st_ino == 0:  # Windows reports 0 for some filesystems
                    pass
            except OSError:
                self._close_handle()
        if self._handle is not None:
            if self.max_bytes and self._handle.tell() >= self.max_bytes:
                self._rotate("size")
            else:
                return

        self.path.parent.mkdir(parents=True, exist_ok=True)

        header = self._existing_header()
        if header is not None and header != self.fieldnames:
            if self.on_schema_change == "error":
                raise SchemaMismatch(
                    f"{self.path} has header {header} but this writer produces {self.fieldnames}"
                )
            self._rotate("schema change")

        write_header = not self.path.exists() or self.path.stat().st_size == 0

        last_error: Optional[OSError] = None
        for delay in _RETRY_DELAYS + (0,):
            try:
                self._handle = self.path.open("a", encoding="utf-8", newline="")
                last_error = None
                break
            except OSError as exc:
                last_error = exc
                if delay:
                    time.sleep(delay)
        if last_error is not None or self._handle is None:
            raise OSError(f"Cannot open {self.path} for append: {last_error}")

        try:
            stat = os.fstat(self._handle.fileno())
            self._inode = (stat.st_ino, stat.st_dev)
        except OSError:
            self._inode = None

        self._writer = csv.DictWriter(
            self._handle,
            fieldnames=self.fieldnames,
            extrasaction="ignore",
            restval="",
            lineterminator="\n",
        )
        if write_header:
            self._writer.writeheader()
            self._handle.flush()

    # -- writing ---------------------------------------------------------- #

    def write_row(self, row: Dict[str, Any]) -> int:
        return self.write_rows((row,))

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> int:
        """Append ``rows``; returns how many were written."""
        batch = [r for r in rows if r]
        if not batch:
            return 0
        with self._lock:
            self._ensure_open()
            assert self._writer is not None and self._handle is not None
            if self.sanitize:
                batch = [{k: _sanitize(v) for k, v in row.items()} for row in batch]
            self._writer.writerows(batch)
            self._handle.flush()
            self.rows_written += len(batch)
            if self.max_bytes and self._handle.tell() >= self.max_bytes:
                self._rotate("size")
        return len(batch)

    def flush(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.flush()
                except OSError:
                    pass

    def __repr__(self) -> str:
        return f"<CsvSink {self.path} cols={len(self.fieldnames)} written={self.rows_written}>"


# --------------------------------------------------------------------------- #
# Reading helpers
# --------------------------------------------------------------------------- #


def iter_csv_rows(path: str | Path) -> Iterator[Dict[str, str]]:
    """Stream a CSV as dicts, skipping malformed lines instead of aborting."""
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return
    with target.open("r", encoding="utf-8", newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return
        width = len(reader.fieldnames)
        for row in reader:
            # csv.DictReader files surplus fields under the None key and pads
            # missing ones with a None value. Either means the line is short,
            # long or otherwise corrupt, so it is skipped rather than yielding
            # silently wrong data.
            if None in row or len(row) != width:
                continue
            if any(value is None for value in row.values()):
                continue
            yield dict(row)


def read_csv_rows(path: str | Path, limit: int = 0) -> List[Dict[str, str]]:
    """Materialise a CSV as a list of dicts (``limit`` 0 means everything)."""
    out: List[Dict[str, str]] = []
    for row in iter_csv_rows(path):
        out.append(row)
        if limit and len(out) >= limit:
            break
    return out
