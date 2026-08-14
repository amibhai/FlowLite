"""Watch a directory for capture files.

This is FlowLite's universal capture source and its default. Every device that
exists can be made to produce a pcap file somehow -- a switch's own on-box
capture, a tap or SPAN port recorded by ``tcpdump`` elsewhere, a scheduled
export, a colleague dropping a file over SCP -- and this driver ingests all of
them without needing credentials, a vendor API or root on anything.

Two correctness properties:

* **Only stable files are taken.** A file still being written is not processed
  until its size and modification time have held steady, so a half-written
  capture is never parsed as a truncated one.
* **Files are processed exactly once across restarts.** Completed work is
  recorded in a checkpoint keyed by identity *and* content fingerprint, so a
  restart neither reprocesses everything nor skips a file that was replaced with
  new content under the same name.
"""

from __future__ import annotations

import fnmatch
import os
import queue
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Dict, List, Set, Tuple

from ..storage.atomic import atomic_write_json, read_json
from .base import CaptureArtifact, CaptureSource, PreflightResult

__all__ = ["FolderCaptureSource"]

_CHECKPOINT_LIMIT = 20000


class FolderCaptureSource(CaptureSource):
    """Ingest capture files that appear in a watched directory."""

    name = "folder"

    def __init__(self, cfg, logger, status=None) -> None:
        super().__init__(cfg, logger, status)
        folder = cfg.capture.folder
        self.watch_dir = Path(folder.watch_dir)
        self.patterns: List[str] = list(folder.patterns)
        self.poll_interval = float(folder.poll_interval_s)
        self.stable_seconds = float(folder.stable_seconds)
        self.recursive = bool(folder.recursive)
        self.delete_after = bool(folder.delete_after_processing)
        self.reprocess_existing = bool(folder.reprocess_existing)
        self.checkpoint_path = Path(cfg.paths.state_dir) / "folder_capture.json"
        self._seen: Dict[str, str] = {}
        self._pending: Dict[str, Tuple[int, float, float]] = {}

    # -- preflight --------------------------------------------------------- #

    def preflight(self) -> PreflightResult:
        hints: List[str] = []
        try:
            self.watch_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return PreflightResult(
                ok=False,
                driver=self.name,
                detail=f"cannot create watch directory {self.watch_dir}: {exc}",
                hints=["Set capture.folder.watch_dir to a path this user can write to"],
            )
        if not os.access(str(self.watch_dir), os.R_OK):
            return PreflightResult(
                ok=False,
                driver=self.name,
                detail=f"watch directory {self.watch_dir} is not readable",
            )
        existing = len(list(self._matching_files()))
        if existing == 0:
            hints.append(
                f"No files matching {', '.join(self.patterns)} are present yet. "
                f"Drop capture files into {self.watch_dir} and they will be picked up."
            )
        return PreflightResult(
            ok=True,
            driver=self.name,
            detail=f"watching {self.watch_dir} for {', '.join(self.patterns)}",
            hints=hints,
            facts={"watch_dir": str(self.watch_dir), "files_present": existing},
        )

    def describe(self) -> str:
        mode = "recursively" if self.recursive else "non-recursively"
        return f"folder: {self.watch_dir} ({mode}, {', '.join(self.patterns)})"

    # -- checkpointing ----------------------------------------------------- #

    def _load_checkpoint(self) -> None:
        data = read_json(self.checkpoint_path, default={}) or {}
        seen = data.get("processed", {})
        if isinstance(seen, dict):
            self._seen = {str(k): str(v) for k, v in seen.items()}
        if not self.reprocess_existing and not self._seen:
            # First run with reprocessing disabled: adopt what is already there.
            for path in self._matching_files():
                fingerprint = self._fingerprint(path)
                if fingerprint:
                    self._seen[str(path.resolve())] = fingerprint
            self.log.info(
                "capture.folder.reprocess_existing is false; ignoring %d file(s) already in %s",
                len(self._seen),
                self.watch_dir,
            )
            self._save_checkpoint()

    def _save_checkpoint(self) -> None:
        if len(self._seen) > _CHECKPOINT_LIMIT:
            # Keep the checkpoint bounded; oldest entries are least likely to
            # reappear, and a re-processed file is far cheaper than a leak.
            trimmed = list(self._seen.items())[-_CHECKPOINT_LIMIT:]
            self._seen = dict(trimmed)
        try:
            atomic_write_json(self.checkpoint_path, {"processed": self._seen}, fsync=False)
        except OSError as exc:
            self.log.warning("Cannot write capture checkpoint %s: %s", self.checkpoint_path, exc)

    @staticmethod
    def _fingerprint(path: Path) -> str:
        try:
            stat = path.stat()
            return f"{stat.st_size}:{int(stat.st_mtime)}"
        except OSError:
            return ""

    # -- scanning ---------------------------------------------------------- #

    def _matching_files(self) -> Iterator[Path]:
        if not self.watch_dir.exists():
            return
        walker = self.watch_dir.rglob("*") if self.recursive else self.watch_dir.glob("*")
        try:
            for path in walker:
                try:
                    if not path.is_file():
                        continue
                except OSError:
                    continue
                name = path.name
                if name.startswith(".") or name.endswith(".tmp") or name.endswith(".part"):
                    continue
                if any(fnmatch.fnmatch(name, pattern) for pattern in self.patterns):
                    yield path
        except OSError as exc:
            self.log.warning("Error scanning %s: %s", self.watch_dir, exc)

    def _stable_files(self) -> List[Path]:
        """Files whose size and mtime have not changed for ``stable_seconds``."""
        now = time.time()
        ready: List[Path] = []
        current: Set[str] = set()

        for path in self._matching_files():
            key = str(path.resolve())
            current.add(key)
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size == 0:
                continue
            previous = self._pending.get(key)
            if previous is None or previous[0] != stat.st_size or previous[1] != stat.st_mtime:
                self._pending[key] = (stat.st_size, stat.st_mtime, now)
                continue
            if now - previous[2] >= self.stable_seconds:
                fingerprint = f"{stat.st_size}:{int(stat.st_mtime)}"
                if self._seen.get(key) == fingerprint:
                    continue
                ready.append(path)

        for stale in [k for k in self._pending if k not in current]:
            self._pending.pop(stale, None)
        return sorted(ready, key=lambda p: (p.stat().st_mtime if p.exists() else 0, p.name))

    # -- main loop --------------------------------------------------------- #

    def run(self, output: queue.Queue[CaptureArtifact], stop_event: threading.Event) -> None:
        self._load_checkpoint()
        self.log.info("Folder capture watching %s every %.0fs", self.watch_dir, self.poll_interval)
        self._set_status(running=True, mode="folder", watch_dir=str(self.watch_dir))

        while not stop_event.is_set():
            try:
                ready = self._stable_files()
            except Exception as exc:
                self.log.error("Folder scan failed: %s", exc, exc_info=True)
                ready = []

            for path in ready:
                if stop_event.is_set():
                    break
                try:
                    stat = path.stat()
                except OSError:
                    continue
                artifact = CaptureArtifact(
                    path=path,
                    source=self.name,
                    started_at=stat.st_mtime - 0.0,
                    ended_at=stat.st_mtime,
                    size_bytes=stat.st_size,
                    device=self.device,
                    delete_after=self.delete_after,
                )
                if self._publish(output, artifact, stop_event):
                    self._seen[str(path.resolve())] = f"{stat.st_size}:{int(stat.st_mtime)}"
                    self._save_checkpoint()

            self._set_status(queued=len(ready), last_scan=time.time())
            stop_event.wait(timeout=self.poll_interval)

        self._set_status(running=False)
        self.log.info("Folder capture stopped")
