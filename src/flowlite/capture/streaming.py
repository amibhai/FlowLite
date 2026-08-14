"""Shared machinery for drivers that read a live capture byte stream.

Both the SSH driver and the local-interface driver do the same thing: run a
capture tool that writes a pcap/pcapng stream, split it into rotated files, and
publish each completed file. Only the transport differs, so it lives here once.

Failure handling is the point of this module:

* stderr is **captured and reported**, not discarded. The predecessor appended
  ``2>/dev/null`` to the remote command, so "tcpdump: no such device" became an
  empty file and a generic "capture failed" every fifteen seconds forever.
* The stream is validated as pcap/pcapng within the first bytes, so a device
  that prints a CLI banner or an error instead of packets fails immediately with
  the device's own message quoted back.
* Reconnects use exponential backoff with jitter, so a switch that is down does
  not get hammered once every retry interval indefinitely.
"""

from __future__ import annotations

import queue
import random
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from ..errors import ParseError
from .base import CaptureArtifact, CaptureSource
from .splitter import MAX_HEADER_WAIT, StreamSplitter, header_bytes_needed, make_splitter

__all__ = ["StreamingCaptureSource", "StreamHandle"]


class StreamHandle:
    """A running capture process, abstracted away from its transport."""

    def __init__(
        self,
        read: Callable[[int], bytes],
        close: Callable[[], None],
        stderr_text: Callable[[], str],
        exit_status: Callable[[], Optional[int]],
        description: str = "",
    ) -> None:
        self.read = read
        self.close = close
        self.stderr_text = stderr_text
        self.exit_status = exit_status
        self.description = description


class StreamingCaptureSource(CaptureSource):
    """Base for drivers that consume a live pcap stream and rotate it to files."""

    name = "streaming"

    def __init__(self, cfg, logger, status=None) -> None:
        super().__init__(cfg, logger, status)
        self.rotate_seconds = float(cfg.capture.rotate_seconds)
        self.max_file_bytes = int(cfg.capture.max_file_mb) * 1_048_576
        self.retry_initial = float(cfg.capture.retry_initial_s)
        self.retry_max = float(cfg.capture.retry_max_s)
        self.output_dir = Path(cfg.paths.pcap_dir)
        self._cycle = 0

    # -- transport hook ---------------------------------------------------- #

    def open_stream(self) -> StreamHandle:  # pragma: no cover - overridden
        raise NotImplementedError

    def command_line(self) -> str:  # pragma: no cover - overridden
        return ""

    # -- naming ------------------------------------------------------------- #

    def _next_path(self, started_at: float) -> Path:
        stamp = datetime.fromtimestamp(started_at, tz=timezone.utc)
        day_dir = self.output_dir / stamp.strftime("%Y-%m-%d")
        safe_device = (
            "".join(c if c.isalnum() or c in "-_." else "_" for c in self.device) or "capture"
        )
        return day_dir / f"{safe_device}_{stamp.strftime('%H%M%SZ')}.pcap"

    # -- main loop ---------------------------------------------------------- #

    def run(self, output: queue.Queue[CaptureArtifact], stop_event: threading.Event) -> None:
        backoff = self.retry_initial
        self._set_status(running=True, mode=self.name)

        while not stop_event.is_set():
            self._cycle += 1
            self._set_status(cycle=self._cycle)
            started = time.time()
            try:
                produced = self._capture_once(output, stop_event)
                if produced > 0:
                    backoff = self.retry_initial
                    continue
                if stop_event.is_set():
                    break
                self.log.warning(
                    "Capture cycle #%d produced no complete files after %.0fs",
                    self._cycle,
                    time.time() - started,
                )
            except ParseError as exc:
                self.log.error("Capture cycle #%d rejected the stream: %s", self._cycle, exc)
            except Exception as exc:
                self.log.error("Capture cycle #%d failed: %s", self._cycle, exc, exc_info=True)

            if stop_event.is_set():
                break
            # Full jitter keeps a fleet of collectors from reconnecting in lockstep.
            delay = min(self.retry_max, backoff) * (0.5 + random.random() * 0.5)
            self.log.info("Retrying capture in %.0fs", delay)
            self._set_status(retry_in_s=round(delay, 1))
            stop_event.wait(timeout=delay)
            backoff = min(self.retry_max, max(self.retry_initial, backoff * 2))

        self._set_status(running=False)
        self.log.info("%s capture stopped", self.name)

    def _capture_once(
        self, output: queue.Queue[CaptureArtifact], stop_event: threading.Event
    ) -> int:
        completed: List[Tuple[Path, int, float, float]] = []
        rotation_started = time.time()

        def on_complete(path: Path, records: int) -> None:
            completed.append((path, records, rotation_started, time.time()))

        handle = self.open_stream()
        self.log.info("Capture started: %s", handle.description or self.command_line())

        splitter: Optional[StreamSplitter] = None
        head = bytearray()
        published = 0
        file_started = time.time()

        try:
            for chunk in self._read_chunks(handle, stop_event):
                if splitter is None:
                    head.extend(chunk)
                    if header_bytes_needed(bytes(head)) > 0:
                        if len(head) > MAX_HEADER_WAIT:
                            raise ParseError("no capture file header appeared in the first 1 MB")
                        continue
                    splitter = make_splitter(bytes(head), on_complete)
                    file_started = rotation_started = time.time()
                    splitter.open_file(self._next_path(file_started))
                    splitter.feed(bytes(head[splitter.head_bytes_consumed :]))
                    head = bytearray()
                else:
                    splitter.feed(chunk)

                now = time.time()
                self._set_status(
                    current_file=str(splitter.current_path.name) if splitter.current_path else "",
                    current_mb=round(splitter.bytes_in_file / 1_048_576, 2),
                    packets=splitter.total_records,
                )
                too_old = now - file_started >= self.rotate_seconds
                too_big = self.max_file_bytes and splitter.bytes_in_file >= self.max_file_bytes
                if too_old or too_big:
                    splitter.close_file()
                    published += self._publish_completed(completed, output, stop_event)
                    file_started = rotation_started = time.time()
                    splitter.open_file(self._next_path(file_started))
        finally:
            if splitter is not None:
                splitter.close_file()
            try:
                handle.close()
            except Exception:
                pass

        stderr = (handle.stderr_text() or "").strip()
        status = handle.exit_status()
        if stderr:
            level = self.log.warning if published or completed else self.log.error
            level("Capture command stderr: %s", stderr[-1500:])
        if status not in (None, 0) and not stop_event.is_set():
            self.log.error("Capture command exited with status %s", status)

        published += self._publish_completed(completed, output, stop_event)
        return published

    def _publish_completed(
        self,
        completed: List[Tuple[Path, int, float, float]],
        output: queue.Queue[CaptureArtifact],
        stop_event: threading.Event,
    ) -> int:
        published = 0
        while completed:
            path, records, started, ended = completed.pop(0)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if records <= 0:
                # A rotation that captured no packets is not worth a pipeline run.
                self.log.info("Discarding %s: no packets were captured in this interval", path.name)
                try:
                    path.unlink()
                except OSError:
                    pass
                continue
            artifact = CaptureArtifact(
                path=path,
                source=self.name,
                started_at=started,
                ended_at=ended,
                size_bytes=size,
                records=records,
                device=self.device,
            )
            if self._publish(output, artifact, stop_event):
                published += 1
        return published

    def _read_chunks(
        self, handle: StreamHandle, stop_event: threading.Event, chunk_size: int = 262144
    ) -> Iterator[bytes]:
        while not stop_event.is_set():
            try:
                chunk = handle.read(chunk_size)
            except TimeoutError:
                continue
            except OSError as exc:
                self.log.warning("Capture stream read error: %s", exc)
                return
            if chunk is None:
                continue
            if not chunk:
                return
            yield chunk
