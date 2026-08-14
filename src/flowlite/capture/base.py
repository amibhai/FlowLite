"""Capture driver interface.

Every capture source -- a directory someone drops files into, an SSH session to
a switch, a local interface -- produces the same thing: a completed capture file
announced on a queue. The rest of the pipeline neither knows nor cares which
driver produced it, which is what makes FlowLite device-agnostic.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["CaptureArtifact", "CaptureSource", "PreflightResult"]


@dataclass
class CaptureArtifact:
    """A capture file that is complete and ready to process."""

    path: Path
    source: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    size_bytes: int = 0
    records: int = 0
    device: str = ""
    delete_after: bool = False

    @property
    def duration_s(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    def label(self) -> str:
        stamp = datetime.fromtimestamp(self.started_at or 0, tz=timezone.utc)
        return stamp.strftime("%Y%m%dT%H%M%SZ")

    def __str__(self) -> str:
        return f"{self.path.name} ({self.size_bytes / 1_048_576:.1f} MB via {self.source})"


@dataclass
class PreflightResult:
    """Outcome of checking whether a driver can actually run."""

    ok: bool
    driver: str = ""
    detail: str = ""
    hints: List[str] = field(default_factory=list)
    facts: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        status = "OK" if self.ok else "FAILED"
        lines = [f"{self.driver}: {status} -- {self.detail}"]
        lines.extend(f"    hint: {hint}" for hint in self.hints)
        return "\n".join(lines)


class CaptureSource:
    """Base class for capture drivers."""

    name = "base"

    def __init__(self, cfg, logger, status: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = cfg
        self.log = logger
        self.status: Dict[str, Any] = status if status is not None else {}
        self.device = cfg.device.name or cfg.device.host or cfg.instance

    # -- interface --------------------------------------------------------- #

    def preflight(self) -> PreflightResult:
        """Check prerequisites without capturing anything."""
        return PreflightResult(ok=True, driver=self.name, detail="no preflight checks defined")

    def describe(self) -> str:
        return self.name

    def run(self, output: queue.Queue[CaptureArtifact], stop_event: threading.Event) -> None:
        """Capture until ``stop_event`` is set, putting artifacts on ``output``."""
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------- #

    def _set_status(self, **fields: Any) -> None:
        self.status.update(fields)

    def _publish(
        self,
        output: queue.Queue[CaptureArtifact],
        artifact: CaptureArtifact,
        stop_event: threading.Event,
    ) -> bool:
        """Enqueue an artifact, applying back-pressure rather than dropping it.

        A bounded queue is what keeps a slow analysis stage from letting capture
        files pile up until the disk fills. If the consumer is behind, this
        blocks -- with a timeout so shutdown still works -- instead of silently
        discarding data.
        """
        while not stop_event.is_set():
            try:
                output.put(artifact, timeout=1.0)
                self.log.info("Capture ready: %s", artifact)
                self._set_status(
                    last_file=artifact.path.name,
                    last_file_mb=round(artifact.size_bytes / 1_048_576, 2),
                    files_produced=int(self.status.get("files_produced", 0)) + 1,
                )
                return True
            except queue.Full:
                self.log.warning(
                    "Processing queue is full; capture is waiting for the analysis stage "
                    "to catch up (%s)",
                    artifact.path.name,
                )
        return False
