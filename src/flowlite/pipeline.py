"""The analysis stage: capture file in, three CSVs out.

Sequence per capture file: extract flows, write the per-file flow CSV, fold the
same rows into host profiles and the network time series, join in whatever
telemetry has arrived, then apply retention.

Notable corrections over the previous pipeline:

* Flow rows are streamed straight to the CSV sink as they are produced, so peak
  memory does not scale with the number of flows in a file.
* The network time series spine comes from the flow data's own timestamps
  instead of "one hour before now", which is why every joined column used to be
  zero.
* Retention never deletes ``network_ts.csv`` (or anything else named in
  ``retention.protect``) and never walks the current working directory because a
  path was left empty.
* Analysis runs in-process. The predecessor shelled out to ``python3 -m ...``,
  which does not exist on Windows and made failures invisible.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analytics.host_profiles import HOST_PROFILE_FIELDS, HostProfileAggregator
from .analytics.network_ts import NETWORK_TS_FIELDS, NetworkTimeSeriesBuilder
from .capture.base import CaptureArtifact
from .enrich.geoip import Enricher
from .flow.schema import FLOW_FIELDS, flow_record_to_row
from .flow.table import PcapFlowExtractor
from .storage.csvsink import CsvSink

__all__ = ["PipelineWorker", "PipelineResult", "apply_retention"]


@dataclass
class PipelineResult:
    """Outcome of processing one capture file."""

    artifact: str = ""
    ok: bool = True
    error: str = ""
    flows: int = 0
    packets: int = 0
    packets_decoded: int = 0
    host_profiles: int = 0
    ts_rows: int = 0
    elapsed_s: float = 0.0
    flows_csv: str = ""
    warnings: List[str] = field(default_factory=list)
    finished_at: float = field(default_factory=time.time)

    def summary(self) -> str:
        if not self.ok:
            return f"{self.artifact}: FAILED -- {self.error}"
        return (
            f"{self.artifact}: {self.flows:,} flows, {self.host_profiles:,} host profiles, "
            f"{self.ts_rows:,} time buckets in {self.elapsed_s:.1f}s"
        )


class PipelineWorker:
    """Consume capture artifacts and produce the three analysis CSVs."""

    def __init__(
        self,
        cfg,
        logger,
        enricher: Optional[Enricher] = None,
        status: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.cfg = cfg
        self.log = logger
        self.enricher = enricher if enricher is not None else Enricher()
        self.status: Dict[str, Any] = status if status is not None else {}
        self.device = cfg.device.name or cfg.device.host or cfg.instance

        flow_cfg = cfg.analytics.flow
        self.extractor = PcapFlowExtractor(
            active_timeout_s=flow_cfg.active_timeout_s,
            idle_timeout_s=flow_cfg.idle_timeout_s,
            burst_gap_s=flow_cfg.burst_gap_s,
            max_flows=flow_cfg.max_flows_in_memory,
            min_packets=flow_cfg.min_packets_per_flow,
            max_packets_per_flow=flow_cfg.max_packets_per_flow,
            logger=logger,
        )

        self.profile_sink: Optional[CsvSink] = None
        self.ts_sink: Optional[CsvSink] = None
        if cfg.analytics.host_profiles.enabled:
            self.profile_sink = CsvSink(
                Path(cfg.paths.profiles_dir) / "host_profiles.csv", HOST_PROFILE_FIELDS
            )
        if cfg.analytics.network_ts.enabled:
            self.ts_sink = CsvSink(Path(cfg.paths.network_ts), NETWORK_TS_FIELDS)

        self.history: List[PipelineResult] = []
        self.processed = 0
        self.failed = 0

    # -- per-artifact ------------------------------------------------------- #

    def _flows_csv_path(self, artifact: CaptureArtifact) -> Path:
        stamp = datetime.fromtimestamp(
            artifact.started_at or time.time(), tz=timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")
        stem = "".join(c if c.isalnum() or c in "-_." else "_" for c in artifact.path.stem)
        return Path(self.cfg.paths.flows_dir) / f"{stamp}_{stem}_flows.csv"

    def process(
        self, artifact: CaptureArtifact, stop_event: Optional[threading.Event] = None
    ) -> PipelineResult:
        """Run one capture file through the whole analysis stage."""
        started = time.monotonic()
        result = PipelineResult(artifact=artifact.path.name)
        self.status.update({"busy": True, "current": artifact.path.name})

        try:
            if not artifact.path.exists():
                raise FileNotFoundError(
                    f"capture file disappeared before processing: {artifact.path}"
                )
            if artifact.path.stat().st_size == 0:
                raise ValueError("capture file is empty")

            flows_csv = self._flows_csv_path(artifact)
            result.flows_csv = str(flows_csv)

            profiles = (
                HostProfileAggregator(
                    window_minutes=self.cfg.analytics.host_profiles.window_minutes,
                    device=self.device,
                    logger=self.log,
                )
                if self.profile_sink is not None
                else None
            )
            timeseries = (
                NetworkTimeSeriesBuilder(
                    bucket_seconds=self.cfg.analytics.network_ts.bucket_seconds,
                    device=self.device,
                    logger=self.log,
                )
                if self.ts_sink is not None
                else None
            )

            batch: List[Dict[str, Any]] = []
            with CsvSink(flows_csv, FLOW_FIELDS) as flow_sink:

                def on_flow(record) -> None:
                    row = flow_record_to_row(
                        record,
                        device=self.device,
                        capture_file=artifact.path.name,
                        enricher=self.enricher,
                    )
                    batch.append(row)
                    if profiles is not None:
                        profiles.add_flow(row)
                    if timeseries is not None:
                        timeseries.add_flow(row)
                    # Write in batches so a huge capture never holds every row.
                    if len(batch) >= 2000:
                        flow_sink.write_rows(batch)
                        batch.clear()

                extraction = self.extractor.extract(
                    artifact.path,
                    on_flow,
                    should_stop=(stop_event.is_set if stop_event is not None else None),
                )
                if batch:
                    flow_sink.write_rows(batch)
                    batch.clear()

            result.flows = extraction.flows
            result.packets = extraction.packets_total
            result.packets_decoded = extraction.packets_decoded
            result.warnings.extend(extraction.warnings)

            if profiles is not None and self.profile_sink is not None:
                rows = profiles.rows()
                result.host_profiles = self.profile_sink.write_rows(rows)

            if timeseries is not None and self.ts_sink is not None:
                self._join_external(timeseries)
                rows = timeseries.rows()
                result.ts_rows = self.ts_sink.write_rows(rows)

            if artifact.delete_after:
                try:
                    artifact.path.unlink()
                    self.log.debug("Deleted source capture %s after processing", artifact.path.name)
                except OSError as exc:
                    self.log.warning("Cannot delete %s: %s", artifact.path, exc)

            result.ok = True
            self.processed += 1
        except Exception as exc:
            result.ok = False
            result.error = f"{type(exc).__name__}: {exc}"
            self.failed += 1
            self.log.error("Pipeline failed for %s: %s", artifact.path.name, exc, exc_info=True)

        result.elapsed_s = time.monotonic() - started
        result.finished_at = time.time()
        self.history.append(result)
        if len(self.history) > 50:
            self.history.pop(0)

        self.status.update(
            {
                "busy": False,
                "current": "",
                "processed": self.processed,
                "failed": self.failed,
                "last_result": result.summary(),
                "last_finished": result.finished_at,
            }
        )
        if result.ok:
            self.log.info("%s", result.summary())
            for warning in result.warnings:
                self.log.warning("%s: %s", artifact.path.name, warning)
        return result

    def _join_external(self, timeseries: NetworkTimeSeriesBuilder) -> None:
        """Fold telemetry and flow-protocol CSVs onto the same time spine."""
        for label, path, method in (
            ("telemetry", self.cfg.paths.telemetry_csv, timeseries.add_telemetry_csv),
            ("sFlow", self.cfg.paths.sflow_csv, timeseries.add_sflow_csv),
            ("NetFlow", self.cfg.paths.netflow_csv, timeseries.add_netflow_csv),
        ):
            try:
                consumed = method(path)
                if consumed:
                    self.log.debug("Joined %d %s row(s) from %s", consumed, label, path)
            except Exception as exc:
                self.log.warning("Cannot join %s data from %s: %s", label, path, exc)

    # -- loop --------------------------------------------------------------- #

    def run(self, queue, stop_event: threading.Event) -> None:
        """Consume artifacts until stopped."""
        import queue as _queue

        self.log.info("Pipeline worker started")
        self.status.update({"running": True})
        last_retention = 0.0

        while not stop_event.is_set():
            try:
                artifact = queue.get(timeout=1.0)
            except _queue.Empty:
                if time.monotonic() - last_retention > 3600:
                    last_retention = time.monotonic()
                    apply_retention(self.cfg, self.log)
                continue

            try:
                self.process(artifact, stop_event)
            finally:
                queue.task_done()

            if time.monotonic() - last_retention > 900:
                last_retention = time.monotonic()
                apply_retention(self.cfg, self.log)

        self.close()
        self.status.update({"running": False})
        self.log.info(
            "Pipeline worker stopped after %d file(s), %d failure(s)", self.processed, self.failed
        )

    def close(self) -> None:
        for sink in (self.profile_sink, self.ts_sink):
            if sink is not None:
                try:
                    sink.close()
                except Exception:
                    pass


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def apply_retention(cfg, logger) -> Dict[str, int]:
    """Delete aged capture and CSV files, honouring the protect list."""
    stats = {"pcaps_deleted": 0, "csvs_deleted": 0, "bytes_freed": 0}
    if not cfg.retention.enabled:
        return stats

    protected = {str(name).lower() for name in cfg.retention.protect}
    protected.add(Path(cfg.paths.network_ts).name.lower())
    protected.add(Path(cfg.paths.telemetry_csv).name.lower())
    protected.add(Path(cfg.paths.interfaces_csv).name.lower())
    now = time.time()

    def sweep(root: str, patterns: List[str], max_age_days: int, key: str) -> None:
        if max_age_days <= 0:
            return
        # An empty or "." path must never be swept: the predecessor globbed the
        # process working directory for *.pcap when base_dir was unset.
        text = str(root or "").strip()
        if not text or text in (".", "..", "/", "\\"):
            return
        base = Path(text)
        if not base.exists() or not base.is_dir():
            return
        cutoff = now - max_age_days * 86400
        for pattern in patterns:
            for path in base.rglob(pattern):
                try:
                    if not path.is_file() or path.name.lower() in protected:
                        continue
                    stat = path.stat()
                    if stat.st_mtime >= cutoff:
                        continue
                    size = stat.st_size
                    path.unlink()
                    stats[key] += 1
                    stats["bytes_freed"] += size
                except OSError:
                    continue

    sweep(cfg.paths.pcap_dir, ["*.pcap", "*.pcapng"], cfg.retention.pcap_days, "pcaps_deleted")
    sweep(
        cfg.capture.folder.watch_dir,
        ["*.pcap", "*.pcapng", "*.pcap.gz", "*.pcapng.gz"],
        cfg.retention.pcap_days,
        "pcaps_deleted",
    )
    sweep(cfg.paths.flows_dir, ["*.csv"], cfg.retention.csv_days, "csvs_deleted")
    sweep(cfg.paths.profiles_dir, ["*.csv"], cfg.retention.csv_days, "csvs_deleted")

    cap_gb = float(cfg.retention.max_data_dir_gb or 0)
    if cap_gb > 0:
        stats["bytes_freed"] += _enforce_size_cap(cfg, cap_gb, protected, logger)

    if stats["pcaps_deleted"] or stats["csvs_deleted"]:
        logger.info(
            "Retention removed %d capture file(s) and %d CSV(s), freeing %.1f MB",
            stats["pcaps_deleted"],
            stats["csvs_deleted"],
            stats["bytes_freed"] / 1_048_576,
        )
    return stats


def _enforce_size_cap(cfg, cap_gb: float, protected: set, logger) -> int:
    """Delete the oldest capture files until the data directory fits the cap."""
    root = Path(cfg.paths.data_dir)
    if not root.exists():
        return 0
    entries: List[tuple] = []
    total = 0
    for path in root.rglob("*"):
        try:
            if not path.is_file():
                continue
            stat = path.stat()
            total += stat.st_size
            if (
                path.suffix.lower() in (".pcap", ".pcapng", ".gz")
                and path.name.lower() not in protected
            ):
                entries.append((stat.st_mtime, stat.st_size, path))
        except OSError:
            continue

    cap_bytes = int(cap_gb * 1_073_741_824)
    if total <= cap_bytes:
        return 0

    freed = 0
    entries.sort()
    for _mtime, size, path in entries:
        if total - freed <= cap_bytes:
            break
        try:
            path.unlink()
            freed += size
        except OSError:
            continue
    if freed:
        logger.warning(
            "Data directory exceeded retention.max_data_dir_gb (%.1f GB); deleted the oldest "
            "capture files to free %.1f MB",
            cap_gb,
            freed / 1_048_576,
        )
    return freed
