"""The telemetry polling loop: driver snapshots in, normalised CSV rows out."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..storage.csvsink import CsvSink
from .base import (
    DEVICE_TELEMETRY_FIELDS,
    INTERFACE_FIELDS,
    CounterTracker,
    DeviceSnapshot,
    TelemetryDriver,
    counter_rate,
    utilisation_pct,
)

__all__ = ["TelemetryCollector", "snapshot_to_rows"]


def _round(value: Optional[float], digits: int = 3) -> Any:
    if value is None:
        return ""
    if value != value or value in (float("inf"), float("-inf")):
        return ""
    return round(float(value), digits)


def snapshot_to_rows(
    snapshot: DeviceSnapshot, tracker: CounterTracker
) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Convert a snapshot into one device row and one row per interface.

    Counter deltas need a previous sample, so a snapshot that cannot be compared
    yet reports blank rates rather than inventing zeros.
    """
    now = snapshot.epoch
    interface_rows: List[Dict[str, Any]] = []

    totals = {
        "in_bytes": 0.0,
        "out_bytes": 0.0,
        "in_packets": 0.0,
        "out_packets": 0.0,
        "in_errors": 0.0,
        "out_errors": 0.0,
        "in_discards": 0.0,
        "out_discards": 0.0,
    }
    rated_interfaces = 0
    resets = 0
    interval_seen = 0.0

    if not snapshot.reachable:
        device_row = {
            "timestamp": snapshot.timestamp,
            "epoch": round(now, 3),
            "device": snapshot.device,
            "driver": snapshot.driver,
            "reachable": 0,
            "poll_ms": _round(snapshot.poll_ms, 1),
            "error": snapshot.error,
        }
        # Every metric column stays empty: an unreachable device is not a device
        # reporting zero, and downstream consumers must be able to tell them apart.
        for field in DEVICE_TELEMETRY_FIELDS:
            device_row.setdefault(field, "")
        return device_row, interface_rows

    for interface in snapshot.interfaces:
        key = f"{snapshot.device}|{interface.index}|{interface.name}"
        deltas = tracker.update(
            key,
            {
                "in_octets": interface.in_octets,
                "out_octets": interface.out_octets,
                "in_packets": interface.in_packets,
                "out_packets": interface.out_packets,
                "in_errors": interface.in_errors,
                "out_errors": interface.out_errors,
                "in_discards": interface.in_discards,
                "out_discards": interface.out_discards,
            },
            now,
            speed_bps=interface.speed_bps,
        )
        interval = float(deltas.get("interval_s", 0.0) or 0.0)
        first = bool(deltas.get("first_sample"))
        resets += int(deltas.get("counter_reset", 0) or 0)
        if interval > 0:
            interval_seen = max(interval_seen, interval)
            rated_interfaces += 1

        in_rate = counter_rate(deltas, "in_octets", interval)
        out_rate = counter_rate(deltas, "out_octets", interval)

        if isinstance(in_rate, float):
            totals["in_bytes"] += in_rate
        if isinstance(out_rate, float):
            totals["out_bytes"] += out_rate
        for name, bucket in (
            ("in_packets", "in_packets"),
            ("out_packets", "out_packets"),
            ("in_errors", "in_errors"),
            ("out_errors", "out_errors"),
            ("in_discards", "in_discards"),
            ("out_discards", "out_discards"),
        ):
            value = deltas.get(f"{name}_delta")
            if value is not None and not first:
                totals[bucket] += float(value)

        interface_rows.append(
            {
                "timestamp": snapshot.timestamp,
                "epoch": round(now, 3),
                "device": snapshot.device,
                "if_index": interface.index,
                "if_name": interface.name,
                "if_alias": interface.alias,
                "admin_status": interface.admin_status,
                "oper_status": interface.oper_status,
                "speed_bps": interface.speed_bps,
                "in_octets": interface.in_octets if interface.in_octets is not None else "",
                "out_octets": interface.out_octets if interface.out_octets is not None else "",
                "in_packets": interface.in_packets if interface.in_packets is not None else "",
                "out_packets": interface.out_packets if interface.out_packets is not None else "",
                "in_errors": interface.in_errors if interface.in_errors is not None else "",
                "out_errors": interface.out_errors if interface.out_errors is not None else "",
                "in_discards": interface.in_discards if interface.in_discards is not None else "",
                "out_discards": interface.out_discards
                if interface.out_discards is not None
                else "",
                "interval_s": interval if interval else "",
                "in_octets_delta": deltas.get("in_octets_delta", ""),
                "out_octets_delta": deltas.get("out_octets_delta", ""),
                "in_bytes_per_s": in_rate,
                "out_bytes_per_s": out_rate,
                "utilisation_in_pct": utilisation_pct(in_rate, interface.speed_bps),
                "utilisation_out_pct": utilisation_pct(out_rate, interface.speed_bps),
                "counter_reset": deltas.get("counter_reset", 0),
            }
        )

    up = sum(1 for i in snapshot.interfaces if i.is_up)
    device_row = {
        "timestamp": snapshot.timestamp,
        "epoch": round(now, 3),
        "device": snapshot.device,
        "driver": snapshot.driver,
        "reachable": 1,
        "poll_ms": _round(snapshot.poll_ms, 1),
        "error": snapshot.error,
        "interfaces_total": len(snapshot.interfaces),
        "interfaces_up": up,
        "interfaces_down": len(snapshot.interfaces) - up,
        "in_bytes_per_s": round(totals["in_bytes"], 3) if rated_interfaces else "",
        "out_bytes_per_s": round(totals["out_bytes"], 3) if rated_interfaces else "",
        "in_packets_per_s": (
            round(totals["in_packets"] / interval_seen, 3) if interval_seen else ""
        ),
        "out_packets_per_s": (
            round(totals["out_packets"] / interval_seen, 3) if interval_seen else ""
        ),
        "in_errors_delta": int(totals["in_errors"]) if rated_interfaces else "",
        "out_errors_delta": int(totals["out_errors"]) if rated_interfaces else "",
        "in_discards_delta": int(totals["in_discards"]) if rated_interfaces else "",
        "out_discards_delta": int(totals["out_discards"]) if rated_interfaces else "",
        "counter_resets": resets,
        "arp_entries": snapshot.arp_entries if snapshot.arp_entries is not None else "",
        "mac_entries": snapshot.mac_entries if snapshot.mac_entries is not None else "",
        "route_entries": snapshot.route_entries if snapshot.route_entries is not None else "",
        "cpu_percent": _round(snapshot.cpu_percent, 2),
        "memory_percent": _round(snapshot.memory_percent, 2),
        "uptime_s": _round(snapshot.uptime_s, 1),
        "system_name": snapshot.system_name,
        "system_description": snapshot.system_description,
    }
    return device_row, interface_rows


class TelemetryCollector:
    """Poll a device on a fixed interval and write normalised CSV rows."""

    def __init__(self, cfg, driver: TelemetryDriver, logger, status: Optional[Dict] = None) -> None:
        self.cfg = cfg
        self.driver = driver
        self.log = logger
        self.status: Dict[str, Any] = status if status is not None else {}
        self.interval = float(cfg.telemetry.interval_s)
        self.tracker = CounterTracker()
        self.device_sink = CsvSink(Path(cfg.paths.telemetry_csv), DEVICE_TELEMETRY_FIELDS)
        self.interface_sink = CsvSink(Path(cfg.paths.interfaces_csv), INTERFACE_FIELDS)
        self.polls = 0
        self.failures = 0
        self.consecutive_failures = 0

    def poll_once(self) -> DeviceSnapshot:
        """Run one poll and persist its rows. Never raises."""
        try:
            snapshot = self.driver.collect()
        except Exception as exc:
            self.log.error("Telemetry driver raised: %s", exc, exc_info=True)
            snapshot = DeviceSnapshot(
                device=self.driver.device,
                driver=self.driver.name,
                reachable=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        self.polls += 1
        if snapshot.reachable:
            self.consecutive_failures = 0
        else:
            self.failures += 1
            self.consecutive_failures += 1

        try:
            device_row, interface_rows = snapshot_to_rows(snapshot, self.tracker)
            self.device_sink.write_row(device_row)
            if interface_rows:
                self.interface_sink.write_rows(interface_rows)
        except Exception as exc:
            self.log.error("Cannot write telemetry rows: %s", exc, exc_info=True)

        self.status.update(
            {
                "running": True,
                "driver": self.driver.name,
                "last_poll": time.time(),
                "reachable": snapshot.reachable,
                "interfaces": len(snapshot.interfaces),
                "polls": self.polls,
                "failures": self.failures,
                "last_error": snapshot.error,
            }
        )
        return snapshot

    def run(self, stop_event: threading.Event) -> None:
        self.log.info(
            "Telemetry collector started: %s every %.0fs", self.driver.describe(), self.interval
        )
        warned = False
        while not stop_event.is_set():
            started = time.monotonic()
            snapshot = self.poll_once()

            if snapshot.reachable:
                self.log.debug("%s", snapshot.summary())
                warned = False
            elif self.consecutive_failures in (1, 5) or self.consecutive_failures % 20 == 0:
                # Log the first failure, again at five, then hourly-ish. A device
                # down for a week must not write a log line every minute.
                self.log.error(
                    "Telemetry poll failed (%d consecutive): %s",
                    self.consecutive_failures,
                    snapshot.error,
                )
                warned = True
            elif not warned:
                self.log.debug("Telemetry poll failed: %s", snapshot.error)

            elapsed = time.monotonic() - started
            if elapsed > self.interval:
                self.log.warning(
                    "Telemetry poll took %.1fs, longer than the %.0fs interval; "
                    "raise telemetry.interval_s or reduce the data collected",
                    elapsed,
                    self.interval,
                )
            stop_event.wait(timeout=max(0.0, self.interval - elapsed))

        self.close()
        self.log.info(
            "Telemetry collector stopped after %d poll(s), %d failure(s)", self.polls, self.failures
        )

    def close(self) -> None:
        for closeable in (self.device_sink, self.interface_sink):
            try:
                closeable.close()
            except Exception:
                pass
        try:
            self.driver.close()
        except Exception:
            pass
        self.status["running"] = False
