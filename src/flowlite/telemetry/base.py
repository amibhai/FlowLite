"""The vendor-neutral device telemetry model.

Every telemetry driver -- SNMP, RESTCONF, Arista eAPI, Cisco NX-API, raw CLI over
SSH -- returns the same :class:`DeviceSnapshot`. Downstream code, the CSV schema
and the time series therefore never learn which vendor produced the numbers.
Adding support for a new platform means writing one ``collect()`` method; it
changes nothing else.

The predecessor wrote a row of zeros whenever a poll failed, which is worse than
writing nothing: an unreachable switch and a genuinely idle switch produced
byte-identical output. Snapshots here carry ``reachable`` and ``error``, and
failed polls are recorded as failures.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def counter_rate(deltas: Mapping[str, Any], name: str, interval_s: float) -> Any:
    """Per-second rate for one counter, or ``""`` when it cannot be computed.

    An empty string, not a zero: the first poll after a start or a counter reset
    has no previous sample, and reporting 0 bytes/s there would be indis-
    tinguishable from a genuinely idle link.
    """
    if interval_s <= 0 or deltas.get("first_sample"):
        return ""
    value = deltas.get(f"{name}_delta")
    if value is None:
        return ""
    return round(float(value) / interval_s, 3)


def utilisation_pct(rate_bytes_per_s: Any, speed_bps: int) -> Any:
    """Link utilisation as a percentage, or ``""`` when the speed is unknown."""
    if not speed_bps or not isinstance(rate_bytes_per_s, float):
        return ""
    capacity_bytes = speed_bps / 8.0
    if capacity_bytes <= 0:
        return ""
    return round(100.0 * rate_bytes_per_s / capacity_bytes, 3)


__all__ = [
    "counter_rate",
    "utilisation_pct",
    "InterfaceCounters",
    "DeviceSnapshot",
    "TelemetryDriver",
    "DEVICE_TELEMETRY_FIELDS",
    "INTERFACE_FIELDS",
    "CounterTracker",
]

DEVICE_TELEMETRY_FIELDS = [
    "timestamp",
    "epoch",
    "device",
    "driver",
    "reachable",
    "poll_ms",
    "error",
    "interfaces_total",
    "interfaces_up",
    "interfaces_down",
    "in_bytes_per_s",
    "out_bytes_per_s",
    "in_packets_per_s",
    "out_packets_per_s",
    "in_errors_delta",
    "out_errors_delta",
    "in_discards_delta",
    "out_discards_delta",
    "counter_resets",
    "arp_entries",
    "mac_entries",
    "route_entries",
    "cpu_percent",
    "memory_percent",
    "uptime_s",
    "system_name",
    "system_description",
]

INTERFACE_FIELDS = [
    "timestamp",
    "epoch",
    "device",
    "if_index",
    "if_name",
    "if_alias",
    "admin_status",
    "oper_status",
    "speed_bps",
    "in_octets",
    "out_octets",
    "in_packets",
    "out_packets",
    "in_errors",
    "out_errors",
    "in_discards",
    "out_discards",
    "interval_s",
    "in_octets_delta",
    "out_octets_delta",
    "in_bytes_per_s",
    "out_bytes_per_s",
    "utilisation_in_pct",
    "utilisation_out_pct",
    "counter_reset",
]

_UINT32 = 1 << 32
_UINT64 = 1 << 64


@dataclass
class InterfaceCounters:
    """One interface as reported by a device, in normalised units."""

    index: int = 0
    name: str = ""
    alias: str = ""
    admin_status: str = ""
    oper_status: str = ""
    speed_bps: int = 0
    in_octets: Optional[int] = None
    out_octets: Optional[int] = None
    in_packets: Optional[int] = None
    out_packets: Optional[int] = None
    in_errors: Optional[int] = None
    out_errors: Optional[int] = None
    in_discards: Optional[int] = None
    out_discards: Optional[int] = None
    high_capacity: bool = False

    @property
    def is_up(self) -> bool:
        return self.oper_status.lower() in ("up", "connected", "1")

    @property
    def is_admin_down(self) -> bool:
        return self.admin_status.lower() in ("down", "2", "disabled", "adminDown".lower())


@dataclass
class DeviceSnapshot:
    """One poll of one device, normalised across vendors."""

    device: str = ""
    driver: str = ""
    epoch: float = field(default_factory=time.time)
    reachable: bool = True
    error: str = ""
    poll_ms: float = 0.0
    interfaces: List[InterfaceCounters] = field(default_factory=list)
    arp_entries: Optional[int] = None
    mac_entries: Optional[int] = None
    route_entries: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    uptime_s: Optional[float] = None
    system_name: str = ""
    system_description: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> str:
        return datetime.fromtimestamp(self.epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def summary(self) -> str:
        if not self.reachable:
            return f"{self.device} unreachable via {self.driver}: {self.error}"
        up = sum(1 for i in self.interfaces if i.is_up)
        return (
            f"{self.device} via {self.driver}: {len(self.interfaces)} interfaces "
            f"({up} up) in {self.poll_ms:.0f}ms"
        )


class CounterTracker:
    """Turn monotonic device counters into per-second rates.

    Interface counters wrap and they reset. A 32-bit octet counter on a 10G link
    wraps in under four seconds of line rate; a device reboot or an agent restart
    zeroes everything. Treating either as a plain subtraction produces enormous
    negative rates or enormous positive ones, both of which poison every average
    computed downstream.

    Rules applied here:

    * A decrease on a value that fits in 32 bits, where the 32-bit wrap-corrected
      delta is physically plausible for the interface speed, is treated as a wrap.
    * Any other decrease is treated as a counter reset: the delta is reported as
      zero and the sample is flagged rather than guessed at.
    * The first observation of a counter yields no rate at all -- there is no
      previous value, so any number would be invented.
    """

    def __init__(self) -> None:
        self._previous: Dict[str, Dict[str, int]] = {}
        self._previous_time: Dict[str, float] = {}
        self.resets = 0

    def update(
        self, key: str, counters: Dict[str, Optional[int]], now: float, speed_bps: int = 0
    ) -> Dict[str, Any]:
        """Return ``{name_delta: value}`` plus ``interval_s`` and ``counter_reset``."""
        previous = self._previous.get(key)
        previous_time = self._previous_time.get(key)
        clean = {name: int(value) for name, value in counters.items() if value is not None}

        self._previous[key] = clean
        self._previous_time[key] = now

        if previous is None or previous_time is None:
            return {"interval_s": 0.0, "counter_reset": 0, "first_sample": True}

        interval = max(0.0, now - previous_time)
        result: Dict[str, Any] = {"interval_s": round(interval, 3), "first_sample": False}
        reset = 0

        for name, value in clean.items():
            old = previous.get(name)
            if old is None:
                continue
            if value >= old:
                delta = value - old
            else:
                wrapped = value + _UINT32 - old
                plausible = (
                    interval > 0 and speed_bps > 0 and wrapped <= (speed_bps / 8.0) * interval * 1.5
                )
                if old < _UINT32 and (plausible or (speed_bps == 0 and wrapped < _UINT32 // 2)):
                    delta = wrapped
                else:
                    delta = 0
                    reset = 1
            result[f"{name}_delta"] = delta

        if reset:
            self.resets += 1
        result["counter_reset"] = reset
        return result

    def forget(self, key: str) -> None:
        self._previous.pop(key, None)
        self._previous_time.pop(key, None)


class TelemetryDriver:
    """Base class for device telemetry drivers."""

    name = "base"

    def __init__(self, cfg, logger) -> None:
        self.cfg = cfg
        self.log = logger
        self.device = cfg.device.name or cfg.device.host or cfg.instance
        self.timeout = float(cfg.telemetry.timeout_s)

    def preflight(self) -> PreflightReport:
        return PreflightReport(ok=True, driver=self.name, detail="no preflight checks defined")

    def describe(self) -> str:
        return self.name

    def collect(self) -> DeviceSnapshot:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:
        return None

    def _failed(self, error: str, started: float) -> DeviceSnapshot:
        return DeviceSnapshot(
            device=self.device,
            driver=self.name,
            reachable=False,
            error=error[:500],
            poll_ms=(time.monotonic() - started) * 1000.0,
        )


@dataclass
class PreflightReport:
    ok: bool
    driver: str = ""
    detail: str = ""
    hints: List[str] = field(default_factory=list)

    def render(self) -> str:
        status = "OK" if self.ok else "FAILED"
        lines = [f"{self.driver}: {status} -- {self.detail}"]
        lines.extend(f"    hint: {hint}" for hint in self.hints)
        return "\n".join(lines)
