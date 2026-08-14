"""Network-wide time series: one row per time bucket, joined across sources.

Three defects made the previous version's output unusable:

1. The time spine was built from ``utcnow() - 1 hour`` while the flows it was
   joined against came from the current hour, so every joined column was zero.
   The spine is now derived from the data itself.
2. Rows were appended with ``to_csv(mode="a")`` and a column set that varied
   between runs, producing a file whose rows had different widths -- structurally
   corrupt and unparseable. The schema here is fixed and enforced by
   :class:`~flowlite.storage.CsvSink`.
3. Buckets with no data were emitted as zeros indistinguishable from "measured
   and genuinely zero". Each source now carries a ``*_samples`` count so a
   consumer can tell "quiet" from "not observed".
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..storage.csvsink import iter_csv_rows

__all__ = ["NETWORK_TS_FIELDS", "NetworkTimeSeriesBuilder", "shannon_entropy"]

NETWORK_TS_FIELDS = [
    "timestamp",
    "epoch",
    "device",
    "bucket_seconds",
    # -- flow-derived ------------------------------------------------------ #
    "flow_samples",
    "flows_per_s",
    "packets_per_s",
    "bytes_per_s",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "active_src_ips",
    "active_dst_ips",
    "active_dst_ports",
    "dst_port_entropy",
    "dst_ip_entropy",
    "byte_asymmetry",
    "mean_flow_duration_s",
    "mean_flow_iat_s",
    "mean_pkt_len",
    "syn_no_ack_per_s",
    "rst_flows_per_s",
    "short_flows_ratio",
    "public_dst_ratio",
    "ipv6_ratio",
    "new_flows_per_s",
    # -- device telemetry -------------------------------------------------- #
    "telemetry_samples",
    "iface_in_bytes_per_s",
    "iface_out_bytes_per_s",
    "iface_errors",
    "iface_discards",
    "ifaces_total",
    "ifaces_down",
    "arp_entries",
    "mac_entries",
    "route_entries",
    "device_cpu_pct",
    "device_mem_pct",
    # -- sFlow / NetFlow --------------------------------------------------- #
    "sflow_samples",
    "sflow_frames_per_s",
    "sflow_bytes_per_s",
    "sflow_payload_entropy",
    "netflow_samples",
    "netflow_flows_per_s",
    "netflow_bytes_per_s",
]


def shannon_entropy(histogram: Dict[Any, int]) -> float:
    """Shannon entropy in bits of a value-count histogram."""
    total = sum(histogram.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in histogram.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    return int(_num(value, default))


def _round(value: float, digits: int = 6) -> float:
    if value != value or value in (math.inf, -math.inf):
        return 0.0
    return round(value, digits)


def _ratio(numerator: float, denominator: float) -> float:
    return _round(numerator / denominator) if denominator else 0.0


def parse_timestamp(value: Any) -> Optional[float]:
    """Parse an epoch number or an ISO-8601 string into an epoch float."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        cleaned = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


class _FlowBucket:
    __slots__ = (
        "flows",
        "packets",
        "bytes",
        "fwd_bytes",
        "bwd_bytes",
        "tcp",
        "udp",
        "icmp",
        "ipv6",
        "src_ips",
        "dst_ips",
        "dst_ports",
        "dst_port_hist",
        "dst_ip_hist",
        "duration_sum",
        "iat_sum",
        "pkt_len_sum",
        "syn_no_ack",
        "rst_flows",
        "short_flows",
        "public_dst",
        "new_flows",
    )

    def __init__(self) -> None:
        self.flows = 0
        self.packets = 0
        self.bytes = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.ipv6 = 0
        self.src_ips: set = set()
        self.dst_ips: set = set()
        self.dst_ports: set = set()
        self.dst_port_hist: Dict[int, int] = defaultdict(int)
        self.dst_ip_hist: Dict[str, int] = defaultdict(int)
        self.duration_sum = 0.0
        self.iat_sum = 0.0
        self.pkt_len_sum = 0.0
        self.syn_no_ack = 0
        self.rst_flows = 0
        self.short_flows = 0
        self.public_dst = 0
        self.new_flows = 0


class _CounterBucket:
    """Generic accumulator for telemetry-style rows."""

    __slots__ = ("samples", "sums", "maxes", "sets")

    def __init__(self) -> None:
        self.samples = 0
        self.sums: Dict[str, float] = defaultdict(float)
        self.maxes: Dict[str, float] = defaultdict(float)
        self.sets: Dict[str, set] = defaultdict(set)

    def add_sum(self, key: str, value: float) -> None:
        self.sums[key] += value

    def add_max(self, key: str, value: float) -> None:
        if value > self.maxes[key]:
            self.maxes[key] = value


class NetworkTimeSeriesBuilder:
    """Bucket flows and device telemetry onto a shared, data-derived time spine."""

    def __init__(
        self,
        bucket_seconds: int = 60,
        device: str = "",
        logger=None,
    ) -> None:
        self.bucket_seconds = max(1, int(bucket_seconds))
        self.device = device
        self.log = logger
        self._flows: Dict[int, _FlowBucket] = {}
        self._telemetry: Dict[int, _CounterBucket] = {}
        self._sflow: Dict[int, _CounterBucket] = {}
        self._netflow: Dict[int, _CounterBucket] = {}
        self._min_bucket: Optional[int] = None
        self._max_bucket: Optional[int] = None

    # -- ingestion --------------------------------------------------------- #

    def _bucket_of(self, epoch: float) -> int:
        bucket = int(epoch // self.bucket_seconds) * self.bucket_seconds
        if self._min_bucket is None or bucket < self._min_bucket:
            self._min_bucket = bucket
        if self._max_bucket is None or bucket > self._max_bucket:
            self._max_bucket = bucket
        return bucket

    def add_flow(self, row: Dict[str, Any]) -> None:
        """Fold one flow row in. Flows are attributed to their *start* bucket."""
        epoch = _num(row.get("start_epoch"), -1.0)
        if epoch < 0:
            parsed = parse_timestamp(row.get("start_time"))
            if parsed is None:
                return
            epoch = parsed
        bucket_key = self._bucket_of(epoch)
        bucket = self._flows.get(bucket_key)
        if bucket is None:
            bucket = _FlowBucket()
            self._flows[bucket_key] = bucket

        fwd_bytes = _int(row.get("fwd_bytes"))
        bwd_bytes = _int(row.get("bwd_bytes"))
        packets = _int(row.get("total_packets"))
        protocol = str(row.get("protocol_name", "")).upper()
        dst_port = _int(row.get("dst_port"))
        src_ip = str(row.get("src_ip", ""))
        dst_ip = str(row.get("dst_ip", ""))

        bucket.flows += 1
        bucket.packets += packets
        bucket.bytes += fwd_bytes + bwd_bytes
        bucket.fwd_bytes += fwd_bytes
        bucket.bwd_bytes += bwd_bytes
        if protocol == "TCP":
            bucket.tcp += 1
        elif protocol == "UDP":
            bucket.udp += 1
        elif protocol in ("ICMP", "ICMPV6"):
            bucket.icmp += 1
        if _int(row.get("ip_version")) == 6:
            bucket.ipv6 += 1
        if src_ip:
            bucket.src_ips.add(src_ip)
        if dst_ip:
            bucket.dst_ips.add(dst_ip)
            bucket.dst_ip_hist[dst_ip] += 1
        bucket.dst_ports.add(dst_port)
        bucket.dst_port_hist[dst_port] += 1
        bucket.duration_sum += _num(row.get("duration_s"))
        bucket.iat_sum += _num(row.get("flow_iat_mean"))
        bucket.pkt_len_sum += _num(row.get("pkt_len_mean"))

        # A half-open connection: SYN sent, nothing acknowledged back.
        if _int(row.get("syn_count")) > 0 and _int(row.get("ack_count")) == 0:
            bucket.syn_no_ack += 1
        if str(row.get("tcp_state", "")) == "syn-sent":
            bucket.new_flows += 1
        if _int(row.get("rst_count")) > 0:
            bucket.rst_flows += 1
        if packets <= 2:
            bucket.short_flows += 1
        if str(row.get("dst_scope", "")) == "public":
            bucket.public_dst += 1

    def add_flows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for row in rows:
            self.add_flow(row)

    def _ingest_csv(
        self,
        path: str | Path,
        store: Dict[int, _CounterBucket],
        handler: Callable[[_CounterBucket, Dict[str, str]], None],
        window: Optional[Tuple[float, float]] = None,
    ) -> int:
        target = Path(path)
        if not target.exists():
            return 0
        consumed = 0
        for row in iter_csv_rows(target):
            epoch = parse_timestamp(row.get("timestamp") or row.get("epoch"))
            if epoch is None:
                continue
            if window is not None and not (window[0] <= epoch <= window[1]):
                continue
            bucket_key = int(epoch // self.bucket_seconds) * self.bucket_seconds
            bucket = store.get(bucket_key)
            if bucket is None:
                bucket = _CounterBucket()
                store[bucket_key] = bucket
            bucket.samples += 1
            try:
                handler(bucket, row)
            except (TypeError, ValueError):
                continue
            consumed += 1
        return consumed

    def add_telemetry_csv(self, path: str | Path) -> int:
        """Join a device telemetry CSV onto the spine."""

        def handle(bucket: _CounterBucket, row: Dict[str, str]) -> None:
            bucket.add_sum("in_bytes_per_s", _num(row.get("in_bytes_per_s")))
            bucket.add_sum("out_bytes_per_s", _num(row.get("out_bytes_per_s")))
            bucket.add_sum(
                "errors", _num(row.get("in_errors_delta")) + _num(row.get("out_errors_delta"))
            )
            bucket.add_sum(
                "discards", _num(row.get("in_discards_delta")) + _num(row.get("out_discards_delta"))
            )
            bucket.add_max("ifaces_total", _num(row.get("interfaces_total")))
            bucket.add_max("ifaces_down", _num(row.get("interfaces_down")))
            bucket.add_max("arp_entries", _num(row.get("arp_entries")))
            bucket.add_max("mac_entries", _num(row.get("mac_entries")))
            bucket.add_max("route_entries", _num(row.get("route_entries")))
            bucket.add_max("cpu_pct", _num(row.get("cpu_percent")))
            bucket.add_max("mem_pct", _num(row.get("memory_percent")))

        return self._ingest_csv(path, self._telemetry, handle, self._window())

    def add_sflow_csv(self, path: str | Path) -> int:
        def handle(bucket: _CounterBucket, row: Dict[str, str]) -> None:
            rate = _num(row.get("sampling_rate"), 1.0) or 1.0
            bucket.add_sum("frames", rate)
            bucket.add_sum("bytes", _num(row.get("frame_length")) * rate)
            bucket.add_sum("entropy_sum", _num(row.get("payload_entropy")))
            bucket.add_sum("entropy_n", 1.0 if row.get("payload_entropy") else 0.0)

        return self._ingest_csv(path, self._sflow, handle, self._window())

    def add_netflow_csv(self, path: str | Path) -> int:
        def handle(bucket: _CounterBucket, row: Dict[str, str]) -> None:
            bucket.add_sum("flows", 1.0)
            bucket.add_sum("bytes", _num(row.get("bytes")))

        return self._ingest_csv(path, self._netflow, handle, self._window())

    def _window(self) -> Optional[Tuple[float, float]]:
        if self._min_bucket is None or self._max_bucket is None:
            return None
        # One bucket of slack on each side absorbs collector clock skew.
        return (
            float(self._min_bucket - self.bucket_seconds),
            float(self._max_bucket + 2 * self.bucket_seconds),
        )

    # -- emission ---------------------------------------------------------- #

    def rows(self, fill_gaps: bool = True) -> List[Dict[str, Any]]:
        """Render the spine. ``fill_gaps`` emits zero rows for quiet buckets."""
        keys = set(self._flows) | set(self._telemetry) | set(self._sflow) | set(self._netflow)
        if not keys:
            return []
        start, end = min(keys), max(keys)
        if fill_gaps:
            span = (end - start) // self.bucket_seconds
            # A pathological clock skew must not materialise a billion rows.
            if span > 200_000:
                ordered = sorted(keys)
            else:
                ordered = list(range(start, end + self.bucket_seconds, self.bucket_seconds))
        else:
            ordered = sorted(keys)

        seconds = float(self.bucket_seconds)
        output: List[Dict[str, Any]] = []
        for key in ordered:
            flow = self._flows.get(key)
            telemetry = self._telemetry.get(key)
            sflow = self._sflow.get(key)
            netflow = self._netflow.get(key)

            row: Dict[str, Any] = {
                "timestamp": datetime.fromtimestamp(key, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "epoch": key,
                "device": self.device,
                "bucket_seconds": self.bucket_seconds,
                "flow_samples": flow.flows if flow else 0,
                "flows_per_s": _ratio(flow.flows, seconds) if flow else 0.0,
                "packets_per_s": _ratio(flow.packets, seconds) if flow else 0.0,
                "bytes_per_s": _ratio(flow.bytes, seconds) if flow else 0.0,
                "tcp_ratio": _ratio(flow.tcp, flow.flows) if flow else 0.0,
                "udp_ratio": _ratio(flow.udp, flow.flows) if flow else 0.0,
                "icmp_ratio": _ratio(flow.icmp, flow.flows) if flow else 0.0,
                "active_src_ips": len(flow.src_ips) if flow else 0,
                "active_dst_ips": len(flow.dst_ips) if flow else 0,
                "active_dst_ports": len(flow.dst_ports) if flow else 0,
                "dst_port_entropy": _round(shannon_entropy(flow.dst_port_hist)) if flow else 0.0,
                "dst_ip_entropy": _round(shannon_entropy(flow.dst_ip_hist)) if flow else 0.0,
                "byte_asymmetry": (
                    _ratio(abs(flow.fwd_bytes - flow.bwd_bytes), flow.bytes) if flow else 0.0
                ),
                "mean_flow_duration_s": _ratio(flow.duration_sum, flow.flows) if flow else 0.0,
                "mean_flow_iat_s": _ratio(flow.iat_sum, flow.flows) if flow else 0.0,
                "mean_pkt_len": _ratio(flow.pkt_len_sum, flow.flows) if flow else 0.0,
                "syn_no_ack_per_s": _ratio(flow.syn_no_ack, seconds) if flow else 0.0,
                "rst_flows_per_s": _ratio(flow.rst_flows, seconds) if flow else 0.0,
                "short_flows_ratio": _ratio(flow.short_flows, flow.flows) if flow else 0.0,
                "public_dst_ratio": _ratio(flow.public_dst, flow.flows) if flow else 0.0,
                "ipv6_ratio": _ratio(flow.ipv6, flow.flows) if flow else 0.0,
                "new_flows_per_s": _ratio(flow.new_flows, seconds) if flow else 0.0,
                "telemetry_samples": telemetry.samples if telemetry else 0,
                "iface_in_bytes_per_s": _round(telemetry.sums["in_bytes_per_s"])
                if telemetry
                else 0.0,
                "iface_out_bytes_per_s": (
                    _round(telemetry.sums["out_bytes_per_s"]) if telemetry else 0.0
                ),
                "iface_errors": _round(telemetry.sums["errors"]) if telemetry else 0.0,
                "iface_discards": _round(telemetry.sums["discards"]) if telemetry else 0.0,
                "ifaces_total": int(telemetry.maxes["ifaces_total"]) if telemetry else 0,
                "ifaces_down": int(telemetry.maxes["ifaces_down"]) if telemetry else 0,
                "arp_entries": int(telemetry.maxes["arp_entries"]) if telemetry else 0,
                "mac_entries": int(telemetry.maxes["mac_entries"]) if telemetry else 0,
                "route_entries": int(telemetry.maxes["route_entries"]) if telemetry else 0,
                "device_cpu_pct": _round(telemetry.maxes["cpu_pct"], 2) if telemetry else 0.0,
                "device_mem_pct": _round(telemetry.maxes["mem_pct"], 2) if telemetry else 0.0,
                "sflow_samples": sflow.samples if sflow else 0,
                "sflow_frames_per_s": _ratio(sflow.sums["frames"], seconds) if sflow else 0.0,
                "sflow_bytes_per_s": _ratio(sflow.sums["bytes"], seconds) if sflow else 0.0,
                "sflow_payload_entropy": (
                    _ratio(sflow.sums["entropy_sum"], sflow.sums["entropy_n"]) if sflow else 0.0
                ),
                "netflow_samples": netflow.samples if netflow else 0,
                "netflow_flows_per_s": _ratio(netflow.sums["flows"], seconds) if netflow else 0.0,
                "netflow_bytes_per_s": _ratio(netflow.sums["bytes"], seconds) if netflow else 0.0,
            }
            output.append(row)
        return output

    def reset(self) -> None:
        self._flows.clear()
        self._telemetry.clear()
        self._sflow.clear()
        self._netflow.clear()
        self._min_bucket = None
        self._max_bucket = None

    def summary(self) -> str:
        return (
            f"{len(self._flows)} flow bucket(s), {len(self._telemetry)} telemetry bucket(s), "
            f"{len(self._sflow)} sFlow bucket(s), {len(self._netflow)} NetFlow bucket(s)"
        )
