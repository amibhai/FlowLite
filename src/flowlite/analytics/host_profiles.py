"""Per-host behavioural profiles over fixed time windows.

Two structural fixes over the previous implementation:

* **Linear, not quadratic.** Window-wide totals used to be recomputed with a
  DataFrame filter *inside* the per-host loop, so a window with 5,000 hosts did
  5,000 full scans. Totals are now accumulated in the same single pass as the
  per-host statistics.
* **Both directions.** A host was previously profiled only as a traffic source,
  so a machine being scanned or exfiltrated *to* was invisible. Each row now
  carries what the host sent and what it received.

Cardinality sets are capped. An unbounded ``set`` of destination IPs is a memory
leak with an attacker-controlled size -- exactly what a scan or a DDoS produces.
Past the cap, counting stops and ``cardinality_truncated`` is set so a consumer
knows the number is a floor rather than an exact count.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set, Tuple

__all__ = ["HOST_PROFILE_FIELDS", "HostProfileAggregator"]

HOST_PROFILE_FIELDS = [
    "window_start",
    "window_end",
    "device",
    "host_ip",
    "host_scope",
    "flows_out",
    "flows_in",
    "flows_total",
    "packets_sent",
    "packets_received",
    "bytes_sent",
    "bytes_received",
    "bytes_total",
    "frame_bytes_sent",
    "frame_bytes_received",
    "bytes_per_s_sent",
    "bytes_per_s_received",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_dst_asns",
    "unique_dst_countries",
    "unique_peer_sources",
    "unique_listening_ports",
    "dst_port_entropy",
    "dst_ip_entropy",
    "fan_out_ratio",
    "public_dst_ratio",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "other_proto_ratio",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "failed_handshake_ratio",
    "short_flow_ratio",
    "mean_flow_duration_s",
    "max_flow_duration_s",
    "mean_pkt_len",
    "mean_flow_iat_s",
    "mean_active_s",
    "mean_idle_s",
    "mean_ttl",
    "down_up_byte_ratio",
    "share_of_window_flows",
    "share_of_window_bytes",
    "share_of_window_dst_ports",
    "cardinality_truncated",
]

_CARDINALITY_CAP = 20000


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


class _CappedCounter:
    """Counts distinct values up to a cap, then stops growing."""

    __slots__ = ("_values", "truncated", "_cap")

    def __init__(self, cap: int = _CARDINALITY_CAP) -> None:
        self._values: Set[Any] = set()
        self._cap = cap
        self.truncated = False

    def add(self, value: Any) -> None:
        if len(self._values) >= self._cap:
            self.truncated = True
            return
        self._values.add(value)

    def __len__(self) -> int:
        return len(self._values)


class _HostAccumulator:
    """Mutable per-(window, host) state."""

    __slots__ = (
        "flows_out",
        "flows_in",
        "packets_sent",
        "packets_received",
        "bytes_sent",
        "bytes_received",
        "frame_sent",
        "frame_received",
        "dst_ips",
        "dst_ports",
        "dst_asns",
        "dst_countries",
        "peer_sources",
        "listening_ports",
        "dst_port_hist",
        "dst_ip_hist",
        "public_dst_flows",
        "proto_counts",
        "syn",
        "rst",
        "fin",
        "packets_for_flags",
        "tcp_flows",
        "failed_handshakes",
        "short_flows",
        "duration_sum",
        "duration_max",
        "pkt_len_sum",
        "iat_sum",
        "active_sum",
        "idle_sum",
        "ttl_sum",
        "scope",
    )

    def __init__(self) -> None:
        self.flows_out = 0
        self.flows_in = 0
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.frame_sent = 0
        self.frame_received = 0
        self.dst_ips = _CappedCounter()
        self.dst_ports = _CappedCounter()
        self.dst_asns = _CappedCounter()
        self.dst_countries = _CappedCounter()
        self.peer_sources = _CappedCounter()
        self.listening_ports = _CappedCounter()
        self.dst_port_hist: Dict[int, int] = defaultdict(int)
        self.dst_ip_hist: Dict[str, int] = defaultdict(int)
        self.public_dst_flows = 0
        self.proto_counts: Dict[str, int] = defaultdict(int)
        self.syn = 0
        self.rst = 0
        self.fin = 0
        self.packets_for_flags = 0
        self.tcp_flows = 0
        self.failed_handshakes = 0
        self.short_flows = 0
        self.duration_sum = 0.0
        self.duration_max = 0.0
        self.pkt_len_sum = 0.0
        self.iat_sum = 0.0
        self.active_sum = 0.0
        self.idle_sum = 0.0
        self.ttl_sum = 0.0
        self.scope = ""


class _WindowTotals:
    __slots__ = ("flows", "bytes", "dst_ports")

    def __init__(self) -> None:
        self.flows = 0
        self.bytes = 0
        self.dst_ports = _CappedCounter(cap=_CARDINALITY_CAP * 4)


def _entropy_from_histogram(histogram: Dict[Any, int]) -> float:
    """Shannon entropy in bits of a value-count histogram."""
    total = sum(histogram.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in histogram.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _parse_epoch(row: Dict[str, Any]) -> float:
    epoch = _num(row.get("start_epoch"), -1.0)
    if epoch >= 0:
        return epoch
    text = str(row.get("start_time", "")).strip()
    if not text:
        return 0.0
    try:
        cleaned = text[:-1] + "+00:00" if text.endswith("Z") else text
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return 0.0


class HostProfileAggregator:
    """Fold flow rows into per-host, per-window behavioural profiles."""

    def __init__(self, window_minutes: int = 10, device: str = "", logger=None) -> None:
        self.window_seconds = max(60, int(window_minutes) * 60)
        self.device = device
        self.log = logger
        self._hosts: Dict[Tuple[int, str], _HostAccumulator] = {}
        self._windows: Dict[int, _WindowTotals] = defaultdict(_WindowTotals)
        self.rows_consumed = 0

    # -- ingestion --------------------------------------------------------- #

    def add_flow(self, row: Dict[str, Any]) -> None:
        """Fold one flow row (as produced by ``flow_record_to_row``) in."""
        self.rows_consumed += 1
        epoch = _parse_epoch(row)
        window = int(epoch // self.window_seconds) * self.window_seconds

        src_ip = str(row.get("src_ip", ""))
        dst_ip = str(row.get("dst_ip", ""))
        if not src_ip and not dst_ip:
            return

        fwd_packets = _int(row.get("fwd_packets"))
        bwd_packets = _int(row.get("bwd_packets"))
        fwd_bytes = _int(row.get("fwd_bytes"))
        bwd_bytes = _int(row.get("bwd_bytes"))
        fwd_frame = _int(row.get("fwd_frame_bytes"))
        bwd_frame = _int(row.get("bwd_frame_bytes"))
        total_packets = fwd_packets + bwd_packets
        total_bytes = fwd_bytes + bwd_bytes
        dst_port = _int(row.get("dst_port"))
        protocol = str(row.get("protocol_name", "")).upper()
        duration = _num(row.get("duration_s"))

        totals = self._windows[window]
        totals.flows += 1
        totals.bytes += total_bytes
        totals.dst_ports.add(dst_port)

        # -- the initiator's perspective ----------------------------------- #
        if src_ip:
            source = self._accumulator(window, src_ip)
            source.scope = source.scope or str(row.get("src_scope", ""))
            source.flows_out += 1
            source.packets_sent += fwd_packets
            source.packets_received += bwd_packets
            source.bytes_sent += fwd_bytes
            source.bytes_received += bwd_bytes
            source.frame_sent += fwd_frame
            source.frame_received += bwd_frame
            source.dst_ips.add(dst_ip)
            source.dst_ports.add(dst_port)
            asn = str(row.get("dst_asn", ""))
            if asn:
                source.dst_asns.add(asn)
            country = str(row.get("dst_country", ""))
            if country:
                source.dst_countries.add(country)
            if len(source.dst_port_hist) < _CARDINALITY_CAP:
                source.dst_port_hist[dst_port] += 1
            if len(source.dst_ip_hist) < _CARDINALITY_CAP:
                source.dst_ip_hist[dst_ip] += 1
            if str(row.get("dst_scope", "")) == "public":
                source.public_dst_flows += 1

            key = protocol if protocol in ("TCP", "UDP", "ICMP", "ICMPV6") else "OTHER"
            source.proto_counts["ICMP" if key == "ICMPV6" else key] += 1

            source.syn += _int(row.get("syn_count"))
            source.rst += _int(row.get("rst_count"))
            source.fin += _int(row.get("fin_count"))
            source.packets_for_flags += total_packets

            if protocol == "TCP":
                source.tcp_flows += 1
                if str(row.get("tcp_state", "")) == "syn-sent":
                    source.failed_handshakes += 1
            if total_packets <= 2:
                source.short_flows += 1

            source.duration_sum += duration
            source.duration_max = max(source.duration_max, duration)
            source.pkt_len_sum += _num(row.get("pkt_len_mean"))
            source.iat_sum += _num(row.get("flow_iat_mean"))
            source.active_sum += _num(row.get("active_mean"))
            source.idle_sum += _num(row.get("idle_mean"))
            source.ttl_sum += _num(row.get("ttl_mean"))

        # -- the responder's perspective ------------------------------------ #
        if dst_ip:
            target = self._accumulator(window, dst_ip)
            target.scope = target.scope or str(row.get("dst_scope", ""))
            target.flows_in += 1
            target.packets_sent += bwd_packets
            target.packets_received += fwd_packets
            target.bytes_sent += bwd_bytes
            target.bytes_received += fwd_bytes
            target.frame_sent += bwd_frame
            target.frame_received += fwd_frame
            target.peer_sources.add(src_ip)
            target.listening_ports.add(dst_port)

    def _accumulator(self, window: int, host: str) -> _HostAccumulator:
        key = (window, host)
        accumulator = self._hosts.get(key)
        if accumulator is None:
            accumulator = _HostAccumulator()
            self._hosts[key] = accumulator
        return accumulator

    def add_flows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for row in rows:
            self.add_flow(row)

    # -- emission ---------------------------------------------------------- #

    def rows(self) -> List[Dict[str, Any]]:
        """Render every accumulated (window, host) pair as a CSV row."""
        output: List[Dict[str, Any]] = []
        for (window, host), acc in sorted(self._hosts.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            totals = self._windows.get(window)
            window_flows = totals.flows if totals else 0
            window_bytes = totals.bytes if totals else 0
            window_ports = len(totals.dst_ports) if totals else 0

            start = datetime.fromtimestamp(window, tz=timezone.utc)
            end = start + timedelta(seconds=self.window_seconds)
            flows_out = acc.flows_out
            flows_total = flows_out + acc.flows_in
            proto_total = sum(acc.proto_counts.values()) or 0

            output.append(
                {
                    "window_start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "window_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "device": self.device,
                    "host_ip": host,
                    "host_scope": acc.scope,
                    "flows_out": flows_out,
                    "flows_in": acc.flows_in,
                    "flows_total": flows_total,
                    "packets_sent": acc.packets_sent,
                    "packets_received": acc.packets_received,
                    "bytes_sent": acc.bytes_sent,
                    "bytes_received": acc.bytes_received,
                    "bytes_total": acc.bytes_sent + acc.bytes_received,
                    "frame_bytes_sent": acc.frame_sent,
                    "frame_bytes_received": acc.frame_received,
                    "bytes_per_s_sent": _ratio(acc.bytes_sent, self.window_seconds),
                    "bytes_per_s_received": _ratio(acc.bytes_received, self.window_seconds),
                    "unique_dst_ips": len(acc.dst_ips),
                    "unique_dst_ports": len(acc.dst_ports),
                    "unique_dst_asns": len(acc.dst_asns),
                    "unique_dst_countries": len(acc.dst_countries),
                    "unique_peer_sources": len(acc.peer_sources),
                    "unique_listening_ports": len(acc.listening_ports),
                    "dst_port_entropy": _round(_entropy_from_histogram(acc.dst_port_hist), 6),
                    "dst_ip_entropy": _round(_entropy_from_histogram(acc.dst_ip_hist), 6),
                    "fan_out_ratio": _ratio(len(acc.dst_ips), flows_out),
                    "public_dst_ratio": _ratio(acc.public_dst_flows, flows_out),
                    "tcp_ratio": _ratio(acc.proto_counts.get("TCP", 0), proto_total),
                    "udp_ratio": _ratio(acc.proto_counts.get("UDP", 0), proto_total),
                    "icmp_ratio": _ratio(acc.proto_counts.get("ICMP", 0), proto_total),
                    "other_proto_ratio": _ratio(acc.proto_counts.get("OTHER", 0), proto_total),
                    "syn_ratio": _ratio(acc.syn, acc.packets_for_flags),
                    "rst_ratio": _ratio(acc.rst, acc.packets_for_flags),
                    "fin_ratio": _ratio(acc.fin, acc.packets_for_flags),
                    "failed_handshake_ratio": _ratio(acc.failed_handshakes, acc.tcp_flows),
                    "short_flow_ratio": _ratio(acc.short_flows, flows_out),
                    "mean_flow_duration_s": _ratio(acc.duration_sum, flows_out),
                    "max_flow_duration_s": _round(acc.duration_max),
                    "mean_pkt_len": _ratio(acc.pkt_len_sum, flows_out),
                    "mean_flow_iat_s": _ratio(acc.iat_sum, flows_out),
                    "mean_active_s": _ratio(acc.active_sum, flows_out),
                    "mean_idle_s": _ratio(acc.idle_sum, flows_out),
                    "mean_ttl": _ratio(acc.ttl_sum, flows_out),
                    "down_up_byte_ratio": _ratio(acc.bytes_received, acc.bytes_sent),
                    "share_of_window_flows": _ratio(flows_out, window_flows),
                    "share_of_window_bytes": _ratio(
                        acc.bytes_sent + acc.bytes_received, window_bytes
                    ),
                    "share_of_window_dst_ports": _ratio(len(acc.dst_ports), window_ports),
                    "cardinality_truncated": int(
                        acc.dst_ips.truncated
                        or acc.dst_ports.truncated
                        or acc.peer_sources.truncated
                    ),
                }
            )
        return output

    def reset(self) -> None:
        self._hosts.clear()
        self._windows.clear()
        self.rows_consumed = 0

    def __len__(self) -> int:
        return len(self._hosts)

    def summary(self) -> str:
        windows = len(self._windows)
        return (
            f"{len(self._hosts)} host-windows across {windows} window(s) "
            f"from {self.rows_consumed} flows"
        )
