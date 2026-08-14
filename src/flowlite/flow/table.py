"""Bidirectional flow assembly with bounded memory.

Behaviour that matters, and why:

* **Constant memory per flow.** Every feature is maintained incrementally, so a
  flow costs a fixed handful of floats no matter how many packets it carries.
* **Bounded flow count.** Flows are held in an LRU-ordered map. Idle flows are
  swept out as capture time advances, long-lived flows are cut at the active
  timeout the way any real flow exporter does, and if the table still reaches
  its ceiling the least-recently-updated flows are evicted and emitted rather
  than the process being allowed to grow without limit.
* **Deterministic direction.** The endpoint that sent the first packet of a flow
  is "forward" for that flow's whole life. Initial TCP window sizes are recorded
  from the first packet seen *in each direction*, so a capture that starts
  mid-connection cannot attribute the responder's window to the initiator.
* **Timestamps are treated as untrusted.** Merged or reordered captures produce
  negative inter-arrival times; those are clamped to zero instead of poisoning
  every downstream mean and standard deviation.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..pcap.decode import (
    IPPROTO_TCP,
    PROTO_NAMES,
    TCP_ACK,
    TCP_CWR,
    TCP_ECE,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
    Packet,
    decode_packet,
)
from ..pcap.reader import CaptureFile, CaptureInfo
from .stats import OnlineStats

__all__ = ["FlowKey", "FlowRecord", "FlowTable", "PcapFlowExtractor", "ExtractionResult"]

FlowKey = Tuple[str, int, str, int, int, int]

_SWEEP_EVERY_PACKETS = 8192


class FlowRecord:
    """Accumulated state and features for one bidirectional flow."""

    __slots__ = (
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "ip_version",
        "vlan_id",
        "first_ts",
        "last_ts",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "fwd_frame_bytes",
        "bwd_frame_bytes",
        "all_len",
        "fwd_len",
        "bwd_len",
        "all_iat",
        "fwd_iat",
        "bwd_iat",
        "ttl",
        "active",
        "idle",
        "_last_fwd_ts",
        "_last_bwd_ts",
        "_burst_start",
        "_burst_end",
        "flags",
        "init_win_fwd",
        "init_win_bwd",
        "fwd_min_seg",
        "syn_ts",
        "synack_ts",
        "fin_fwd",
        "fin_bwd",
        "saw_rst",
        "fragment_packets",
        "expiry_reason",
    )

    def __init__(self, packet: Packet) -> None:
        self.src_ip = packet.src_ip
        self.src_port = packet.src_port
        self.dst_ip = packet.dst_ip
        self.dst_port = packet.dst_port
        self.protocol = packet.proto
        self.ip_version = packet.ip_version
        self.vlan_id = packet.vlan_id

        self.first_ts = packet.ts
        self.last_ts = packet.ts

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_frame_bytes = 0
        self.bwd_frame_bytes = 0

        self.all_len = OnlineStats()
        self.fwd_len = OnlineStats()
        self.bwd_len = OnlineStats()
        self.all_iat = OnlineStats()
        self.fwd_iat = OnlineStats()
        self.bwd_iat = OnlineStats()
        self.ttl = OnlineStats()
        self.active = OnlineStats()
        self.idle = OnlineStats()

        self._last_fwd_ts: Optional[float] = None
        self._last_bwd_ts: Optional[float] = None
        self._burst_start = packet.ts
        self._burst_end = packet.ts

        self.flags: Dict[str, int] = {
            "syn": 0,
            "fin": 0,
            "rst": 0,
            "psh": 0,
            "ack": 0,
            "urg": 0,
            "ece": 0,
            "cwr": 0,
        }
        self.init_win_fwd = -1
        self.init_win_bwd = -1
        self.fwd_min_seg = -1
        self.syn_ts: Optional[float] = None
        self.synack_ts: Optional[float] = None
        self.fin_fwd = False
        self.fin_bwd = False
        self.saw_rst = False
        self.fragment_packets = 0
        self.expiry_reason = "end-of-capture"

    # -- ingestion --------------------------------------------------------- #

    def add(self, packet: Packet, forward: bool, burst_gap: float) -> None:
        ts = packet.ts
        # Reordered or merged captures can move time backwards; never let that
        # produce a negative interval.
        gap = ts - self.last_ts
        if gap < 0.0:
            gap = 0.0
            ts = self.last_ts

        if self.all_iat.count or self.fwd_packets or self.bwd_packets:
            self.all_iat.add(gap)

        if gap > burst_gap:
            self.active.add(max(0.0, self._burst_end - self._burst_start))
            self.idle.add(gap)
            self._burst_start = ts
        self._burst_end = ts
        self.last_ts = ts

        payload = packet.payload_len
        self.all_len.add(payload)
        if packet.ttl:
            self.ttl.add(packet.ttl)
        if packet.is_fragment:
            self.fragment_packets += 1

        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += payload
            self.fwd_frame_bytes += packet.frame_len
            self.fwd_len.add(payload)
            if self._last_fwd_ts is not None:
                self.fwd_iat.add(max(0.0, ts - self._last_fwd_ts))
            self._last_fwd_ts = ts
            if self.init_win_fwd < 0 and packet.proto == IPPROTO_TCP:
                self.init_win_fwd = packet.tcp_window
            if payload > 0 and (self.fwd_min_seg < 0 or payload < self.fwd_min_seg):
                self.fwd_min_seg = payload
        else:
            self.bwd_packets += 1
            self.bwd_bytes += payload
            self.bwd_frame_bytes += packet.frame_len
            self.bwd_len.add(payload)
            if self._last_bwd_ts is not None:
                self.bwd_iat.add(max(0.0, ts - self._last_bwd_ts))
            self._last_bwd_ts = ts
            if self.init_win_bwd < 0 and packet.proto == IPPROTO_TCP:
                self.init_win_bwd = packet.tcp_window

        flags = packet.tcp_flags
        if flags:
            if flags & TCP_SYN:
                self.flags["syn"] += 1
                if flags & TCP_ACK:
                    if self.synack_ts is None and not forward:
                        self.synack_ts = ts
                elif self.syn_ts is None and forward:
                    self.syn_ts = ts
            if flags & TCP_FIN:
                self.flags["fin"] += 1
                if forward:
                    self.fin_fwd = True
                else:
                    self.fin_bwd = True
            if flags & TCP_RST:
                self.flags["rst"] += 1
                self.saw_rst = True
            if flags & TCP_PSH:
                self.flags["psh"] += 1
            if flags & TCP_ACK:
                self.flags["ack"] += 1
            if flags & TCP_URG:
                self.flags["urg"] += 1
            if flags & TCP_ECE:
                self.flags["ece"] += 1
            if flags & TCP_CWR:
                self.flags["cwr"] += 1

    def finalise(self) -> None:
        """Close the trailing burst so active/idle statistics are complete."""
        self.active.add(max(0.0, self._burst_end - self._burst_start))

    # -- derived properties ------------------------------------------------ #

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def total_frame_bytes(self) -> int:
        return self.fwd_frame_bytes + self.bwd_frame_bytes

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def protocol_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, str(self.protocol))

    @property
    def tcp_state(self) -> str:
        if self.protocol != IPPROTO_TCP:
            return "n/a"
        if self.saw_rst:
            return "reset"
        if self.fin_fwd and self.fin_bwd:
            return "closed"
        if self.fin_fwd or self.fin_bwd:
            return "closing"
        if self.syn_ts is not None and self.synack_ts is not None:
            return "established"
        if self.syn_ts is not None:
            return "syn-sent"
        return "ongoing"

    @property
    def handshake_ms(self) -> float:
        if self.syn_ts is None or self.synack_ts is None:
            return 0.0
        return max(0.0, (self.synack_ts - self.syn_ts) * 1000.0)

    @property
    def is_complete(self) -> bool:
        return self.protocol == IPPROTO_TCP and (self.saw_rst or (self.fin_fwd and self.fin_bwd))

    def __repr__(self) -> str:
        return (
            f"<FlowRecord {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"{self.protocol_name} pkts={self.total_packets} bytes={self.total_bytes}>"
        )


def _canonical_key(packet: Packet) -> Tuple[FlowKey, bool]:
    """Return an endpoint-order-independent key and whether this is forward.

    Ordering the two endpoints means one dictionary lookup per packet instead of
    two, and guarantees both directions land on the same entry.
    """
    a = (packet.src_ip, packet.src_port)
    b = (packet.dst_ip, packet.dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1], packet.proto, packet.vlan_id), True
    return (b[0], b[1], a[0], a[1], packet.proto, packet.vlan_id), False


class FlowTable:
    """An LRU-bounded table of in-progress flows."""

    def __init__(
        self,
        *,
        active_timeout_s: float = 300.0,
        idle_timeout_s: float = 60.0,
        burst_gap_s: float = 1.0,
        max_flows: int = 250_000,
        min_packets: int = 1,
        max_packets_per_flow: int = 0,
        close_on_teardown: bool = True,
        on_flow: Optional[Callable[[FlowRecord], None]] = None,
    ) -> None:
        self.active_timeout = float(active_timeout_s)
        self.idle_timeout = float(idle_timeout_s)
        self.burst_gap = float(burst_gap_s)
        self.max_flows = int(max_flows)
        self.min_packets = max(1, int(min_packets))
        self.max_packets_per_flow = max(0, int(max_packets_per_flow))
        self.close_on_teardown = close_on_teardown
        self.on_flow = on_flow

        self._flows: OrderedDict[FlowKey, Tuple[FlowRecord, bool]] = OrderedDict()
        self._packets_since_sweep = 0
        self._now = 0.0

        self.emitted = 0
        self.dropped_short = 0
        self.evicted_capacity = 0
        self.expired_idle = 0
        self.expired_active = 0
        self.expired_packet_cap = 0
        self.closed_teardown = 0

    # -- ingestion --------------------------------------------------------- #

    def add_packet(self, packet: Packet) -> None:
        key, is_forward_of_canonical = _canonical_key(packet)
        if packet.ts > self._now:
            self._now = packet.ts

        entry = self._flows.get(key)
        if entry is None:
            record = FlowRecord(packet)
            record.add(packet, True, self.burst_gap)
            self._flows[key] = (record, is_forward_of_canonical)
            self._after_insert()
            return

        record, canonical_is_forward = entry
        forward = is_forward_of_canonical == canonical_is_forward

        over_active = packet.ts - record.first_ts > self.active_timeout
        over_packets = (
            self.max_packets_per_flow > 0 and record.total_packets >= self.max_packets_per_flow
        )
        if over_active or over_packets:
            # Cut a record and start a fresh one for the same key, exactly as a
            # hardware exporter does at its active timeout. The packet cap stops
            # one elephant flow from dominating every window it touches.
            self._flows.pop(key, None)
            if over_active:
                self.expired_active += 1
            else:
                self.expired_packet_cap += 1
            self._emit(record, "active-timeout" if over_active else "packet-cap")
            new_record = FlowRecord(packet)
            new_record.add(packet, True, self.burst_gap)
            self._flows[key] = (new_record, is_forward_of_canonical)
            self._after_insert()
            return

        record.add(packet, forward, self.burst_gap)
        self._flows.move_to_end(key)

        if self.close_on_teardown and record.is_complete:
            self._flows.pop(key, None)
            self.closed_teardown += 1
            self._emit(record, "teardown")
            return

        self._after_insert()

    def _after_insert(self) -> None:
        self._packets_since_sweep += 1
        if self._packets_since_sweep >= _SWEEP_EVERY_PACKETS:
            self._packets_since_sweep = 0
            self.expire_idle(self._now)
        while len(self._flows) > self.max_flows:
            key, (record, _) = self._flows.popitem(last=False)
            self.evicted_capacity += 1
            self._emit(record, "capacity")
            del key

    # -- expiry ------------------------------------------------------------ #

    def expire_idle(self, now: Optional[float] = None) -> int:
        """Emit flows whose last packet is older than the idle timeout."""
        current = self._now if now is None else now
        cutoff = current - self.idle_timeout
        expired = 0
        # The map is LRU-ordered, so scanning stops at the first fresh flow.
        while self._flows:
            key, (record, _) = next(iter(self._flows.items()))
            if record.last_ts > cutoff:
                break
            self._flows.pop(key, None)
            expired += 1
            self.expired_idle += 1
            self._emit(record, "idle-timeout")
        return expired

    def flush(self) -> int:
        """Emit every remaining flow. Called once the capture is exhausted."""
        count = 0
        while self._flows:
            _key, (record, _) = self._flows.popitem(last=False)
            count += 1
            self._emit(record, "end-of-capture")
        return count

    def _emit(self, record: FlowRecord, reason: str) -> None:
        if record.total_packets < self.min_packets:
            self.dropped_short += 1
            return
        record.finalise()
        record.expiry_reason = reason
        self.emitted += 1
        if self.on_flow is not None:
            self.on_flow(record)

    # -- introspection ----------------------------------------------------- #

    def __len__(self) -> int:
        return len(self._flows)

    def active_flows(self) -> Iterator[FlowRecord]:
        for record, _ in self._flows.values():
            yield record

    def stats(self) -> Dict[str, int]:
        return {
            "emitted": self.emitted,
            "in_memory": len(self._flows),
            "expired_idle": self.expired_idle,
            "expired_active": self.expired_active,
            "expired_packet_cap": self.expired_packet_cap,
            "closed_teardown": self.closed_teardown,
            "evicted_capacity": self.evicted_capacity,
            "dropped_short": self.dropped_short,
        }


@dataclass
class ExtractionResult:
    """Outcome of running one capture file through the flow table."""

    path: Path
    flows: int = 0
    packets_total: int = 0
    packets_decoded: int = 0
    packets_skipped: int = 0
    bytes_read: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    linktypes: Dict[int, int] = field(default_factory=dict)
    capture_format: str = "unknown"
    truncated: bool = False
    warnings: List[str] = field(default_factory=list)
    table_stats: Dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0

    @property
    def decode_rate(self) -> float:
        return self.packets_decoded / self.packets_total if self.packets_total else 0.0

    def summary(self) -> str:
        return (
            f"{self.path.name}: {self.flows:,} flows from {self.packets_decoded:,}/"
            f"{self.packets_total:,} packets ({self.decode_rate:.1%} IP) in {self.elapsed_s:.1f}s"
        )


class PcapFlowExtractor:
    """Turn a capture file into flow records."""

    def __init__(
        self,
        *,
        active_timeout_s: float = 300.0,
        idle_timeout_s: float = 60.0,
        burst_gap_s: float = 1.0,
        max_flows: int = 250_000,
        min_packets: int = 1,
        max_packets_per_flow: int = 0,
        logger=None,
    ) -> None:
        self.active_timeout_s = active_timeout_s
        self.idle_timeout_s = idle_timeout_s
        self.burst_gap_s = burst_gap_s
        self.max_flows = max_flows
        self.min_packets = min_packets
        self.max_packets_per_flow = max_packets_per_flow
        self.log = logger

    def extract(
        self,
        path: str | Path,
        on_flow: Callable[[FlowRecord], None],
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> ExtractionResult:
        """Stream ``path`` through a flow table, calling ``on_flow`` per flow.

        ``should_stop`` is polled periodically so a shutdown signal interrupts a
        multi-gigabyte file instead of being ignored until it finishes.
        """
        import time as _time

        started = _time.monotonic()
        target = Path(path)
        result = ExtractionResult(path=target)

        emitted = 0

        def _sink(record: FlowRecord) -> None:
            nonlocal emitted
            emitted += 1
            on_flow(record)

        table = FlowTable(
            active_timeout_s=self.active_timeout_s,
            idle_timeout_s=self.idle_timeout_s,
            burst_gap_s=self.burst_gap_s,
            max_flows=self.max_flows,
            min_packets=self.min_packets,
            max_packets_per_flow=self.max_packets_per_flow,
            on_flow=_sink,
        )

        capture = CaptureFile(target)
        checked = 0
        for ts, data, linktype in capture.packets():
            result.packets_total += 1
            checked += 1
            if should_stop is not None and checked >= 20000:
                checked = 0
                if should_stop():
                    result.warnings.append("extraction interrupted by shutdown request")
                    break
            packet = decode_packet(ts, data, linktype)
            if packet is None:
                result.packets_skipped += 1
                continue
            result.packets_decoded += 1
            table.add_packet(packet)

        table.flush()

        info: CaptureInfo = capture.info
        result.flows = emitted
        result.bytes_read = info.bytes_read
        result.first_ts = info.first_ts
        result.last_ts = info.last_ts
        result.linktypes = dict(info.linktypes)
        result.capture_format = info.format
        result.truncated = info.truncated
        result.warnings.extend(info.warnings)
        result.table_stats = table.stats()
        result.elapsed_s = _time.monotonic() - started

        if info.truncated and self.log is not None:
            self.log.warning(
                "%s was truncated; %d complete packets were still recovered",
                target.name,
                info.packets_read,
            )
        if result.packets_total and result.packets_decoded == 0 and self.log is not None:
            names = ", ".join(str(v) for v in info.linktypes.values()) or "unknown"
            self.log.warning(
                "%s produced no IP packets from %d frames (link type %s). "
                "The capture may contain only non-IP traffic, or the mirror session may be "
                "delivering encapsulated frames this decoder does not recognise.",
                target.name,
                result.packets_total,
                names,
            )
        return result
