"""The flow CSV schema.

:data:`FLOW_FIELDS` is the single source of truth for the column set, and
:func:`flow_record_to_row` is the only function that produces rows. A test
asserts the two agree, so a feature can never be added to one and forgotten in
the other -- the drift that previously left documented columns missing from the
actual output.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .table import FlowRecord

__all__ = ["FLOW_FIELDS", "flow_record_to_row", "iso_utc"]

FLOW_FIELDS = [
    # -- identity ---------------------------------------------------------- #
    "flow_id",
    "device",
    "capture_file",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "protocol_name",
    "ip_version",
    "vlan_id",
    # -- timing ------------------------------------------------------------ #
    "start_time",
    "end_time",
    "start_epoch",
    "end_epoch",
    "duration_s",
    "expiry_reason",
    # -- volume ------------------------------------------------------------ #
    "total_packets",
    "fwd_packets",
    "bwd_packets",
    "total_bytes",
    "fwd_bytes",
    "bwd_bytes",
    "total_frame_bytes",
    "fwd_frame_bytes",
    "bwd_frame_bytes",
    "packets_per_s",
    "bytes_per_s",
    "fwd_bytes_per_s",
    "bwd_bytes_per_s",
    # -- packet size ------------------------------------------------------- #
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_var",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "fwd_pkt_len_min",
    "fwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "bwd_pkt_len_min",
    "bwd_pkt_len_max",
    # -- inter-arrival times ----------------------------------------------- #
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_min",
    "flow_iat_max",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_min",
    "fwd_iat_max",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_min",
    "bwd_iat_max",
    # -- burst structure ---------------------------------------------------- #
    "active_mean",
    "active_std",
    "active_max",
    "active_count",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_count",
    # -- TCP ---------------------------------------------------------------- #
    "syn_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_count",
    "urg_count",
    "ece_count",
    "cwr_count",
    "syn_ratio",
    "fin_ratio",
    "rst_ratio",
    "psh_ratio",
    "ack_ratio",
    "urg_ratio",
    "init_win_fwd",
    "init_win_bwd",
    "fwd_min_seg_size",
    "tcp_handshake_ms",
    "tcp_state",
    # -- IP ----------------------------------------------------------------- #
    "ttl_mean",
    "ttl_std",
    "ttl_min",
    "ttl_max",
    "fragment_packets",
    # -- shape -------------------------------------------------------------- #
    "down_up_byte_ratio",
    "fwd_bwd_packet_ratio",
    "byte_asymmetry",
    # -- enrichment ---------------------------------------------------------- #
    "src_scope",
    "dst_scope",
    "dst_asn",
    "dst_asn_org",
    "dst_country",
]


def iso_utc(epoch: float) -> str:
    """Format an epoch as a UTC ISO-8601 string with millisecond precision.

    All FlowLite timestamps are UTC. The previous release mixed
    ``datetime.now()`` (local) with ``datetime.utcnow()`` (UTC) across modules,
    so joining flows against telemetry silently misaligned by the UTC offset.
    """
    try:
        return (
            datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            + "Z"
        )
    except (OverflowError, OSError, ValueError):
        return ""


def _round(value: float, digits: int = 6) -> float:
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return round(float(value), digits)


def _ratio(numerator: float, denominator: float) -> float:
    """Divide, returning 0.0 rather than infinity when the denominator is zero."""
    return _round(numerator / denominator) if denominator else 0.0


def flow_record_to_row(
    record: FlowRecord,
    *,
    device: str = "",
    capture_file: str = "",
    enricher: Optional[Any] = None,
) -> Dict[str, Any]:
    """Render one :class:`FlowRecord` as a CSV row keyed by :data:`FLOW_FIELDS`."""
    duration = record.duration
    total_packets = record.total_packets
    total_bytes = record.total_bytes

    src_scope = dst_scope = ""
    dst_asn = dst_org = dst_country = ""
    if enricher is not None:
        src_scope = enricher.scope(record.src_ip)
        dst_scope = enricher.scope(record.dst_ip)
        dst_asn, dst_org = enricher.asn(record.dst_ip)
        dst_country = enricher.country(record.dst_ip)

    flags = record.flags
    row: Dict[str, Any] = {
        "flow_id": (
            f"{record.src_ip}|{record.src_port}|{record.dst_ip}|{record.dst_port}"
            f"|{record.protocol}|{record.first_ts:.6f}"
        ),
        "device": device,
        "capture_file": capture_file,
        "src_ip": record.src_ip,
        "src_port": record.src_port,
        "dst_ip": record.dst_ip,
        "dst_port": record.dst_port,
        "protocol": record.protocol,
        "protocol_name": record.protocol_name,
        "ip_version": record.ip_version,
        "vlan_id": record.vlan_id,
        "start_time": iso_utc(record.first_ts),
        "end_time": iso_utc(record.last_ts),
        "start_epoch": _round(record.first_ts),
        "end_epoch": _round(record.last_ts),
        "duration_s": _round(duration),
        "expiry_reason": record.expiry_reason,
        "total_packets": total_packets,
        "fwd_packets": record.fwd_packets,
        "bwd_packets": record.bwd_packets,
        "total_bytes": total_bytes,
        "fwd_bytes": record.fwd_bytes,
        "bwd_bytes": record.bwd_bytes,
        "total_frame_bytes": record.total_frame_bytes,
        "fwd_frame_bytes": record.fwd_frame_bytes,
        "bwd_frame_bytes": record.bwd_frame_bytes,
        "packets_per_s": _ratio(total_packets, duration),
        "bytes_per_s": _ratio(total_bytes, duration),
        "fwd_bytes_per_s": _ratio(record.fwd_bytes, duration),
        "bwd_bytes_per_s": _ratio(record.bwd_bytes, duration),
        "pkt_len_mean": _round(record.all_len.mean),
        "pkt_len_std": _round(record.all_len.std),
        "pkt_len_min": _round(record.all_len.minimum),
        "pkt_len_max": _round(record.all_len.maximum),
        "pkt_len_var": _round(record.all_len.variance),
        "fwd_pkt_len_mean": _round(record.fwd_len.mean),
        "fwd_pkt_len_std": _round(record.fwd_len.std),
        "fwd_pkt_len_min": _round(record.fwd_len.minimum),
        "fwd_pkt_len_max": _round(record.fwd_len.maximum),
        "bwd_pkt_len_mean": _round(record.bwd_len.mean),
        "bwd_pkt_len_std": _round(record.bwd_len.std),
        "bwd_pkt_len_min": _round(record.bwd_len.minimum),
        "bwd_pkt_len_max": _round(record.bwd_len.maximum),
        "flow_iat_mean": _round(record.all_iat.mean),
        "flow_iat_std": _round(record.all_iat.std),
        "flow_iat_min": _round(record.all_iat.minimum),
        "flow_iat_max": _round(record.all_iat.maximum),
        "fwd_iat_mean": _round(record.fwd_iat.mean),
        "fwd_iat_std": _round(record.fwd_iat.std),
        "fwd_iat_min": _round(record.fwd_iat.minimum),
        "fwd_iat_max": _round(record.fwd_iat.maximum),
        "bwd_iat_mean": _round(record.bwd_iat.mean),
        "bwd_iat_std": _round(record.bwd_iat.std),
        "bwd_iat_min": _round(record.bwd_iat.minimum),
        "bwd_iat_max": _round(record.bwd_iat.maximum),
        "active_mean": _round(record.active.mean),
        "active_std": _round(record.active.std),
        "active_max": _round(record.active.maximum),
        "active_count": record.active.count,
        "idle_mean": _round(record.idle.mean),
        "idle_std": _round(record.idle.std),
        "idle_max": _round(record.idle.maximum),
        "idle_count": record.idle.count,
        "syn_count": flags["syn"],
        "fin_count": flags["fin"],
        "rst_count": flags["rst"],
        "psh_count": flags["psh"],
        "ack_count": flags["ack"],
        "urg_count": flags["urg"],
        "ece_count": flags["ece"],
        "cwr_count": flags["cwr"],
        "syn_ratio": _ratio(flags["syn"], total_packets),
        "fin_ratio": _ratio(flags["fin"], total_packets),
        "rst_ratio": _ratio(flags["rst"], total_packets),
        "psh_ratio": _ratio(flags["psh"], total_packets),
        "ack_ratio": _ratio(flags["ack"], total_packets),
        "urg_ratio": _ratio(flags["urg"], total_packets),
        "init_win_fwd": max(0, record.init_win_fwd),
        "init_win_bwd": max(0, record.init_win_bwd),
        "fwd_min_seg_size": max(0, record.fwd_min_seg),
        "tcp_handshake_ms": _round(record.handshake_ms, 3),
        "tcp_state": record.tcp_state,
        "ttl_mean": _round(record.ttl.mean, 2),
        "ttl_std": _round(record.ttl.std, 3),
        "ttl_min": int(record.ttl.minimum),
        "ttl_max": int(record.ttl.maximum),
        "fragment_packets": record.fragment_packets,
        "down_up_byte_ratio": _ratio(record.bwd_bytes, record.fwd_bytes),
        "fwd_bwd_packet_ratio": _ratio(record.fwd_packets, record.bwd_packets),
        "byte_asymmetry": _ratio(abs(record.fwd_bytes - record.bwd_bytes), total_bytes),
        "src_scope": src_scope,
        "dst_scope": dst_scope,
        "dst_asn": dst_asn,
        "dst_asn_org": dst_org,
        "dst_country": dst_country,
    }
    return row
