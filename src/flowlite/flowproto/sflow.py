"""sFlow v5 decoder.

Fixes over the previous implementation, all of which caused silent data loss on
real hardware:

* **Expanded samples are decoded.** Formats 3 and 4 (expanded flow and expanded
  counter samples) are what switches emit once interface indices exceed 2^24 --
  which is normal on stacked and chassis platforms. Previously they were skipped
  entirely, so those devices produced an empty CSV and no error.
* **Enterprise-tagged records are handled.** Sample and record type fields are
  ``(enterprise << 12) | format``; treating the whole word as a format number
  mis-parses every vendor-extended datagram.
* **Bounds are checked everywhere.** A malformed or truncated datagram from the
  network is expected input, not a crash: each record is confined to its
  declared extent and anything inconsistent is counted and dropped.
* **The sampling rate is preserved**, so a consumer can scale sampled counts
  back to an estimate of real traffic instead of under-reporting by the sample
  ratio.
"""

from __future__ import annotations

import math
import socket
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..pcap.decode import DLT_EN10MB, decode_packet

__all__ = [
    "SFLOW_SAMPLE_FIELDS",
    "SFlowDatagram",
    "decode_sflow",
    "payload_entropy",
]

SFLOW_SAMPLE_FIELDS = [
    "timestamp",
    "epoch",
    "agent_ip",
    "sub_agent_id",
    "sequence",
    "sampling_rate",
    "sample_pool",
    "drops",
    "input_if",
    "output_if",
    "frame_length",
    "stripped",
    "header_bytes",
    "payload_entropy",
    "ip_version",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "protocol_name",
    "tcp_flags",
    "vlan_id",
    "ttl",
]

_SAMPLE_FLOW = 1
_SAMPLE_COUNTER = 2
_SAMPLE_FLOW_EXPANDED = 3
_SAMPLE_COUNTER_EXPANDED = 4

_RECORD_RAW_HEADER = 1
_RECORD_ETHERNET = 2
_RECORD_IPV4 = 3
_RECORD_IPV6 = 4

_COUNTER_GENERIC = 1
_COUNTER_ETHERNET = 2

_HEADER_PROTOCOL_ETHERNET = 1
_HEADER_PROTOCOL_IPV4 = 11
_HEADER_PROTOCOL_IPV6 = 12

_MAX_SAMPLES = 512
_MAX_RECORDS = 256


def payload_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string, in bits per byte (0..8).

    High entropy in a packet header sample indicates encryption, compression or
    tunnelling; a sudden shift in the average is a useful signal.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class SFlowDatagram:
    """Everything decoded from one sFlow datagram."""

    agent_ip: str = ""
    sub_agent_id: int = 0
    sequence: int = 0
    uptime_ms: int = 0
    samples_declared: int = 0
    flow_samples: List[Dict[str, Any]] = field(default_factory=list)
    counter_samples: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class _Cursor:
    """Bounds-checked big-endian reader over an untrusted datagram."""

    __slots__ = ("data", "offset", "limit")

    def __init__(self, data: bytes, offset: int = 0, limit: Optional[int] = None) -> None:
        self.data = data
        self.offset = offset
        self.limit = len(data) if limit is None else min(limit, len(data))

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.offset)

    def u32(self) -> int:
        if self.remaining < 4:
            raise ValueError("truncated: expected 4 bytes")
        value = struct.unpack_from("!I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def u64(self) -> int:
        if self.remaining < 8:
            raise ValueError("truncated: expected 8 bytes")
        value = struct.unpack_from("!Q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def raw(self, length: int) -> bytes:
        if length < 0 or self.remaining < length:
            raise ValueError(f"truncated: expected {length} bytes")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def skip(self, length: int) -> None:
        self.offset = min(self.limit, self.offset + max(0, length))

    def sub(self, length: int) -> _Cursor:
        if length < 0 or self.remaining < length:
            raise ValueError("declared length exceeds the datagram")
        cursor = _Cursor(self.data, self.offset, self.offset + length)
        self.offset += length
        return cursor


def _split_format(word: int) -> Tuple[int, int]:
    """Split an sFlow type word into ``(enterprise, format)``."""
    return word >> 12, word & 0xFFF


def _decode_raw_header(cursor: _Cursor, epoch: float) -> Dict[str, Any]:
    header_protocol = cursor.u32()
    frame_length = cursor.u32()
    stripped = cursor.u32()
    header_length = cursor.u32()
    header = cursor.raw(min(header_length, cursor.remaining))

    result: Dict[str, Any] = {
        "frame_length": frame_length,
        "stripped": stripped,
        "header_bytes": len(header),
        "payload_entropy": round(payload_entropy(header), 6),
    }

    linktype = {
        _HEADER_PROTOCOL_ETHERNET: DLT_EN10MB,
        _HEADER_PROTOCOL_IPV4: 228,
        _HEADER_PROTOCOL_IPV6: 229,
    }.get(header_protocol)
    if linktype is None or not header:
        return result

    packet = decode_packet(epoch, header, linktype)
    if packet is not None:
        result.update(
            {
                "ip_version": packet.ip_version,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "protocol": packet.proto,
                "protocol_name": packet.proto_name,
                "tcp_flags": packet.tcp_flags,
                "vlan_id": packet.vlan_id,
                "ttl": packet.ttl,
            }
        )
    return result


def _decode_flow_sample(cursor: _Cursor, expanded: bool, epoch: float) -> List[Dict[str, Any]]:
    sequence = cursor.u32()
    if expanded:
        cursor.u32()  # source id type
        cursor.u32()  # source id index
    else:
        cursor.u32()  # packed source id
    sampling_rate = cursor.u32()
    sample_pool = cursor.u32()
    drops = cursor.u32()
    if expanded:
        cursor.u32()  # input format
        input_if = cursor.u32()
        cursor.u32()  # output format
        output_if = cursor.u32()
    else:
        input_if = cursor.u32()
        output_if = cursor.u32()
    record_count = cursor.u32()

    base = {
        "sequence": sequence,
        "sampling_rate": sampling_rate,
        "sample_pool": sample_pool,
        "drops": drops,
        "input_if": input_if,
        "output_if": output_if,
    }

    rows: List[Dict[str, Any]] = []
    for _ in range(min(record_count, _MAX_RECORDS)):
        if cursor.remaining < 8:
            break
        type_word = cursor.u32()
        length = cursor.u32()
        if length > cursor.remaining:
            break
        record = cursor.sub(length)
        enterprise, record_format = _split_format(type_word)
        if enterprise != 0:
            continue
        try:
            if record_format == _RECORD_RAW_HEADER:
                row = dict(base)
                row.update(_decode_raw_header(record, epoch))
                rows.append(row)
            elif record_format in (_RECORD_IPV4, _RECORD_IPV6):
                row = dict(base)
                row.update(_decode_ip_record(record, record_format == _RECORD_IPV6))
                rows.append(row)
            elif record_format == _RECORD_ETHERNET:
                continue
        except ValueError:
            continue
    return rows


def _decode_ip_record(cursor: _Cursor, is_v6: bool) -> Dict[str, Any]:
    """sFlow's pre-parsed IPv4/IPv6 flow records (formats 3 and 4)."""
    length = cursor.u32()
    protocol = cursor.u32()
    if is_v6:
        src = socket.inet_ntop(socket.AF_INET6, cursor.raw(16))
        dst = socket.inet_ntop(socket.AF_INET6, cursor.raw(16))
    else:
        src = socket.inet_ntoa(cursor.raw(4))
        dst = socket.inet_ntoa(cursor.raw(4))
    src_port = cursor.u32()
    dst_port = cursor.u32()
    tcp_flags = cursor.u32()
    if not is_v6:
        cursor.u32()  # tos
    else:
        cursor.u32()  # priority
    from ..pcap.decode import PROTO_NAMES

    return {
        "frame_length": length,
        "ip_version": 6 if is_v6 else 4,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "protocol_name": PROTO_NAMES.get(protocol, str(protocol)),
        "tcp_flags": tcp_flags,
        "payload_entropy": 0.0,
        "header_bytes": 0,
    }


def _decode_counter_sample(cursor: _Cursor, expanded: bool) -> List[Dict[str, Any]]:
    cursor.u32()  # sequence
    if expanded:
        cursor.u32()  # source id type
        cursor.u32()  # source id index
    else:
        cursor.u32()  # packed source id
    record_count = cursor.u32()

    rows: List[Dict[str, Any]] = []
    for _ in range(min(record_count, _MAX_RECORDS)):
        if cursor.remaining < 8:
            break
        type_word = cursor.u32()
        length = cursor.u32()
        if length > cursor.remaining:
            break
        record = cursor.sub(length)
        enterprise, record_format = _split_format(type_word)
        if enterprise != 0 or record_format != _COUNTER_GENERIC:
            continue
        try:
            rows.append(
                {
                    "if_index": record.u32(),
                    "if_type": record.u32(),
                    "speed_bps": record.u64(),
                    "direction": record.u32(),
                    "status": record.u32(),
                    "in_octets": record.u64(),
                    "in_packets": record.u32(),
                    "in_multicast": record.u32(),
                    "in_broadcast": record.u32(),
                    "in_discards": record.u32(),
                    "in_errors": record.u32(),
                    "in_unknown_protos": record.u32(),
                    "out_octets": record.u64(),
                    "out_packets": record.u32(),
                    "out_multicast": record.u32(),
                    "out_broadcast": record.u32(),
                    "out_discards": record.u32(),
                    "out_errors": record.u32(),
                }
            )
        except ValueError:
            continue
    return rows


def decode_sflow(data: bytes, epoch: float = 0.0) -> SFlowDatagram:
    """Decode one sFlow v5 datagram. Never raises on malformed input."""
    result = SFlowDatagram()
    cursor = _Cursor(data)
    try:
        version = cursor.u32()
        if version != 5:
            result.errors.append(f"unsupported sFlow version {version} (only v5 is supported)")
            return result
        address_type = cursor.u32()
        if address_type == 1:
            result.agent_ip = socket.inet_ntoa(cursor.raw(4))
        elif address_type == 2:
            result.agent_ip = socket.inet_ntop(socket.AF_INET6, cursor.raw(16))
        else:
            result.errors.append(f"unknown agent address type {address_type}")
            return result
        result.sub_agent_id = cursor.u32()
        result.sequence = cursor.u32()
        result.uptime_ms = cursor.u32()
        result.samples_declared = cursor.u32()
    except ValueError as exc:
        result.errors.append(f"datagram header truncated: {exc}")
        return result

    for _ in range(min(result.samples_declared, _MAX_SAMPLES)):
        if cursor.remaining < 8:
            break
        try:
            type_word = cursor.u32()
            length = cursor.u32()
            if length > cursor.remaining:
                result.errors.append("sample length exceeds the datagram")
                break
            sample = cursor.sub(length)
        except ValueError:
            break

        enterprise, sample_format = _split_format(type_word)
        if enterprise != 0:
            continue
        try:
            if sample_format in (_SAMPLE_FLOW, _SAMPLE_FLOW_EXPANDED):
                result.flow_samples.extend(
                    _decode_flow_sample(sample, sample_format == _SAMPLE_FLOW_EXPANDED, epoch)
                )
            elif sample_format in (_SAMPLE_COUNTER, _SAMPLE_COUNTER_EXPANDED):
                result.counter_samples.extend(
                    _decode_counter_sample(sample, sample_format == _SAMPLE_COUNTER_EXPANDED)
                )
        except ValueError as exc:
            result.errors.append(f"sample format {sample_format} truncated: {exc}")
            continue
    return result
