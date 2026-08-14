"""NetFlow v5, NetFlow v9 and IPFIX (v10) decoding.

Adding these makes FlowLite work with devices that cannot mirror traffic at all.
A router exporting NetFlow, a firewall exporting IPFIX and a switch exporting
sFlow all become the same rows in the same CSV, so the tool is genuinely
device-agnostic rather than "agnostic as long as you can get a SPAN port".

Template handling is the part that decides whether a v9/IPFIX collector works in
production:

* Templates are cached per ``(exporter, observation domain, template id)``.
  Different exporters reuse the same template ids for different layouts, so a
  global cache silently decodes one device's records with another's schema.
* The cache is **persisted**. Exporters resend templates on a timer that is
  commonly 10-30 minutes; a collector restart without persistence discards every
  data record until the next refresh.
* A template that is redefined with new contents replaces the old one, and data
  records arriving before their template are counted rather than dropped
  silently, so the "no data" case is diagnosable.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..pcap.decode import PROTO_NAMES
from ..storage.atomic import atomic_write_json, read_json

__all__ = [
    "NETFLOW_FIELDS",
    "NetFlowDecoder",
    "TemplateCache",
    "decode_netflow_v5",
]

NETFLOW_FIELDS = [
    "timestamp",
    "epoch",
    "exporter",
    "version",
    "observation_domain",
    "template_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "protocol_name",
    "tcp_flags",
    "ip_version",
    "packets",
    "bytes",
    "first_switched",
    "last_switched",
    "duration_s",
    "input_if",
    "output_if",
    "src_vlan",
    "tos",
    "src_asn",
    "dst_asn",
    "sampling_rate",
]

# IANA IPFIX information elements that NetFlow v9 shares by number.
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_PROTOCOL = 4
FIELD_TOS = 5
FIELD_TCP_FLAGS = 6
FIELD_SRC_PORT = 7
FIELD_IPV4_SRC = 8
FIELD_INPUT_SNMP = 10
FIELD_DST_PORT = 11
FIELD_IPV4_DST = 12
FIELD_OUTPUT_SNMP = 14
FIELD_SRC_AS = 16
FIELD_DST_AS = 17
FIELD_LAST_SWITCHED = 21
FIELD_FIRST_SWITCHED = 22
FIELD_OUT_BYTES = 23
FIELD_OUT_PKTS = 24
FIELD_IPV6_SRC = 27
FIELD_IPV6_DST = 28
FIELD_SRC_VLAN = 58
FIELD_FLOW_START_SECONDS = 150
FIELD_FLOW_END_SECONDS = 151
FIELD_FLOW_START_MILLIS = 152
FIELD_FLOW_END_MILLIS = 153
FIELD_FLOW_START_MICROS = 154
FIELD_FLOW_END_MICROS = 155
FIELD_SAMPLING_INTERVAL = 34
FIELD_SAMPLING_PACKET_INTERVAL = 305
FIELD_OCTET_TOTAL = 85
FIELD_PACKET_TOTAL = 86

_V5_HEADER = struct.Struct("!HHIIIIBBH")
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBB2s")


def _int_from(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


@dataclass
class Template:
    """A decoded template: the field layout for a set of data records."""

    template_id: int
    fields: List[Tuple[int, int]] = field(default_factory=list)  # (element id, length)
    scope_count: int = 0
    updated: float = field(default_factory=time.time)

    @property
    def length(self) -> int:
        """Total record length, or -1 when a variable-length field is present."""
        total = 0
        for _element, size in self.fields:
            if size == 0xFFFF:
                return -1
            total += size
        return total

    def to_json(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "fields": [list(f) for f in self.fields],
            "scope_count": self.scope_count,
            "updated": self.updated,
        }

    @staticmethod
    def from_json(payload: Dict[str, Any]) -> Template:
        return Template(
            template_id=int(payload.get("template_id", 0)),
            fields=[(int(a), int(b)) for a, b in payload.get("fields", [])],
            scope_count=int(payload.get("scope_count", 0)),
            updated=float(payload.get("updated", time.time())),
        )


class TemplateCache:
    """Templates keyed by exporter and observation domain, persisted to disk."""

    def __init__(self, path: Optional[str | Path] = None, ttl_s: float = 3600.0) -> None:
        self.path = Path(path) if path else None
        self.ttl_s = float(ttl_s)
        self._templates: Dict[Tuple[str, int, int], Template] = {}
        self.load()

    def key(self, exporter: str, domain: int, template_id: int) -> Tuple[str, int, int]:
        return (exporter, int(domain), int(template_id))

    def put(self, exporter: str, domain: int, template: Template) -> bool:
        """Store a template; returns True when it is new or changed."""
        key = self.key(exporter, domain, template.template_id)
        existing = self._templates.get(key)
        changed = existing is None or existing.fields != template.fields
        self._templates[key] = template
        return changed

    def get(self, exporter: str, domain: int, template_id: int) -> Optional[Template]:
        template = self._templates.get(self.key(exporter, domain, template_id))
        if template is None:
            return None
        if self.ttl_s and time.time() - template.updated > self.ttl_s:
            # Expired templates are dropped so a re-used id cannot be decoded
            # with a stale layout after an exporter reconfiguration.
            self._templates.pop(self.key(exporter, domain, template_id), None)
            return None
        return template

    def __len__(self) -> int:
        return len(self._templates)

    def load(self) -> None:
        if self.path is None:
            return
        payload = read_json(self.path, default=None)
        if not isinstance(payload, dict):
            return
        for raw_key, raw_template in (payload.get("templates") or {}).items():
            try:
                exporter, domain, template_id = raw_key.split("|")
                self._templates[(exporter, int(domain), int(template_id))] = Template.from_json(
                    raw_template
                )
            except (ValueError, TypeError, AttributeError):
                continue

    def save(self) -> None:
        if self.path is None:
            return
        payload = {
            "templates": {
                f"{exporter}|{domain}|{template_id}": template.to_json()
                for (exporter, domain, template_id), template in self._templates.items()
            }
        }
        try:
            atomic_write_json(self.path, payload, fsync=False)
        except OSError:
            pass


def decode_netflow_v5(data: bytes, exporter: str, epoch: float) -> List[Dict[str, Any]]:
    """Decode a NetFlow v5 datagram (a fixed 48-byte record layout)."""
    if len(data) < _V5_HEADER.size:
        return []
    (
        version,
        count,
        sys_uptime,
        unix_secs,
        _unix_nsecs,
        _sequence,
        _engine_type,
        _engine_id,
        sampling,
    ) = _V5_HEADER.unpack_from(data, 0)
    if version != 5:
        return []

    sampling_rate = sampling & 0x3FFF or 1
    boot_time = unix_secs - sys_uptime / 1000.0
    rows: List[Dict[str, Any]] = []
    offset = _V5_HEADER.size
    usable = min(count, (len(data) - offset) // _V5_RECORD.size)

    for _ in range(usable):
        (
            src_raw,
            dst_raw,
            _next_hop,
            input_if,
            output_if,
            packets,
            octets,
            first,
            last,
            src_port,
            dst_port,
            _pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            _src_mask,
            _dst_mask,
            _pad2,
        ) = _V5_RECORD.unpack_from(data, offset)
        offset += _V5_RECORD.size

        start = boot_time + first / 1000.0
        end = boot_time + last / 1000.0
        rows.append(
            {
                "epoch": round(unix_secs or epoch, 3),
                "exporter": exporter,
                "version": 5,
                "observation_domain": 0,
                "template_id": 0,
                "src_ip": socket.inet_ntoa(src_raw),
                "dst_ip": socket.inet_ntoa(dst_raw),
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "protocol_name": PROTO_NAMES.get(protocol, str(protocol)),
                "tcp_flags": tcp_flags,
                "ip_version": 4,
                "packets": packets,
                "bytes": octets,
                "first_switched": round(start, 3),
                "last_switched": round(end, 3),
                "duration_s": round(max(0.0, end - start), 3),
                "input_if": input_if,
                "output_if": output_if,
                "src_vlan": 0,
                "tos": tos,
                "src_asn": src_as,
                "dst_asn": dst_as,
                "sampling_rate": sampling_rate,
            }
        )
    return rows


class NetFlowDecoder:
    """Stateful decoder for NetFlow v5/v9 and IPFIX."""

    def __init__(self, cache: Optional[TemplateCache] = None, logger=None) -> None:
        self.cache = cache if cache is not None else TemplateCache()
        self.log = logger
        self.records_decoded = 0
        self.records_awaiting_template = 0
        self.datagrams = 0
        self.errors = 0

    def decode(
        self, data: bytes, exporter: str, epoch: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Decode one datagram of any supported version."""
        now = time.time() if epoch is None else epoch
        self.datagrams += 1
        if len(data) < 4:
            self.errors += 1
            return []
        version = struct.unpack_from("!H", data, 0)[0]
        try:
            if version == 5:
                rows = decode_netflow_v5(data, exporter, now)
            elif version == 9:
                rows = self._decode_v9(data, exporter, now)
            elif version == 10:
                rows = self._decode_ipfix(data, exporter, now)
            elif version in (1, 7, 8):
                self.errors += 1
                if self.log is not None:
                    self.log.warning(
                        "NetFlow v%d is not supported; configure the exporter for v5, v9 or IPFIX",
                        version,
                    )
                return []
            else:
                self.errors += 1
                return []
        except (struct.error, ValueError, IndexError) as exc:
            self.errors += 1
            if self.log is not None:
                self.log.debug("Malformed NetFlow datagram from %s: %s", exporter, exc)
            return []
        self.records_decoded += len(rows)
        return rows

    # -- v9 ---------------------------------------------------------------- #

    def _decode_v9(self, data: bytes, exporter: str, epoch: float) -> List[Dict[str, Any]]:
        if len(data) < 20:
            return []
        _version, _count, sys_uptime, unix_secs, _sequence, domain = struct.unpack_from(
            "!HHIIII", data, 0
        )
        boot_time = unix_secs - sys_uptime / 1000.0
        return self._decode_sets(
            data, 20, exporter, domain, 9, epoch, unix_secs or epoch, boot_time, len(data)
        )

    # -- IPFIX -------------------------------------------------------------- #

    def _decode_ipfix(self, data: bytes, exporter: str, epoch: float) -> List[Dict[str, Any]]:
        if len(data) < 16:
            return []
        _version, length, export_time, _sequence, domain = struct.unpack_from("!HHIII", data, 0)
        limit = min(length, len(data)) if length >= 16 else len(data)
        return self._decode_sets(
            data, 16, exporter, domain, 10, epoch, export_time or epoch, 0.0, limit
        )

    def _decode_sets(
        self,
        data: bytes,
        offset: int,
        exporter: str,
        domain: int,
        version: int,
        epoch: float,
        export_time: float,
        boot_time: float,
        limit: int,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        template_set_id = 0 if version == 9 else 2
        options_set_id = 1 if version == 9 else 3
        templates_changed = False

        while offset + 4 <= limit:
            set_id, set_length = struct.unpack_from("!HH", data, offset)
            if set_length < 4 or offset + set_length > limit:
                break
            body_start = offset + 4
            body_end = offset + set_length
            offset = body_end

            if set_id == template_set_id:
                templates_changed |= self._read_templates(
                    data, body_start, body_end, exporter, domain, version
                )
            elif set_id == options_set_id:
                templates_changed |= self._read_option_templates(
                    data, body_start, body_end, exporter, domain, version
                )
            elif set_id >= 256:
                template = self.cache.get(exporter, domain, set_id)
                if template is None:
                    self.records_awaiting_template += 1
                    continue
                rows.extend(
                    self._read_data_records(
                        data,
                        body_start,
                        body_end,
                        template,
                        exporter,
                        domain,
                        version,
                        epoch,
                        export_time,
                        boot_time,
                    )
                )

        if templates_changed:
            self.cache.save()
        return rows

    def _read_templates(
        self, data: bytes, start: int, end: int, exporter: str, domain: int, version: int
    ) -> bool:
        changed = False
        offset = start
        while offset + 4 <= end:
            template_id, field_count = struct.unpack_from("!HH", data, offset)
            offset += 4
            if template_id < 256 or field_count == 0:
                break
            fields, offset = self._read_field_specs(data, offset, end, field_count, version)
            if fields is None:
                break
            changed |= self.cache.put(exporter, domain, Template(template_id, fields))
        return changed

    def _read_option_templates(
        self, data: bytes, start: int, end: int, exporter: str, domain: int, version: int
    ) -> bool:
        """Option templates carry metadata such as the sampling interval."""
        changed = False
        offset = start
        while offset + 6 <= end:
            if version == 9:
                template_id, scope_length, option_length = struct.unpack_from("!HHH", data, offset)
                offset += 6
                scope_count = scope_length // 4
                option_count = option_length // 4
                total = scope_count + option_count
            else:
                template_id, total, scope_count = struct.unpack_from("!HHH", data, offset)
                offset += 6
            if template_id < 256 or total == 0:
                break
            fields, offset = self._read_field_specs(data, offset, end, total, version)
            if fields is None:
                break
            changed |= self.cache.put(
                exporter, domain, Template(template_id, fields, scope_count=scope_count)
            )
        return changed

    @staticmethod
    def _read_field_specs(
        data: bytes, offset: int, end: int, count: int, version: int
    ) -> Tuple[Optional[List[Tuple[int, int]]], int]:
        fields: List[Tuple[int, int]] = []
        for _ in range(count):
            if offset + 4 > end:
                return None, offset
            element, length = struct.unpack_from("!HH", data, offset)
            offset += 4
            if version == 10 and element & 0x8000:
                # Enterprise-specific element: skip the 4-byte PEN but keep the
                # length so record offsets stay aligned.
                if offset + 4 > end:
                    return None, offset
                offset += 4
                element = 0
            fields.append((element, length))
        return fields, offset

    def _read_data_records(
        self,
        data: bytes,
        start: int,
        end: int,
        template: Template,
        exporter: str,
        domain: int,
        version: int,
        epoch: float,
        export_time: float,
        boot_time: float,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        offset = start
        record_length = template.length

        while offset < end:
            if record_length > 0:
                if offset + record_length > end:
                    break
                values, offset = self._read_fixed_record(data, offset, template)
            else:
                values, offset = self._read_variable_record(data, offset, end, template)
                if values is None:
                    break
            if not values:
                break
            row = self._render(
                values,
                exporter,
                domain,
                template.template_id,
                version,
                epoch,
                export_time,
                boot_time,
            )
            if row is not None:
                rows.append(row)
            # Trailing padding is shorter than any record.
            if end - offset < 4:
                break
        return rows

    @staticmethod
    def _read_fixed_record(
        data: bytes, offset: int, template: Template
    ) -> Tuple[Dict[int, bytes], int]:
        values: Dict[int, bytes] = {}
        for element, length in template.fields:
            values[element] = data[offset : offset + length]
            offset += length
        return values, offset

    @staticmethod
    def _read_variable_record(
        data: bytes, offset: int, end: int, template: Template
    ) -> Tuple[Optional[Dict[int, bytes]], int]:
        values: Dict[int, bytes] = {}
        for element, length in template.fields:
            if length == 0xFFFF:
                if offset >= end:
                    return None, offset
                size = data[offset]
                offset += 1
                if size == 255:
                    if offset + 2 > end:
                        return None, offset
                    size = struct.unpack_from("!H", data, offset)[0]
                    offset += 2
            else:
                size = length
            if offset + size > end:
                return None, offset
            values[element] = data[offset : offset + size]
            offset += size
        return values, offset

    @staticmethod
    def _render(
        values: Dict[int, bytes],
        exporter: str,
        domain: int,
        template_id: int,
        version: int,
        epoch: float,
        export_time: float,
        boot_time: float,
    ) -> Optional[Dict[str, Any]]:
        def number(element: int, default: int = 0) -> int:
            raw = values.get(element)
            return _int_from(raw) if raw else default

        src_ip = dst_ip = ""
        ip_version = 0
        if FIELD_IPV4_SRC in values and len(values[FIELD_IPV4_SRC]) == 4:
            src_ip = socket.inet_ntoa(values[FIELD_IPV4_SRC])
            dst_ip = socket.inet_ntoa(values.get(FIELD_IPV4_DST, b"\x00\x00\x00\x00")[:4])
            ip_version = 4
        elif FIELD_IPV6_SRC in values and len(values[FIELD_IPV6_SRC]) == 16:
            src_ip = socket.inet_ntop(socket.AF_INET6, values[FIELD_IPV6_SRC])
            dst_ip = socket.inet_ntop(
                socket.AF_INET6, values.get(FIELD_IPV6_DST, b"\x00" * 16)[:16]
            )
            ip_version = 6
        else:
            # No addresses: an options record, not a flow.
            return None

        protocol = number(FIELD_PROTOCOL)
        packets = number(FIELD_IN_PKTS) or number(FIELD_PACKET_TOTAL) or number(FIELD_OUT_PKTS)
        octets = number(FIELD_IN_BYTES) or number(FIELD_OCTET_TOTAL) or number(FIELD_OUT_BYTES)

        start = end = 0.0
        if FIELD_FLOW_START_MILLIS in values:
            start = number(FIELD_FLOW_START_MILLIS) / 1000.0
            end = number(FIELD_FLOW_END_MILLIS) / 1000.0
        elif FIELD_FLOW_START_SECONDS in values:
            start = float(number(FIELD_FLOW_START_SECONDS))
            end = float(number(FIELD_FLOW_END_SECONDS))
        elif FIELD_FLOW_START_MICROS in values:
            start = number(FIELD_FLOW_START_MICROS) / 1_000_000.0
            end = number(FIELD_FLOW_END_MICROS) / 1_000_000.0
        elif FIELD_FIRST_SWITCHED in values:
            # v9 sysUpTime deltas in milliseconds since the exporter booted.
            start = boot_time + number(FIELD_FIRST_SWITCHED) / 1000.0
            end = boot_time + number(FIELD_LAST_SWITCHED) / 1000.0
        else:
            start = end = export_time

        sampling = number(FIELD_SAMPLING_INTERVAL) or number(FIELD_SAMPLING_PACKET_INTERVAL) or 1

        return {
            "epoch": round(export_time or epoch, 3),
            "exporter": exporter,
            "version": version,
            "observation_domain": domain,
            "template_id": template_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": number(FIELD_SRC_PORT),
            "dst_port": number(FIELD_DST_PORT),
            "protocol": protocol,
            "protocol_name": PROTO_NAMES.get(protocol, str(protocol)),
            "tcp_flags": number(FIELD_TCP_FLAGS),
            "ip_version": ip_version,
            "packets": packets,
            "bytes": octets,
            "first_switched": round(start, 3),
            "last_switched": round(end, 3),
            "duration_s": round(max(0.0, end - start), 3),
            "input_if": number(FIELD_INPUT_SNMP),
            "output_if": number(FIELD_OUTPUT_SNMP),
            "src_vlan": number(FIELD_SRC_VLAN),
            "tos": number(FIELD_TOS),
            "src_asn": number(FIELD_SRC_AS),
            "dst_asn": number(FIELD_DST_AS),
            "sampling_rate": sampling,
        }

    def stats(self) -> Dict[str, int]:
        return {
            "datagrams": self.datagrams,
            "records": self.records_decoded,
            "awaiting_template": self.records_awaiting_template,
            "errors": self.errors,
            "templates": len(self.cache),
        }
