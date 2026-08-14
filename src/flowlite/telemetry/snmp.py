"""SNMP v1/v2c client and telemetry driver, implemented on the standard library.

SNMP is what makes FlowLite vendor-neutral in practice. IF-MIB is supported by
every managed switch, router, firewall and load balancer ever shipped, from a
five-port desk switch to a chassis core -- so one driver covers the entire
market, with no vendor SDK, no API enablement and no per-platform parsing.

There is no dependency on ``pysnmp``: the BER encoder/decoder and the GETBULK
walker below are a few hundred lines of the standard library, which is a smaller
maintenance surface than a large third-party stack and removes a hard install
requirement from the critical path.

Scope: SNMP v1 and v2c. v3 (authentication and privacy) is not implemented; the
configuration validator rejects it explicitly rather than silently downgrading.
"""

from __future__ import annotations

import os
import socket
import time
from collections.abc import Iterator, Sequence
from typing import Any, Dict, List, Optional, Tuple

from ..errors import ParseError, TransientTelemetryError
from .base import DeviceSnapshot, InterfaceCounters, PreflightReport, TelemetryDriver

__all__ = ["SnmpClient", "SnmpTelemetryDriver", "OID", "encode_oid", "decode_oid"]

# -- ASN.1 / BER tags --------------------------------------------------------- #
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW = 0x82

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5

_ERROR_STATUS = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


class OID:
    """Well-known object identifiers, as dotted strings."""

    SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
    SYS_NAME = "1.3.6.1.2.1.1.5.0"
    IF_NUMBER = "1.3.6.1.2.1.2.1.0"

    IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
    IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
    IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
    IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
    IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
    IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
    IF_IN_UCAST = "1.3.6.1.2.1.2.2.1.11"
    IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
    IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
    IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
    IF_OUT_UCAST = "1.3.6.1.2.1.2.2.1.17"
    IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
    IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

    IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
    IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
    IF_HC_IN_UCAST = "1.3.6.1.2.1.31.1.1.1.7"
    IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
    IF_HC_OUT_UCAST = "1.3.6.1.2.1.31.1.1.1.11"
    IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
    IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

    ARP_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"
    FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
    IP_CIDR_ROUTE_NUMBER = "1.3.6.1.2.1.4.24.3.0"
    INET_CIDR_ROUTE_NUMBER = "1.3.6.1.2.1.4.24.6.0"

    _ADMIN = {1: "up", 2: "down", 3: "testing"}
    _OPER = {
        1: "up",
        2: "down",
        3: "testing",
        4: "unknown",
        5: "dormant",
        6: "notPresent",
        7: "lowerLayerDown",
    }


# --------------------------------------------------------------------------- #
# BER encoding
# --------------------------------------------------------------------------- #


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = b""
    value = length
    while value:
        body = bytes([value & 0xFF]) + body
        value >>= 8
    return bytes([0x80 | len(body)]) + body


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(value: int, tag: int = TAG_INTEGER) -> bytes:
    if value == 0:
        return _encode_tlv(tag, b"\x00")
    negative = value < 0
    body = b""
    work = value
    if negative:
        # Two's complement over the minimum number of octets.
        length = ((value + 1).bit_length() // 8) + 1
        work = value + (1 << (8 * length))
        for _ in range(length):
            body = bytes([work & 0xFF]) + body
            work >>= 8
    else:
        while work:
            body = bytes([work & 0xFF]) + body
            work >>= 8
        if body[0] & 0x80:
            body = b"\x00" + body
    return _encode_tlv(tag, body)


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID string as BER content octets."""
    parts = [int(p) for p in oid.strip(". ").split(".") if p != ""]
    if len(parts) < 2:
        raise ValueError(f"OID {oid!r} needs at least two arcs")
    if parts[0] > 6 or parts[1] > 39:
        raise ValueError(f"OID {oid!r} has invalid leading arcs")
    body = bytearray([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        if arc < 0:
            raise ValueError(f"OID {oid!r} contains a negative arc")
        if arc < 0x80:
            body.append(arc)
            continue
        chunk = bytearray()
        value = arc
        while value:
            chunk.insert(0, (value & 0x7F) | 0x80)
            value >>= 7
        chunk[-1] &= 0x7F
        body.extend(chunk)
    return _encode_tlv(TAG_OID, bytes(body))


# --------------------------------------------------------------------------- #
# BER decoding
# --------------------------------------------------------------------------- #


def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ParseError("SNMP response truncated while reading a length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ParseError("SNMP response has an unsupported or truncated length field")
    length = int.from_bytes(data[offset : offset + count], "big")
    return length, offset + count


def _decode_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ParseError("SNMP response truncated while reading a tag")
    tag = data[offset]
    length, offset = _decode_length(data, offset + 1)
    end = offset + length
    if end > len(data):
        raise ParseError("SNMP response truncated inside a value")
    return tag, data[offset:end], end


def _decode_integer(body: bytes) -> int:
    if not body:
        return 0
    value = int.from_bytes(body, "big")
    if body[0] & 0x80:
        value -= 1 << (8 * len(body))
    return value


def decode_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(a) for a in arcs)


def _decode_value(tag: int, body: bytes) -> Any:
    if tag == TAG_INTEGER:
        return _decode_integer(body)
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return int.from_bytes(body, "big") if body else 0
    if tag == TAG_OCTET_STRING:
        try:
            text = body.decode("utf-8")
            if all(ch.isprintable() or ch in "\t " for ch in text):
                return text.strip()
        except UnicodeDecodeError:
            pass
        return ":".join(f"{b:02x}" for b in body)
    if tag == TAG_OID:
        return decode_oid(body)
    if tag == TAG_IPADDRESS:
        return ".".join(str(b) for b in body) if len(body) == 4 else body.hex()
    if tag == TAG_NULL:
        return None
    if tag == TAG_NO_SUCH_OBJECT:
        return "__noSuchObject__"
    if tag == TAG_NO_SUCH_INSTANCE:
        return "__noSuchInstance__"
    if tag == TAG_END_OF_MIB_VIEW:
        return "__endOfMibView__"
    return body


_SENTINELS = frozenset({"__noSuchObject__", "__noSuchInstance__", "__endOfMibView__"})


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class SnmpClient:
    """A minimal, dependency-free SNMP v1/v2c client."""

    def __init__(
        self,
        host: str,
        community: str,
        port: int = 161,
        version: str = "2c",
        timeout: float = 5.0,
        retries: int = 2,
        max_repetitions: int = 25,
    ) -> None:
        self.host = host
        self.community = community
        self.port = int(port)
        self.version_code = 1 if str(version) == "2c" else 0
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.max_repetitions = max(1, int(max_repetitions))
        self._request_id = int.from_bytes(os.urandom(2), "big") | 1
        self._socket: Optional[socket.socket] = None

    # -- transport --------------------------------------------------------- #

    def _ensure_socket(self) -> socket.socket:
        if self._socket is None:
            family = socket.AF_INET
            try:
                info = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)
                family = info[0][0]
            except socket.gaierror as exc:
                raise TransientTelemetryError(f"cannot resolve {self.host}: {exc}") from exc
            self._socket = socket.socket(family, socket.SOCK_DGRAM)
            self._socket.settimeout(self.timeout)
        return self._socket

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def __enter__(self) -> SnmpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _next_request_id(self) -> int:
        self._request_id = (self._request_id + 1) & 0x7FFFFFFF or 1
        return self._request_id

    def _build(
        self, pdu_type: int, oids: Sequence[str], non_repeaters: int, max_reps: int
    ) -> Tuple[bytes, int]:
        request_id = self._next_request_id()
        varbinds = b"".join(
            _encode_tlv(TAG_SEQUENCE, encode_oid(o) + _encode_tlv(TAG_NULL, b"")) for o in oids
        )
        pdu_body = (
            _encode_integer(request_id)
            + _encode_integer(non_repeaters)
            + _encode_integer(max_reps)
            + _encode_tlv(TAG_SEQUENCE, varbinds)
        )
        message = (
            _encode_integer(self.version_code)
            + _encode_tlv(TAG_OCTET_STRING, self.community.encode("utf-8"))
            + _encode_tlv(pdu_type, pdu_body)
        )
        return _encode_tlv(TAG_SEQUENCE, message), request_id

    def _parse(self, data: bytes, expected_id: int) -> List[Tuple[str, Any]]:
        tag, body, _ = _decode_tlv(data, 0)
        if tag != TAG_SEQUENCE:
            raise ParseError("SNMP response is not a SEQUENCE")
        offset = 0
        _tag, version_body, offset = _decode_tlv(body, offset)
        _tag, _community, offset = _decode_tlv(body, offset)
        pdu_tag, pdu_body, _offset = _decode_tlv(body, offset)
        if pdu_tag != PDU_RESPONSE:
            raise ParseError(f"expected an SNMP response PDU, got tag 0x{pdu_tag:02x}")
        del version_body

        position = 0
        _tag, request_id_body, position = _decode_tlv(pdu_body, position)
        _tag, error_status_body, position = _decode_tlv(pdu_body, position)
        _tag, error_index_body, position = _decode_tlv(pdu_body, position)
        request_id = _decode_integer(request_id_body)
        error_status = _decode_integer(error_status_body)
        error_index = _decode_integer(error_index_body)

        if request_id != expected_id:
            raise ParseError(f"SNMP response id {request_id} does not match request {expected_id}")
        if error_status:
            name = _ERROR_STATUS.get(error_status, str(error_status))
            raise TransientTelemetryError(
                f"agent returned error {name} at varbind index {error_index}"
            )

        _tag, varbind_list, _position = _decode_tlv(pdu_body, position)
        results: List[Tuple[str, Any]] = []
        cursor = 0
        while cursor < len(varbind_list):
            _tag, varbind, cursor = _decode_tlv(varbind_list, cursor)
            inner = 0
            oid_tag, oid_body, inner = _decode_tlv(varbind, inner)
            if oid_tag != TAG_OID:
                continue
            value_tag, value_body, _inner = _decode_tlv(varbind, inner)
            results.append((decode_oid(oid_body), _decode_value(value_tag, value_body)))
        return results

    def _exchange(self, packet: bytes, request_id: int) -> List[Tuple[str, Any]]:
        sock = self._ensure_socket()
        last_error: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                sock.sendto(packet, (self.host, self.port))
                deadline = time.monotonic() + self.timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout("no response within the timeout")
                    sock.settimeout(remaining)
                    data, _addr = sock.recvfrom(65535)
                    try:
                        return self._parse(data, request_id)
                    except ParseError as exc:
                        # A late reply to an earlier request: keep waiting.
                        if "does not match request" in str(exc):
                            continue
                        raise
            except (socket.timeout, TimeoutError) as exc:
                last_error = TransientTelemetryError(
                    f"no SNMP response from {self.host}:{self.port} after {self.timeout:.0f}s"
                )
                del exc
            except OSError as exc:
                last_error = TransientTelemetryError(f"SNMP socket error: {exc}")
                self.close()
                sock = self._ensure_socket()
            if attempt < self.retries:
                time.sleep(min(1.0, 0.25 * (attempt + 1)))
        raise last_error or TransientTelemetryError("SNMP request failed")

    # -- operations -------------------------------------------------------- #

    def get(self, oids: Sequence[str]) -> Dict[str, Any]:
        """GET one or more scalar OIDs."""
        if not oids:
            return {}
        packet, request_id = self._build(PDU_GET, list(oids), 0, 0)
        return {
            oid: value
            for oid, value in self._exchange(packet, request_id)
            if value not in _SENTINELS
        }

    def walk(self, root: str, limit: int = 100000) -> Iterator[Tuple[str, Any]]:
        """Walk a subtree with GETBULK (v2c) or GETNEXT (v1)."""
        prefix = root.strip(". ")
        current = prefix
        produced = 0
        seen_guard = 0

        while produced < limit:
            if self.version_code == 1:
                packet, request_id = self._build(PDU_GETBULK, [current], 0, self.max_repetitions)
            else:
                packet, request_id = self._build(PDU_GETNEXT, [current], 0, 0)
            varbinds = self._exchange(packet, request_id)
            if not varbinds:
                return

            advanced = False
            for oid, value in varbinds:
                if not (oid == prefix or oid.startswith(prefix + ".")):
                    return
                if value == "__endOfMibView__":
                    return
                if value in _SENTINELS:
                    continue
                if oid == current:
                    # A non-advancing agent would otherwise loop forever.
                    seen_guard += 1
                    if seen_guard > 3:
                        return
                    continue
                current = oid
                advanced = True
                produced += 1
                yield oid, value
                if produced >= limit:
                    return
            if not advanced:
                return

    def walk_column(self, root: str, limit: int = 100000) -> Dict[str, Any]:
        """Walk a table column, keyed by the row index (the OID suffix)."""
        prefix = root.strip(". ") + "."
        out: Dict[str, Any] = {}
        for oid, value in self.walk(root, limit):
            out[oid[len(prefix) :]] = value
        return out

    def count(self, root: str, limit: int = 200000) -> int:
        """Count entries in a table column without retaining them."""
        total = 0
        for _oid, _value in self.walk(root, limit):
            total += 1
        return total


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


class SnmpTelemetryDriver(TelemetryDriver):
    """Collect IF-MIB and system data from any SNMP-capable device."""

    name = "snmp"

    def __init__(self, cfg, logger) -> None:
        super().__init__(cfg, logger)
        snmp = cfg.telemetry.snmp
        self.host = snmp.host
        self.port = int(snmp.port)
        self.community = snmp.community
        self.version = snmp.version
        self.max_repetitions = int(snmp.max_repetitions)
        self.retries = int(snmp.retries)
        self.collect_names = bool(snmp.collect_interface_names)
        self.collect_hc = bool(snmp.collect_high_capacity)
        self.tables = {str(t).lower() for t in getattr(snmp, "tables", []) or []}
        self._client: Optional[SnmpClient] = None
        self._hc_supported: Optional[bool] = None

    def describe(self) -> str:
        return f"snmp v{self.version} {self.host}:{self.port}"

    def _get_client(self) -> SnmpClient:
        if self._client is None:
            self._client = SnmpClient(
                host=self.host,
                community=self.community,
                port=self.port,
                version=self.version,
                timeout=self.timeout,
                retries=self.retries,
                max_repetitions=self.max_repetitions,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def preflight(self) -> PreflightReport:
        try:
            client = self._get_client()
            result = client.get([OID.SYS_DESCR, OID.SYS_NAME, OID.IF_NUMBER])
        except Exception as exc:
            return PreflightReport(
                ok=False,
                driver=self.name,
                detail=f"no usable response from {self.host}:{self.port}: {exc}",
                hints=[
                    "Confirm the device has SNMP enabled and this host is permitted by its ACL",
                    "Check credentials.snmp_community and telemetry.snmp.version",
                    f"Try: snmpget -v2c -c <community> {self.host} {OID.SYS_DESCR}",
                ],
            )
        descr = str(result.get(OID.SYS_DESCR, ""))[:90]
        count = result.get(OID.IF_NUMBER, "?")
        return PreflightReport(
            ok=True,
            driver=self.name,
            detail=f"{result.get(OID.SYS_NAME, self.host)} ({count} interfaces) -- {descr}",
        )

    def collect(self) -> DeviceSnapshot:
        started = time.monotonic()
        try:
            client = self._get_client()
            snapshot = DeviceSnapshot(device=self.device, driver=self.name, epoch=time.time())

            system = client.get([OID.SYS_DESCR, OID.SYS_NAME, OID.SYS_UPTIME])
            snapshot.system_description = str(system.get(OID.SYS_DESCR, ""))[:200]
            snapshot.system_name = str(system.get(OID.SYS_NAME, ""))
            ticks = system.get(OID.SYS_UPTIME)
            if isinstance(ticks, int):
                snapshot.uptime_s = ticks / 100.0

            snapshot.interfaces = self._collect_interfaces(client)

            if "arp" in self.tables:
                snapshot.arp_entries = client.count(OID.ARP_PHYS_ADDRESS)
            if "mac" in self.tables:
                snapshot.mac_entries = client.count(OID.FDB_ADDRESS)
            if "routes" in self.tables:
                routes = client.get([OID.INET_CIDR_ROUTE_NUMBER, OID.IP_CIDR_ROUTE_NUMBER])
                for key in (OID.INET_CIDR_ROUTE_NUMBER, OID.IP_CIDR_ROUTE_NUMBER):
                    if isinstance(routes.get(key), int):
                        snapshot.route_entries = int(routes[key])
                        break

            snapshot.poll_ms = (time.monotonic() - started) * 1000.0
            return snapshot
        except Exception as exc:
            self.close()
            return self._failed(f"{type(exc).__name__}: {exc}", started)

    def _collect_interfaces(self, client: SnmpClient) -> List[InterfaceCounters]:
        descriptions = client.walk_column(OID.IF_DESCR)
        if not descriptions:
            return []

        admin = client.walk_column(OID.IF_ADMIN_STATUS)
        oper = client.walk_column(OID.IF_OPER_STATUS)
        in_errors = client.walk_column(OID.IF_IN_ERRORS)
        out_errors = client.walk_column(OID.IF_OUT_ERRORS)
        in_discards = client.walk_column(OID.IF_IN_DISCARDS)
        out_discards = client.walk_column(OID.IF_OUT_DISCARDS)

        names: Dict[str, Any] = {}
        aliases: Dict[str, Any] = {}
        high_speed: Dict[str, Any] = {}
        hc_in: Dict[str, Any] = {}
        hc_out: Dict[str, Any] = {}
        hc_in_pkts: Dict[str, Any] = {}
        hc_out_pkts: Dict[str, Any] = {}

        if self.collect_names:
            names = client.walk_column(OID.IF_NAME)
            aliases = client.walk_column(OID.IF_ALIAS)
        if self.collect_hc and self._hc_supported is not False:
            hc_in = client.walk_column(OID.IF_HC_IN_OCTETS)
            hc_out = client.walk_column(OID.IF_HC_OUT_OCTETS)
            high_speed = client.walk_column(OID.IF_HIGH_SPEED)
            if hc_in:
                hc_in_pkts = client.walk_column(OID.IF_HC_IN_UCAST)
                hc_out_pkts = client.walk_column(OID.IF_HC_OUT_UCAST)
            # A device without ifXTable should not be re-polled for it forever.
            self._hc_supported = bool(hc_in)
            if not hc_in:
                self.log.info(
                    "Device does not expose the 64-bit ifXTable counters; falling back to the "
                    "32-bit ifTable, which wraps quickly on high-speed links"
                )

        use_hc = bool(hc_in)
        in_octets = hc_in if use_hc else client.walk_column(OID.IF_IN_OCTETS)
        out_octets = hc_out if use_hc else client.walk_column(OID.IF_OUT_OCTETS)
        in_packets = hc_in_pkts if use_hc else client.walk_column(OID.IF_IN_UCAST)
        out_packets = hc_out_pkts if use_hc else client.walk_column(OID.IF_OUT_UCAST)
        speeds = client.walk_column(OID.IF_SPEED) if not high_speed else {}

        def as_int(mapping: Dict[str, Any], key: str) -> Optional[int]:
            value = mapping.get(key)
            return int(value) if isinstance(value, int) else None

        interfaces: List[InterfaceCounters] = []
        for index_str in sorted(descriptions, key=lambda k: (len(k), k)):
            try:
                index = int(index_str)
            except ValueError:
                continue
            speed = 0
            if index_str in high_speed and isinstance(high_speed[index_str], int):
                speed = int(high_speed[index_str]) * 1_000_000
            elif index_str in speeds and isinstance(speeds[index_str], int):
                speed = int(speeds[index_str])

            interfaces.append(
                InterfaceCounters(
                    index=index,
                    name=str(names.get(index_str) or descriptions.get(index_str) or f"if{index}"),
                    alias=str(aliases.get(index_str, "") or ""),
                    admin_status=OID._ADMIN.get(
                        admin.get(index_str), str(admin.get(index_str, ""))
                    ),
                    oper_status=OID._OPER.get(oper.get(index_str), str(oper.get(index_str, ""))),
                    speed_bps=speed,
                    in_octets=as_int(in_octets, index_str),
                    out_octets=as_int(out_octets, index_str),
                    in_packets=as_int(in_packets, index_str),
                    out_packets=as_int(out_packets, index_str),
                    in_errors=as_int(in_errors, index_str),
                    out_errors=as_int(out_errors, index_str),
                    in_discards=as_int(in_discards, index_str),
                    out_discards=as_int(out_discards, index_str),
                    high_capacity=use_hc,
                )
            )
        return interfaces
