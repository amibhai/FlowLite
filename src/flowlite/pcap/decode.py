"""Link-layer, network-layer and transport-layer packet decoding.

The predecessor assumed every capture was Ethernet and handed raw bytes to an
Ethernet parser regardless of the file's link type. On a Linux cooked capture
(``tcpdump -i any``, the single most common way to capture on a switch or
router) that silently produced garbage addresses instead of an error -- the
worst possible failure mode for a data pipeline.

This decoder reads the link type from the capture file and handles what network
devices actually emit:

* Ethernet II and 802.3/LLC/SNAP
* 802.1Q, 802.1ad (QinQ) and 802.1ah tag stacks of arbitrary depth
* MPLS label stacks, terminating at the IP payload
* Linux cooked capture v1 (SLL) and v2 (SLL2)
* raw IPv4/IPv6, BSD loopback (NULL/LOOP), PPP and PPP-HDLC
* IPv4 including fragmentation, and IPv6 including extension-header chains
* TCP, UDP, ICMP, ICMPv6, SCTP and GRE

Every decoder is total: malformed input returns ``None``, never an exception.
"""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional, Tuple

__all__ = [
    "Packet",
    "decode_packet",
    "supported_linktypes",
    "LINKTYPE_NAMES",
    "PROTO_NAMES",
    "TCP_FIN",
    "TCP_SYN",
    "TCP_RST",
    "TCP_PSH",
    "TCP_ACK",
    "TCP_URG",
    "TCP_ECE",
    "TCP_CWR",
]

# -- Link types (libpcap DLT_* values) -------------------------------------- #
DLT_NULL = 0
DLT_EN10MB = 1
DLT_PPP = 9
DLT_FDDI = 10
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_PPP_ETHER = 51
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276
# Some builds report raw IP as 12 or 14 instead of 101.
DLT_RAW_ALT1 = 12
DLT_RAW_ALT2 = 14

LINKTYPE_NAMES: Dict[int, str] = {
    DLT_NULL: "NULL/BSD-loopback",
    DLT_EN10MB: "Ethernet",
    DLT_PPP: "PPP",
    DLT_FDDI: "FDDI",
    DLT_PPP_ETHER: "PPPoE",
    DLT_IEEE802_11: "IEEE 802.11",
    DLT_IEEE802_11_RADIO: "IEEE 802.11 + radiotap",
    DLT_RAW: "Raw IP",
    DLT_RAW_ALT1: "Raw IP",
    DLT_RAW_ALT2: "Raw IP",
    DLT_LOOP: "OpenBSD loopback",
    DLT_LINUX_SLL: "Linux cooked v1",
    DLT_LINUX_SLL2: "Linux cooked v2",
    DLT_IPV4: "Raw IPv4",
    DLT_IPV6: "Raw IPv6",
}

# -- EtherTypes -------------------------------------------------------------- #
ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_QINQ_ALT = 0x9100
ETH_QINQ_ALT2 = 0x9200
ETH_PBB = 0x88E7
ETH_MPLS_UC = 0x8847
ETH_MPLS_MC = 0x8848
ETH_PPPOE_SESSION = 0x8864

_VLAN_TYPES = frozenset({ETH_VLAN, ETH_QINQ, ETH_QINQ_ALT, ETH_QINQ_ALT2})
_MPLS_TYPES = frozenset({ETH_MPLS_UC, ETH_MPLS_MC})

# -- IP protocols ------------------------------------------------------------ #
IPPROTO_HOPOPTS = 0
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_IPIP = 4
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58
IPPROTO_NONE = 59
IPPROTO_DSTOPTS = 60
IPPROTO_SCTP = 132
IPPROTO_MOBILITY = 135
IPPROTO_HIP = 139
IPPROTO_SHIM6 = 140

PROTO_NAMES: Dict[int, str] = {
    IPPROTO_ICMP: "ICMP",
    IPPROTO_IGMP: "IGMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    IPPROTO_GRE: "GRE",
    IPPROTO_ESP: "ESP",
    IPPROTO_AH: "AH",
    IPPROTO_ICMPV6: "ICMPv6",
    IPPROTO_SCTP: "SCTP",
}

_IPV6_EXT_HEADERS = frozenset(
    {
        IPPROTO_HOPOPTS,
        IPPROTO_ROUTING,
        IPPROTO_FRAGMENT,
        IPPROTO_DSTOPTS,
        IPPROTO_AH,
        IPPROTO_MOBILITY,
        IPPROTO_HIP,
        IPPROTO_SHIM6,
    }
)

# -- TCP flags --------------------------------------------------------------- #
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

_U16 = struct.Struct("!H")
_ETH_HEADER = struct.Struct("!6s6sH")
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
_IPV6_HEADER = struct.Struct("!IHBB16s16s")
_TCP_HEADER = struct.Struct("!HHIIBBHHH")
_UDP_HEADER = struct.Struct("!HHHH")

# Address formatting dominates decode time on large captures, and real traffic
# revisits the same addresses constantly, so results are memoised.
_V4_CACHE: Dict[bytes, str] = {}
_V6_CACHE: Dict[bytes, str] = {}
_CACHE_LIMIT = 200_000


def _ipv4_str(raw: bytes) -> str:
    cached = _V4_CACHE.get(raw)
    if cached is not None:
        return cached
    text = f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"
    if len(_V4_CACHE) < _CACHE_LIMIT:
        _V4_CACHE[raw] = text
    return text


def _ipv6_str(raw: bytes) -> str:
    cached = _V6_CACHE.get(raw)
    if cached is not None:
        return cached
    try:
        text = socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        text = raw.hex()
    if len(_V6_CACHE) < _CACHE_LIMIT:
        _V6_CACHE[raw] = text
    return text


class Packet:
    """One decoded packet, flattened to the fields flow features need."""

    __slots__ = (
        "ts",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "ip_version",
        "ttl",
        "tcp_flags",
        "tcp_window",
        "frame_len",
        "ip_len",
        "payload_len",
        "vlan_id",
        "is_fragment",
    )

    def __init__(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        ip_version: int,
        ttl: int,
        tcp_flags: int,
        tcp_window: int,
        frame_len: int,
        ip_len: int,
        payload_len: int,
        vlan_id: int = 0,
        is_fragment: bool = False,
    ) -> None:
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.ip_version = ip_version
        self.ttl = ttl
        self.tcp_flags = tcp_flags
        self.tcp_window = tcp_window
        self.frame_len = frame_len
        self.ip_len = ip_len
        self.payload_len = payload_len
        self.vlan_id = vlan_id
        self.is_fragment = is_fragment

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.proto, str(self.proto))

    def __repr__(self) -> str:
        return (
            f"<Packet {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"{self.proto_name} len={self.frame_len}>"
        )


def supported_linktypes() -> Dict[int, str]:
    """Link types this decoder understands, keyed by DLT value."""
    return dict(LINKTYPE_NAMES)


# --------------------------------------------------------------------------- #
# Link layer
# --------------------------------------------------------------------------- #


def _strip_ethernet(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    """Return ``(ethertype, payload, outer_vlan_id)`` for an Ethernet frame."""
    if len(data) < 14:
        return None
    _dst, _src, ethertype = _ETH_HEADER.unpack_from(data, 0)
    offset = 14
    vlan_id = 0
    depth = 0

    while depth < 8:
        depth += 1
        if ethertype in _VLAN_TYPES:
            if len(data) < offset + 4:
                return None
            tci = _U16.unpack_from(data, offset)[0]
            if vlan_id == 0:
                vlan_id = tci & 0x0FFF
            ethertype = _U16.unpack_from(data, offset + 2)[0]
            offset += 4
            continue
        if ethertype in _MPLS_TYPES:
            # Walk the label stack to the bottom-of-stack bit, then sniff the
            # first nibble to tell IPv4 from IPv6 (MPLS carries no next-proto).
            while offset + 4 <= len(data):
                label_entry = struct.unpack_from("!I", data, offset)[0]
                offset += 4
                if label_entry & 0x100:  # bottom of stack
                    break
            if offset >= len(data):
                return None
            version = data[offset] >> 4
            if version == 4:
                return ETH_IPV4, data[offset:], vlan_id
            if version == 6:
                return ETH_IPV6, data[offset:], vlan_id
            return None
        if ethertype == ETH_PBB:
            # 802.1ah backbone tag: 4-byte I-TAG then a complete inner frame.
            if len(data) < offset + 4 + 14:
                return None
            inner = _strip_ethernet(data[offset + 4 :])
            if inner is None:
                return None
            return inner[0], inner[1], vlan_id or inner[2]
        if ethertype == ETH_PPPOE_SESSION:
            if len(data) < offset + 8:
                return None
            ppp_proto = _U16.unpack_from(data, offset + 6)[0]
            payload = data[offset + 8 :]
            if ppp_proto == 0x0021:
                return ETH_IPV4, payload, vlan_id
            if ppp_proto == 0x0057:
                return ETH_IPV6, payload, vlan_id
            return None
        break

    if ethertype <= 1500:
        # 802.3 length field: an LLC header follows; only SNAP carries EtherType.
        if len(data) < offset + 3:
            return None
        dsap, ssap, control = data[offset], data[offset + 1], data[offset + 2]
        if dsap == 0xAA and ssap == 0xAA:
            if len(data) < offset + 8:
                return None
            snap_type = _U16.unpack_from(data, offset + 6)[0]
            return snap_type, data[offset + 8 :], vlan_id
        del control
        return None

    return ethertype, data[offset:], vlan_id


def _strip_sll(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if len(data) < 16:
        return None
    ethertype = _U16.unpack_from(data, 14)[0]
    return ethertype, data[16:], 0


def _strip_sll2(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if len(data) < 20:
        return None
    ethertype = _U16.unpack_from(data, 0)[0]
    return ethertype, data[20:], 0


def _strip_loopback(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    """BSD loopback: a 4-byte host-order address family."""
    if len(data) < 4:
        return None
    for fmt in ("<I", ">I"):
        family = struct.unpack_from(fmt, data, 0)[0]
        if family == 2:
            return ETH_IPV4, data[4:], 0
        if family in (24, 28, 30, 10):  # AF_INET6 varies across BSDs and Linux
            return ETH_IPV6, data[4:], 0
    return None


def _strip_ppp(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if len(data) < 2:
        return None
    offset = 0
    if data[0] == 0xFF and data[1] == 0x03:  # HDLC address/control
        offset = 2
    if len(data) < offset + 1:
        return None
    if data[offset] & 0x01:  # single-octet protocol field
        proto = data[offset]
        offset += 1
    else:
        if len(data) < offset + 2:
            return None
        proto = _U16.unpack_from(data, offset)[0]
        offset += 2
    if proto == 0x0021:
        return ETH_IPV4, data[offset:], 0
    if proto == 0x0057:
        return ETH_IPV6, data[offset:], 0
    return None


def _strip_radiotap(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if len(data) < 4:
        return None
    header_len = struct.unpack_from("<H", data, 2)[0]
    if header_len < 4 or header_len > len(data):
        return None
    return _strip_ieee80211(data[header_len:])


def _strip_ieee80211(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if len(data) < 24:
        return None
    frame_control = _U16.unpack_from(data, 0)[0]
    ftype = (frame_control >> 2) & 0x03
    if ftype != 2:  # only data frames carry IP
        return None
    subtype = (frame_control >> 4) & 0x0F
    to_ds = bool(data[1] & 0x01)
    from_ds = bool(data[1] & 0x02)
    offset = 30 if (to_ds and from_ds) else 24
    if subtype & 0x08:  # QoS data
        offset += 2
    if len(data) < offset + 8:
        return None
    if data[offset] == 0xAA and data[offset + 1] == 0xAA:  # LLC/SNAP
        ethertype = _U16.unpack_from(data, offset + 6)[0]
        return ethertype, data[offset + 8 :], 0
    return None


def _strip_raw_ip(data: bytes) -> Optional[Tuple[int, bytes, int]]:
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        return ETH_IPV4, data, 0
    if version == 6:
        return ETH_IPV6, data, 0
    return None


_LINK_STRIPPERS = {
    DLT_EN10MB: _strip_ethernet,
    DLT_LINUX_SLL: _strip_sll,
    DLT_LINUX_SLL2: _strip_sll2,
    DLT_NULL: _strip_loopback,
    DLT_LOOP: _strip_loopback,
    DLT_RAW: _strip_raw_ip,
    DLT_RAW_ALT1: _strip_raw_ip,
    DLT_RAW_ALT2: _strip_raw_ip,
    DLT_IPV4: _strip_raw_ip,
    DLT_IPV6: _strip_raw_ip,
    DLT_PPP: _strip_ppp,
    DLT_IEEE802_11: _strip_ieee80211,
    DLT_IEEE802_11_RADIO: _strip_radiotap,
}


# --------------------------------------------------------------------------- #
# Network + transport layers
# --------------------------------------------------------------------------- #


def _decode_transport(proto: int, data: bytes) -> Tuple[int, int, int, int, int, int]:
    """Return ``(proto, sport, dport, flags, window, l4_header_len)``."""
    if proto == IPPROTO_TCP:
        if len(data) < 20:
            return proto, 0, 0, 0, 0, len(data)
        sport, dport, _seq, _ack, offset_byte, flags, window, _sum, _urg = _TCP_HEADER.unpack_from(
            data, 0
        )
        header_len = (offset_byte >> 4) * 4
        if header_len < 20 or header_len > len(data):
            header_len = min(20, len(data))
        return proto, sport, dport, flags, window, header_len
    if proto == IPPROTO_UDP:
        if len(data) < 8:
            return proto, 0, 0, 0, 0, len(data)
        sport, dport, _length, _sum = _UDP_HEADER.unpack_from(data, 0)
        return proto, sport, dport, 0, 0, 8
    if proto == IPPROTO_SCTP:
        if len(data) < 12:
            return proto, 0, 0, 0, 0, len(data)
        sport, dport = struct.unpack_from("!HH", data, 0)
        return proto, sport, dport, 0, 0, 12
    if proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        if len(data) < 4:
            return proto, 0, 0, 0, 0, len(data)
        # ICMP has no ports; type and code identify the conversation, so they
        # take the port slots. This keeps one flow key shape for all protocols.
        return proto, data[0], data[1], 0, 0, min(8, len(data))
    if proto == IPPROTO_GRE:
        if len(data) < 4:
            return proto, 0, 0, 0, 0, len(data)
        return proto, 0, 0, 0, 0, 4
    return proto, 0, 0, 0, 0, 0


def _decode_ipv4(data: bytes, ts: float, frame_len: int, vlan_id: int) -> Optional[Packet]:
    if len(data) < 20:
        return None
    (
        version_ihl,
        _tos,
        total_len,
        _ident,
        frag_field,
        ttl,
        proto,
        _checksum,
        src_raw,
        dst_raw,
    ) = _IPV4_HEADER.unpack_from(data, 0)
    if version_ihl >> 4 != 4:
        return None
    header_len = (version_ihl & 0x0F) * 4
    if header_len < 20 or header_len > len(data):
        return None

    # total_len is authoritative unless the frame was snapped short.
    ip_len = total_len if 0 < total_len <= len(data) else len(data)
    frag_offset = frag_field & 0x1FFF
    more_fragments = bool(frag_field & 0x2000)
    is_fragment = frag_offset > 0 or more_fragments

    body = data[header_len:ip_len]
    if frag_offset > 0:
        # Non-initial fragments carry no transport header.
        return Packet(
            ts,
            _ipv4_str(src_raw),
            _ipv4_str(dst_raw),
            0,
            0,
            proto,
            4,
            ttl,
            0,
            0,
            frame_len,
            ip_len,
            len(body),
            vlan_id,
            True,
        )

    proto, sport, dport, flags, window, l4_len = _decode_transport(proto, body)
    payload_len = max(0, len(body) - l4_len)
    return Packet(
        ts,
        _ipv4_str(src_raw),
        _ipv4_str(dst_raw),
        sport,
        dport,
        proto,
        4,
        ttl,
        flags,
        window,
        frame_len,
        ip_len,
        payload_len,
        vlan_id,
        is_fragment,
    )


def _decode_ipv6(data: bytes, ts: float, frame_len: int, vlan_id: int) -> Optional[Packet]:
    if len(data) < 40:
        return None
    version_class_label, payload_len_field, next_header, hop_limit = struct.unpack_from(
        "!IHBB", data, 0
    )
    if version_class_label >> 28 != 6:
        return None
    src_raw = data[8:24]
    dst_raw = data[24:40]

    declared = 40 + payload_len_field
    ip_len = declared if 40 < declared <= len(data) else len(data)

    offset = 40
    proto = next_header
    is_fragment = False
    frag_offset = 0
    hops = 0

    while proto in _IPV6_EXT_HEADERS and hops < 16:
        hops += 1
        if offset + 8 > len(data):
            return None
        if proto == IPPROTO_FRAGMENT:
            is_fragment = True
            frag_offset = (struct.unpack_from("!H", data, offset + 2)[0] >> 3) & 0x1FFF
            proto = data[offset]
            offset += 8
            if frag_offset > 0:
                break
            continue
        if proto == IPPROTO_AH:
            ext_len = (data[offset + 1] + 2) * 4
        else:
            ext_len = (data[offset + 1] + 1) * 8
        proto = data[offset]
        offset += ext_len
        if offset > len(data):
            return None

    if proto == IPPROTO_NONE:
        return None

    body = data[offset:ip_len] if offset < ip_len else b""
    if frag_offset > 0:
        return Packet(
            ts,
            _ipv6_str(src_raw),
            _ipv6_str(dst_raw),
            0,
            0,
            proto,
            6,
            hop_limit,
            0,
            0,
            frame_len,
            ip_len,
            len(body),
            vlan_id,
            True,
        )

    proto, sport, dport, flags, window, l4_len = _decode_transport(proto, body)
    payload = max(0, len(body) - l4_len)
    return Packet(
        ts,
        _ipv6_str(src_raw),
        _ipv6_str(dst_raw),
        sport,
        dport,
        proto,
        6,
        hop_limit,
        flags,
        window,
        frame_len,
        ip_len,
        payload,
        vlan_id,
        is_fragment,
    )


def decode_packet(ts: float, data: bytes, linktype: int = DLT_EN10MB) -> Optional[Packet]:
    """Decode one captured frame.

    Returns ``None`` for frames that carry no IP payload (ARP, LLDP, STP, raw
    L2), for unsupported link types, and for anything malformed. Callers count
    ``None`` results as "skipped" rather than treating them as errors.
    """
    if not data:
        return None
    stripper = _LINK_STRIPPERS.get(linktype)
    if stripper is None:
        # An unknown link type is still worth a guess if the bytes look like IP.
        stripped = _strip_raw_ip(data)
    else:
        try:
            stripped = stripper(data)
        except (struct.error, IndexError):
            return None
    if stripped is None:
        return None

    ethertype, payload, vlan_id = stripped
    if not payload:
        return None

    try:
        if ethertype == ETH_IPV4:
            return _decode_ipv4(payload, ts, len(data), vlan_id)
        if ethertype == ETH_IPV6:
            return _decode_ipv6(payload, ts, len(data), vlan_id)
    except (struct.error, IndexError, ValueError):
        return None
    return None
