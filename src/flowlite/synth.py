"""Synthetic packet and capture-file construction.

Used by the test suite and by ``flowlite selftest``, which exercises the whole
pipeline end to end against generated data. Being able to prove the pipeline
works without a switch, a mirror port or root privileges is the difference
between "it should work" and "it demonstrably works on this machine".
"""

from __future__ import annotations

import random
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import List, Tuple

from .pcap.decode import (
    DLT_EN10MB,
    ETH_IPV4,
    ETH_IPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_SYN,
)

__all__ = [
    "ethernet_frame",
    "ipv4_packet",
    "ipv6_packet",
    "tcp_segment",
    "udp_datagram",
    "icmp_message",
    "make_tcp_frame",
    "make_udp_frame",
    "write_pcap",
    "write_pcapng",
    "synthetic_session",
    "sflow_datagram",
    "netflow_v5_datagram",
    "netflow_v9_datagram",
    "ipfix_datagram",
]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_frame(payload: bytes, ethertype: int = ETH_IPV4, vlan: int = 0) -> bytes:
    """Wrap ``payload`` in an Ethernet II header, optionally 802.1Q tagged."""
    dst = b"\x02\x00\x00\x00\x00\x01"
    src = b"\x02\x00\x00\x00\x00\x02"
    if vlan:
        return dst + src + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, ethertype) + payload
    return dst + src + struct.pack("!H", ethertype) + payload


def _ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def ipv4_packet(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    ttl: int = 64,
    ident: int = 0,
    frag_offset: int = 0,
    more_fragments: bool = False,
) -> bytes:
    """Build an IPv4 packet with a correct header checksum."""
    total_length = 20 + len(payload)
    frag_field = (frag_offset & 0x1FFF) | (0x2000 if more_fragments else 0)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident,
        frag_field,
        ttl,
        proto,
        0,
        _ip_bytes(src),
        _ip_bytes(dst),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def ipv6_packet(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    """Build an IPv6 packet."""
    import socket as _socket

    header = struct.pack(
        "!IHBB",
        (6 << 28),
        len(payload),
        next_header,
        hop_limit,
    )
    header += _socket.inet_pton(_socket.AF_INET6, src)
    header += _socket.inet_pton(_socket.AF_INET6, dst)
    return header + payload


def tcp_segment(
    sport: int,
    dport: int,
    payload: bytes = b"",
    flags: int = TCP_ACK,
    window: int = 65535,
    seq: int = 1,
    ack: int = 1,
) -> bytes:
    """Build a TCP segment with a 20-byte header."""
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0) + payload


def udp_datagram(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_message(icmp_type: int = 8, code: int = 0, payload: bytes = b"") -> bytes:
    return struct.pack("!BBHHH", icmp_type, code, 0, 1, 1) + payload


def make_tcp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    payload: bytes = b"",
    flags: int = TCP_ACK,
    window: int = 65535,
    ttl: int = 64,
    vlan: int = 0,
) -> bytes:
    """A complete Ethernet/IPv4/TCP frame."""
    segment = tcp_segment(sport, dport, payload, flags, window)
    packet = ipv4_packet(src, dst, IPPROTO_TCP, segment, ttl=ttl)
    return ethernet_frame(packet, ETH_IPV4, vlan)


def make_udp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    payload: bytes = b"",
    ttl: int = 64,
    vlan: int = 0,
) -> bytes:
    datagram = udp_datagram(sport, dport, payload)
    packet = ipv4_packet(src, dst, IPPROTO_UDP, datagram, ttl=ttl)
    return ethernet_frame(packet, ETH_IPV4, vlan)


# --------------------------------------------------------------------------- #
# Capture files
# --------------------------------------------------------------------------- #


def write_pcap(
    path: str | Path,
    packets: Sequence[Tuple[float, bytes]],
    linktype: int = DLT_EN10MB,
    endian: str = "<",
    nanosecond: bool = False,
) -> Path:
    """Write a classic pcap file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    divisor = 1_000_000_000 if nanosecond else 1_000_000
    with target.open("wb") as handle:
        handle.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype))
        for ts, data in packets:
            seconds = int(ts)
            fraction = int(round((ts - seconds) * divisor))
            if fraction >= divisor:
                seconds += 1
                fraction -= divisor
            handle.write(struct.pack(endian + "IIII", seconds, fraction, len(data), len(data)))
            handle.write(data)
    return target


def write_pcapng(
    path: str | Path,
    packets: Sequence[Tuple[float, bytes]],
    linktype: int = DLT_EN10MB,
) -> Path:
    """Write a pcapng file with one section and one interface."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        # Section Header Block
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb_len = 12 + len(shb_body)
        handle.write(
            struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
        )

        # Interface Description Block with if_tsresol = 6 (microseconds)
        option = struct.pack("<HH", 9, 1) + b"\x06" + b"\x00\x00\x00" + struct.pack("<HH", 0, 0)
        idb_body = struct.pack("<HHI", linktype, 0, 262144) + option
        idb_len = 12 + len(idb_body)
        handle.write(
            struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
        )

        for ts, data in packets:
            micros = int(round(ts * 1_000_000))
            padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
            epb_body = (
                struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF, len(data), len(data))
                + padded
            )
            epb_len = 12 + len(epb_body)
            handle.write(
                struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
            )
    return target


def synthetic_session(
    start_ts: float = 1_700_000_000.0,
    hosts: int = 6,
    flows_per_host: int = 4,
    seed: int = 1234,
    include_ipv6: bool = True,
) -> List[Tuple[float, bytes]]:
    """Generate a deterministic, realistic-looking mix of traffic.

    Produces complete TCP handshakes with data transfer and teardown, UDP/DNS
    exchanges, an ICMP echo pair, and optionally IPv6 -- enough variety to
    exercise every branch of the decoder and every feature in the schema.
    """
    rng = random.Random(seed)
    packets: List[Tuple[float, bytes]] = []
    ts = start_ts

    for host_index in range(hosts):
        client = f"10.10.{host_index // 254}.{host_index % 254 + 1}"
        for flow_index in range(flows_per_host):
            server = f"203.0.{flow_index}.{rng.randint(1, 250)}"
            sport = 40000 + host_index * 100 + flow_index
            dport = rng.choice([80, 443, 22, 8080, 3306])

            ts += rng.uniform(0.001, 0.05)
            packets.append((ts, make_tcp_frame(client, server, sport, dport, b"", TCP_SYN, 64240)))
            ts += rng.uniform(0.005, 0.04)
            packets.append(
                (ts, make_tcp_frame(server, client, dport, sport, b"", TCP_SYN | TCP_ACK, 65535))
            )
            ts += rng.uniform(0.0005, 0.005)
            packets.append((ts, make_tcp_frame(client, server, sport, dport, b"", TCP_ACK, 64240)))

            for _ in range(rng.randint(2, 8)):
                ts += rng.uniform(0.001, 0.3)
                size = rng.randint(40, 1400)
                packets.append(
                    (ts, make_tcp_frame(client, server, sport, dport, b"\xab" * size, TCP_ACK))
                )
                ts += rng.uniform(0.001, 0.2)
                back = rng.randint(40, 1400)
                packets.append(
                    (ts, make_tcp_frame(server, client, dport, sport, b"\xcd" * back, TCP_ACK))
                )

            ts += rng.uniform(0.01, 0.5)
            packets.append(
                (ts, make_tcp_frame(client, server, sport, dport, b"", TCP_FIN | TCP_ACK))
            )
            ts += rng.uniform(0.001, 0.05)
            packets.append(
                (ts, make_tcp_frame(server, client, dport, sport, b"", TCP_FIN | TCP_ACK))
            )

        # A DNS-shaped UDP exchange per host.
        ts += rng.uniform(0.01, 0.2)
        packets.append(
            (ts, make_udp_frame(client, "8.8.8.8", 50000 + host_index, 53, b"\x00" * 40))
        )
        ts += rng.uniform(0.005, 0.08)
        packets.append(
            (ts, make_udp_frame("8.8.8.8", client, 53, 50000 + host_index, b"\x00" * 90))
        )

    # One ICMP echo pair.
    ts += 0.1
    echo = ipv4_packet("10.10.0.1", "10.10.0.2", 1, icmp_message(8))
    packets.append((ts, ethernet_frame(echo, ETH_IPV4)))
    ts += 0.02
    reply = ipv4_packet("10.10.0.2", "10.10.0.1", 1, icmp_message(0))
    packets.append((ts, ethernet_frame(reply, ETH_IPV4)))

    if include_ipv6:
        ts += 0.05
        segment = tcp_segment(45000, 443, b"\x01" * 200, TCP_SYN, 65535)
        v6 = ipv6_packet("2001:db8::1", "2606:4700::1111", IPPROTO_TCP, segment)
        packets.append((ts, ethernet_frame(v6, ETH_IPV6)))
        ts += 0.03
        segment = tcp_segment(443, 45000, b"\x02" * 300, TCP_SYN | TCP_ACK, 65535)
        v6 = ipv6_packet("2606:4700::1111", "2001:db8::1", IPPROTO_TCP, segment)
        packets.append((ts, ethernet_frame(v6, ETH_IPV6)))

    packets.sort(key=lambda item: item[0])
    return packets


# --------------------------------------------------------------------------- #
# Flow-export protocol datagrams
# --------------------------------------------------------------------------- #


def _xdr_bytes(payload: bytes) -> bytes:
    """Pad to a 4-byte boundary, as XDR (and therefore sFlow) requires."""
    return payload + b"\x00" * ((4 - len(payload) % 4) % 4)


def sflow_datagram(
    agent_ip: str = "192.0.2.1",
    sub_agent_id: int = 0,
    sequence: int = 1,
    uptime_ms: int = 100000,
    sampled_frames: Sequence[bytes] = (),
    sampling_rate: int = 1024,
    counters: Sequence[dict] = (),
    expanded: bool = False,
) -> bytes:
    """Build an sFlow v5 datagram containing flow and/or counter samples."""
    samples: List[bytes] = []

    for frame in sampled_frames:
        record = struct.pack("!IIII", 1, len(frame), 0, len(frame)) + _xdr_bytes(frame)
        record_block = struct.pack("!II", 1, len(record)) + record
        if expanded:
            body = struct.pack(
                "!IIIIIIIIIII",
                sequence,
                0,
                3,
                sampling_rate,
                sampling_rate * 10,
                0,
                0,
                1,
                0,
                2,
                1,
            )
        else:
            body = struct.pack(
                "!IIIIIII", sequence, 3, sampling_rate, sampling_rate * 10, 0, 1, 2
            ) + struct.pack("!I", 1)
        body += record_block
        samples.append(struct.pack("!II", 3 if expanded else 1, len(body)) + body)

    for entry in counters:
        record = struct.pack(
            "!IIQIIQIIIIIIQIIIII",
            int(entry.get("if_index", 1)),
            6,
            int(entry.get("speed_bps", 1_000_000_000)),
            1,
            int(entry.get("status", 3)),
            int(entry.get("in_octets", 0)),
            int(entry.get("in_packets", 0)),
            0,
            0,
            int(entry.get("in_discards", 0)),
            int(entry.get("in_errors", 0)),
            0,
            int(entry.get("out_octets", 0)),
            int(entry.get("out_packets", 0)),
            0,
            0,
            int(entry.get("out_discards", 0)),
            int(entry.get("out_errors", 0)),
        )
        record += struct.pack("!I", 0)  # ifPromiscuousMode
        record_block = struct.pack("!II", 1, len(record)) + record
        if expanded:
            body = struct.pack("!IIII", sequence, 0, 3, 1) + record_block
        else:
            body = struct.pack("!III", sequence, 3, 1) + record_block
        samples.append(struct.pack("!II", 4 if expanded else 2, len(body)) + body)

    header = struct.pack("!II", 5, 1)
    header += bytes(int(p) for p in agent_ip.split("."))
    header += struct.pack("!III", sub_agent_id, sequence, uptime_ms)
    header += struct.pack("!I", len(samples))
    return header + b"".join(samples)


def netflow_v5_datagram(
    records: Sequence[dict],
    unix_secs: int = 1_700_000_000,
    sys_uptime_ms: int = 3_600_000,
    sampling_interval: int = 0,
) -> bytes:
    """Build a NetFlow v5 datagram."""
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        len(records),
        sys_uptime_ms,
        unix_secs,
        0,
        0,
        0,
        0,
        sampling_interval,
    )
    body = b""
    for entry in records:
        body += struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBB2s",
            bytes(int(p) for p in entry["src_ip"].split(".")),
            bytes(int(p) for p in entry["dst_ip"].split(".")),
            b"\x00\x00\x00\x00",
            int(entry.get("input_if", 1)),
            int(entry.get("output_if", 2)),
            int(entry.get("packets", 1)),
            int(entry.get("bytes", 100)),
            int(entry.get("first", 1000)),
            int(entry.get("last", 2000)),
            int(entry.get("src_port", 1234)),
            int(entry.get("dst_port", 80)),
            0,
            int(entry.get("tcp_flags", 0x18)),
            int(entry.get("protocol", 6)),
            int(entry.get("tos", 0)),
            int(entry.get("src_asn", 0)),
            int(entry.get("dst_asn", 0)),
            24,
            24,
            b"\x00\x00",
        )
    return header + body


def _v9_template_set(template_id: int, fields: Sequence[Tuple[int, int]]) -> bytes:
    body = struct.pack("!HH", template_id, len(fields))
    for element, length in fields:
        body += struct.pack("!HH", element, length)
    payload = struct.pack("!HH", 0, len(body) + 4) + body
    pad = (4 - len(payload) % 4) % 4
    return payload[:2] + struct.pack("!H", len(payload) + pad) + payload[4:] + b"\x00" * pad


def netflow_v9_datagram(
    template_id: int = 256,
    fields: Sequence[Tuple[int, int]] = (),
    records: Sequence[dict] = (),
    include_template: bool = True,
    domain: int = 1,
    unix_secs: int = 1_700_000_000,
    sys_uptime_ms: int = 3_600_000,
) -> bytes:
    """Build a NetFlow v9 datagram with an optional template set."""
    fields = list(fields) or [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (2, 4), (1, 4)]
    sets = b""
    count = 0
    if include_template:
        sets += _v9_template_set(template_id, fields)
        count += 1

    if records:
        body = b""
        for entry in records:
            for element, length in fields:
                body += _encode_v9_field(element, length, entry)
        data_set = struct.pack("!HH", template_id, len(body) + 4) + body
        pad = (4 - len(data_set) % 4) % 4
        data_set = (
            data_set[:2] + struct.pack("!H", len(data_set) + pad) + data_set[4:] + b"\x00" * pad
        )
        sets += data_set
        count += len(records)

    header = struct.pack("!HHIIII", 9, count, sys_uptime_ms, unix_secs, 1, domain)
    return header + sets


def ipfix_datagram(
    template_id: int = 300,
    fields: Sequence[Tuple[int, int]] = (),
    records: Sequence[dict] = (),
    include_template: bool = True,
    domain: int = 7,
    export_time: int = 1_700_000_000,
) -> bytes:
    """Build an IPFIX (v10) datagram with an optional template set."""
    fields = list(fields) or [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (2, 8), (1, 8)]
    sets = b""
    if include_template:
        body = struct.pack("!HH", template_id, len(fields))
        for element, length in fields:
            body += struct.pack("!HH", element, length)
        sets += struct.pack("!HH", 2, len(body) + 4) + body

    if records:
        body = b""
        for entry in records:
            for element, length in fields:
                body += _encode_v9_field(element, length, entry)
        sets += struct.pack("!HH", template_id, len(body) + 4) + body

    header = struct.pack("!HHIII", 10, 16 + len(sets), export_time, 1, domain)
    return header + sets


def _encode_v9_field(element: int, length: int, entry: dict) -> bytes:
    """Encode one template field from a record dict."""
    if element == 8:
        return bytes(int(p) for p in entry.get("src_ip", "0.0.0.0").split("."))
    if element == 12:
        return bytes(int(p) for p in entry.get("dst_ip", "0.0.0.0").split("."))
    if element == 27:
        import socket as _socket

        return _socket.inet_pton(_socket.AF_INET6, entry.get("src_ip", "::"))
    if element == 28:
        import socket as _socket

        return _socket.inet_pton(_socket.AF_INET6, entry.get("dst_ip", "::"))

    mapping = {
        1: "bytes",
        2: "packets",
        4: "protocol",
        5: "tos",
        6: "tcp_flags",
        7: "src_port",
        10: "input_if",
        11: "dst_port",
        14: "output_if",
        21: "last",
        22: "first",
        58: "src_vlan",
        152: "start_ms",
        153: "end_ms",
    }
    value = int(entry.get(mapping.get(element, ""), 0) or 0)
    return value.to_bytes(length, "big")
