"""Capture-file reading and packet decoding."""

from __future__ import annotations

import gzip
import os
import struct
from pathlib import Path

import pytest

from flowlite import synth
from flowlite.errors import ParseError
from flowlite.pcap.decode import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_NULL,
    DLT_RAW,
    ETH_IPV4,
    ETH_IPV6,
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_ACK,
    TCP_SYN,
    decode_packet,
)
from flowlite.pcap.reader import CaptureFile, read_packets


class TestReader:
    def test_pcap_little_and_big_endian(self, tmp_path, packets):
        for name, endian in (("little", "<"), ("big", ">")):
            path = synth.write_pcap(tmp_path / f"{name}.pcap", packets, endian=endian)
            read, info = read_packets(path)
            assert len(read) == len(packets)
            assert info.format == "pcap"
            assert not info.truncated

    def test_nanosecond_pcap(self, tmp_path, packets):
        path = synth.write_pcap(tmp_path / "ns.pcap", packets, nanosecond=True)
        read, _info = read_packets(path)
        assert len(read) == len(packets)
        assert abs(read[0][0] - packets[0][0]) < 1e-6

    def test_pcapng(self, tmp_path, packets):
        path = synth.write_pcapng(tmp_path / "s.pcapng", packets)
        read, info = read_packets(path)
        assert len(read) == len(packets)
        assert info.format == "pcapng"
        assert info.linktypes == {0: DLT_EN10MB}

    def test_timestamps_survive_the_round_trip(self, tmp_path, packets):
        path = synth.write_pcap(tmp_path / "t.pcap", packets)
        read, _info = read_packets(path)
        for (want_ts, _), (got_ts, _, _) in zip(packets, read):
            assert abs(got_ts - want_ts) < 1e-6

    def test_gzip_is_transparent(self, tmp_path, packets):
        plain = synth.write_pcap(tmp_path / "p.pcap", packets)
        compressed = tmp_path / "p.pcap.gz"
        compressed.write_bytes(gzip.compress(plain.read_bytes()))
        read, _info = read_packets(compressed)
        assert len(read) == len(packets)

    def test_truncated_file_yields_complete_packets(self, tmp_path, packets):
        path = synth.write_pcap(tmp_path / "t.pcap", packets)
        data = path.read_bytes()
        path.write_bytes(data[: len(data) // 2])
        read, info = read_packets(path)
        assert 0 < len(read) < len(packets)
        assert info.truncated

    def test_empty_file_is_not_an_error(self, tmp_path):
        path = tmp_path / "empty.pcap"
        path.touch()
        read, info = read_packets(path)
        assert read == []
        assert "empty" in " ".join(info.warnings)

    def test_non_capture_file_is_rejected_clearly(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("this is not a capture", encoding="utf-8")
        with pytest.raises(ParseError, match="not a pcap or pcapng"):
            read_packets(path)

    def test_absurd_packet_length_is_rejected(self, tmp_path):
        path = tmp_path / "bad.pcap"
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
        record = struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        path.write_bytes(header + record)
        with pytest.raises(ParseError, match="corrupt"):
            read_packets(path)

    def test_missing_file(self, tmp_path):
        with pytest.raises(ParseError, match="does not exist"):
            read_packets(tmp_path / "absent.pcap")

    def test_info_reports_span_and_counts(self, tmp_path, packets):
        path = synth.write_pcap(tmp_path / "s.pcap", packets)
        capture = CaptureFile(path)
        list(capture.packets())
        assert capture.info.packets_read == len(packets)
        assert capture.info.duration_s > 0
        assert capture.info.bytes_read > 0


class TestLinkLayers:
    def test_ethernet(self):
        frame = synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1000, 80, b"hi", TCP_SYN)
        packet = decode_packet(1.0, frame, DLT_EN10MB)
        assert packet is not None
        assert (packet.src_ip, packet.dst_port, packet.proto) == ("10.0.0.1", 80, IPPROTO_TCP)
        assert packet.tcp_flags & TCP_SYN

    def test_vlan_tag(self):
        frame = synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1000, 80, vlan=42)
        packet = decode_packet(1.0, frame, DLT_EN10MB)
        assert packet is not None and packet.vlan_id == 42

    def test_qinq_double_tag(self):
        inner = synth.ipv4_packet("10.0.0.1", "10.0.0.2", IPPROTO_TCP, synth.tcp_segment(1, 2))
        frame = (
            b"\x02" * 12
            + struct.pack("!HH", 0x88A8, 100)
            + struct.pack("!HH", 0x8100, 200)
            + struct.pack("!H", ETH_IPV4)
            + inner
        )
        packet = decode_packet(1.0, frame, DLT_EN10MB)
        assert packet is not None and packet.vlan_id == 100

    def test_linux_cooked_v1(self):
        ip = synth.ipv4_packet("192.168.1.1", "192.168.1.2", IPPROTO_UDP, synth.udp_datagram(1, 53))
        frame = b"\x00" * 14 + struct.pack("!H", ETH_IPV4) + ip
        packet = decode_packet(1.0, frame, DLT_LINUX_SLL)
        assert packet is not None and packet.dst_port == 53

    def test_linux_cooked_v2(self):
        ip = synth.ipv4_packet("192.168.1.1", "192.168.1.2", IPPROTO_UDP, synth.udp_datagram(1, 53))
        frame = struct.pack("!H", ETH_IPV4) + b"\x00" * 18 + ip
        packet = decode_packet(1.0, frame, DLT_LINUX_SLL2)
        assert packet is not None and packet.dst_port == 53

    def test_raw_ip(self):
        ip = synth.ipv4_packet("1.1.1.1", "2.2.2.2", IPPROTO_ICMP, synth.icmp_message())
        packet = decode_packet(1.0, ip, DLT_RAW)
        assert packet is not None and packet.proto == IPPROTO_ICMP

    def test_bsd_loopback(self):
        ip = synth.ipv4_packet("127.0.0.1", "127.0.0.1", IPPROTO_UDP, synth.udp_datagram(1, 2))
        packet = decode_packet(1.0, struct.pack("<I", 2) + ip, DLT_NULL)
        assert packet is not None and packet.src_ip == "127.0.0.1"

    def test_mpls_stack(self):
        ip = synth.ipv4_packet("10.1.1.1", "10.2.2.2", IPPROTO_TCP, synth.tcp_segment(80, 443))
        labels = struct.pack("!I", (100 << 12)) + struct.pack("!I", (200 << 12) | 0x100)
        frame = b"\x02" * 12 + struct.pack("!H", 0x8847) + labels + ip
        packet = decode_packet(1.0, frame, DLT_EN10MB)
        assert packet is not None and packet.dst_ip == "10.2.2.2"

    def test_non_ip_frames_are_skipped_not_misparsed(self):
        arp = b"\x02" * 12 + struct.pack("!H", 0x0806) + b"\x00" * 28
        assert decode_packet(1.0, arp, DLT_EN10MB) is None

    def test_unknown_linktype_still_tries_raw_ip(self):
        ip = synth.ipv4_packet("1.2.3.4", "5.6.7.8", IPPROTO_TCP, synth.tcp_segment(1, 2))
        assert decode_packet(1.0, ip, 9999) is not None


class TestNetworkLayer:
    def test_ipv6_with_extension_headers(self):
        segment = synth.tcp_segment(1234, 443, b"x" * 50)
        # Hop-by-hop options header ahead of the TCP header.
        hop_by_hop = bytes([IPPROTO_TCP, 0]) + b"\x00" * 6
        packet_bytes = synth.ipv6_packet("2001:db8::1", "2001:db8::2", 0, hop_by_hop + segment)
        packet = decode_packet(1.0, synth.ethernet_frame(packet_bytes, ETH_IPV6), DLT_EN10MB)
        assert packet is not None
        assert packet.ip_version == 6 and packet.dst_port == 443 and packet.payload_len == 50

    def test_ipv4_fragment_has_no_ports(self):
        payload = b"\xaa" * 100
        fragment = synth.ipv4_packet("10.0.0.1", "10.0.0.2", IPPROTO_TCP, payload, frag_offset=185)
        packet = decode_packet(1.0, synth.ethernet_frame(fragment), DLT_EN10MB)
        assert packet is not None
        assert packet.is_fragment and packet.src_port == 0

    def test_icmp_type_and_code_take_the_port_slots(self):
        icmp = synth.ipv4_packet("10.0.0.1", "10.0.0.2", IPPROTO_ICMP, synth.icmp_message(8, 0))
        packet = decode_packet(1.0, synth.ethernet_frame(icmp), DLT_EN10MB)
        assert packet is not None and (packet.src_port, packet.dst_port) == (8, 0)

    def test_payload_length_excludes_headers(self):
        frame = synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, b"z" * 300, TCP_ACK)
        packet = decode_packet(1.0, frame, DLT_EN10MB)
        assert packet is not None and packet.payload_len == 300

    def test_truncated_headers_return_none(self):
        frame = synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2)
        for cut in range(1, len(frame)):
            decode_packet(1.0, frame[:cut], DLT_EN10MB)  # must not raise

    def test_random_bytes_never_raise(self):
        for size in (0, 1, 14, 20, 54, 200, 1500):
            for linktype in (DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW, DLT_NULL, 999):
                decode_packet(1.0, os.urandom(size), linktype)


def test_reader_handles_every_synthetic_format(tmp_path: Path, packets):
    """A regression net over the formats FlowLite claims to read."""
    variants = {
        "le": synth.write_pcap(tmp_path / "le.pcap", packets, endian="<"),
        "be": synth.write_pcap(tmp_path / "be.pcap", packets, endian=">"),
        "ns": synth.write_pcap(tmp_path / "ns.pcap", packets, nanosecond=True),
        "ng": synth.write_pcapng(tmp_path / "ng.pcapng", packets),
    }
    for name, path in variants.items():
        read, info = read_packets(path)
        assert len(read) == len(packets), name
        assert not info.truncated, name
