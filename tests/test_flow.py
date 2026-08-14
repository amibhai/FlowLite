"""Flow assembly, streaming statistics and the flow CSV schema."""

from __future__ import annotations

import math
import random

import pytest

from flowlite import synth
from flowlite.enrich.addresses import classify_address, is_private
from flowlite.flow.schema import FLOW_FIELDS, flow_record_to_row, iso_utc
from flowlite.flow.stats import OnlineStats
from flowlite.flow.table import FlowTable, PcapFlowExtractor
from flowlite.pcap.decode import DLT_EN10MB, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, decode_packet


def packet_from(frame: bytes, ts: float):
    packet = decode_packet(ts, frame, DLT_EN10MB)
    assert packet is not None
    return packet


class TestOnlineStats:
    def test_matches_a_direct_computation(self):
        values = [random.Random(7).uniform(0, 1000) for _ in range(500)]
        stats = OnlineStats()
        for value in values:
            stats.add(value)
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        assert stats.count == len(values)
        assert stats.mean == pytest.approx(mean)
        assert stats.variance == pytest.approx(variance)
        assert stats.std == pytest.approx(math.sqrt(variance))
        assert stats.minimum == pytest.approx(min(values))
        assert stats.maximum == pytest.approx(max(values))
        assert stats.sum == pytest.approx(sum(values))

    def test_stable_for_large_offsets(self):
        """Naive sum-of-squares loses all precision near epoch-sized values."""
        stats = OnlineStats()
        for offset in (0.0, 0.5, 1.0, 1.5, 2.0):
            stats.add(1_700_000_000.0 + offset)
        assert stats.variance == pytest.approx(0.5, abs=1e-6)
        assert stats.variance >= 0.0

    def test_empty_and_single_value(self):
        empty = OnlineStats()
        assert (empty.mean, empty.std, empty.minimum, empty.maximum) == (0.0, 0.0, 0.0, 0.0)
        one = OnlineStats()
        one.add(5)
        assert (one.mean, one.std, one.minimum, one.maximum) == (5.0, 0.0, 5.0, 5.0)

    def test_merge(self):
        left, right, both = OnlineStats(), OnlineStats(), OnlineStats()
        for value in range(50):
            left.add(value)
            both.add(value)
        for value in range(50, 120):
            right.add(value)
            both.add(value)
        left.merge(right)
        assert left.count == both.count
        assert left.mean == pytest.approx(both.mean)
        assert left.variance == pytest.approx(both.variance)


class TestFlowTable:
    def test_both_directions_join_one_flow(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2), 0.0))
        table.add_packet(packet_from(synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1), 0.1))
        table.flush()
        assert len(emitted) == 1
        record = emitted[0]
        assert record.fwd_packets == 1 and record.bwd_packets == 1

    def test_direction_is_fixed_by_the_first_packet(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(packet_from(synth.make_tcp_frame("10.0.0.9", "10.0.0.1", 9, 1), 0.0))
        table.add_packet(packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.9", 1, 9), 0.1))
        table.flush()
        assert emitted[0].src_ip == "10.0.0.9"

    def test_initial_windows_come_from_the_right_direction(self):
        """A capture starting mid-connection must not swap the two windows."""
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, window=1000), 0.0)
        )
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1, window=2000), 0.1)
        )
        table.flush()
        assert emitted[0].init_win_fwd == 1000
        assert emitted[0].init_win_bwd == 2000

    def test_teardown_closes_the_flow_immediately(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, close_on_teardown=True)
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, flags=TCP_SYN), 0.0)
        )
        table.add_packet(
            packet_from(
                synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1, flags=TCP_SYN | TCP_ACK), 0.1
            )
        )
        table.add_packet(
            packet_from(
                synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, flags=TCP_FIN | TCP_ACK), 0.2
            )
        )
        table.add_packet(
            packet_from(
                synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1, flags=TCP_FIN | TCP_ACK), 0.3
            )
        )
        assert len(emitted) == 1
        assert emitted[0].tcp_state == "closed"
        assert len(table) == 0

    def test_reset_marks_the_flow(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, flags=TCP_SYN), 0.0)
        )
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1, flags=TCP_RST), 0.05)
        )
        assert emitted and emitted[0].tcp_state == "reset"

    def test_idle_timeout_evicts(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, idle_timeout_s=10)
        table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), 0.0))
        table.expire_idle(now=100.0)
        assert len(emitted) == 1 and emitted[0].expiry_reason == "idle-timeout"

    def test_active_timeout_cuts_a_long_flow(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, active_timeout_s=60)
        for i in range(5):
            table.add_packet(
                packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), i * 40.0)
            )
        table.flush()
        assert len(emitted) >= 2
        assert any(r.expiry_reason == "active-timeout" for r in emitted)

    def test_packet_cap_cuts_an_elephant_flow(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, max_packets_per_flow=10)
        for i in range(35):
            table.add_packet(
                packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), i * 0.001)
            )
        table.flush()
        assert len(emitted) >= 3
        assert all(r.total_packets <= 10 for r in emitted)

    def test_memory_is_bounded_under_a_scan(self):
        """The failure this prevents: unbounded growth on attacker-chosen keys."""
        emitted = []
        table = FlowTable(on_flow=emitted.append, max_flows=100)
        for port in range(3000):
            table.add_packet(
                packet_from(
                    synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 40000, port, flags=TCP_SYN),
                    port * 0.001,
                )
            )
        assert len(table) <= 100
        table.flush()
        assert len(emitted) == 3000
        assert table.evicted_capacity > 0

    def test_backwards_timestamps_do_not_poison_statistics(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        for ts in (10.0, 9.0, 11.0, 8.0):
            table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), ts))
        table.flush()
        record = emitted[0]
        assert record.all_iat.minimum >= 0.0
        assert record.duration >= 0.0

    def test_min_packets_filter(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, min_packets=3)
        table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), 0.0))
        table.flush()
        assert emitted == []
        assert table.dropped_short == 1

    def test_active_and_idle_bursts(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append, burst_gap_s=1.0, idle_timeout_s=1e9)
        for ts in (0.0, 0.1, 0.2, 10.0, 10.1, 20.0):
            table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), ts))
        table.flush()
        record = emitted[0]
        assert record.idle.count == 2
        assert record.idle.maximum == pytest.approx(9.9, abs=0.01)
        assert record.active.count == 3

    def test_stats_are_reported(self):
        table = FlowTable()
        table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), 0.0))
        assert table.stats()["in_memory"] == 1


class TestSchema:
    def test_row_keys_match_the_declared_schema(self, flow_rows):
        assert flow_rows
        for row in flow_rows[:20]:
            assert set(row) == set(FLOW_FIELDS)

    def test_field_names_are_unique(self):
        assert len(FLOW_FIELDS) == len(set(FLOW_FIELDS))

    def test_no_nan_or_infinity_reaches_the_row(self, flow_rows):
        for row in flow_rows:
            for value in row.values():
                if isinstance(value, float):
                    assert value == value and abs(value) != float("inf")

    def test_zero_duration_flow_has_finite_rates(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(packet_from(synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, 2), 5.0))
        table.flush()
        row = flow_record_to_row(emitted[0])
        assert row["duration_s"] == 0.0
        assert row["packets_per_s"] == 0.0
        assert row["bytes_per_s"] == 0.0

    def test_handshake_timing(self):
        emitted = []
        table = FlowTable(on_flow=emitted.append)
        table.add_packet(
            packet_from(synth.make_tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, flags=TCP_SYN), 1.000)
        )
        table.add_packet(
            packet_from(
                synth.make_tcp_frame("10.0.0.2", "10.0.0.1", 2, 1, flags=TCP_SYN | TCP_ACK), 1.025
            )
        )
        table.flush()
        row = flow_record_to_row(emitted[0])
        assert row["tcp_handshake_ms"] == pytest.approx(25.0, abs=0.5)
        assert row["tcp_state"] == "established"

    def test_timestamps_are_utc_iso(self):
        assert iso_utc(0).startswith("1970-01-01T00:00:00")
        assert iso_utc(1_700_000_000).endswith("Z")

    def test_enrichment_columns_are_populated(self, flow_rows):
        private = [r for r in flow_rows if r["src_scope"] == "private"]
        public = [r for r in flow_rows if r["dst_scope"] == "public"]
        assert private and public


class TestExtractor:
    def test_extracts_from_pcap_and_pcapng_identically(
        self, sample_pcap, sample_pcapng, quiet_logger
    ):
        results = []
        for path in (sample_pcap, sample_pcapng):
            rows = []
            PcapFlowExtractor(logger=quiet_logger).extract(path, rows.append)
            results.append(
                sorted((r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.total_packets) for r in rows)
            )
        assert results[0] == results[1]

    def test_result_reports_counts(self, sample_pcap, quiet_logger, packets):
        result = PcapFlowExtractor(logger=quiet_logger).extract(sample_pcap, lambda _r: None)
        assert result.packets_total == len(packets)
        assert result.packets_decoded == len(packets)
        assert result.flows > 0
        assert result.decode_rate == 1.0
        assert "flows" in result.summary()

    def test_stop_request_is_honoured(self, tmp_path, quiet_logger):
        many = [
            (i * 0.0001, synth.make_udp_frame("10.0.0.1", "10.0.0.2", 1, i % 60000))
            for i in range(60000)
        ]
        path = synth.write_pcap(tmp_path / "big.pcap", many)
        result = PcapFlowExtractor(logger=quiet_logger).extract(
            path, lambda _r: None, should_stop=lambda: True
        )
        assert result.packets_total < len(many)
        assert any("interrupted" in w for w in result.warnings)

    def test_non_ip_capture_produces_no_flows_without_raising(self, tmp_path, quiet_logger):
        arp = b"\x02" * 12 + b"\x08\x06" + b"\x00" * 28
        path = synth.write_pcap(tmp_path / "arp.pcap", [(1.0, arp), (2.0, arp)])
        result = PcapFlowExtractor(logger=quiet_logger).extract(path, lambda _r: None)
        assert result.flows == 0 and result.packets_skipped == 2


class TestAddressClassification:
    @pytest.mark.parametrize(
        "address,expected",
        [
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("172.32.0.1", "public"),
            ("192.168.1.1", "private"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "cgnat"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast"),
            ("8.8.8.8", "public"),
            ("192.0.2.1", "reserved"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("fd00::1", "private"),
            ("ff02::1", "multicast"),
            ("2606:4700::1111", "public"),
            ("not-an-address", "invalid"),
        ],
    )
    def test_scopes(self, address, expected):
        assert classify_address(address) == expected

    def test_is_private(self):
        assert is_private("10.0.0.1") and is_private("100.64.0.1")
        assert not is_private("8.8.8.8")
