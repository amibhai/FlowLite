"""Host profiles and the network time series."""

from __future__ import annotations

import time

import pytest

from flowlite.analytics.host_profiles import HOST_PROFILE_FIELDS, HostProfileAggregator
from flowlite.analytics.network_ts import (
    NETWORK_TS_FIELDS,
    NetworkTimeSeriesBuilder,
    parse_timestamp,
    shannon_entropy,
)
from flowlite.storage import CsvSink


def make_flow(**overrides):
    row = {
        "start_epoch": 1_700_000_000.0,
        "start_time": "2023-11-14T22:13:20.000Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 40000,
        "dst_port": 443,
        "protocol_name": "TCP",
        "ip_version": 4,
        "fwd_packets": 5,
        "bwd_packets": 4,
        "total_packets": 9,
        "fwd_bytes": 500,
        "bwd_bytes": 400,
        "fwd_frame_bytes": 800,
        "bwd_frame_bytes": 700,
        "duration_s": 1.5,
        "flow_iat_mean": 0.2,
        "pkt_len_mean": 100.0,
        "active_mean": 1.0,
        "idle_mean": 0.0,
        "ttl_mean": 64.0,
        "syn_count": 1,
        "ack_count": 8,
        "rst_count": 0,
        "fin_count": 1,
        "tcp_state": "closed",
        "src_scope": "private",
        "dst_scope": "public",
        "dst_asn": "AS15169",
        "dst_country": "US",
    }
    row.update(overrides)
    return row


class TestHostProfiles:
    def test_schema_matches(self):
        aggregator = HostProfileAggregator(window_minutes=10, device="d")
        aggregator.add_flow(make_flow())
        rows = aggregator.rows()
        assert len(rows) == 2  # one for the source, one for the destination
        for row in rows:
            assert set(row) == set(HOST_PROFILE_FIELDS)

    def test_both_directions_are_profiled(self):
        aggregator = HostProfileAggregator()
        aggregator.add_flow(make_flow())
        rows = {r["host_ip"]: r for r in aggregator.rows()}
        assert rows["10.0.0.1"]["flows_out"] == 1 and rows["10.0.0.1"]["flows_in"] == 0
        assert rows["8.8.8.8"]["flows_in"] == 1 and rows["8.8.8.8"]["flows_out"] == 0
        # A host that only receives still records what reached it.
        assert rows["8.8.8.8"]["bytes_received"] == 500
        assert rows["8.8.8.8"]["unique_peer_sources"] == 1

    def test_windows_split_by_time(self):
        aggregator = HostProfileAggregator(window_minutes=10)
        aggregator.add_flow(make_flow(start_epoch=1_700_000_000.0))
        aggregator.add_flow(make_flow(start_epoch=1_700_000_000.0 + 1200))
        windows = {r["window_start"] for r in aggregator.rows() if r["host_ip"] == "10.0.0.1"}
        assert len(windows) == 2

    def test_cardinality_and_entropy(self):
        aggregator = HostProfileAggregator()
        for port in range(20):
            aggregator.add_flow(make_flow(dst_port=port, dst_ip=f"203.0.113.{port}"))
        row = next(r for r in aggregator.rows() if r["host_ip"] == "10.0.0.1")
        assert row["unique_dst_ports"] == 20
        assert row["unique_dst_ips"] == 20
        assert row["dst_port_entropy"] == pytest.approx(4.32, abs=0.02)
        assert row["fan_out_ratio"] == 1.0

    def test_window_shares_sum_to_one(self):
        aggregator = HostProfileAggregator()
        for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            aggregator.add_flow(make_flow(src_ip=host))
        senders = [r for r in aggregator.rows() if r["flows_out"]]
        # Shares are rounded to six decimals, so three thirds land a hair short.
        assert sum(r["share_of_window_flows"] for r in senders) == pytest.approx(1.0, abs=1e-5)

    def test_failed_handshake_ratio(self):
        aggregator = HostProfileAggregator()
        for _ in range(3):
            aggregator.add_flow(make_flow(tcp_state="syn-sent"))
        aggregator.add_flow(make_flow(tcp_state="closed"))
        row = next(r for r in aggregator.rows() if r["host_ip"] == "10.0.0.1")
        assert row["failed_handshake_ratio"] == pytest.approx(0.75)

    def test_is_linear_not_quadratic(self):
        """5,000 hosts in one window used to trigger 5,000 full table scans."""
        aggregator = HostProfileAggregator()
        started = time.monotonic()
        for i in range(5000):
            aggregator.add_flow(make_flow(src_ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"))
        aggregator.rows()
        assert time.monotonic() - started < 10.0

    def test_missing_columns_do_not_raise(self):
        aggregator = HostProfileAggregator()
        aggregator.add_flow({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
        assert aggregator.rows()

    def test_empty_aggregator(self):
        assert HostProfileAggregator().rows() == []


class TestNetworkTimeSeries:
    def test_schema_matches(self):
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60, device="d")
        builder.add_flow(make_flow())
        rows = builder.rows()
        assert rows and set(rows[0]) == set(NETWORK_TS_FIELDS)

    def test_spine_comes_from_the_data_not_the_clock(self):
        """The old builder used `utcnow() - 1h`, so every joined column was 0."""
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60)
        builder.add_flow(make_flow(start_epoch=1_600_000_000.0))
        rows = builder.rows()
        assert rows[0]["epoch"] == 1_600_000_000 - (1_600_000_000 % 60)
        assert rows[0]["flow_samples"] == 1

    def test_gaps_are_filled_and_flagged(self):
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60)
        builder.add_flow(make_flow(start_epoch=1_700_000_000.0))
        builder.add_flow(make_flow(start_epoch=1_700_000_000.0 + 300))
        rows = builder.rows(fill_gaps=True)
        assert len(rows) == 6
        quiet = [r for r in rows if r["flow_samples"] == 0]
        assert len(quiet) == 4
        # A quiet bucket is distinguishable from an unmeasured one.
        assert all(r["telemetry_samples"] == 0 for r in rows)

    def test_rates_use_the_bucket_width(self):
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60)
        for _ in range(60):
            builder.add_flow(make_flow())
        row = builder.rows()[0]
        assert row["flows_per_s"] == pytest.approx(1.0)
        assert row["bytes_per_s"] == pytest.approx(60 * 900 / 60)

    def test_protocol_ratios(self):
        builder = NetworkTimeSeriesBuilder()
        builder.add_flow(make_flow(protocol_name="TCP"))
        builder.add_flow(make_flow(protocol_name="UDP"))
        builder.add_flow(make_flow(protocol_name="ICMP"))
        builder.add_flow(make_flow(protocol_name="TCP"))
        row = builder.rows()[0]
        assert row["tcp_ratio"] == pytest.approx(0.5)
        assert row["udp_ratio"] == pytest.approx(0.25)
        assert row["icmp_ratio"] == pytest.approx(0.25)

    def test_telemetry_join(self, tmp_path):
        from flowlite.telemetry.base import DEVICE_TELEMETRY_FIELDS

        path = tmp_path / "telemetry.csv"
        with CsvSink(path, DEVICE_TELEMETRY_FIELDS) as sink:
            sink.write_row(
                {
                    "timestamp": "2023-11-14T22:13:30Z",
                    "epoch": 1_700_000_010,
                    "device": "d",
                    "reachable": 1,
                    "in_bytes_per_s": 1000,
                    "out_bytes_per_s": 2000,
                    "interfaces_total": 48,
                    "interfaces_down": 2,
                }
            )
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60)
        builder.add_flow(make_flow(start_epoch=1_700_000_000.0))
        assert builder.add_telemetry_csv(path) == 1
        row = builder.rows()[0]
        assert row["telemetry_samples"] == 1
        assert row["iface_in_bytes_per_s"] == 1000
        assert row["ifaces_down"] == 2

    def test_join_ignores_rows_outside_the_window(self, tmp_path):
        from flowlite.telemetry.base import DEVICE_TELEMETRY_FIELDS

        path = tmp_path / "telemetry.csv"
        with CsvSink(path, DEVICE_TELEMETRY_FIELDS) as sink:
            sink.write_row(
                {"timestamp": "2020-01-01T00:00:00Z", "epoch": 1_577_836_800, "device": "d"}
            )
        builder = NetworkTimeSeriesBuilder()
        builder.add_flow(make_flow(start_epoch=1_700_000_000.0))
        assert builder.add_telemetry_csv(path) == 0

    def test_missing_join_file_is_harmless(self, tmp_path):
        builder = NetworkTimeSeriesBuilder()
        builder.add_flow(make_flow())
        assert builder.add_telemetry_csv(tmp_path / "absent.csv") == 0
        assert builder.rows()

    def test_absurd_clock_skew_does_not_explode_row_count(self):
        builder = NetworkTimeSeriesBuilder(bucket_seconds=1)
        builder.add_flow(make_flow(start_epoch=0.0))
        builder.add_flow(make_flow(start_epoch=1_700_000_000.0))
        rows = builder.rows(fill_gaps=True)
        assert len(rows) == 2

    def test_empty_builder(self):
        assert NetworkTimeSeriesBuilder().rows() == []


class TestHelpers:
    def test_entropy(self):
        assert shannon_entropy({}) == 0.0
        assert shannon_entropy({"a": 10}) == 0.0
        assert shannon_entropy({"a": 1, "b": 1}) == pytest.approx(1.0)
        assert shannon_entropy(dict.fromkeys(range(256), 1)) == pytest.approx(8.0)

    @pytest.mark.parametrize(
        "value,expected",
        [
            (1_700_000_000, 1_700_000_000.0),
            ("1700000000", 1_700_000_000.0),
            ("2023-11-14T22:13:20Z", 1_700_000_000.0),
            ("2023-11-14T22:13:20+00:00", 1_700_000_000.0),
            ("", None),
            (None, None),
            ("nonsense", None),
        ],
    )
    def test_parse_timestamp(self, value, expected):
        result = parse_timestamp(value)
        if expected is None:
            assert result is None
        else:
            assert result == pytest.approx(expected)
