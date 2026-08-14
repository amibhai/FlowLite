"""sFlow and NetFlow/IPFIX decoding, and the UDP collectors."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time

import pytest

from flowlite import synth
from flowlite.config import load_config
from flowlite.flowproto import (
    NETFLOW_FIELDS,
    SFLOW_SAMPLE_FIELDS,
    NetFlowDecoder,
    TemplateCache,
    build_collectors,
    decode_netflow_v5,
    decode_sflow,
    payload_entropy,
)
from flowlite.flowproto.netflow import Template
from flowlite.storage import read_csv_rows
from flowlite.telemetry.base import INTERFACE_FIELDS

SAMPLE_FRAME = synth.make_tcp_frame("10.0.0.5", "93.184.216.34", 51000, 443, b"\xaa" * 200)
SAMPLE_COUNTER = {
    "if_index": 11,
    "in_octets": 1_000_000,
    "out_octets": 2_000_000,
    "in_packets": 900,
    "out_packets": 800,
    "in_errors": 2,
    "out_errors": 1,
    "in_discards": 3,
    "out_discards": 4,
    "speed_bps": 10_000_000_000,
    "status": 3,
}


class TestSFlow:
    @pytest.mark.parametrize("expanded", [False, True])
    def test_flow_and_counter_samples(self, expanded):
        datagram = synth.sflow_datagram(
            sampled_frames=[SAMPLE_FRAME], counters=[SAMPLE_COUNTER], expanded=expanded
        )
        result = decode_sflow(datagram, 1_700_000_000.0)
        assert not result.errors
        assert result.agent_ip == "192.0.2.1"
        assert len(result.flow_samples) == 1
        assert len(result.counter_samples) == 1

        sample = result.flow_samples[0]
        assert sample["src_ip"] == "10.0.0.5"
        assert sample["dst_port"] == 443
        assert sample["protocol_name"] == "TCP"
        assert sample["sampling_rate"] == 1024
        assert 0.0 < sample["payload_entropy"] <= 8.0

        counter = result.counter_samples[0]
        assert counter["if_index"] == 11
        assert counter["in_octets"] == 1_000_000
        assert counter["speed_bps"] == 10_000_000_000

    def test_expanded_matches_standard(self):
        """Expanded samples were previously skipped entirely, losing all data."""
        standard = decode_sflow(
            synth.sflow_datagram(sampled_frames=[SAMPLE_FRAME], counters=[SAMPLE_COUNTER])
        )
        expanded = decode_sflow(
            synth.sflow_datagram(
                sampled_frames=[SAMPLE_FRAME], counters=[SAMPLE_COUNTER], expanded=True
            )
        )
        assert standard.flow_samples[0]["src_ip"] == expanded.flow_samples[0]["src_ip"]
        assert standard.counter_samples == expanded.counter_samples

    def test_wrong_version_is_reported(self):
        result = decode_sflow(struct.pack("!I", 4) + b"\x00" * 40)
        assert result.errors and "version" in result.errors[0]

    def test_truncation_is_survivable(self):
        datagram = synth.sflow_datagram(sampled_frames=[SAMPLE_FRAME], counters=[SAMPLE_COUNTER])
        for cut in range(0, len(datagram), 7):
            decode_sflow(datagram[:cut])  # must not raise

    def test_random_input_never_raises(self):
        for size in (0, 1, 4, 27, 28, 100, 1500):
            decode_sflow(os.urandom(size))
        for _ in range(200):
            decode_sflow(struct.pack("!I", 5) + os.urandom(200))

    def test_entropy(self):
        assert payload_entropy(b"") == 0.0
        assert payload_entropy(b"\x00" * 100) == 0.0
        assert payload_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_declared_sample_count_is_not_trusted(self):
        """A datagram claiming a billion samples must not be believed."""
        header = struct.pack("!II", 5, 1) + bytes([192, 0, 2, 1])
        header += struct.pack("!IIII", 0, 1, 1000, 2**31)
        result = decode_sflow(header)
        assert result.flow_samples == []


class TestNetFlowV5:
    def test_decode(self):
        datagram = synth.netflow_v5_datagram(
            [
                {
                    "src_ip": "10.1.1.1",
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "protocol": 17,
                    "packets": 3,
                    "bytes": 300,
                    "first": 1000,
                    "last": 1500,
                },
                {
                    "src_ip": "10.1.1.2",
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443,
                    "protocol": 6,
                    "packets": 10,
                    "bytes": 5000,
                    "first": 2000,
                    "last": 9000,
                },
            ]
        )
        rows = decode_netflow_v5(datagram, "192.0.2.9", 0.0)
        assert len(rows) == 2
        assert rows[0]["protocol_name"] == "UDP"
        assert rows[1]["bytes"] == 5000
        assert rows[1]["duration_s"] == pytest.approx(7.0)
        assert set(rows[0]) <= set(NETFLOW_FIELDS)

    def test_declared_count_larger_than_the_payload(self):
        datagram = synth.netflow_v5_datagram([{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}])
        tampered = struct.pack("!HH", 5, 500) + datagram[4:]
        assert len(decode_netflow_v5(tampered, "x", 0.0)) == 1

    def test_sampling_interval(self):
        datagram = synth.netflow_v5_datagram(
            [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}], sampling_interval=100
        )
        assert decode_netflow_v5(datagram, "x", 0.0)[0]["sampling_rate"] == 100


class TestNetFlowV9AndIpfix:
    def test_data_before_template_is_counted_not_lost_silently(self):
        decoder = NetFlowDecoder(TemplateCache())
        records = [{"src_ip": "172.16.0.9", "dst_ip": "52.1.2.3", "bytes": 800, "packets": 7}]
        assert (
            decoder.decode(synth.netflow_v9_datagram(records=records, include_template=False), "e1")
            == []
        )
        assert decoder.records_awaiting_template == 1

        decoder.decode(synth.netflow_v9_datagram(records=[]), "e1")
        rows = decoder.decode(
            synth.netflow_v9_datagram(records=records, include_template=False), "e1"
        )
        assert len(rows) == 1 and rows[0]["bytes"] == 800

    def test_template_and_data_in_one_datagram(self):
        decoder = NetFlowDecoder(TemplateCache())
        rows = decoder.decode(
            synth.netflow_v9_datagram(
                records=[{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "packets": 4}]
            ),
            "e1",
        )
        assert len(rows) == 1 and rows[0]["packets"] == 4

    def test_templates_are_isolated_per_exporter(self):
        """A shared template id from two devices must not cross-decode."""
        decoder = NetFlowDecoder(TemplateCache())
        layout_a = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (2, 4), (1, 4)]
        layout_b = [(8, 4), (12, 4), (4, 1), (2, 4)]
        decoder.decode(synth.netflow_v9_datagram(256, layout_a, records=[]), "exporter-a")
        decoder.decode(synth.netflow_v9_datagram(256, layout_b, records=[]), "exporter-b")

        rows_a = decoder.decode(
            synth.netflow_v9_datagram(
                256,
                layout_a,
                records=[{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "bytes": 111}],
                include_template=False,
            ),
            "exporter-a",
        )
        rows_b = decoder.decode(
            synth.netflow_v9_datagram(
                256,
                layout_b,
                records=[{"src_ip": "10.9.9.9", "dst_ip": "10.9.9.8", "packets": 42}],
                include_template=False,
            ),
            "exporter-b",
        )
        assert rows_a[0]["bytes"] == 111
        assert rows_b[0]["packets"] == 42

    def test_ipfix_with_64_bit_counters_and_millisecond_times(self):
        decoder = NetFlowDecoder(TemplateCache())
        fields = [
            (8, 4),
            (12, 4),
            (7, 2),
            (11, 2),
            (4, 1),
            (6, 1),
            (2, 8),
            (1, 8),
            (152, 8),
            (153, 8),
        ]
        rows = decoder.decode(
            synth.ipfix_datagram(
                fields=fields,
                records=[
                    {
                        "src_ip": "192.168.5.5",
                        "dst_ip": "140.82.121.4",
                        "src_port": 33333,
                        "dst_port": 22,
                        "protocol": 6,
                        "packets": 99,
                        "bytes": 123456,
                        "start_ms": 1_700_000_000_000,
                        "end_ms": 1_700_000_012_500,
                    }
                ],
            ),
            "203.0.113.5",
        )
        assert len(rows) == 1
        assert rows[0]["version"] == 10
        assert rows[0]["bytes"] == 123456
        assert rows[0]["duration_s"] == pytest.approx(12.5)

    def test_ipv6_records(self):
        decoder = NetFlowDecoder(TemplateCache())
        fields = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
        rows = decoder.decode(
            synth.ipfix_datagram(
                fields=fields,
                records=[
                    {
                        "src_ip": "2001:db8::1",
                        "dst_ip": "2606:4700::1111",
                        "dst_port": 443,
                        "protocol": 6,
                        "bytes": 900,
                    }
                ],
            ),
            "e1",
        )
        assert rows[0]["ip_version"] == 6
        assert rows[0]["src_ip"] == "2001:db8::1"

    def test_unsupported_versions_are_reported(self, quiet_logger):
        decoder = NetFlowDecoder(TemplateCache(), quiet_logger)
        assert decoder.decode(struct.pack("!HH", 7, 1) + b"\x00" * 40, "e1") == []
        assert decoder.errors == 1

    def test_random_input_never_raises(self):
        decoder = NetFlowDecoder(TemplateCache())
        for size in (0, 2, 7, 16, 20, 40, 300):
            decoder.decode(os.urandom(size), "e1")
        for version in (5, 9, 10):
            for _ in range(50):
                decoder.decode(struct.pack("!H", version) + os.urandom(120), "e1")

    def test_template_cache_persists_across_restarts(self, tmp_path):
        path = tmp_path / "templates.json"
        first = NetFlowDecoder(TemplateCache(path))
        first.decode(synth.netflow_v9_datagram(records=[]), "e1")
        first.cache.save()

        # A fresh collector must decode data without waiting for a resend.
        second = NetFlowDecoder(TemplateCache(path))
        rows = second.decode(
            synth.netflow_v9_datagram(
                records=[{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "bytes": 5}],
                include_template=False,
            ),
            "e1",
        )
        assert len(rows) == 1 and rows[0]["bytes"] == 5

    def test_expired_templates_are_dropped(self):
        cache = TemplateCache(ttl_s=0.01)
        cache.put("e1", 0, Template(256, [(8, 4)]))
        time.sleep(0.05)
        assert cache.get("e1", 0, 256) is None

    def test_corrupt_cache_file_is_ignored(self, tmp_path):
        path = tmp_path / "templates.json"
        path.write_text("{not json", encoding="utf-8")
        assert len(TemplateCache(path)) == 0


class TestCollectors:
    def _cfg(self, tmp_path, sflow_port=0, netflow_port=0):
        overrides = [
            f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
            "flowproto.enabled=true",
            "flowproto.flush_interval_s=1",
        ]
        if sflow_port:
            overrides += [
                "flowproto.sflow.enabled=true",
                "flowproto.sflow.bind=127.0.0.1",
                f"flowproto.sflow.port={sflow_port}",
            ]
        if netflow_port:
            overrides += [
                "flowproto.netflow.enabled=true",
                "flowproto.netflow.bind=127.0.0.1",
                f"flowproto.netflow.port={netflow_port}",
            ]
        return load_config(overrides=overrides, allow_missing=True, _skip_search=True)

    @staticmethod
    def _free_port() -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def test_sflow_collector_writes_samples_and_counters(self, tmp_path, quiet_logger):
        port = self._free_port()
        cfg = self._cfg(tmp_path, sflow_port=port)
        collector = build_collectors(cfg, quiet_logger)[0]
        collector.bind_socket()
        stop = threading.Event()
        thread = threading.Thread(target=collector.run, args=(stop,), daemon=True)
        thread.start()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        datagram = synth.sflow_datagram(sampled_frames=[SAMPLE_FRAME], counters=[SAMPLE_COUNTER])
        deadline = time.monotonic() + 10
        while collector.rows_written == 0 and time.monotonic() < deadline:
            sender.sendto(datagram, ("127.0.0.1", port))
            time.sleep(0.2)
        stop.set()
        thread.join(timeout=5)
        sender.close()

        samples = read_csv_rows(cfg.paths.sflow_csv)
        assert samples, "no sFlow samples were written"
        assert set(samples[0]) == set(SFLOW_SAMPLE_FIELDS)
        assert samples[0]["src_ip"] == "10.0.0.5"

        interfaces = read_csv_rows(cfg.paths.interfaces_csv)
        assert interfaces, "sFlow counter samples were not written as interface rows"
        assert set(interfaces[0]) == set(INTERFACE_FIELDS)
        assert interfaces[0]["if_index"] == "11"

    def test_netflow_collector_writes_records(self, tmp_path, quiet_logger):
        port = self._free_port()
        cfg = self._cfg(tmp_path, netflow_port=port)
        collector = build_collectors(cfg, quiet_logger)[0]
        collector.bind_socket()
        stop = threading.Event()
        thread = threading.Thread(target=collector.run, args=(stop,), daemon=True)
        thread.start()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        datagram = synth.netflow_v5_datagram(
            [{"src_ip": "10.5.5.5", "dst_ip": "8.8.4.4", "bytes": 77}]
        )
        deadline = time.monotonic() + 10
        while collector.rows_written == 0 and time.monotonic() < deadline:
            sender.sendto(datagram, ("127.0.0.1", port))
            time.sleep(0.2)
        stop.set()
        thread.join(timeout=5)
        sender.close()

        rows = read_csv_rows(cfg.paths.netflow_csv)
        assert rows and set(rows[0]) == set(NETFLOW_FIELDS)
        assert rows[0]["src_ip"] == "10.5.5.5"

    def test_bind_failure_raises_instead_of_dying_silently(self, tmp_path, quiet_logger):
        """The old listener swallowed this and then reported itself healthy."""
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        cfg = self._cfg(tmp_path, sflow_port=port)
        collector = build_collectors(cfg, quiet_logger)[0]
        try:
            with pytest.raises(OSError, match="cannot bind"):
                collector.bind_socket()
        finally:
            holder.close()

    def test_queue_overflow_is_counted_not_unbounded(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path, sflow_port=self._free_port())
        collector = build_collectors(cfg, quiet_logger)[0]
        collector.max_queue = 5
        for _ in range(50):
            collector._enqueue([{"a": 1}])
        assert collector.dropped > 0
        assert len(collector._queue) <= 5
        collector.close()

    def test_no_collectors_when_disabled(self, tmp_path, quiet_logger):
        cfg = load_config(
            overrides=[f"paths.data_dir={json.dumps(str(tmp_path))}", "flowproto.enabled=false"],
            allow_missing=True,
            _skip_search=True,
        )
        assert build_collectors(cfg, quiet_logger) == []
