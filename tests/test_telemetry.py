"""SNMP codec, telemetry drivers, counter tracking and the collector loop."""

from __future__ import annotations

import json
import os
import socket
import threading

import pytest

from flowlite.config import load_config
from flowlite.storage import read_csv_rows
from flowlite.telemetry import (
    DEVICE_TELEMETRY_FIELDS,
    INTERFACE_FIELDS,
    CounterTracker,
    DeviceSnapshot,
    InterfaceCounters,
    TelemetryCollector,
    available_drivers,
    build_telemetry_driver,
    snapshot_to_rows,
)
from flowlite.telemetry.snmp import (
    OID,
    PDU_RESPONSE,
    TAG_COUNTER64,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    SnmpClient,
    _decode_integer,
    _decode_tlv,
    _encode_integer,
    _encode_tlv,
    decode_oid,
    encode_oid,
)


class TestSnmpCodec:
    @pytest.mark.parametrize(
        "oid",
        [
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.2.1.2.2.1.10.1",
            "1.3.6.1.2.1.31.1.1.1.6.16777216",
            "1.3.6.1.4.1.9.9.999.1.2.3",
            "0.0",
            "2.16.840.1.101.3.4.2.1",
        ],
    )
    def test_oid_round_trip(self, oid):
        assert decode_oid(encode_oid(oid)[2:]) == oid

    def test_invalid_oids_are_rejected(self):
        for bad in ("1", "", "1.99.3", "7.1.2"):
            with pytest.raises(ValueError):
                encode_oid(bad)

    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 65535, -1, -128, -129, 2**31 - 1])
    def test_integer_round_trip(self, value):
        encoded = _encode_integer(value)
        _tag, body, _end = _decode_tlv(encoded, 0)
        assert _decode_integer(body) == value

    def test_long_form_lengths(self):
        payload = b"x" * 300
        encoded = _encode_tlv(TAG_OCTET_STRING, payload)
        _tag, body, _end = _decode_tlv(encoded, 0)
        assert body == payload

    def test_truncated_input_raises_parse_error(self):
        from flowlite.errors import ParseError

        with pytest.raises(ParseError):
            _decode_tlv(b"\x04\x10ab", 0)


class FakeAgent:
    """A minimal in-process SNMP agent, so driver tests need no device."""

    def __init__(self, interfaces: int = 3, drops: int = 0) -> None:
        self.mib = {
            OID.SYS_DESCR: ("str", "Generic Switch OS 1.0"),
            OID.SYS_NAME: ("str", "fake-switch"),
            OID.SYS_UPTIME: ("int", 4_567_800),
        }
        for index in range(1, interfaces + 1):
            self.mib[f"{OID.IF_DESCR}.{index}"] = ("str", f"Ethernet{index}")
            self.mib[f"{OID.IF_NAME}.{index}"] = ("str", f"Et{index}")
            self.mib[f"{OID.IF_ALIAS}.{index}"] = ("str", f"link-{index}")
            self.mib[f"{OID.IF_ADMIN_STATUS}.{index}"] = ("int", 1)
            self.mib[f"{OID.IF_OPER_STATUS}.{index}"] = ("int", 1 if index < interfaces else 2)
            self.mib[f"{OID.IF_HIGH_SPEED}.{index}"] = ("int", 1000)
            self.mib[f"{OID.IF_HC_IN_OCTETS}.{index}"] = ("c64", 1_000 * index)
            self.mib[f"{OID.IF_HC_OUT_OCTETS}.{index}"] = ("c64", 2_000 * index)
            self.mib[f"{OID.IF_HC_IN_UCAST}.{index}"] = ("c64", 10 * index)
            self.mib[f"{OID.IF_HC_OUT_UCAST}.{index}"] = ("c64", 20 * index)
            for column in (
                OID.IF_IN_ERRORS,
                OID.IF_OUT_ERRORS,
                OID.IF_IN_DISCARDS,
                OID.IF_OUT_DISCARDS,
            ):
                self.mib[f"{column}.{index}"] = ("c32", index)

        self.drops = drops
        self.received = 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeAgent:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        self.socket.close()

    @staticmethod
    def _key(oid: str):
        return tuple(int(part) for part in oid.split("."))

    def _encode(self, kind: str, value):
        if kind == "str":
            return _encode_tlv(TAG_OCTET_STRING, value.encode())
        if kind == "int":
            return _encode_integer(value, TAG_INTEGER)
        if kind == "c64":
            return _encode_tlv(TAG_COUNTER64, value.to_bytes(8, "big"))
        return _encode_tlv(0x41, value.to_bytes(4, "big"))

    def _serve(self) -> None:
        self.socket.settimeout(0.3)
        while not self.stop.is_set():
            try:
                data, address = self.socket.recvfrom(65535)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            self.received += 1
            if self.drops > 0:
                self.drops -= 1
                continue
            try:
                self.socket.sendto(self._respond(data), address)
            except OSError:
                return

    def _respond(self, data: bytes) -> bytes:
        _tag, body, _end = _decode_tlv(data, 0)
        offset = 0
        _tag, _version, offset = _decode_tlv(body, offset)
        _tag, _community, offset = _decode_tlv(body, offset)
        pdu_tag, pdu, _end = _decode_tlv(body, offset)

        position = 0
        _tag, request_id_body, position = _decode_tlv(pdu, position)
        _tag, _non_repeaters, position = _decode_tlv(pdu, position)
        _tag, max_reps_body, position = _decode_tlv(pdu, position)
        request_id = _decode_integer(request_id_body)
        max_reps = _decode_integer(max_reps_body)
        _tag, varbind_list, _end = _decode_tlv(pdu, position)

        cursor = 0
        oids = []
        while cursor < len(varbind_list):
            _tag, varbind, cursor = _decode_tlv(varbind_list, cursor)
            inner = 0
            _tag, oid_body, inner = _decode_tlv(varbind, inner)
            oids.append(decode_oid(oid_body))

        ordered = sorted(self.mib, key=self._key)
        out = b""
        if pdu_tag == 0xA0:  # GET
            for oid in oids:
                if oid in self.mib:
                    out += _encode_tlv(TAG_SEQUENCE, encode_oid(oid) + self._encode(*self.mib[oid]))
                else:
                    out += _encode_tlv(TAG_SEQUENCE, encode_oid(oid) + _encode_tlv(0x81, b""))
        else:  # GETNEXT / GETBULK
            repetitions = max_reps if pdu_tag == 0xA5 else 1
            current = oids[0]
            for _ in range(max(1, repetitions)):
                following = next((o for o in ordered if self._key(o) > self._key(current)), None)
                if following is None:
                    out += _encode_tlv(TAG_SEQUENCE, encode_oid(current) + _encode_tlv(0x82, b""))
                    break
                out += _encode_tlv(
                    TAG_SEQUENCE, encode_oid(following) + self._encode(*self.mib[following])
                )
                current = following

        pdu_body = (
            _encode_integer(request_id)
            + _encode_integer(0)
            + _encode_integer(0)
            + _encode_tlv(TAG_SEQUENCE, out)
        )
        message = (
            _encode_integer(1)
            + _encode_tlv(TAG_OCTET_STRING, b"public")
            + _encode_tlv(PDU_RESPONSE, pdu_body)
        )
        return _encode_tlv(TAG_SEQUENCE, message)


class TestSnmpClient:
    def test_get(self):
        with FakeAgent() as agent:
            client = SnmpClient("127.0.0.1", "public", port=agent.port, timeout=2)
            result = client.get([OID.SYS_DESCR, OID.SYS_NAME])
            assert result[OID.SYS_NAME] == "fake-switch"
            client.close()

    def test_walk_stays_inside_the_subtree(self):
        with FakeAgent(interfaces=4) as agent:
            client = SnmpClient("127.0.0.1", "public", port=agent.port, timeout=2)
            column = client.walk_column(OID.IF_DESCR)
            assert column == {str(i): f"Ethernet{i}" for i in range(1, 5)}
            client.close()

    def test_count(self):
        with FakeAgent(interfaces=6) as agent:
            client = SnmpClient("127.0.0.1", "public", port=agent.port, timeout=2)
            assert client.count(OID.IF_DESCR) == 6
            client.close()

    def test_retries_recover_from_a_dropped_request(self):
        with FakeAgent(drops=1) as agent:
            client = SnmpClient("127.0.0.1", "public", port=agent.port, timeout=1, retries=2)
            assert client.get([OID.SYS_NAME])
            assert agent.received >= 2
            client.close()

    def test_timeout_raises_a_transient_error(self):
        from flowlite.errors import TransientTelemetryError

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        client = SnmpClient("127.0.0.1", "public", port=port, timeout=0.3, retries=0)
        with pytest.raises(TransientTelemetryError):
            client.get([OID.SYS_NAME])
        client.close()


class TestSnmpDriver:
    def _cfg(self, tmp_path, port):
        return load_config(
            overrides=[
                f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
                "device.host=127.0.0.1",
                "device.name=fake-switch",
                "credentials.snmp_community=public",
                "telemetry.driver=snmp",
                "telemetry.interval_s=5",
                "telemetry.timeout_s=2",
                f"telemetry.snmp.port={port}",
            ],
            allow_missing=True,
            _skip_search=True,
        )

    def test_preflight_and_collect(self, tmp_path, quiet_logger):
        with FakeAgent(interfaces=3) as agent:
            cfg = self._cfg(tmp_path, agent.port)
            driver = build_telemetry_driver(cfg, quiet_logger)
            assert driver.preflight().ok
            snapshot = driver.collect()
            assert snapshot.reachable
            assert len(snapshot.interfaces) == 3
            assert snapshot.system_name == "fake-switch"
            assert snapshot.uptime_s == pytest.approx(45678.0)
            first = snapshot.interfaces[0]
            assert first.name == "Et1" and first.alias == "link-1"
            assert first.speed_bps == 1_000_000_000 and first.high_capacity
            driver.close()

    def test_unreachable_device_reports_a_failure_not_zeros(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path, 1)  # nothing listens on port 1
        driver = build_telemetry_driver(cfg, quiet_logger)
        snapshot = driver.collect()
        assert not snapshot.reachable and snapshot.error
        assert not driver.preflight().ok
        driver.close()

    def test_collector_writes_rates_after_two_polls(self, tmp_path, quiet_logger):
        with FakeAgent(interfaces=2) as agent:
            cfg = self._cfg(tmp_path, agent.port)
            driver = build_telemetry_driver(cfg, quiet_logger)
            collector = TelemetryCollector(cfg, driver, quiet_logger)
            collector.poll_once()
            for index in (1, 2):
                agent.mib[f"{OID.IF_HC_IN_OCTETS}.{index}"] = ("c64", 1_000 * index + 100_000)
            import time

            time.sleep(1.05)
            collector.poll_once()
            collector.close()

            device_rows = read_csv_rows(cfg.paths.telemetry_csv)
            interface_rows = read_csv_rows(cfg.paths.interfaces_csv)
            assert len(device_rows) == 2
            assert set(device_rows[0]) == set(DEVICE_TELEMETRY_FIELDS)
            assert set(interface_rows[0]) == set(INTERFACE_FIELDS)
            # The first poll has no previous sample, so no rate is invented.
            assert device_rows[0]["in_bytes_per_s"] == ""
            assert float(device_rows[1]["in_bytes_per_s"]) > 0

    def test_unreachable_poll_is_recorded_as_unreachable(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path, 1)
        driver = build_telemetry_driver(cfg, quiet_logger)
        collector = TelemetryCollector(cfg, driver, quiet_logger)
        collector.poll_once()
        collector.close()
        rows = read_csv_rows(cfg.paths.telemetry_csv)
        assert rows[0]["reachable"] == "0"
        assert rows[0]["error"]
        assert rows[0]["interfaces_total"] == ""


class TestCounterTracker:
    def test_first_sample_yields_no_rate(self):
        tracker = CounterTracker()
        result = tracker.update("a", {"in_octets": 100}, 0.0)
        assert result["first_sample"] is True
        assert "in_octets_delta" not in result

    def test_normal_delta(self):
        tracker = CounterTracker()
        tracker.update("a", {"in_octets": 100}, 0.0)
        result = tracker.update("a", {"in_octets": 400}, 10.0)
        assert result["in_octets_delta"] == 300
        assert result["interval_s"] == 10.0
        assert result["counter_reset"] == 0

    def test_32_bit_wrap_is_corrected(self):
        tracker = CounterTracker()
        tracker.update("a", {"in_octets": 2**32 - 1000}, 0.0, speed_bps=1_000_000_000)
        result = tracker.update("a", {"in_octets": 500}, 1.0, speed_bps=1_000_000_000)
        assert result["in_octets_delta"] == 1500
        assert result["counter_reset"] == 0

    def test_reset_is_flagged_not_guessed(self):
        tracker = CounterTracker()
        tracker.update("a", {"in_octets": 900_000_000_000}, 0.0, speed_bps=1_000_000_000)
        result = tracker.update("a", {"in_octets": 5}, 1.0, speed_bps=1_000_000_000)
        assert result["in_octets_delta"] == 0
        assert result["counter_reset"] == 1
        assert tracker.resets == 1

    def test_implausible_wrap_is_treated_as_a_reset(self):
        """A 'wrap' faster than the link can carry is a reset, not a wrap."""
        tracker = CounterTracker()
        tracker.update("a", {"in_octets": 2**32 - 10}, 0.0, speed_bps=1_000_000)
        result = tracker.update("a", {"in_octets": 2**31}, 1.0, speed_bps=1_000_000)
        assert result["counter_reset"] == 1

    def test_none_values_are_skipped(self):
        tracker = CounterTracker()
        tracker.update("a", {"in_octets": None, "out_octets": 5}, 0.0)
        result = tracker.update("a", {"in_octets": None, "out_octets": 15}, 1.0)
        assert "in_octets_delta" not in result
        assert result["out_octets_delta"] == 10


class TestSnapshotRendering:
    def test_utilisation_uses_the_interface_speed(self):
        tracker = CounterTracker()
        snapshot = DeviceSnapshot(device="d", driver="snmp", epoch=0.0)
        snapshot.interfaces = [
            InterfaceCounters(
                index=1, name="Et1", speed_bps=1_000_000_000, in_octets=0, out_octets=0
            )
        ]
        snapshot_to_rows(snapshot, tracker)
        snapshot.epoch = 1.0
        snapshot.interfaces[0].in_octets = 12_500_000  # 100 Mbit/s on a 1 Gbit link
        _device, interfaces = snapshot_to_rows(snapshot, tracker)
        assert interfaces[0]["utilisation_in_pct"] == pytest.approx(10.0, abs=0.1)

    def test_up_and_down_counts(self):
        snapshot = DeviceSnapshot(device="d", driver="snmp")
        snapshot.interfaces = [
            InterfaceCounters(index=1, oper_status="up"),
            InterfaceCounters(index=2, oper_status="down"),
            InterfaceCounters(index=3, oper_status="up"),
        ]
        device, _interfaces = snapshot_to_rows(snapshot, CounterTracker())
        assert device["interfaces_up"] == 2 and device["interfaces_down"] == 1


def test_driver_registry():
    names = available_drivers()
    for expected in ("snmp", "restconf", "eapi", "nxapi", "ssh_cli", "none"):
        assert expected in names


def test_unknown_driver_is_rejected(tmp_path, quiet_logger):
    from flowlite.errors import ConfigError

    with pytest.raises(ConfigError, match="not one of"):
        load_config(overrides=["telemetry.driver=telepathy"], allow_missing=True, _skip_search=True)
    os.environ.pop("FLOWLITE_CONFIG", None)
