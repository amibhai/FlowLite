"""Capture drivers and the lossless stream splitter."""

from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path

import pytest

from flowlite import synth
from flowlite.capture import build_capture_command, build_capture_source
from flowlite.capture.base import CaptureArtifact
from flowlite.capture.splitter import header_bytes_needed, make_splitter
from flowlite.capture.streaming import StreamHandle, StreamingCaptureSource
from flowlite.config import load_config
from flowlite.errors import ParseError
from flowlite.pcap import read_packets


class TestSplitter:
    def test_pcap_rotation_is_lossless_and_each_file_is_valid(self, tmp_path, packets):
        """Rotation must not drop packets or produce headerless fragments."""
        source = synth.write_pcap(tmp_path / "src.pcap", packets)
        raw = source.read_bytes()
        completed = []
        splitter = make_splitter(raw[:24], lambda path, count: completed.append((path, count)))
        splitter.open_file(tmp_path / "out1.pcap")

        offset = splitter.head_bytes_consumed
        rotated = False
        while offset < len(raw):
            splitter.feed(raw[offset : offset + 997])
            offset += 997
            if not rotated and splitter.records_in_file > 100:
                splitter.close_file()
                splitter.open_file(tmp_path / "out2.pcap")
                rotated = True
        splitter.close_file()

        assert len(completed) == 2
        total = 0
        for path, count in completed:
            read, info = read_packets(path)
            assert len(read) == count
            assert not info.truncated
            total += count
        assert total == len(packets)

    def test_pcapng_rotation_repeats_section_and_interface_blocks(self, tmp_path, packets):
        source = synth.write_pcapng(tmp_path / "src.pcapng", packets)
        raw = source.read_bytes()
        completed = []
        splitter = make_splitter(raw[:12], lambda path, count: completed.append((path, count)))
        splitter.open_file(tmp_path / "out1.pcapng")

        offset = 0
        rotated = False
        while offset < len(raw):
            splitter.feed(raw[offset : offset + 1301])
            offset += 1301
            if not rotated and splitter.records_in_file > 150:
                splitter.close_file()
                splitter.open_file(tmp_path / "out2.pcapng")
                rotated = True
        splitter.close_file()

        total = 0
        for path, count in completed:
            read, info = read_packets(path)
            assert len(read) == count, f"{path} lost packets"
            assert info.format == "pcapng"
            total += count
        assert total == len(packets)

    def test_byte_at_a_time_feeding(self, tmp_path, packets):
        source = synth.write_pcap(tmp_path / "src.pcap", packets[:20])
        raw = source.read_bytes()
        splitter = make_splitter(raw[:24])
        splitter.open_file(tmp_path / "slow.pcap")
        for index in range(splitter.head_bytes_consumed, len(raw)):
            splitter.feed(raw[index : index + 1])
        splitter.close_file()
        read, _info = read_packets(tmp_path / "slow.pcap")
        assert len(read) == 20

    def test_a_device_error_message_is_rejected_with_its_own_text(self):
        with pytest.raises(ParseError, match="Invalid input"):
            make_splitter(b"% Invalid input detected at '^' marker.\r\n")

    def test_permission_error_text_is_surfaced(self):
        with pytest.raises(ParseError, match="Operation not permitted"):
            make_splitter(b"tcpdump: eth0: You don't have permission. Operation not permitted\n")

    def test_header_bytes_needed(self, tmp_path, packets):
        raw = synth.write_pcap(tmp_path / "s.pcap", packets[:2]).read_bytes()
        assert header_bytes_needed(b"") == 4
        assert header_bytes_needed(raw[:4]) == 20
        assert header_bytes_needed(raw[:24]) == 0

    def test_corrupt_stream_raises(self, tmp_path, packets):
        raw = synth.write_pcap(tmp_path / "s.pcap", packets[:2]).read_bytes()
        splitter = make_splitter(raw[:24])
        splitter.open_file(tmp_path / "out.pcap")
        with pytest.raises(ParseError, match="corrupt"):
            splitter.feed(b"\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff")
        splitter.close_file()


class TestCommandBuilding:
    def test_default_tcpdump(self):
        command = build_capture_command("tcpdump", "eth0")
        assert command.startswith("tcpdump -i eth0")
        assert "-w -" in command

    def test_filter_and_snaplen(self):
        command = build_capture_command("tcpdump", "eth0", bpf_filter="port 80", snaplen=128)
        assert "-s 128" in command and "port 80" in command

    def test_tshark_uses_capture_filter_flag(self):
        command = build_capture_command("tshark", "eth0", bpf_filter="tcp")
        assert "-f " in command

    def test_template_override_wins(self):
        command = build_capture_command(
            "tcpdump", "Ethernet49", template="bash -c 'tcpdump -i {interface} -w -'"
        )
        assert command == "bash -c 'tcpdump -i Ethernet49 -w -'"

    def test_sudo_prefix(self):
        assert build_capture_command("tcpdump", "eth0", sudo=True).startswith("sudo -n ")

    def test_interface_names_are_quoted(self):
        command = build_capture_command("tcpdump", "eth0; rm -rf /")
        assert "; rm -rf /" not in command.replace("'eth0; rm -rf /'", "")


class TestFolderSource:
    def _cfg(self, tmp_path, **extra):
        overrides = [
            f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
            "capture.source=folder",
            "capture.folder.stable_seconds=0",
            "capture.folder.poll_interval_s=1",
        ]
        overrides += [f"{k}={json.dumps(v)}" for k, v in extra.items()]
        return load_config(overrides=overrides, allow_missing=True, _skip_search=True)

    def _drain(self, source, output: queue.Queue, expected: int, timeout: float = 15.0):
        stop = threading.Event()
        thread = threading.Thread(target=source.run, args=(output, stop), daemon=True)
        thread.start()
        artifacts = []
        deadline = time.monotonic() + timeout
        try:
            while len(artifacts) < expected and time.monotonic() < deadline:
                try:
                    artifacts.append(output.get(timeout=1.0))
                except queue.Empty:
                    continue
        finally:
            stop.set()
            thread.join(timeout=5)
        return artifacts

    def test_picks_up_files(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path)
        source = build_capture_source(cfg, quiet_logger)
        watch = Path(cfg.capture.folder.watch_dir)
        synth.write_pcap(watch / "a.pcap", packets[:20])
        synth.write_pcapng(watch / "b.pcapng", packets[:10])

        artifacts = self._drain(source, queue.Queue(maxsize=8), expected=2)
        assert {a.path.name for a in artifacts} == {"a.pcap", "b.pcapng"}
        assert all(a.size_bytes > 0 for a in artifacts)

    def test_preflight_creates_the_directory(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path)
        report = build_capture_source(cfg, quiet_logger).preflight()
        assert report.ok
        assert Path(cfg.capture.folder.watch_dir).is_dir()

    def test_a_file_is_not_taken_twice(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path)
        watch = Path(cfg.capture.folder.watch_dir)
        watch.mkdir(parents=True, exist_ok=True)
        synth.write_pcap(watch / "a.pcap", packets[:5])

        first = self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1)
        assert len(first) == 1
        # A fresh source with the same checkpoint must not reprocess it.
        second = self._drain(
            build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1, timeout=4.0
        )
        assert second == []

    def test_replaced_content_is_processed_again(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path)
        watch = Path(cfg.capture.folder.watch_dir)
        watch.mkdir(parents=True, exist_ok=True)
        target = watch / "a.pcap"
        synth.write_pcap(target, packets[:5])
        assert (
            len(self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1))
            == 1
        )

        time.sleep(1.1)
        synth.write_pcap(target, packets[:40])  # same name, new content
        again = self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1)
        assert len(again) == 1

    def test_unstable_files_are_left_alone(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path, **{"capture.folder.stable_seconds": 30})
        watch = Path(cfg.capture.folder.watch_dir)
        watch.mkdir(parents=True, exist_ok=True)
        synth.write_pcap(watch / "growing.pcap", packets[:5])
        assert (
            self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1, 4.0)
            == []
        )

    def test_temporary_and_hidden_files_are_ignored(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path)
        watch = Path(cfg.capture.folder.watch_dir)
        watch.mkdir(parents=True, exist_ok=True)
        synth.write_pcap(watch / "a.pcap.tmp", packets[:5])
        synth.write_pcap(watch / ".hidden.pcap", packets[:5])
        synth.write_pcap(watch / "real.pcap", packets[:5])
        artifacts = self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1)
        assert [a.path.name for a in artifacts] == ["real.pcap"]

    def test_reprocess_existing_false_adopts_current_files(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path, **{"capture.folder.reprocess_existing": False})
        watch = Path(cfg.capture.folder.watch_dir)
        watch.mkdir(parents=True, exist_ok=True)
        synth.write_pcap(watch / "old.pcap", packets[:5])
        assert (
            self._drain(build_capture_source(cfg, quiet_logger), queue.Queue(maxsize=8), 1, 4.0)
            == []
        )


class TestStreamingSource:
    """The rotation engine, driven by an in-memory stream instead of a device."""

    class _FakeStreamSource(StreamingCaptureSource):
        name = "fake"

        def __init__(self, cfg, logger, payload: bytes, status=None) -> None:
            super().__init__(cfg, logger, status)
            self.payload = payload
            self.opened = 0

        def open_stream(self) -> StreamHandle:
            self.opened += 1
            state = {"offset": 0}

            def read(size: int) -> bytes:
                start = state["offset"]
                chunk = self.payload[start : start + 512]
                state["offset"] += len(chunk)
                return chunk

            return StreamHandle(read, lambda: None, lambda: "", lambda: 0, "fake stream")

    def test_stream_is_split_into_valid_files(self, tmp_path, quiet_logger, packets):
        payload = synth.write_pcap(tmp_path / "src.pcap", packets).read_bytes()
        cfg = load_config(
            overrides=[
                f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
                "capture.rotate_seconds=10",
                "capture.max_file_mb=1",
            ],
            allow_missing=True,
            _skip_search=True,
        )
        source = self._FakeStreamSource(cfg, quiet_logger, payload)
        output: queue.Queue[CaptureArtifact] = queue.Queue(maxsize=32)
        stop = threading.Event()

        produced = source._capture_once(output, stop)
        assert produced >= 1
        total = 0
        while not output.empty():
            artifact = output.get()
            read, info = read_packets(artifact.path)
            assert not info.truncated
            total += len(read)
        assert total == len(packets)

    def test_a_stream_that_is_not_a_capture_is_rejected(self, tmp_path, quiet_logger):
        cfg = load_config(
            overrides=[f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}"],
            allow_missing=True,
            _skip_search=True,
        )
        source = self._FakeStreamSource(cfg, quiet_logger, b"Permission denied\n" * 10)
        with pytest.raises(ParseError):
            source._capture_once(queue.Queue(maxsize=4), threading.Event())

    def test_empty_rotations_are_discarded(self, tmp_path, quiet_logger, packets):
        """A rotation with no packets should not create a pipeline run."""
        payload = synth.write_pcap(tmp_path / "src.pcap", packets[:1]).read_bytes()
        cfg = load_config(
            overrides=[f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}"],
            allow_missing=True,
            _skip_search=True,
        )
        source = self._FakeStreamSource(cfg, quiet_logger, payload[:24])  # header only
        output: queue.Queue[CaptureArtifact] = queue.Queue(maxsize=4)
        assert source._capture_once(output, threading.Event()) == 0
        assert output.empty()


def test_capture_registry(tmp_path, quiet_logger):
    from flowlite.capture import available_drivers

    assert set(available_drivers()) == {"folder", "ssh", "local", "none"}
    cfg = load_config(overrides=["capture.source=none"], allow_missing=True, _skip_search=True)
    assert build_capture_source(cfg, quiet_logger) is None
