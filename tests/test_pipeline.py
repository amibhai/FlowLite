"""The analysis stage, retention, the supervisor and the CLI."""

from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path

import pytest

from flowlite import synth
from flowlite.analytics.host_profiles import HOST_PROFILE_FIELDS
from flowlite.analytics.network_ts import NETWORK_TS_FIELDS
from flowlite.capture.base import CaptureArtifact
from flowlite.cli import main
from flowlite.config import load_config
from flowlite.flow.schema import FLOW_FIELDS
from flowlite.pipeline import PipelineWorker, apply_retention
from flowlite.runtime import ServiceState, Supervisor
from flowlite.storage import CsvSink, read_csv_rows


def artifact_for(path: Path, device: str = "test-device") -> CaptureArtifact:
    stat = path.stat()
    return CaptureArtifact(
        path=path,
        source="test",
        started_at=stat.st_mtime,
        ended_at=stat.st_mtime,
        size_bytes=stat.st_size,
        device=device,
    )


class TestPipelineWorker:
    def test_produces_all_three_outputs(self, cfg, quiet_logger, sample_pcap):
        worker = PipelineWorker(cfg, quiet_logger)
        result = worker.process(artifact_for(sample_pcap))
        worker.close()

        assert result.ok, result.error
        assert result.flows > 0
        flows = read_csv_rows(result.flows_csv)
        assert len(flows) == result.flows
        assert set(flows[0]) == set(FLOW_FIELDS)

        profiles = read_csv_rows(Path(cfg.paths.profiles_dir) / "host_profiles.csv")
        assert profiles and set(profiles[0]) == set(HOST_PROFILE_FIELDS)

        series = read_csv_rows(cfg.paths.network_ts)
        assert series and set(series[0]) == set(NETWORK_TS_FIELDS)

    def test_pcap_and_pcapng_give_identical_flow_counts(
        self, cfg, quiet_logger, sample_pcap, sample_pcapng
    ):
        worker = PipelineWorker(cfg, quiet_logger)
        first = worker.process(artifact_for(sample_pcap))
        second = worker.process(artifact_for(sample_pcapng))
        worker.close()
        assert first.flows == second.flows > 0

    def test_repeated_runs_append_without_corrupting(self, cfg, quiet_logger, sample_pcap):
        worker = PipelineWorker(cfg, quiet_logger)
        for _ in range(3):
            assert worker.process(artifact_for(sample_pcap)).ok
        worker.close()

        series = Path(cfg.paths.network_ts)
        assert series.exists()
        text = series.read_text(encoding="utf-8")
        assert text.count("timestamp,epoch") == 1
        rows = read_csv_rows(series)
        assert len(rows) == 3 * 1  # one bucket per run for this sample
        assert all(set(row) == set(NETWORK_TS_FIELDS) for row in rows)

    def test_missing_file_fails_cleanly(self, cfg, quiet_logger, tmp_path):
        worker = PipelineWorker(cfg, quiet_logger)
        artifact = CaptureArtifact(path=tmp_path / "gone.pcap", source="test")
        result = worker.process(artifact)
        worker.close()
        assert not result.ok and "disappeared" in result.error

    def test_empty_file_fails_cleanly(self, cfg, quiet_logger, tmp_path):
        empty = tmp_path / "empty.pcap"
        empty.touch()
        worker = PipelineWorker(cfg, quiet_logger)
        result = worker.process(artifact_for(empty))
        worker.close()
        assert not result.ok and "empty" in result.error

    def test_garbage_file_fails_cleanly(self, cfg, quiet_logger, tmp_path):
        junk = tmp_path / "junk.pcap"
        junk.write_bytes(b"definitely not a capture file")
        worker = PipelineWorker(cfg, quiet_logger)
        result = worker.process(artifact_for(junk))
        worker.close()
        assert not result.ok
        assert worker.failed == 1

    def test_one_failure_does_not_stop_the_next_file(
        self, cfg, quiet_logger, tmp_path, sample_pcap
    ):
        junk = tmp_path / "junk.pcap"
        junk.write_bytes(b"nope")
        worker = PipelineWorker(cfg, quiet_logger)
        assert not worker.process(artifact_for(junk)).ok
        assert worker.process(artifact_for(sample_pcap)).ok
        worker.close()

    def test_delete_after_processing(self, cfg, quiet_logger, sample_pcap):
        artifact = artifact_for(sample_pcap)
        artifact.delete_after = True
        worker = PipelineWorker(cfg, quiet_logger)
        worker.process(artifact)
        worker.close()
        assert not sample_pcap.exists()

    def test_telemetry_is_joined_onto_the_time_series(self, cfg, quiet_logger, tmp_path):
        from flowlite.telemetry.base import DEVICE_TELEMETRY_FIELDS

        base = 1_700_000_000.0
        pcap = synth.write_pcap(
            tmp_path / "joined.pcap",
            [
                (base + i * 0.5, synth.make_tcp_frame("10.0.0.1", "8.8.8.8", 1000 + i, 443))
                for i in range(20)
            ],
        )
        with CsvSink(Path(cfg.paths.telemetry_csv), DEVICE_TELEMETRY_FIELDS) as sink:
            sink.write_row(
                {
                    "timestamp": "2023-11-14T22:13:25Z",
                    "epoch": base + 5,
                    "device": "test-device",
                    "reachable": 1,
                    "in_bytes_per_s": 5000,
                    "interfaces_total": 24,
                }
            )
        worker = PipelineWorker(cfg, quiet_logger)
        assert worker.process(artifact_for(pcap)).ok
        worker.close()

        rows = read_csv_rows(cfg.paths.network_ts)
        joined = [r for r in rows if r["telemetry_samples"] not in ("", "0")]
        assert joined, "telemetry was not joined onto the flow time spine"
        assert float(joined[0]["iface_in_bytes_per_s"]) == 5000.0

    def test_run_loop_consumes_a_queue(self, cfg, quiet_logger, sample_pcap):
        worker = PipelineWorker(cfg, quiet_logger)
        work: queue.Queue[CaptureArtifact] = queue.Queue()
        work.put(artifact_for(sample_pcap))
        stop = threading.Event()
        thread = threading.Thread(target=worker.run, args=(work, stop), daemon=True)
        thread.start()
        work.join()
        stop.set()
        thread.join(timeout=10)
        assert worker.processed == 1


class TestRetention:
    def _cfg(self, tmp_path, **extra):
        overrides = [f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}"]
        overrides += [f"{k}={json.dumps(v)}" for k, v in extra.items()]
        return load_config(overrides=overrides, allow_missing=True, _skip_search=True)

    def test_old_files_are_deleted_and_new_ones_kept(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path, **{"retention.pcap_days": 1})
        pcap_dir = Path(cfg.paths.pcap_dir)
        old = synth.write_pcap(pcap_dir / "old.pcap", packets[:5])
        new = synth.write_pcap(pcap_dir / "new.pcap", packets[:5])
        ancient = time.time() - 10 * 86400
        import os

        os.utime(old, (ancient, ancient))

        stats = apply_retention(cfg, quiet_logger)
        assert stats["pcaps_deleted"] == 1
        assert not old.exists() and new.exists()

    def test_protected_files_are_never_deleted(self, tmp_path, quiet_logger):
        """network_ts.csv used to be deleted despite the docs promising otherwise."""
        cfg = self._cfg(tmp_path, **{"retention.csv_days": 1})
        series = Path(cfg.paths.network_ts)
        series.parent.mkdir(parents=True, exist_ok=True)
        series.write_text("timestamp\n1\n", encoding="utf-8")
        flows = Path(cfg.paths.flows_dir) / "old_flows.csv"
        flows.parent.mkdir(parents=True, exist_ok=True)
        flows.write_text("a\n1\n", encoding="utf-8")

        import os

        ancient = time.time() - 100 * 86400
        os.utime(series, (ancient, ancient))
        os.utime(flows, (ancient, ancient))

        apply_retention(cfg, quiet_logger)
        assert series.exists(), "network_ts.csv must never be deleted by retention"
        assert not flows.exists()

    def test_empty_paths_do_not_sweep_the_working_directory(
        self, tmp_path, quiet_logger, monkeypatch
    ):
        """The old cleanup rglob'd the CWD for *.pcap when a path was empty."""
        monkeypatch.chdir(tmp_path)
        decoy = tmp_path / "precious.pcap"
        decoy.write_bytes(b"do not delete me")
        import os

        ancient = time.time() - 999 * 86400
        os.utime(decoy, (ancient, ancient))

        cfg = self._cfg(tmp_path, **{"retention.pcap_days": 1})
        object.__setattr__(cfg.paths, "_data", dict(cfg.paths._data, pcap_dir=""))
        apply_retention(cfg, quiet_logger)
        assert decoy.exists()

    def test_disabled_retention_deletes_nothing(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(tmp_path, **{"retention.enabled": False, "retention.pcap_days": 1})
        old = synth.write_pcap(Path(cfg.paths.pcap_dir) / "old.pcap", packets[:5])
        import os

        ancient = time.time() - 999 * 86400
        os.utime(old, (ancient, ancient))
        assert apply_retention(cfg, quiet_logger)["pcaps_deleted"] == 0
        assert old.exists()

    def test_size_cap_removes_the_oldest_captures(self, tmp_path, quiet_logger, packets):
        cfg = self._cfg(
            tmp_path, **{"retention.max_data_dir_gb": 0.0000001, "retention.pcap_days": 0}
        )
        pcap_dir = Path(cfg.paths.pcap_dir)
        for index in range(4):
            path = synth.write_pcap(pcap_dir / f"c{index}.pcap", packets)
            import os

            os.utime(path, (time.time() - (10 - index) * 3600,) * 2)
        apply_retention(cfg, quiet_logger)
        assert len(list(pcap_dir.glob("*.pcap"))) < 4


class TestSupervisor:
    def _cfg(self, tmp_path, **extra):
        overrides = [f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}"]
        overrides += [f"{k}={json.dumps(v)}" for k, v in extra.items()]
        return load_config(overrides=overrides, allow_missing=True, _skip_search=True)

    def test_a_crashed_worker_is_restarted(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path, **{"runtime.restart_backoff_s": [1, 1]})
        supervisor = Supervisor(cfg, quiet_logger, ServiceState())
        attempts = []

        def flaky(stop: threading.Event) -> None:
            attempts.append(1)
            if len(attempts) < 3:
                raise RuntimeError("boom")
            stop.wait(timeout=30)

        supervisor.add("flaky", flaky)
        thread = threading.Thread(target=supervisor.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 20
        while len(attempts) < 3 and time.monotonic() < deadline:
            time.sleep(0.2)
        supervisor.request_stop()
        thread.join(timeout=10)
        assert len(attempts) >= 3

    def test_a_fatal_error_is_not_retried(self, tmp_path, quiet_logger):
        from flowlite.errors import ConfigError

        cfg = self._cfg(tmp_path, **{"runtime.restart_backoff_s": [1]})
        supervisor = Supervisor(cfg, quiet_logger, ServiceState())
        attempts = []

        def broken(_stop: threading.Event) -> None:
            attempts.append(1)
            raise ConfigError("this will never work")

        supervisor.add("broken", broken, critical=False)
        thread = threading.Thread(target=supervisor.run, daemon=True)
        thread.start()
        time.sleep(4)
        supervisor.request_stop()
        thread.join(timeout=10)
        assert len(attempts) == 1

    def test_health_file_is_written(self, tmp_path, quiet_logger):
        health = tmp_path / "health.json"
        cfg = self._cfg(tmp_path, **{"runtime.health_file": str(health)})
        supervisor = Supervisor(cfg, quiet_logger, ServiceState(instance="probe"))
        supervisor.add("idle", lambda stop: stop.wait(timeout=30))
        thread = threading.Thread(target=supervisor.run, daemon=True)
        thread.start()
        time.sleep(1.0)
        supervisor.write_health()
        supervisor.request_stop()
        thread.join(timeout=10)

        payload = json.loads(health.read_text(encoding="utf-8"))
        assert payload["instance"] == "probe"
        assert payload["status"] in ("ok", "stopped", "stopping")
        assert "idle" in payload["threads"]

    def test_pid_file_blocks_a_second_instance(self, tmp_path, quiet_logger):
        import os

        from flowlite.errors import FlowLiteError

        pid_file = tmp_path / "flowlite.pid"
        pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, **{"runtime.pid_file": str(pid_file)})
        supervisor = Supervisor(cfg, quiet_logger, ServiceState())
        # The stored PID is this live process, standing in for another instance.
        object.__setattr__(supervisor, "pid_path", pid_file)
        import flowlite.runtime as runtime_module

        original = runtime_module.os.getpid
        runtime_module.os.getpid = lambda: original() + 1
        try:
            with pytest.raises(FlowLiteError, match="already running|appears to be running"):
                supervisor.write_pid_file()
        finally:
            runtime_module.os.getpid = original

    def test_shutdown_is_orderly(self, tmp_path, quiet_logger):
        cfg = self._cfg(tmp_path)
        supervisor = Supervisor(cfg, quiet_logger, ServiceState())
        finished = []

        def worker(stop: threading.Event) -> None:
            stop.wait(timeout=30)
            finished.append(1)

        for name in ("a", "b", "c"):
            supervisor.add(name, worker)
        thread = threading.Thread(target=supervisor.run, daemon=True)
        thread.start()
        time.sleep(0.5)
        supervisor.request_stop()
        thread.join(timeout=15)
        assert len(finished) == 3


class TestCli:
    def test_version(self, capsys):
        assert main(["version"]) == 0
        assert "flowlite" in capsys.readouterr().out

    def test_selftest_passes(self, capsys):
        assert main(["selftest"]) == 0
        assert "Self-test PASSED" in capsys.readouterr().out

    def test_process_writes_outputs(self, tmp_path, sample_pcap, capsys):
        code = main(
            [
                "process",
                str(sample_pcap),
                "--set",
                f"paths.data_dir={json.dumps(str(tmp_path / 'out'))}",
            ]
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "flows" in output
        assert (tmp_path / "out" / "host_profiles" / "host_profiles.csv").exists()
        assert (tmp_path / "out" / "network_ts.csv").exists()

    def test_process_a_whole_directory(self, tmp_path, packets, capsys):
        incoming = tmp_path / "in"
        synth.write_pcap(incoming / "a.pcap", packets[:20])
        synth.write_pcapng(incoming / "b.pcapng", packets[:20])
        code = main(
            [
                "process",
                str(incoming),
                "--set",
                f"paths.data_dir={json.dumps(str(tmp_path / 'out'))}",
            ]
        )
        assert code == 0
        assert capsys.readouterr().out.count("flows") >= 2

    def test_process_a_missing_path_fails(self, tmp_path, capsys):
        assert main(["process", str(tmp_path / "absent.pcap")]) == 1
        assert "no such file" in capsys.readouterr().err

    def test_decode(self, sample_pcap, capsys):
        assert main(["decode", str(sample_pcap), "-p", "2"]) == 0
        output = capsys.readouterr().out
        assert "Ethernet" in output and "flows" in output

    def test_decode_a_non_capture(self, tmp_path, capsys):
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"nope")
        assert main(["decode", str(junk)]) == 1
        assert "not a pcap" in capsys.readouterr().err

    def test_config_output_hides_secrets(self, tmp_path, capsys):
        path = tmp_path / "c.yaml"
        path.write_text("credentials:\n  password: hunter2\n", encoding="utf-8")
        assert main(["config", "-c", str(path), "--json"]) == 0
        output = capsys.readouterr().out
        assert "hunter2" not in output and "redacted" in output

    def test_config_rejects_a_bad_file(self, tmp_path, capsys):
        path = tmp_path / "bad.yaml"
        path.write_text("capture:\n  source: nonsense\n", encoding="utf-8")
        assert main(["config", "-c", str(path)]) == 2
        assert "nonsense" in capsys.readouterr().err

    def test_init_writes_a_loadable_config(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "flowlite.yaml"
        assert main(["init", "-o", str(target)]) == 0
        assert target.exists()
        assert load_config(str(target)).capture.source == "folder"
        assert main(["init", "-o", str(target)]) == 1  # refuses to overwrite
        assert main(["init", "-o", str(target), "--force"]) == 0

    def test_init_from_a_profile(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FLOWLITE_SNMP", "public")
        target = tmp_path / "snmp.yaml"
        assert main(["init", "--profile", "generic-snmp", "-o", str(target)]) == 0
        assert load_config(str(target)).telemetry.driver == "snmp"

    def test_doctor_offline(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FLOWLITE_CONFIG", raising=False)
        code = main(["doctor", "--offline", "--set", f"paths.data_dir={json.dumps(str(tmp_path))}"])
        output = capsys.readouterr().out
        assert "FlowLite" in output and "Optional dependencies" in output
        assert code in (0, 1)

    def test_run_rejects_an_invalid_config(self, tmp_path, capsys):
        path = tmp_path / "bad.yaml"
        path.write_text("capture:\n  source: ssh\n", encoding="utf-8")
        assert main(["run", "-c", str(path)]) == 2


def test_end_to_end_folder_capture_to_csv(tmp_path, packets):
    """Drop a file in the watch directory; get three CSVs out. No device needed."""
    from flowlite.capture import build_capture_source
    from flowlite.logging_setup import get_logger

    cfg = load_config(
        overrides=[
            f"paths.data_dir={json.dumps(str(tmp_path / 'data'))}",
            "capture.source=folder",
            "capture.folder.stable_seconds=0",
            "capture.folder.poll_interval_s=1",
            "device.name=e2e",
        ],
        allow_missing=True,
        _skip_search=True,
    )
    log = get_logger("e2e")
    log.handlers = []
    log.propagate = False

    work: queue.Queue[CaptureArtifact] = queue.Queue(maxsize=8)
    stop = threading.Event()
    source = build_capture_source(cfg, log)
    worker = PipelineWorker(cfg, log)

    threads = [
        threading.Thread(target=source.run, args=(work, stop), daemon=True),
        threading.Thread(target=worker.run, args=(work, stop), daemon=True),
    ]
    for thread in threads:
        thread.start()

    synth.write_pcap(Path(cfg.capture.folder.watch_dir) / "drop.pcap", packets)

    deadline = time.monotonic() + 30
    while worker.processed == 0 and time.monotonic() < deadline:
        time.sleep(0.2)
    stop.set()
    for thread in threads:
        thread.join(timeout=10)
    worker.close()

    assert worker.processed == 1 and worker.failed == 0
    flow_files = list(Path(cfg.paths.flows_dir).glob("*_flows.csv"))
    assert len(flow_files) == 1
    assert len(read_csv_rows(flow_files[0])) > 0
    assert read_csv_rows(Path(cfg.paths.profiles_dir) / "host_profiles.csv")
    assert read_csv_rows(cfg.paths.network_ts)
