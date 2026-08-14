"""FlowLite command line interface.

Subcommands are organised so that an operator can always answer "why is this not
working?" without reading source: ``doctor`` checks the environment and the
device, ``selftest`` proves the pipeline works end to end on generated data, and
``process`` runs a single file through the exact production code path.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import CONFIG_SEARCH_PATH, Config, load_config
from .errors import ConfigError, FlowLiteError
from .logging_setup import get_logger, setup_logging

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_INTERRUPTED = 130


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _print_warnings(cfg: Config) -> None:
    for warning in cfg.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _load(args: argparse.Namespace, allow_missing: bool = True) -> Config:
    return load_config(
        path=getattr(args, "config", None),
        overrides=getattr(args, "set", None) or [],
        allow_missing=allow_missing,
        strict_unknown=getattr(args, "strict", False),
    )


def _optional_module(name: str) -> Optional[str]:
    try:
        module = __import__(name)
    except ImportError:
        return None
    return getattr(module, "__version__", "installed")


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def cmd_run(args: argparse.Namespace) -> int:
    from .capture import build_capture_source
    from .enrich.geoip import build_enricher
    from .flowproto.server import build_collectors
    from .pipeline import PipelineWorker
    from .runtime import ServiceState, Supervisor
    from .telemetry import TelemetryCollector, build_telemetry_driver
    from .ui.dashboard import Dashboard, supports_ansi

    cfg = _load(args)
    _print_warnings(cfg)

    dashboard_setting = cfg.runtime.dashboard
    if args.no_dashboard:
        dashboard_setting = "off"
    dashboard_on = dashboard_setting == "on" or (dashboard_setting == "auto" and supports_ansi())

    log = setup_logging(cfg, dashboard_active=dashboard_on, force=True)
    log.info("FlowLite %s starting (instance=%s)", __version__, cfg.instance)
    if cfg.source_path:
        log.info("Configuration: %s", cfg.source_path)
    else:
        log.warning("No configuration file was found; running on defaults")

    for directory in (
        cfg.paths.data_dir,
        cfg.paths.flows_dir,
        cfg.paths.profiles_dir,
        cfg.paths.state_dir,
        Path(cfg.paths.network_ts).parent,
        Path(cfg.paths.telemetry_csv).parent,
        Path(cfg.paths.sflow_csv).parent,
    ):
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"error: cannot create {directory}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    state = ServiceState(instance=cfg.instance, device=cfg.device.name or cfg.device.host)
    supervisor = Supervisor(cfg, log, state)
    enricher = build_enricher(cfg, log)

    started_components: List[str] = []

    capture_source = None
    if not args.no_capture:
        try:
            capture_source = build_capture_source(cfg, get_logger("capture"), state.capture)
        except FlowLiteError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
    if capture_source is not None:
        report = capture_source.preflight()
        if not report.ok:
            log.error("Capture preflight failed: %s", report.detail)
            for hint in report.hints:
                log.error("  hint: %s", hint)
            if not args.force:
                print(
                    "error: capture cannot start. Fix the problem above, or pass --force to "
                    "start anyway.",
                    file=sys.stderr,
                )
                return EXIT_CONFIG
        else:
            for hint in report.hints:
                log.info("capture: %s", hint)
        supervisor.add(
            "capture",
            lambda stop: capture_source.run(supervisor.queue, stop),
            critical=True,
        )
        started_components.append(f"capture[{capture_source.name}]")

    worker = PipelineWorker(cfg, get_logger("pipeline"), enricher, state.pipeline)
    supervisor.add("pipeline", lambda stop: worker.run(supervisor.queue, stop), critical=True)
    started_components.append("pipeline")

    if not args.no_telemetry:
        try:
            driver = build_telemetry_driver(cfg, get_logger("telemetry"))
        except FlowLiteError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        if driver is not None:
            collector = TelemetryCollector(cfg, driver, get_logger("telemetry"), state.telemetry)
            supervisor.add("telemetry", collector.run)
            started_components.append(f"telemetry[{driver.name}]")

    if not args.no_flowproto:
        for collector in build_collectors(cfg, get_logger("flowproto"), state.flowproto):
            try:
                collector.bind_socket()
            except OSError as exc:
                log.error("%s", exc)
                if not args.force:
                    print(f"error: {exc}", file=sys.stderr)
                    return EXIT_CONFIG
                continue
            supervisor.add(collector.name, collector.run, critical=False)
            started_components.append(f"{collector.name}:{collector.port}")

    log.info("Components: %s", ", ".join(started_components) or "none")

    if dashboard_on:
        dashboard = Dashboard(state, supervisor)
        supervisor.add("dashboard", dashboard.run, restart=False)

    try:
        code = supervisor.run()
    except KeyboardInterrupt:
        code = EXIT_INTERRUPTED
    finally:
        worker.close()
        enricher.close()

    log.info("FlowLite stopped")
    return code


# --------------------------------------------------------------------------- #
# process
# --------------------------------------------------------------------------- #


def cmd_process(args: argparse.Namespace) -> int:
    from .capture.base import CaptureArtifact
    from .enrich.geoip import build_enricher
    from .pipeline import PipelineWorker

    cfg = _load(args)
    _print_warnings(cfg)
    log = setup_logging(cfg, force=True)

    targets: List[Path] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_dir():
            for pattern in ("*.pcap", "*.pcapng", "*.pcap.gz", "*.pcapng.gz"):
                targets.extend(sorted(path.rglob(pattern)))
        elif path.exists():
            targets.append(path)
        else:
            print(f"error: no such file or directory: {path}", file=sys.stderr)
            return EXIT_ERROR
    if not targets:
        print("error: no capture files matched", file=sys.stderr)
        return EXIT_ERROR

    enricher = build_enricher(cfg, log)
    worker = PipelineWorker(cfg, log, enricher)
    failures = 0
    try:
        for path in targets:
            stat = path.stat()
            artifact = CaptureArtifact(
                path=path,
                source="cli",
                started_at=stat.st_mtime,
                ended_at=stat.st_mtime,
                size_bytes=stat.st_size,
                device=cfg.device.name or cfg.device.host,
            )
            result = worker.process(artifact)
            print(result.summary())
            if result.ok:
                print(f"  flows CSV: {result.flows_csv}")
            else:
                failures += 1
    finally:
        worker.close()
        enricher.close()

    if not failures:
        print(f"\nhost profiles: {Path(cfg.paths.profiles_dir) / 'host_profiles.csv'}")
        print(f"network series: {cfg.paths.network_ts}")
    return EXIT_ERROR if failures else EXIT_OK


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #


def cmd_doctor(args: argparse.Namespace) -> int:
    from .capture import build_capture_source, detect_capture_tool, list_local_interfaces
    from .telemetry import build_telemetry_driver

    problems = 0
    print(f"FlowLite {__version__}")
    print(f"Python  {sys.version.split()[0]} ({sys.executable})")
    print(f"Platform {sys.platform}")
    print()

    print("Optional dependencies")
    for package, purpose, extra in (
        ("yaml", "YAML configuration files", "yaml"),
        ("paramiko", "SSH capture and CLI telemetry with password auth", "ssh"),
        ("geoip2", "ASN and country enrichment", "geoip"),
        ("numpy", "faster statistics on very large captures", "speed"),
    ):
        version = _optional_module(package)
        if version:
            print(f"  [ok]  {package:<10} {version:<12} {purpose}")
        else:
            note = (
                "built-in fallback in use"
                if package in ("yaml", "numpy")
                else "feature unavailable"
            )
            print(
                f"  [--]  {package:<10} {'absent':<12} {purpose}"
                f"  ({note}; pip install 'flowlite[{extra}]')"
            )
    print()

    print("External tools")
    for tool in ("tcpdump", "dumpcap", "tshark", "ssh"):
        location = shutil.which(tool)
        print(f"  [{'ok' if location else '--'}]  {tool:<10} {location or 'not on PATH'}")
    print()

    try:
        cfg = _load(args)
    except ConfigError as exc:
        print("Configuration")
        print(f"  [!!]  {exc}")
        return EXIT_CONFIG

    print("Configuration")
    print(f"  source        {cfg.source_path or '(defaults; no file found)'}")
    if not cfg.source_path:
        print(f"  searched      {', '.join(CONFIG_SEARCH_PATH)}")
    print(f"  instance      {cfg.instance}")
    print(f"  device        {cfg.device.name or '(unset)'}  host={cfg.device.host or '(unset)'}")
    print(f"  capture       {cfg.capture.source}")
    print(f"  telemetry     {cfg.telemetry.driver if cfg.telemetry.enabled else 'disabled'}")
    flowproto = [
        name
        for name, enabled in (
            ("sflow", cfg.flowproto.sflow.enabled),
            ("netflow", cfg.flowproto.netflow.enabled),
        )
        if cfg.flowproto.enabled and enabled
    ]
    print(f"  flowproto     {', '.join(flowproto) or 'disabled'}")
    for warning in cfg.warnings:
        problems += 1
        print(f"  [!]  {warning}")
    print()

    print("Paths")
    for label in ("data_dir", "flows_dir", "profiles_dir", "logs_dir", "state_dir"):
        path = Path(getattr(cfg.paths, label))
        writable = False
        try:
            path.mkdir(parents=True, exist_ok=True)
            writable = os.access(str(path), os.W_OK)
        except OSError as exc:
            print(f"  [!!]  {label:<13} {path}  ({exc})")
            problems += 1
            continue
        print(f"  [{'ok' if writable else '!!'}]  {label:<13} {path}")
        if not writable:
            problems += 1
    free = shutil.disk_usage(str(Path(cfg.paths.data_dir))).free
    print(f"  free space    {free / 1_073_741_824:.1f} GB")
    if free < 1_073_741_824:
        print("  [!]  less than 1 GB free; capture files will fill this volume quickly")
        problems += 1
    print()

    if not args.offline:
        print("Capture driver")
        try:
            source = build_capture_source(cfg, get_logger("doctor"))
        except FlowLiteError as exc:
            print(f"  [!!]  {exc}")
            source = None
            problems += 1
        if source is not None:
            report = source.preflight()
            print(f"  {report.render()}")
            if not report.ok:
                problems += 1
        elif cfg.capture.source == "none":
            print("  capture is disabled (capture.source: none)")
        print()

        if cfg.capture.source == "local":
            tool = detect_capture_tool(cfg.capture.local.tool)
            interfaces = list_local_interfaces()
            print(f"  capture tool  {tool or 'none found'}")
            print(f"  interfaces    {', '.join(interfaces[:15]) or 'none detected'}")
            print()

        print("Telemetry driver")
        try:
            driver = build_telemetry_driver(cfg, get_logger("doctor"))
        except FlowLiteError as exc:
            print(f"  [!!]  {exc}")
            driver = None
            problems += 1
        if driver is None:
            print("  telemetry is disabled")
        else:
            report = driver.preflight()
            print(f"  {report.render()}")
            if not report.ok:
                problems += 1
            driver.close()
        print()

    if problems:
        print(f"{problems} issue(s) found. Address the [!] and [!!] lines above.")
        return EXIT_ERROR
    print("No problems found.")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #


def cmd_selftest(args: argparse.Namespace) -> int:
    from . import synth
    from .analytics.host_profiles import HostProfileAggregator
    from .analytics.network_ts import NetworkTimeSeriesBuilder
    from .capture.base import CaptureArtifact
    from .enrich.geoip import Enricher
    from .flowproto import NetFlowDecoder, TemplateCache, decode_sflow
    from .pipeline import PipelineWorker
    from .storage.csvsink import read_csv_rows

    workdir = (
        Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="flowlite-selftest-"))
    )
    keep = bool(args.workdir)
    print(f"FlowLite {__version__} self-test")
    print(f"Working directory: {workdir}")
    print()

    checks: List[tuple] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))
        print(f"  [{'ok' if ok else 'FAIL'}]  {name}" + (f"  -- {detail}" if detail else ""))

    try:
        cfg = load_config(
            overrides=[
                f"paths.data_dir={json.dumps(str(workdir / 'data'))}",
                "capture.source=folder",
            ],
            allow_missing=True,
            _skip_search=True,
        )
        log = setup_logging(cfg, force=True)
        log.setLevel(50)  # keep the self-test output clean

        packets = synth.synthetic_session()
        pcap = synth.write_pcap(workdir / "sample.pcap", packets)
        pcapng = synth.write_pcapng(workdir / "sample.pcapng", packets)
        check("generate synthetic capture", True, f"{len(packets)} packets")

        from .pcap import read_packets

        read_pcap, info_pcap = read_packets(pcap)
        read_ng, info_ng = read_packets(pcapng)
        check(
            "read pcap",
            len(read_pcap) == len(packets),
            f"{info_pcap.format}, {len(read_pcap)} packets",
        )
        check(
            "read pcapng", len(read_ng) == len(packets), f"{info_ng.format}, {len(read_ng)} packets"
        )

        enricher = Enricher()
        worker = PipelineWorker(cfg, log, enricher)
        stat = pcap.stat()
        result = worker.process(
            CaptureArtifact(
                path=pcap,
                source="selftest",
                started_at=stat.st_mtime,
                ended_at=stat.st_mtime,
                size_bytes=stat.st_size,
                device="selftest",
            )
        )
        worker.close()
        check("flow extraction", result.ok and result.flows > 0, result.summary())

        flow_rows = read_csv_rows(result.flows_csv)
        check("flows CSV readable", len(flow_rows) == result.flows, f"{len(flow_rows)} rows")

        tcp_rows = [r for r in flow_rows if r.get("protocol_name") == "TCP"]
        established = [r for r in tcp_rows if r.get("tcp_state") in ("closed", "established")]
        check(
            "TCP state tracking", bool(established), f"{len(established)}/{len(tcp_rows)} TCP flows"
        )
        v6 = [r for r in flow_rows if r.get("ip_version") == "6"]
        check("IPv6 decoding", bool(v6), f"{len(v6)} IPv6 flow(s)")

        profiles = read_csv_rows(Path(cfg.paths.profiles_dir) / "host_profiles.csv")
        check("host profiles", len(profiles) > 0, f"{len(profiles)} host-window rows")
        series = read_csv_rows(cfg.paths.network_ts)
        check("network time series", len(series) > 0, f"{len(series)} bucket rows")

        aggregator = HostProfileAggregator(window_minutes=10)
        aggregator.add_flows(flow_rows)
        builder = NetworkTimeSeriesBuilder(bucket_seconds=60)
        builder.add_flows(flow_rows)
        check("analytics re-run from CSV", bool(aggregator.rows()) and bool(builder.rows()))

        frame = synth.make_tcp_frame("10.0.0.1", "203.0.113.9", 1234, 443, b"x" * 100)
        sflow = decode_sflow(
            synth.sflow_datagram(sampled_frames=[frame], counters=[{"if_index": 1}])
        )
        check(
            "sFlow v5 decode",
            len(sflow.flow_samples) == 1 and len(sflow.counter_samples) == 1 and not sflow.errors,
        )
        expanded = decode_sflow(
            synth.sflow_datagram(sampled_frames=[frame], counters=[{"if_index": 1}], expanded=True)
        )
        check("sFlow expanded samples", len(expanded.flow_samples) == 1 and not expanded.errors)

        decoder = NetFlowDecoder(TemplateCache())
        v5 = decoder.decode(
            synth.netflow_v5_datagram([{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"}]), "127.0.0.1"
        )
        check("NetFlow v5 decode", len(v5) == 1)
        decoder.decode(synth.netflow_v9_datagram(records=[]), "127.0.0.1")
        v9 = decoder.decode(
            synth.netflow_v9_datagram(
                records=[{"src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "bytes": 42}],
                include_template=False,
            ),
            "127.0.0.1",
        )
        check("NetFlow v9 decode", len(v9) == 1 and v9[0]["bytes"] == 42)
        ipfix = decoder.decode(
            synth.ipfix_datagram(records=[{"src_ip": "10.0.0.3", "dst_ip": "9.9.9.9", "bytes": 7}]),
            "127.0.0.1",
        )
        check("IPFIX decode", len(ipfix) == 1 and ipfix[0]["bytes"] == 7)

        import os as _os

        for size in (0, 1, 7, 33, 200):
            decode_sflow(_os.urandom(size))
            decoder.decode(_os.urandom(size), "127.0.0.1")
        check("malformed datagrams handled without crashing", True)

        enricher.close()
    except Exception as exc:  # a self-test that raises has failed
        check("self-test completed", False, f"{type(exc).__name__}: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)

    passed = sum(1 for _n, ok, _d in checks if ok)
    print()
    print(f"{passed}/{len(checks)} checks passed")
    if passed != len(checks):
        print("Self-test FAILED. Please open an issue with this output.")
        return EXIT_ERROR
    print("Self-test PASSED. FlowLite works correctly on this machine.")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# init / config / decode / version
# --------------------------------------------------------------------------- #


_TEMPLATE_NAME = "flowlite.example.yaml"


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        print(f"error: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_ERROR

    template = _find_template(args.profile)
    if template is None:
        print(
            f"error: no packaged template found for profile {args.profile!r}. "
            f"Copy configs/{_TEMPLATE_NAME} from the repository instead.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {target}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Wrote {target} (from {template.name})")
    print()
    print("Next steps:")
    print(f"  1. Edit {target} -- set device.host and credentials")
    print("  2. flowlite doctor        # verify the environment and reach the device")
    print("  3. flowlite run           # start the pipeline")
    return EXIT_OK


def _find_template(profile: str) -> Optional[Path]:
    name = f"{profile}.yaml" if profile and profile != "default" else _TEMPLATE_NAME
    roots = [
        Path(__file__).resolve().parent.parent.parent / "configs",
        Path(__file__).resolve().parent / "configs",
        Path.cwd() / "configs",
    ]
    for root in roots:
        for candidate in (root / name, root / "profiles" / name):
            if candidate.exists():
                return candidate
    return None


def cmd_config(args: argparse.Namespace) -> int:
    try:
        cfg = _load(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    _print_warnings(cfg)
    if args.json:
        print(json.dumps(cfg.redacted(), indent=2, sort_keys=True, default=str))
    else:
        print(f"# source: {cfg.source_path or '(defaults)'}")
        _print_tree(cfg.redacted())
    return EXIT_OK


def _print_tree(node: Dict[str, Any], indent: int = 0) -> None:
    for key in sorted(node):
        value = node[key]
        pad = "  " * indent
        if isinstance(value, dict):
            print(f"{pad}{key}:")
            _print_tree(value, indent + 1)
        elif isinstance(value, list):
            print(f"{pad}{key}: {json.dumps(value, default=str)}")
        else:
            print(f"{pad}{key}: {value}")


def cmd_decode(args: argparse.Namespace) -> int:
    """Inspect a capture file without running the pipeline."""
    from .flow.table import FlowTable
    from .pcap.decode import LINKTYPE_NAMES, decode_packet
    from .pcap.reader import CaptureFile

    path = Path(args.path)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return EXIT_ERROR

    capture = CaptureFile(path)
    decoded = skipped = 0
    flows: List[Any] = []
    table = FlowTable(on_flow=flows.append, idle_timeout_s=1e9, active_timeout_s=1e9)
    shown = 0

    for ts, data, linktype in capture.packets():
        packet = decode_packet(ts, data, linktype)
        if packet is None:
            skipped += 1
            continue
        decoded += 1
        table.add_packet(packet)
        if args.packets and shown < args.packets:
            shown += 1
            print(
                f"  {ts:.6f}  {packet.src_ip}:{packet.src_port} -> "
                f"{packet.dst_ip}:{packet.dst_port}  {packet.proto_name}  "
                f"len={packet.frame_len} ttl={packet.ttl}"
            )
    table.flush()

    info = capture.info
    links = ", ".join(
        f"{LINKTYPE_NAMES.get(v, 'unknown')} ({v})" for v in dict.fromkeys(info.linktypes.values())
    )
    print()
    print(f"file          {path}")
    print(f"format        {info.format}")
    print(f"link type     {links or 'unknown'}")
    print(
        f"packets       {info.packets_read:,} read, {decoded:,} IP, "
        f"{skipped:,} non-IP or undecodable"
    )
    print(f"bytes         {info.bytes_read:,}")
    if info.first_ts and info.last_ts:
        print(f"time span     {info.duration_s:.3f}s")
    print(f"flows         {len(flows):,}")
    if info.truncated:
        print("warning       file is truncated; complete packets were still recovered")
    for warning in info.warnings:
        print(f"warning       {warning}")
    if decoded == 0 and info.packets_read:
        print()
        print("No IP packets were decoded. The capture may hold only non-IP traffic (ARP, LLDP,")
        print("STP), or use an encapsulation this decoder does not recognise.")
        return EXIT_ERROR
    return EXIT_OK


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"flowlite {__version__}")
    print(f"python   {sys.version.split()[0]}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flowlite",
        description="Vendor-neutral network flow telemetry pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  flowlite init                       create a configuration file\n"
            "  flowlite doctor                     check the environment and the device\n"
            "  flowlite selftest                   prove the pipeline works here\n"
            "  flowlite run                        start the live pipeline\n"
            "  flowlite process capture.pcap       analyse one file\n"
            "  flowlite decode capture.pcapng      inspect a capture file\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"flowlite {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", metavar="PATH", help="path to the configuration file")
    common.add_argument(
        "--set",
        action="append",
        metavar="KEY=VALUE",
        help="override a configuration key, e.g. --set telemetry.interval_s=30",
    )
    common.add_argument(
        "--strict", action="store_true", help="treat unknown configuration keys as errors"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", parents=[common], help="run the live pipeline")
    run.add_argument("--no-capture", action="store_true", help="do not start packet capture")
    run.add_argument("--no-telemetry", action="store_true", help="do not poll device telemetry")
    run.add_argument(
        "--no-flowproto", action="store_true", help="do not start sFlow/NetFlow collectors"
    )
    run.add_argument(
        "--no-dashboard", action="store_true", help="disable the live terminal dashboard"
    )
    run.add_argument("--force", action="store_true", help="start even if preflight checks fail")
    run.set_defaults(func=cmd_run)

    process = sub.add_parser(
        "process", parents=[common], help="analyse capture files that already exist"
    )
    process.add_argument("paths", nargs="+", help="capture files or directories")
    process.set_defaults(func=cmd_process)

    doctor = sub.add_parser(
        "doctor", parents=[common], help="diagnose environment and device problems"
    )
    doctor.add_argument(
        "--offline", action="store_true", help="skip checks that contact the device"
    )
    doctor.set_defaults(func=cmd_doctor)

    selftest = sub.add_parser("selftest", help="verify the whole pipeline on generated data")
    selftest.add_argument(
        "--workdir", help="keep artifacts in this directory instead of a temp one"
    )
    selftest.add_argument("-v", "--verbose", action="store_true", help="show tracebacks on failure")
    selftest.set_defaults(func=cmd_selftest)

    init = sub.add_parser("init", help="write a starter configuration file")
    init.add_argument("-o", "--output", default="flowlite.yaml", help="where to write it")
    init.add_argument(
        "--profile",
        default="default",
        help="device profile to start from (see configs/profiles/), e.g. arista-eos",
    )
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=cmd_init)

    config = sub.add_parser("config", parents=[common], help="show the effective configuration")
    config.add_argument("--json", action="store_true", help="emit JSON")
    config.set_defaults(func=cmd_config)

    decode = sub.add_parser("decode", help="inspect a capture file")
    decode.add_argument("path", help="capture file")
    decode.add_argument(
        "-p",
        "--packets",
        type=int,
        default=0,
        metavar="N",
        help="print the first N decoded packets",
    )
    decode.set_defaults(func=cmd_decode)

    version = sub.add_parser("version", help="print version information")
    version.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except FlowLiteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # `flowlite config | head`
        try:
            sys.stdout.close()
        except Exception:
            pass
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
