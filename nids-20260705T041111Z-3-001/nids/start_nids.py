import argparse
import queue
import signal
import sys
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="NIDS Pipeline")
    parser.add_argument("--config",     default=None,
                        help="Path to config.yaml")
    parser.add_argument("--no-capture", action="store_true",
                        help="Skip SSH tcpdump capture")
    parser.add_argument("--no-eapi",    action="store_true",
                        help="Skip eAPI polling")
    parser.add_argument("--no-sflow",   action="store_true",
                        help="Skip sFlow listener")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Print what would start, then exit")
    args = parser.parse_args()

    # ── Config ──────────────────────────────────────────────────────
    from utils.config_loader import load_config, ConfigError
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print(f"Config error: {e}")
        print("Edit config.yaml and fill in switch.host, switch.user, switch.pass")
        sys.exit(1)

    # ── Logging ─────────────────────────────────────────────────────
    from utils.logger import get_logger
    log = get_logger("nids", cfg)

    # ── Output directories ──────────────────────────────────────────
    for attr in ["output_base", "flows_dir", "profiles_dir", "logs"]:
        Path(getattr(cfg.paths, attr)).mkdir(parents=True, exist_ok=True)
    Path(cfg.paths.network_ts).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.paths.eapi_out).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.paths.sflow_out).parent.mkdir(parents=True, exist_ok=True)

    # ── Dry run ─────────────────────────────────────────────────────
    if args.dry_run:
        print("DRY RUN — would start:")
        if not args.no_capture and cfg.daemons.capture:
            print(
                f"  Capture:  SSH to {cfg.switch.host}:{cfg.switch.ssh_port}"
                f"  iface={cfg.switch.interface}"
            )
        if not args.no_eapi and cfg.daemons.eapi:
            print(
                f"  eAPI:     polling {cfg.switch.host}"
                f" every {cfg.eapi.poll_interval_s}s"
            )
        if not args.no_sflow and cfg.daemons.sflow:
            print(f"  sFlow:    listening UDP port {cfg.sflow.listen_port}")
        print(f"  Watcher:  processing pcaps → {cfg.paths.output_base}")
        sys.exit(0)

    # ── Shared state ────────────────────────────────────────────────
    pcap_queue   = queue.Queue()
    stop_event   = threading.Event()
    status_list  = []

    shared_status = {
        "start_time":   time.time(),
        "capture":      {"running": False, "cycle": 0,
                         "current_file": "", "mb": 0.0},
        "eapi":         {"running": False, "last_poll": "never"},
        "sflow":        {"running": False, "last_pkt":  "never"},
        "watcher":      {"running": False, "queue_depth": 0,
                         "last_run": "never"},
        "recent_hours": status_list,
        "config":       cfg,
    }

    # ── GeoIP ───────────────────────────────────────────────────────
    from sasplite.geoip import GeoIPLookup
    geoip = GeoIPLookup(cfg.sasplite.geoip_asn_db, cfg.sasplite.geoip_city_db)

    threads = []

    # ── Capture thread ──────────────────────────────────────────────
    if not args.no_capture and cfg.daemons.capture:
        from capture.streamer import run as run_capture
        t = threading.Thread(
            target=run_capture,
            args=(pcap_queue, cfg, stop_event, log),
            name="capture",
            daemon=False,
        )
        threads.append(t)

    # ── Watcher thread ──────────────────────────────────────────────
    from pipeline.watcher import run as run_watcher
    wt = threading.Thread(
        target=run_watcher,
        args=(pcap_queue, cfg, stop_event, log, geoip, status_list),
        name="watcher",
        daemon=False,
    )
    threads.append(wt)

    # ── eAPI thread ─────────────────────────────────────────────────
    if not args.no_eapi and cfg.daemons.eapi:
        from collectors.poll_eapi import run as run_eapi
        et = threading.Thread(
            target=run_eapi,
            args=(cfg, stop_event, log, shared_status["eapi"]),
            name="eapi",
            daemon=True,
        )
        threads.append(et)

    # ── sFlow thread ─────────────────────────────────────────────────
    if not args.no_sflow and cfg.daemons.sflow:
        from collectors.sflow_listener import run as run_sflow
        st = threading.Thread(
            target=run_sflow,
            args=(cfg, stop_event, log, shared_status["sflow"]),
            name="sflow",
            daemon=True,
        )
        threads.append(st)

    # ── Dashboard thread ────────────────────────────────────────────
    from pipeline.dashboard import run as run_dashboard
    dt = threading.Thread(
        target=run_dashboard,
        args=(shared_status, stop_event, log),
        name="dashboard",
        daemon=True,
    )
    threads.append(dt)

    # ── Graceful shutdown ────────────────────────────────────────────
    def shutdown(signum, frame):
        print("\nStopping — waiting for current operations to finish...")
        log.info("Shutdown signal received (signal %d)", signum)
        stop_event.set()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start ───────────────────────────────────────────────────────
    log.info("NIDS Pipeline starting — %d threads", len(threads))
    for t in threads:
        t.start()
        log.info("Started thread: %s", t.name)

    # Wait for non-daemon threads (capture + watcher)
    for t in threads:
        if not t.daemon:
            t.join()

    geoip.close()
    log.info("NIDS Pipeline stopped cleanly")
    print("Stopped.")


if __name__ == "__main__":
    main()
