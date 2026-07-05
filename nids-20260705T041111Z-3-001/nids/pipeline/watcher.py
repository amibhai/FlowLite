import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty, Queue
from threading import Event
from typing import Dict, List, Optional

from pipeline.aggregator import HostProfileAggregator
from sasplite.extractor import FlowExtractor
from sasplite.geoip import GeoIPLookup


def _parse_hour_str(pcap_path: Path) -> str:
    # Try to derive YYYYMMDD_HHMM from filename or mtime
    try:
        # filename like HH_MM_to_HH_MM.pcap under .../DD_Mon_YY/Bucket/
        mtime = datetime.fromtimestamp(pcap_path.stat().st_mtime)
        return mtime.strftime("%Y%m%d_%H%M")
    except Exception:
        return datetime.now().strftime("%Y%m%d_%H%M")


def _log_summary(log, hour_str, status, n_flows, n_profiles, elapsed, error):
    if error:
        log.error(
            "Pipeline %s — %s — %s (%.1fs)", hour_str, status, error, elapsed
        )
    else:
        log.info(
            "Pipeline %s — %s — flows=%d profiles=%d (%.1fs)",
            hour_str, status, n_flows, n_profiles, elapsed,
        )


def _cleanup_old_files(cfg, log):
    try:
        keep_pcap  = cfg.retention.keep_pcaps_days
        keep_csv   = cfg.retention.keep_csvs_days
        now        = datetime.now()
        pcap_base  = Path(cfg.capture.base_dir)
        output_base = Path(cfg.paths.output_base)
        flows_dir  = Path(cfg.paths.flows_dir)

        # Delete old pcaps
        if pcap_base.exists():
            cutoff = now - timedelta(days=keep_pcap)
            for pcap in pcap_base.rglob("*.pcap"):
                try:
                    if datetime.fromtimestamp(pcap.stat().st_mtime) < cutoff:
                        pcap.unlink()
                        log.debug("Deleted old pcap: %s", pcap)
                except Exception:
                    pass

        # Delete old flow CSVs
        csv_cutoff = now - timedelta(days=keep_csv)
        for base in [flows_dir, output_base]:
            if base.exists():
                for csv in base.rglob("*.csv"):
                    try:
                        if datetime.fromtimestamp(csv.stat().st_mtime) < csv_cutoff:
                            csv.unlink()
                            log.debug("Deleted old CSV: %s", csv)
                    except Exception:
                        pass
    except Exception as e:
        log.warning("Cleanup error: %s", e)


def run(
    queue: Queue,
    cfg,
    stop_event: Event,
    log,
    geoip: GeoIPLookup,
    status_list: List[Dict],
):
    extractor  = FlowExtractor(cfg, geoip, log)
    aggregator = HostProfileAggregator(cfg, log)

    log.info("Watcher started")

    while not stop_event.is_set():
        try:
            path_str = queue.get(timeout=60)
        except Empty:
            continue

        pcap_path = Path(path_str)
        hour_str  = _parse_hour_str(pcap_path)
        out_dir   = Path(cfg.paths.output_base) / hour_str
        out_dir.mkdir(parents=True, exist_ok=True)

        t0        = time.monotonic()
        error_msg: Optional[str] = None
        n_flows = n_profiles = 0

        if not pcap_path.exists():
            log.error("Watcher: pcap not found: %s", pcap_path)
            error_msg = "file not found"
        elif pcap_path.stat().st_size == 0:
            log.error("Watcher: pcap is empty: %s", pcap_path)
            error_msg = "empty file"
        else:
            try:
                flows_df = extractor.extract(pcap_path)
                n_flows  = len(flows_df)

                flows_csv = Path(cfg.paths.flows_dir) / f"{hour_str}_flows.csv"
                flows_csv.parent.mkdir(parents=True, exist_ok=True)
                flows_df.to_csv(flows_csv, index=False)

                profiles_csv = out_dir / "host_profiles.csv"
                profiles_df  = aggregator.aggregate(flows_df, profiles_csv)
                n_profiles   = len(profiles_df)

                result = subprocess.run(
                    [
                        "python3", "-m", "collectors.build_network_ts",
                        "--flows",  str(flows_csv),
                        "--output", cfg.paths.network_ts,
                    ],
                    cwd=str(Path(__file__).parent.parent),
                    timeout=cfg.timeouts.build_ts_s,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    log.error(
                        "build_network_ts failed: %s", result.stderr[-500:]
                    )
                    error_msg = "build_network_ts failed"

            except Exception as e:
                log.error(
                    "Pipeline failed for %s: %s",
                    pcap_path.name, e, exc_info=True,
                )
                error_msg = str(e)

        elapsed = time.monotonic() - t0
        status  = "FAILED" if error_msg else "OK"

        status_list.append({
            "hour":       hour_str,
            "status":     status,
            "flows":      n_flows,
            "profiles":   n_profiles,
            "duration_s": elapsed,
            "error":      error_msg or "",
        })
        if len(status_list) > 24:
            status_list.pop(0)

        _log_summary(log, hour_str, status, n_flows, n_profiles, elapsed, error_msg)
        _cleanup_old_files(cfg, log)
