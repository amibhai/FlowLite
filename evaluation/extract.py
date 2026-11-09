"""Run FlowLite v2 over one capture with the shipped defaults and record cost.

Usage: python extract.py <pcap> <out_prefix> [--max-flows N] [--no-csv]

Writes <out_prefix>.csv (all 95 flows.csv columns) and <out_prefix>.json with
packet/flow counts, wall/CPU time and peak working set. Run one capture per
process so the peak-memory reading belongs to that capture alone.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import argparse
import csv
import json
import os
import platform
import sys
import time

import psutil

sys.path.insert(0, paths.FLOWLITE_SRC)

from flowlite import __version__ as FL_VERSION  # noqa: E402
from flowlite.enrich.geoip import Enricher  # noqa: E402
from flowlite.flow.schema import FLOW_FIELDS, flow_record_to_row  # noqa: E402
from flowlite.flow.table import PcapFlowExtractor  # noqa: E402

# Shipped defaults from src/flowlite/config.py (analytics.flow.*).
DEFAULTS = dict(
    active_timeout_s=300.0,
    idle_timeout_s=60.0,
    burst_gap_s=1.0,
    max_flows=250_000,
    min_packets=1,
    max_packets_per_flow=20_000,
    teardown_grace_s=5.0,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("out_prefix")
    ap.add_argument("--max-flows", type=int, default=DEFAULTS["max_flows"])
    ap.add_argument("--no-csv", action="store_true")
    ap.add_argument("--max-packets-per-flow", type=int, default=DEFAULTS["max_packets_per_flow"])
    ap.add_argument("--teardown-grace", type=float, default=DEFAULTS["teardown_grace_s"])
    args = ap.parse_args()

    params = dict(DEFAULTS)
    params["max_flows"] = args.max_flows
    params["max_packets_per_flow"] = args.max_packets_per_flow
    params["teardown_grace_s"] = args.teardown_grace

    proc = psutil.Process()
    rss_before = proc.memory_info().rss
    enricher = Enricher()
    extractor = PcapFlowExtractor(**params)

    out_csv = None
    writer = None
    if not args.no_csv:
        out_csv = open(args.out_prefix + ".csv", "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(out_csv, fieldnames=FLOW_FIELDS)
        writer.writeheader()

    reasons: dict[str, int] = {}
    n_flows = 0

    def on_flow(record) -> None:
        nonlocal n_flows
        n_flows += 1
        reasons[record.expiry_reason] = reasons.get(record.expiry_reason, 0) + 1
        if writer is not None:
            writer.writerow(
                flow_record_to_row(record, capture_file=os.path.basename(args.pcap), enricher=enricher)
            )

    cpu0 = proc.cpu_times()
    t0 = time.perf_counter()
    result = extractor.extract(args.pcap, on_flow)
    wall = time.perf_counter() - t0
    cpu1 = proc.cpu_times()
    if out_csv is not None:
        out_csv.close()

    mem = proc.memory_info()
    peak = getattr(mem, "peak_wset", None) or mem.rss
    stats = {
        "tool": "flowlite-v2",
        "flowlite_version": FL_VERSION,
        "python": platform.python_version(),
        "pcap": args.pcap,
        "pcap_bytes": os.path.getsize(args.pcap),
        "params": params,
        "csv": not args.no_csv,
        "packets_total": result.packets_total,
        "packets_decoded": result.packets_decoded,
        "packets_skipped": result.packets_skipped,
        "flows": n_flows,
        "expiry_reasons": reasons,
        "table_stats": result.table_stats,
        "first_ts": result.first_ts,
        "last_ts": result.last_ts,
        "capture_format": result.capture_format,
        "linktypes": {str(k): v for k, v in result.linktypes.items()},
        "wall_s": wall,
        "cpu_user_s": cpu1.user - cpu0.user,
        "cpu_sys_s": cpu1.system - cpu0.system,
        "pkts_per_s": result.packets_total / wall if wall else 0.0,
        "mbit_per_s": result.bytes_read * 8 / wall / 1e6 if wall else 0.0,
        "flows_per_s": n_flows / wall if wall else 0.0,
        "rss_before_mb": rss_before / 2**20,
        "peak_mb": peak / 2**20,
        "warnings": result.warnings,
    }
    with open(args.out_prefix + ".json", "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2)
    print(json.dumps({k: stats[k] for k in ("packets_total", "flows", "wall_s", "pkts_per_s", "peak_mb")}))


if __name__ == "__main__":
    main()
