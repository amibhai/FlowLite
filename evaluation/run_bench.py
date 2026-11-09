"""Run one extractor on one capture in a child process and measure its cost.

Usage: python run_bench.py <tool> <pcap> <result.json> [--repeat K]

Tools are defined in TOOLS below; each is a command that reads the capture,
computes flow features and materialises them (CSV or in-memory table), then
prints a JSON line {"flows": N, "packets": P} as its last line of stdout.

Peak memory is the maximum over 20 ms samples of the summed RSS of the child
and all its descendants (NFStream forks meter processes). CPU time is user+sys
summed over the process tree at its last sample.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import argparse
import json
import os
import platform
import subprocess
import sys
import time

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
PY314 = sys.executable
PY312 = paths.BASELINE_PYTHON

TOOLS = {
    # FlowLite v2 (this paper), shipped defaults, writes the full 95-column CSV.
    "flowlite": [PY314, os.path.join(HERE, "drv_flowlite.py")],
    # FlowLite v2 on the same interpreter as the baselines, for a like-for-like comparison.
    "flowlite_py312": [PY312, os.path.join(HERE, "drv_flowlite.py")],
    # FlowLite v2 on PyPy's JIT, unmodified: possible only because it is pure Python.
    "flowlite_pypy": [paths.PYPY,
                      os.path.join(HERE, "drv_flowlite.py")],
    # Original dpkt/numpy/pandas prototype described in the submitted version.
    "prototype": [PY312, os.path.join(HERE, "drv_prototype.py")],
    # NFStream 6.6 (C engine + Python), statistical features, one meter, no DPI.
    "nfstream": [PY312, os.path.join(HERE, "drv_nfstream.py")],
    # Python port of CICFlowMeter (pip cicflowmeter 0.5.0, scapy-based).
    "cicflowmeter_py": [PY312, os.path.join(HERE, "drv_cicflowmeter.py")],
}


def tree(proc: psutil.Process):
    try:
        return [proc] + proc.children(recursive=True)
    except psutil.NoSuchProcess:
        return []


def measure(cmd, pcap: str, outdir: str):
    t0 = time.perf_counter()
    child = subprocess.Popen(cmd + [pcap, outdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p = psutil.Process(child.pid)
    peak = 0
    cpu_seen: dict[int, float] = {}
    while child.poll() is None:
        total = 0
        for q in tree(p):
            try:
                total += q.memory_info().rss
                ct = q.cpu_times()
                cpu_seen[q.pid] = ct.user + ct.system
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        peak = max(peak, total)
        time.sleep(0.02)
    out, err = child.communicate()
    wall = time.perf_counter() - t0
    last = [ln for ln in out.strip().splitlines() if ln.startswith("{")]
    info = json.loads(last[-1]) if last else {}
    return {
        "returncode": child.returncode,
        "wall_s": wall,
        "cpu_s_lastsample": sum(cpu_seen.values()),
        "peak_rss_mb": peak / 2**20,
        "child": info,
        "stderr_tail": err[-1500:],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool")
    ap.add_argument("pcap")
    ap.add_argument("result")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--outdir", default=paths.BENCH_OUT)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    runs = [measure(TOOLS[args.tool], args.pcap, args.outdir) for _ in range(args.repeat)]
    res = {
        "tool": args.tool,
        "pcap": args.pcap,
        "pcap_bytes": os.path.getsize(args.pcap),
        "host": platform.platform(),
        "cpu": platform.processor(),
        "runs": runs,
    }
    with open(args.result, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    best = min(runs, key=lambda r: r["wall_s"])
    print(json.dumps({"tool": args.tool, "wall_s": round(best["wall_s"], 2),
                      "peak_rss_mb": round(best["peak_rss_mb"], 1), **best["child"],
                      "rc": best["returncode"]}))


if __name__ == "__main__":
    main()
