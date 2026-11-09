"""File-level parallelism: N FlowLite processes on N capture files at once.

FlowLite processes each capture file independently (a live deployment rotates
captures into files), so throughput scales by running one process per file.
Usage: python parallel_scale.py <pcap> <out.json> [N ...]
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def run(n: int, pcap: str):
    outdir = os.path.join(paths.BENCH_OUT, "par")
    os.makedirs(outdir, exist_ok=True)
    t0 = time.perf_counter()
    procs = []
    for i in range(n):
        d = os.path.join(outdir, str(i))
        os.makedirs(d, exist_ok=True)
        procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "drv_flowlite.py"), pcap, d],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))
    outs = [p.communicate()[0] for p in procs]
    wall = time.perf_counter() - t0
    pkts = sum(json.loads(o.strip().splitlines()[-1])["packets"] for o in outs)
    return {"processes": n, "wall_s": wall, "packets": pkts, "kpps": pkts / wall / 1e3}


def main() -> None:
    pcap, out, *ns = sys.argv[1:]
    res = [run(int(n), pcap) for n in (ns or ["1", "2", "4", "8"])]
    for r in res:
        print(json.dumps(r))
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"pcap": pcap, "cpu_count": os.cpu_count(), "runs": res}, fh, indent=1)


if __name__ == "__main__":
    main()
