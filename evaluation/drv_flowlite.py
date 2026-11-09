"""Benchmark driver: FlowLite v2 with shipped defaults, full 95-column CSV output."""

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import csv
import json
import os
import sys

sys.path.insert(0, paths.FLOWLITE_SRC)

from flowlite.enrich.geoip import Enricher  # noqa: E402
from flowlite.flow.schema import FLOW_FIELDS, flow_record_to_row  # noqa: E402
from flowlite.flow.table import PcapFlowExtractor  # noqa: E402

pcap, outdir = sys.argv[1], sys.argv[2]
out = os.path.join(outdir, "flowlite_" + os.path.basename(pcap) + ".csv")
enricher = Enricher()
# Shipped defaults; FLOWLITE_MAX_FLOWS overrides the table ceiling (flood test).
max_flows = int(os.environ.get("FLOWLITE_MAX_FLOWS", "250000"))
ex = PcapFlowExtractor(active_timeout_s=300, idle_timeout_s=60, burst_gap_s=1.0,
                       max_flows=max_flows, min_packets=1, max_packets_per_flow=20_000,
                       teardown_grace_s=5.0)
n = 0
with open(out, "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=FLOW_FIELDS)
    w.writeheader()

    def sink(rec):
        global n
        n += 1
        w.writerow(flow_record_to_row(rec, capture_file=os.path.basename(pcap), enricher=enricher))

    res = ex.extract(pcap, sink)
print(json.dumps({"flows": n, "packets": res.packets_total, "decoded": res.packets_decoded,
                  "columns": len(FLOW_FIELDS), "max_flows": max_flows,
                  "table_stats": res.table_stats}))
