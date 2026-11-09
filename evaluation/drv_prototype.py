"""Benchmark driver: the original dpkt prototype (sasplite/extractor.py) restored
verbatim from git history (commit f5a85a4^), i.e. the implementation the
submitted version of the paper described. Output is its in-memory DataFrame,
also written to CSV for parity with the other tools."""

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json
import logging
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, paths.PROTOTYPE)

from sasplite.extractor import FlowExtractor  # noqa: E402
from sasplite.geoip import GeoIPLookup  # noqa: E402

logging.disable(logging.WARNING)
pcap, outdir = sys.argv[1], sys.argv[2]
cfg = SimpleNamespace(sasplite=SimpleNamespace(subflow_gap_s=1.0))
geo = GeoIPLookup("nonexistent-asn.mmdb", "nonexistent-city.mmdb")
log = logging.getLogger("proto")
from pathlib import Path  # noqa: E402

df = FlowExtractor(cfg, geo, log).extract(Path(pcap))
df.to_csv(os.path.join(outdir, "prototype_" + os.path.basename(pcap) + ".csv"), index=False)
print(json.dumps({"flows": int(len(df)), "columns": int(df.shape[1]) if len(df) else 0}))
