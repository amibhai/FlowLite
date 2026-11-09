"""Benchmark driver: NFStream 6.6 with post-mortem statistical features.

Configured for parity with FlowLite's defaults: idle timeout 60 s, active
timeout 300 s, a single meter process, no nDPI dissection, no SPLT.
"""

import json
import os
import sys

# NFStream's C engine links against Npcap's wpcap.dll, which Npcap installs
# outside the default DLL search path on Windows.
NPCAP = r"C:\Windows\System32\Npcap"
if hasattr(os, "add_dll_directory") and os.path.isdir(NPCAP):
    os.add_dll_directory(NPCAP)
    os.environ["PATH"] = NPCAP + ";" + os.environ.get("PATH", "")

from nfstream import NFStreamer  # noqa: E402

if __name__ == "__main__":
    pcap, outdir = sys.argv[1], sys.argv[2]
    streamer = NFStreamer(source=pcap, statistical_analysis=True, n_dissections=0,
                          splt_analysis=0, idle_timeout=60, active_timeout=300, n_meters=1)
    out = os.path.join(outdir, "nfstream_" + os.path.basename(pcap) + ".csv")
    n = streamer.to_csv(path=out, flows_per_file=0, rotate_files=0)
    with open(out, encoding="utf-8") as fh:
        cols = len(fh.readline().split(","))
    print(json.dumps({"flows": int(n), "columns": cols}))
