"""Benchmark driver: Python CICFlowMeter port (pip cicflowmeter 0.5.0, scapy-based).

Mirrors the package's own file-mode path: create_sniffer -> FlowSession with its
periodic GC thread, then a final flush to CSV. The package applies the BPF
filter "ip and (tcp or udp)" to offline files by piping them through an
external tcpdump binary, which Windows does not ship; the same filter is
applied in Python instead.
"""

import json
import os
import sys

from cicflowmeter import sniffer as cic_sniffer
from scapy.layers.inet import IP, TCP, UDP

_orig_async_sniffer = cic_sniffer.AsyncSniffer


def _python_filtered(*args, **kwargs):
    kwargs.pop("filter", None)
    prn = kwargs["prn"]

    def keep(pkt):
        if IP in pkt and (TCP in pkt or UDP in pkt):
            prn(pkt)

    kwargs["prn"] = keep
    return _orig_async_sniffer(*args, **kwargs)


cic_sniffer.AsyncSniffer = _python_filtered

if __name__ == "__main__":
    pcap, outdir = sys.argv[1], sys.argv[2]
    out = os.path.join(outdir, "cicflowmeter_" + os.path.basename(pcap) + ".csv")
    if os.path.exists(out):
        os.remove(out)
    sniffer, session = cic_sniffer.create_sniffer(input_file=pcap, input_interface=None,
                                                  output_mode="csv", output=out)
    sniffer.start()
    sniffer.join()
    if hasattr(session, "_gc_stop"):
        session._gc_stop.set()
        session._gc_thread.join(timeout=2.0)
    session.flush_flows()
    rows = cols = 0
    if os.path.exists(out):
        with open(out, encoding="utf-8") as fh:
            cols = len(fh.readline().split(","))
            rows = sum(1 for _ in fh)
    print(json.dumps({"flows": rows, "columns": cols}))
