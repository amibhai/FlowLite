"""Bytes of Python heap per in-progress flow (tracemalloc), FlowLite 2.1."""
import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json, sys, tracemalloc
sys.path.insert(0, paths.FLOWLITE_SRC)
from flowlite import synth
from flowlite.flow.table import FlowTable
from flowlite.pcap.decode import decode_packet, TCP_ACK
N = 20000
frames = []
for i in range(N):
    a = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
    frames.append(decode_packet(0.0, synth.make_tcp_frame(a, "192.0.2.1", 1024 + i % 50000, 80, b"x" * 100, TCP_ACK), 1))
    frames.append(decode_packet(0.0, synth.make_tcp_frame("192.0.2.1", a, 80, 1024 + i % 50000, b"y" * 1000, TCP_ACK), 1))
table = FlowTable(max_flows=10**9, idle_timeout_s=1e9, active_timeout_s=1e9)
tracemalloc.start()
base = tracemalloc.take_snapshot()
b0 = tracemalloc.get_traced_memory()[0]
for k, p in enumerate(frames):
    p.ts = k * 1e-4
    table.add_packet(p)
b1 = tracemalloc.get_traced_memory()[0]
print(json.dumps({"flows": len(table), "bytes_per_flow": (b1 - b0) / len(table)}))
