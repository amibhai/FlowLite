"""Write a SYN flood in which every packet opens a new, never-answered flow.

Usage: python make_flood.py <out.pcap> <packets> [rate_pps]
Each packet has a distinct (source address, source port) towards one victim,
so a flow table that kept every flow would grow linearly with the capture.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import struct
import sys

sys.path.insert(0, paths.FLOWLITE_SRC)
from flowlite import synth  # noqa: E402
from flowlite.pcap.decode import TCP_SYN  # noqa: E402


def main() -> None:
    out, count = sys.argv[1], int(sys.argv[2])
    rate = float(sys.argv[3]) if len(sys.argv) > 3 else 100_000.0
    with open(out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t0 = 1_700_000_000.0
        for i in range(count):
            src = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            frame = synth.make_tcp_frame(src, "192.0.2.80", 1024 + (i % 60000), 80, flags=TCP_SYN)
            ts = t0 + i / rate
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    print(f"wrote {count} SYN packets to {out}")


if __name__ == "__main__":
    main()
