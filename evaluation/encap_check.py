"""Capture-source independence: identical features across link-layer framings.

Takes the IP datagrams of a real Ethernet capture and writes them again under
other framings a switch, router or host capture can produce. Every behavioural
feature must come out identical; only the frame-byte columns (header sizes
differ) and vlan_id (when a tag is added) may change.

Usage: python encap_check.py <ethernet.pcap> <workdir> <out.json>
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import csv
import gzip
import io
import json
import os
import struct
import sys

sys.path.insert(0, paths.FLOWLITE_SRC)
from flowlite import synth  # noqa: E402
from flowlite.flow.schema import FLOW_FIELDS, flow_record_to_row  # noqa: E402
from flowlite.flow.table import PcapFlowExtractor  # noqa: E402
from flowlite.pcap.reader import CaptureFile  # noqa: E402

ETH, RAW, SLL, SLL2 = 1, 101, 113, 276
MAC = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02"


def ip_payloads(path):
    for ts, data, lt in CaptureFile(path).packets():
        if lt != ETH or len(data) < 14:
            continue
        ethertype = struct.unpack_from("!H", data, 12)[0]
        if ethertype in (0x0800, 0x86DD):
            yield ts, ethertype, data[14:]


def framings():
    def eth(et, ip):
        return MAC + struct.pack("!H", et) + ip

    def vlan(et, ip):
        return MAC + struct.pack("!HHH", 0x8100, 100, et) + ip

    def qinq(et, ip):
        return MAC + struct.pack("!HHHHH", 0x88A8, 200, 0x8100, 100, et) + ip

    def mpls(_et, ip):
        labels = struct.pack("!I", (16 << 12) | 64) + struct.pack("!I", (17 << 12) | 0x100 | 64)
        return MAC + struct.pack("!H", 0x8847) + labels + ip

    def raw(_et, ip):
        return ip

    def sll(et, ip):
        return struct.pack("!HHH", 0, 1, 6) + b"\x02\x00\x00\x00\x00\x02\x00\x00" + struct.pack("!H", et) + ip

    def sll2(et, ip):
        return struct.pack("!HHIHBB", et, 0, 2, 1, 0, 6) + b"\x02\x00\x00\x00\x00\x02\x00\x00" + ip

    return {
        "Ethernet (re-written)": (ETH, eth, "pcap"),
        "802.1Q VLAN": (ETH, vlan, "pcap"),
        "802.1ad QinQ": (ETH, qinq, "pcap"),
        "MPLS (2 labels)": (ETH, mpls, "pcap"),
        "Raw IP": (RAW, raw, "pcap"),
        "Linux cooked v1": (SLL, sll, "pcap"),
        "Linux cooked v2": (SLL2, sll2, "pcap"),
        "Ethernet, pcapng": (ETH, eth, "pcapng"),
        "Ethernet, gzip pcap": (ETH, eth, "gzip"),
    }


def extract(path):
    rows = {}
    ex = PcapFlowExtractor(active_timeout_s=300, idle_timeout_s=60, burst_gap_s=1.0, max_flows=250_000,
                           min_packets=1, max_packets_per_flow=20_000, teardown_grace_s=5.0)

    def sink(rec):
        r = flow_record_to_row(rec)
        rows[r["flow_id"]] = r

    ex.extract(path, sink)
    return rows


def main() -> None:
    src, work, out = sys.argv[1:4]
    os.makedirs(work, exist_ok=True)
    pkts = list(ip_payloads(src))
    base = extract(src)
    skip = {"total_frame_bytes", "fwd_frame_bytes", "bwd_frame_bytes", "vlan_id", "capture_file"}
    compare = [f for f in FLOW_FIELDS if f not in skip]
    results = {"packets": len(pkts), "flows": len(base), "fields_compared": len(compare), "framings": {}}
    for name, (lt, frame, fmt) in framings().items():
        frames = [(ts, frame(et, ip)) for ts, et, ip in pkts]
        path = os.path.join(work, "encap_" + "".join(c for c in name if c.isalnum()) + (".pcapng" if fmt == "pcapng" else ".pcap"))
        if fmt == "pcapng":
            synth.write_pcapng(path, frames, linktype=lt)
        else:
            synth.write_pcap(path, frames, linktype=lt)
            if fmt == "gzip":
                with open(path, "rb") as fh, gzip.open(path + ".gz", "wb") as gz:
                    gz.write(fh.read())
                os.remove(path)
                path += ".gz"
        got = extract(path)
        same_keys = set(got) == set(base)
        diffs = sum(1 for k in base if k in got for f in compare if str(base[k][f]) != str(got[k][f]))
        results["framings"][name] = {"linktype": lt, "format": fmt, "flows": len(got),
                                     "same_flow_ids": same_keys, "differing_values": diffs}
        print(f"{name:24s} flows={len(got)} same_ids={same_keys} differing_values={diffs}", flush=True)
        os.remove(path)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)


if __name__ == "__main__":
    main()
