"""Differential test: FlowLite's streaming features vs an independent reference.

The reference decodes packets with dpkt (not FlowLite's decoder), groups them
into bidirectional flows with the same keying/direction convention, keeps every
packet in memory and computes each statistic in two passes with NumPy. FlowLite
is run with timeouts, packet caps and teardown closing disabled so both sides
see identical flow boundaries; what is being tested is the decoder and the
single-pass (Welford) feature arithmetic, not the expiry policy.

Usage: python reference_check.py <classic.pcap> <out.json>
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json
import socket
import sys
from collections import defaultdict

import dpkt
import numpy as np

sys.path.insert(0, paths.FLOWLITE_SRC)
from flowlite.flow.schema import flow_record_to_row  # noqa: E402
from flowlite.flow.table import FlowTable  # noqa: E402
from flowlite.pcap.decode import decode_packet  # noqa: E402
from flowlite.pcap.reader import CaptureFile  # noqa: E402

BURST_GAP = 1.0
SYN, ACK, FIN, RST, PSH, URG, ECE, CWR = 0x02, 0x10, 0x01, 0x04, 0x08, 0x20, 0x40, 0x80


def ref_packets(path):
    """Yield per-packet tuples decoded with dpkt."""
    with open(path, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                if ip.off & 0x3FFF:  # any fragment: excluded from the comparison
                    yield None
                    continue
                src, dst, ttl, proto = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.ttl, ip.p
            elif isinstance(ip, dpkt.ip6.IP6):
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                ttl, proto = ip.hlim, ip.p  # ip.p follows the extension-header chain
            else:
                continue
            l4 = ip.data
            flags = win = 0
            if isinstance(l4, dpkt.tcp.TCP):
                sport, dport, pay, flags, win = l4.sport, l4.dport, len(l4.data), l4.flags, l4.win
            elif isinstance(l4, dpkt.udp.UDP):
                sport, dport, pay = l4.sport, l4.dport, len(l4.data)
            elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                raw = bytes(l4)
                sport, dport, pay = raw[0], raw[1], max(0, len(raw) - 8)
                # Documented FlowLite rule, implemented independently: a query
                # reply takes its request's (type, code) slots mirrored.
                replies = {0: 8, 14: 13, 16: 15, 18: 17} if proto == 1 else {129: 128}
                if sport in replies:
                    sport, dport = raw[1], replies[sport]
            else:
                continue
            yield (ts, src, dst, sport, dport, proto, ttl, flags, win, pay, len(buf))


def stats(values):
    a = np.asarray(values, dtype=np.float64)
    if a.size == 0:
        return dict(mean=0.0, std=0.0, min=0.0, max=0.0, var=0.0)
    var = float(a.var()) if a.size >= 2 else 0.0
    return dict(mean=float(a.mean()), std=float(np.sqrt(var)), min=float(a.min()), max=float(a.max()), var=var)


def ref_features(pkts):
    """pkts: list of (ts, fwd(bool), proto, ttl, flags, win, pay, frame_len)."""
    ts = np.array([p[0] for p in pkts])
    ts = np.maximum.accumulate(ts)  # FlowLite clamps time going backwards
    fwd = np.array([p[1] for p in pkts])
    pay = np.array([p[6] for p in pkts], dtype=np.float64)
    frame = np.array([p[7] for p in pkts], dtype=np.float64)
    fl = [p[4] for p in pkts]
    proto = pkts[0][2]
    f = {}
    f["fwd_packets"], f["bwd_packets"] = int(fwd.sum()), int((~fwd).sum())
    f["total_packets"] = len(pkts)
    f["fwd_bytes"], f["bwd_bytes"] = int(pay[fwd].sum()), int(pay[~fwd].sum())
    f["total_bytes"] = int(pay.sum())
    f["fwd_frame_bytes"], f["bwd_frame_bytes"] = int(frame[fwd].sum()), int(frame[~fwd].sum())
    dur = float(ts[-1] - ts[0])
    f["duration_s"] = dur
    for name, arr in (("pkt_len", pay), ("fwd_pkt_len", pay[fwd]), ("bwd_pkt_len", pay[~fwd])):
        s = stats(arr)
        for k in ("mean", "std", "min", "max"):
            f[f"{name}_{k}"] = s[k]
        if name == "pkt_len":
            f["pkt_len_var"] = s["var"]
    for name, arr in (("flow_iat", np.diff(ts)), ("fwd_iat", np.diff(ts[fwd])), ("bwd_iat", np.diff(ts[~fwd]))):
        s = stats(arr)
        for k in ("mean", "std", "min", "max"):
            f[f"{name}_{k}"] = s[k]
    # bursts: a gap strictly greater than BURST_GAP closes the burst
    active, idle = [], []
    start = end = ts[0]
    for i in range(1, len(ts)):
        gap = ts[i] - ts[i - 1]
        if gap > BURST_GAP:
            active.append(end - start)
            idle.append(gap)
            start = ts[i]
        end = ts[i]
    active.append(end - start)
    for name, arr in (("active", active), ("idle", idle)):
        s = stats(arr)
        f[f"{name}_mean"], f[f"{name}_std"], f[f"{name}_max"] = s["mean"], s["std"], s["max"]
        f[f"{name}_count"] = len(arr)
    for nm, bit in (("syn", SYN), ("fin", FIN), ("rst", RST), ("psh", PSH), ("ack", ACK), ("urg", URG),
                    ("ece", ECE), ("cwr", CWR)):
        f[f"{nm}_count"] = sum(1 for x in fl if x & bit)
    if proto == 6:
        fw = [p[5] for p in pkts if p[1]]
        bw = [p[5] for p in pkts if not p[1]]
        f["init_win_fwd"] = fw[0] if fw else 0
        f["init_win_bwd"] = bw[0] if bw else 0
        syn_ts = next((t for p, t in zip(pkts, ts) if p[1] and p[4] & SYN and not p[4] & ACK), None)
        sa_ts = next((t for p, t in zip(pkts, ts) if (not p[1]) and p[4] & SYN and p[4] & ACK), None)
        f["tcp_handshake_ms"] = max(0.0, (sa_ts - syn_ts) * 1000) if syn_ts is not None and sa_ts is not None else 0.0
    else:
        f["init_win_fwd"] = f["init_win_bwd"] = 0
        f["tcp_handshake_ms"] = 0.0
    pos = pay[fwd][pay[fwd] > 0]
    f["fwd_min_seg_size"] = int(pos.min()) if pos.size else 0
    ttl = np.array([p[3] for p in pkts if p[3]], dtype=np.float64)
    s = stats(ttl)
    f["ttl_mean"], f["ttl_std"], f["ttl_min"], f["ttl_max"] = s["mean"], s["std"], s["min"], s["max"]
    return f


def main() -> None:
    path, out = sys.argv[1], sys.argv[2]
    # ---- reference side ------------------------------------------------------ #
    flows = defaultdict(list)
    first_dir = {}
    n_ref = n_frag = 0
    for p in ref_packets(path):
        if p is None:
            n_frag += 1
            continue
        n_ref += 1
        ts, src, dst, sport, dport, proto, ttl, flags, win, pay, flen = p
        a, b = (src, sport), (dst, dport)
        key = (a[0], a[1], b[0], b[1], proto) if a <= b else (b[0], b[1], a[0], a[1], proto)
        if key not in first_dir:
            first_dir[key] = (src, sport)
        fwd = (src, sport) == first_dir[key]
        flows[key].append((ts, fwd, proto, ttl, flags, win, pay, flen))
    ref = {k: ref_features(v) for k, v in flows.items()}

    # ---- FlowLite side ------------------------------------------------------- #
    got = {}

    def sink(rec):
        row = flow_record_to_row(rec)
        a, b = (rec.src_ip, rec.src_port), (rec.dst_ip, rec.dst_port)
        key = (a[0], a[1], b[0], b[1], rec.protocol) if a <= b else (b[0], b[1], a[0], a[1], rec.protocol)
        got[key] = row

    table = FlowTable(active_timeout_s=1e12, idle_timeout_s=1e12, burst_gap_s=BURST_GAP, max_flows=10**9,
                      close_on_teardown=False, max_packets_per_flow=0, on_flow=sink)
    n_fl = 0
    for ts, data, lt in CaptureFile(path).packets():
        pk = decode_packet(ts, data, lt)
        if pk is None or pk.is_fragment:
            continue
        if pk.proto not in (6, 17, 1, 58):
            continue
        n_fl += 1
        table.add_packet(pk)
    table.flush()

    # ---- compare ------------------------------------------------------------- #
    common = sorted(set(ref) & set(got))
    feats = sorted(next(iter(ref.values())).keys())
    worst = {}
    mismatched_flows = set()
    exact = 0
    total = 0
    for k in common:
        r, g = ref[k], got[k]
        for f in feats:
            rv, gv = float(r[f]), float(g[f])
            total += 1
            # FlowLite rounds most features to 6 decimals (TTL mean 2, TTL std 3, handshake 3)
            tol = {"ttl_mean": 6e-3, "ttl_std": 6e-4, "tcp_handshake_ms": 6e-4}.get(f, 6e-7)
            err = abs(rv - gv)
            rel = err / max(1.0, abs(rv))
            if err <= tol or rel <= 1e-9:
                exact += 1
            else:
                mismatched_flows.add(k)
            if rel > worst.get(f, (0.0, None))[0]:
                worst[f] = (rel, [str(x) for x in k], rv, gv)
    res = {
        "pcap": path,
        "ref_packets": n_ref,
        "ref_fragments_skipped": n_frag,
        "flowlite_packets": n_fl,
        "ref_flows": len(ref),
        "flowlite_flows": len(got),
        "common_flows": len(common),
        "only_ref": len(set(ref) - set(got)),
        "only_flowlite": len(set(got) - set(ref)),
        "features_compared": len(feats),
        "comparisons": total,
        "within_tolerance": exact,
        "flows_with_any_mismatch": len(mismatched_flows),
        "worst_relative_error_by_feature": {f: worst[f] for f in sorted(worst, key=lambda x: -worst[x][0])[:15]},
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps({k: res[k] for k in list(res)[:12]}, indent=1))


if __name__ == "__main__":
    main()
