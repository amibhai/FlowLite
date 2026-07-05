import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import dpkt
import numpy as np
import pandas as pd

from sasplite.geoip import GeoIPLookup


class FlowState:
    __slots__ = [
        "first_ts", "last_ts",
        "src_ip", "dst_ip", "src_port", "dst_port", "proto",
        "pkts",
        "syn_ts", "synack_ts",
        "fwd_init_win", "bwd_init_win",
    ]

    def __init__(self):
        self.first_ts: float = 0.0
        self.last_ts: float = 0.0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.proto: int = 0
        self.pkts: List[Dict] = []
        self.syn_ts: Optional[float] = None
        self.synack_ts: Optional[float] = None
        self.fwd_init_win: int = 0
        self.bwd_init_win: int = 0


def _process_packet(ts, raw, flows, cfg):
    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except Exception:
        return

    ip = eth.data
    is_ip4 = isinstance(ip, dpkt.ip.IP)
    is_ip6 = isinstance(ip, dpkt.ip6.IP6)
    if not (is_ip4 or is_ip6):
        return

    if is_ip4:
        try:
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
        except Exception:
            return
        ttl = ip.ttl
        proto = ip.p
    else:
        try:
            src = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return
        ttl = ip.hlim
        proto = ip.nxt

    layer4 = ip.data
    if isinstance(layer4, dpkt.tcp.TCP):
        sport = layer4.sport
        dport = layer4.dport
        payload_len = len(bytes(layer4.data))
        flags = layer4.flags
        win = layer4.win
        is_tcp = True
    elif isinstance(layer4, dpkt.udp.UDP):
        sport = layer4.sport
        dport = layer4.dport
        payload_len = len(bytes(layer4.data))
        flags = 0
        win = 0
        is_tcp = False
    elif isinstance(layer4, dpkt.icmp.ICMP):
        sport = 0
        dport = 0
        payload_len = len(raw)
        flags = 0
        win = 0
        is_tcp = False
    else:
        return

    fwd_key = (src, sport, dst, dport, proto)
    bwd_key = (dst, dport, src, sport, proto)

    if fwd_key in flows:
        key = fwd_key
        direction = "fwd"
    elif bwd_key in flows:
        key = bwd_key
        direction = "bwd"
    else:
        key = fwd_key
        direction = "fwd"
        state = FlowState()
        state.first_ts = ts
        state.last_ts = ts
        state.src_ip = src
        state.dst_ip = dst
        state.src_port = sport
        state.dst_port = dport
        state.proto = proto
        state.pkts = []
        flows[key] = state

    state = flows[key]
    state.last_ts = ts
    state.pkts.append({
        "ts": ts,
        "dir": direction,
        "payload_len": payload_len,
        "flags": flags,
        "ttl": ttl,
        "win": win,
    })

    if is_tcp:
        SYN = 0x02
        ACK = 0x10
        is_syn    = bool(flags & SYN) and not bool(flags & ACK)
        is_synack = bool(flags & SYN) and bool(flags & ACK)
        if is_syn and state.syn_ts is None:
            state.syn_ts = ts
            state.fwd_init_win = win
        elif is_synack and state.synack_ts is None:
            state.synack_ts = ts
            state.bwd_init_win = win


def _iat_stats(ts_arr: np.ndarray) -> Tuple[float, float, float]:
    if len(ts_arr) < 2:
        return 0.0, 0.0, 0.0
    d = np.diff(ts_arr)
    return float(d.mean()), float(d.std()), float(d.max())


def _size_stats(pay_arr: np.ndarray) -> Tuple[float, float, float]:
    if len(pay_arr) == 0:
        return 0.0, 0.0, 0.0
    return float(pay_arr.mean()), float(pay_arr.std()), float(pay_arr.max())


def _active_idle(ts_arr: np.ndarray, gap: float) -> Tuple[float, float]:
    if len(ts_arr) < 2:
        return 0.0, 0.0
    diffs = np.diff(ts_arr)
    active, idle = [], []
    burst_start = ts_arr[0]
    burst_end = ts_arr[0]
    for i, d in enumerate(diffs):
        if d < gap:
            burst_end = ts_arr[i + 1]
        else:
            active.append(burst_end - burst_start)
            idle.append(d)
            burst_start = ts_arr[i + 1]
            burst_end = ts_arr[i + 1]
    active.append(burst_end - burst_start)
    am = float(np.mean(active)) if active else 0.0
    im = float(np.mean(idle)) if idle else 0.0
    return am, im


def _aggregate_flow(
    key: Tuple, state: FlowState, geoip: GeoIPLookup, cfg
) -> Optional[Dict]:
    pkts = state.pkts
    if not pkts:
        return None

    src_ip, src_port, dst_ip, dst_port, proto = key
    fwd = [p for p in pkts if p["dir"] == "fwd"]
    bwd = [p for p in pkts if p["dir"] == "bwd"]
    n_all = len(pkts)

    def arr(lst, k):
        return np.array([p[k] for p in lst], dtype=np.float64)

    all_ts  = arr(pkts, "ts")
    fwd_ts  = arr(fwd,  "ts")
    bwd_ts  = arr(bwd,  "ts")
    all_pay = arr(pkts, "payload_len")
    fwd_pay = arr(fwd,  "payload_len")
    bwd_pay = arr(bwd,  "payload_len")
    all_ttl = arr(pkts, "ttl")
    all_flg = [p["flags"] for p in pkts]

    gap = cfg.sasplite.subflow_gap_s

    flow_iat_mean, flow_iat_std, flow_iat_max = _iat_stats(all_ts)
    fwd_iat_mean,  fwd_iat_std,  fwd_iat_max  = _iat_stats(fwd_ts)
    bwd_iat_mean,  bwd_iat_std,  bwd_iat_max  = _iat_stats(bwd_ts)

    fwd_len_mean, fwd_len_std, fwd_len_max = _size_stats(fwd_pay)
    bwd_len_mean, bwd_len_std, bwd_len_max = _size_stats(bwd_pay)
    pkt_variance = float(np.var(all_pay)) if len(all_pay) else 0.0

    active_mean, idle_mean = _active_idle(all_ts, gap)

    def flag_ratio(bit: int) -> float:
        return sum(1 for f in all_flg if f & bit) / max(n_all, 1)

    SYN = 0x02; ACK = 0x10; FIN = 0x01
    RST = 0x04; PSH = 0x08; URG = 0x20

    fwd_pay_pos = fwd_pay[fwd_pay > 0]
    min_seg_fwd = int(fwd_pay_pos.min()) if len(fwd_pay_pos) else 0

    return {
        "src_ip":               src_ip,
        "dst_ip":               dst_ip,
        "src_port":             src_port,
        "dst_port":             dst_port,
        "proto":                proto,
        "ts_start":             state.first_ts,
        "ts_end":               state.last_ts,
        "flow_duration":        state.last_ts - state.first_ts,
        "flow_iat_mean":        flow_iat_mean,
        "flow_iat_std":         flow_iat_std,
        "flow_iat_max":         flow_iat_max,
        "fwd_iat_mean":         fwd_iat_mean,
        "fwd_iat_std":          fwd_iat_std,
        "fwd_iat_max":          fwd_iat_max,
        "bwd_iat_mean":         bwd_iat_mean,
        "bwd_iat_std":          bwd_iat_std,
        "bwd_iat_max":          bwd_iat_max,
        "fwd_pkt_len_mean":     fwd_len_mean,
        "fwd_pkt_len_std":      fwd_len_std,
        "fwd_pkt_len_max":      fwd_len_max,
        "bwd_pkt_len_mean":     bwd_len_mean,
        "bwd_pkt_len_std":      bwd_len_std,
        "bwd_pkt_len_max":      bwd_len_max,
        "pkt_len_variance":     pkt_variance,
        "init_win_bytes_fwd":   state.fwd_init_win,
        "init_win_bytes_bwd":   state.bwd_init_win,
        "min_seg_size_forward": min_seg_fwd,
        "active_time_mean":     active_mean,
        "idle_time_mean":       idle_mean,
        "syn_flag_ratio":       flag_ratio(SYN),
        "ack_flag_ratio":       flag_ratio(ACK),
        "fin_flag_ratio":       flag_ratio(FIN),
        "rst_flag_ratio":       flag_ratio(RST),
        "psh_flag_ratio":       flag_ratio(PSH),
        "urg_flag_ratio":       flag_ratio(URG),
        "ip_ttl_mean":          float(all_ttl.mean()) if len(all_ttl) else 0.0,
        "ip_ttl_std":           float(all_ttl.std())  if len(all_ttl) else 0.0,
        "ip_proto":             proto,
        "n_fwd_pkts":           len(fwd),
        "n_bwd_pkts":           len(bwd),
        "n_fwd_bytes":          int(fwd_pay.sum()) if len(fwd_pay) else 0,
        "n_bwd_bytes":          int(bwd_pay.sum()) if len(bwd_pay) else 0,
        "dst_asn":              geoip.get_asn(dst_ip),
    }


class FlowExtractor:
    def __init__(self, cfg, geoip: GeoIPLookup, log):
        self.cfg = cfg
        self.geoip = geoip
        self.log = log

    def extract(self, pcap_path: Path) -> pd.DataFrame:
        flows: Dict[tuple, FlowState] = {}

        with open(pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception as e:
                self.log.error("Cannot open pcap %s: %s", pcap_path, e)
                return pd.DataFrame()

            for ts, raw in pcap:
                try:
                    _process_packet(ts, raw, flows, self.cfg)
                except Exception:
                    continue

        rows = []
        for key, state in flows.items():
            row = _aggregate_flow(key, state, self.geoip, self.cfg)
            if row is not None:
                rows.append(row)

        if not rows:
            self.log.warning("No flows extracted from %s", pcap_path)
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df.replace([np.inf, -np.inf], 0.0, inplace=True)
        df.fillna(0.0, inplace=True)
        self.log.info(
            "Extracted %d flows, %d cols from %s",
            len(df), len(df.columns), pcap_path.name,
        )
        return df
