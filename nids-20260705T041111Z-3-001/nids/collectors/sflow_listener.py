import socket
import struct
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import dpkt
import numpy as np

from utils.csv_writer import append_rows

_IFACE_FIELDS = [
    "timestamp", "agent_ip", "if_index",
    "in_octets", "out_octets", "in_discards", "out_discards",
    "in_errors", "out_errors",
    "in_octets_delta", "out_octets_delta",
]

_ENTROPY_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
    "payload_entropy",
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    total = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _unpack_uint32(data: bytes, offset: int):
    return struct.unpack_from("!I", data, offset)[0], offset + 4


def _unpack_uint64(data: bytes, offset: int):
    return struct.unpack_from("!Q", data, offset)[0], offset + 8


def _parse_raw_header(record_data: bytes):
    if len(record_data) < 16:
        return None
    header_protocol = struct.unpack_from("!I", record_data, 0)[0]
    frame_length    = struct.unpack_from("!I", record_data, 4)[0]
    stripped        = struct.unpack_from("!I", record_data, 8)[0]
    header_size     = struct.unpack_from("!I", record_data, 12)[0]
    header_data     = record_data[16: 16 + header_size]

    result = {"entropy": _entropy(header_data), "frame_length": frame_length}

    if header_protocol == 1 and len(header_data) >= 14:
        try:
            eth = dpkt.ethernet.Ethernet(header_data)
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                result["src_ip"]  = socket.inet_ntoa(ip.src)
                result["dst_ip"]  = socket.inet_ntoa(ip.dst)
                result["proto"]   = ip.p
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    result["src_port"] = ip.data.sport
                    result["dst_port"] = ip.data.dport
                else:
                    result["src_port"] = 0
                    result["dst_port"] = 0
        except Exception:
            pass

    return result


def _parse_flow_sample(data: bytes, offset: int, length: int, agent_ip: str):
    end = offset + length
    if offset + 32 > end:
        return [], [], offset + length

    sampling_rate, offset = _unpack_uint32(data, offset + 8)
    offset += 8  # skip sample_pool and drops
    offset += 8  # skip input/output interface
    n_records, offset = _unpack_uint32(data, offset)

    flow_rows = []
    entropy_rows = []

    for _ in range(n_records):
        if offset + 8 > end:
            break
        rec_type,   offset = _unpack_uint32(data, offset)
        rec_length, offset = _unpack_uint32(data, offset)
        rec_end = offset + rec_length

        if rec_type == 1 and offset + 16 <= rec_end:
            parsed = _parse_raw_header(data[offset:rec_end])
            if parsed:
                ts = datetime.utcnow().isoformat()
                entropy_rows.append({
                    "timestamp":       ts,
                    "src_ip":          parsed.get("src_ip", ""),
                    "dst_ip":          parsed.get("dst_ip", ""),
                    "src_port":        parsed.get("src_port", 0),
                    "dst_port":        parsed.get("dst_port", 0),
                    "proto":           parsed.get("proto", 0),
                    "payload_entropy": parsed["entropy"],
                })

        offset = rec_end

    return flow_rows, entropy_rows, end


def _parse_counter_sample(data: bytes, offset: int, length: int, agent_ip: str):
    end = offset + length
    if offset + 12 > end:
        return [], offset + length

    offset += 4  # sequence_number
    offset += 4  # source_id
    n_records, offset = _unpack_uint32(data, offset)

    iface_rows = []
    ts = datetime.utcnow().isoformat()

    for _ in range(n_records):
        if offset + 8 > end:
            break
        rec_type,   offset = _unpack_uint32(data, offset)
        rec_length, offset = _unpack_uint32(data, offset)
        rec_end = offset + rec_length

        if rec_type == 1 and rec_length >= 88:
            try:
                if_index,             o = _unpack_uint32(data, offset);     _=o
                if_type,              o = _unpack_uint32(data, o)
                if_speed,             o = _unpack_uint64(data, o)
                if_direction,         o = _unpack_uint32(data, o)
                if_status,            o = _unpack_uint32(data, o)
                if_in_octets,         o = _unpack_uint64(data, o)
                if_in_unicast_pkts,   o = _unpack_uint32(data, o)
                if_in_multicast_pkts, o = _unpack_uint32(data, o)
                if_in_broadcast_pkts, o = _unpack_uint32(data, o)
                if_in_discards,       o = _unpack_uint32(data, o)
                if_in_errors,         o = _unpack_uint32(data, o)
                if_in_unknown_protos, o = _unpack_uint32(data, o)
                if_out_octets,        o = _unpack_uint64(data, o)
                if_out_unicast_pkts,  o = _unpack_uint32(data, o)
                if_out_multicast_pkts,o = _unpack_uint32(data, o)
                if_out_broadcast_pkts,o = _unpack_uint32(data, o)
                if_out_discards,      o = _unpack_uint32(data, o)
                if_out_errors,        o = _unpack_uint32(data, o)

                iface_rows.append({
                    "timestamp":   ts,
                    "agent_ip":    agent_ip,
                    "if_index":    if_index,
                    "in_octets":   if_in_octets,
                    "out_octets":  if_out_octets,
                    "in_discards": if_in_discards,
                    "out_discards":if_out_discards,
                    "in_errors":   if_in_errors,
                    "out_errors":  if_out_errors,
                    "in_octets_delta":  0,
                    "out_octets_delta": 0,
                })
            except struct.error:
                pass

        offset = rec_end

    return iface_rows, end


def _parse_datagram(data: bytes):
    if len(data) < 28:
        return [], []

    version = struct.unpack_from("!I", data, 0)[0]
    if version != 5:
        return [], []

    addr_type = struct.unpack_from("!I", data, 4)[0]
    if addr_type == 1:
        agent_ip = socket.inet_ntoa(data[8:12])
        base = 28
    elif addr_type == 2:
        agent_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        base = 40
    else:
        return [], []

    if len(data) < base:
        return [], []

    n_samples = struct.unpack_from("!I", data, base - 4)[0]
    offset = base

    all_entropy = []
    all_iface   = []

    for _ in range(n_samples):
        if offset + 8 > len(data):
            break
        sample_type,   offset = _unpack_uint32(data, offset)
        sample_length, offset = _unpack_uint32(data, offset)
        sample_end = offset + sample_length

        if sample_type == 1:
            _, entropy_rows, _ = _parse_flow_sample(
                data, offset, sample_length, agent_ip
            )
            all_entropy.extend(entropy_rows)
        elif sample_type == 2:
            iface_rows, _ = _parse_counter_sample(
                data, offset, sample_length, agent_ip
            )
            all_iface.extend(iface_rows)

        offset = sample_end

    return all_iface, all_entropy


def run(cfg, stop_event, log, status_dict: Optional[Dict] = None):
    port          = cfg.sflow.listen_port
    interval      = cfg.sflow.parse_interval_s
    out_iface     = Path(cfg.paths.sflow_out)
    out_entropy   = out_iface.parent / "entropy_lookup.csv"

    iface_deque   = deque()
    entropy_deque = deque()
    prev_octets: Dict[str, Dict[int, Dict[str, int]]] = {}

    def receive_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1.0)
        log.info("sFlow listener bound to UDP port %d", port)

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                iface_rows, entropy_rows = _parse_datagram(data)
                for r in iface_rows:
                    iface_deque.append(r)
                for r in entropy_rows:
                    entropy_deque.append(r)
                if status_dict is not None:
                    status_dict["running"]  = True
                    status_dict["last_pkt"] = datetime.now().strftime("%H:%M:%S")
            except socket.timeout:
                continue
            except Exception as e:
                log.debug("sFlow receive error: %s", e)

        sock.close()

    def write_thread():
        while not stop_event.is_set():
            stop_event.wait(timeout=interval)

            # Drain iface rows and compute deltas
            iface_batch: List[Dict] = []
            while iface_deque:
                iface_batch.append(iface_deque.popleft())

            for row in iface_batch:
                agent = row["agent_ip"]
                idx   = row["if_index"]
                if agent not in prev_octets:
                    prev_octets[agent] = {}
                prev = prev_octets[agent].get(idx, {})
                row["in_octets_delta"]  = max(0, row["in_octets"]  - prev.get("in",  row["in_octets"]))
                row["out_octets_delta"] = max(0, row["out_octets"] - prev.get("out", row["out_octets"]))
                prev_octets[agent][idx] = {
                    "in":  row["in_octets"],
                    "out": row["out_octets"],
                }

            if iface_batch:
                try:
                    append_rows(out_iface, iface_batch, _IFACE_FIELDS)
                except Exception as e:
                    log.error("sFlow iface CSV write error: %s", e)

            entropy_batch: List[Dict] = []
            while entropy_deque:
                entropy_batch.append(entropy_deque.popleft())

            if entropy_batch:
                try:
                    append_rows(out_entropy, entropy_batch, _ENTROPY_FIELDS)
                except Exception as e:
                    log.error("sFlow entropy CSV write error: %s", e)

    rt = threading.Thread(target=receive_thread, daemon=True, name="sflow-recv")
    wt = threading.Thread(target=write_thread,   daemon=True, name="sflow-write")
    rt.start()
    wt.start()
    rt.join()
    wt.join()
    log.info("sFlow listener stopped")
