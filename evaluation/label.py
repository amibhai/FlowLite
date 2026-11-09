"""Rule-based ground truth for CIC-IDS2017 (Wednesday, Friday).

Rules follow the attack schedule published by the dataset authors
(https://www.unb.ca/cic/datasets/ids-2017.html), converted from local time
(ADT, UTC-3) to UTC. Inside the capture the external attacker 205.174.165.73
appears behind the firewall's NAT address 172.16.0.1, except for the Ares
botnet's C&C traffic, which reaches the infected hosts directly.

A flow is labelled with an attack class when (a) its two endpoints are the
attacker/victim pair of that attack, in either direction, (b) the victim-side
port matches when the attack targets one service, and (c) the flow starts
inside the attack's window. Everything else is BENIGN. The same rules are
applied to FlowLite, NFStream and CICFlowMeter flows so that all three feature
sets are evaluated against identical ground truth.

Windows are the published windows widened to cover the CIC label timestamps
where those extend beyond them (e.g. Hulk is published as 10:43-11:00 local but
labelled flows run to 11:07), so that no tool is penalised by the schedule
being stricter than the reference labels.
"""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd


def utc(day: str, hhmm: str) -> float:
    return datetime.strptime(f"{day} {hhmm}", "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp()


WED, FRI = "2017-07-05", "2017-07-07"
NAT = "172.16.0.1"
WEB = "192.168.10.50"
BOT_VICTIMS = {"192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"}
CNC = "205.174.165.73"

# (label, attacker, victim(s), victim port or None, start UTC, end UTC)
RULES = [
    ("DoS slowloris", NAT, {WEB}, 80, utc(WED, "12:47"), utc(WED, "13:12")),
    ("DoS Slowhttptest", NAT, {WEB}, 80, utc(WED, "13:14"), utc(WED, "13:38")),
    ("DoS Hulk", NAT, {WEB}, 80, utc(WED, "13:43"), utc(WED, "14:08")),
    ("DoS GoldenEye", NAT, {WEB}, 80, utc(WED, "14:10"), utc(WED, "14:24")),
    ("Heartbleed", NAT, {"192.168.10.51"}, 444, utc(WED, "18:11"), utc(WED, "18:33")),
    ("Bot", CNC, BOT_VICTIMS, None, utc(FRI, "11:00"), utc(FRI, "21:00")),
    ("PortScan", NAT, {WEB}, None, utc(FRI, "16:04"), utc(FRI, "18:30")),
    ("DDoS", NAT, {WEB}, 80, utc(FRI, "18:56"), utc(FRI, "19:17")),
]


def apply_rules(src, dst, sport, dport, start) -> np.ndarray:
    """Vectorised labelling. All inputs are aligned 1-D arrays/Series."""
    src = np.asarray(src, dtype=object)
    dst = np.asarray(dst, dtype=object)
    sport = np.asarray(sport, dtype=np.int64)
    dport = np.asarray(dport, dtype=np.int64)
    start = np.asarray(start, dtype=np.float64)
    label = np.full(len(src), "BENIGN", dtype=object)
    for name, attacker, victims, vport, t0, t1 in RULES:
        vic = np.array(sorted(victims), dtype=object)
        fwd = (src == attacker) & np.isin(dst, vic)
        rev = (dst == attacker) & np.isin(src, vic)
        if vport is not None:
            fwd &= dport == vport
            rev &= sport == vport
        when = (start >= t0) & (start < t1)
        hit = (fwd | rev) & when & (label == "BENIGN")
        label[hit] = name
    return label


def label_flowlite(df: pd.DataFrame) -> np.ndarray:
    return apply_rules(df["src_ip"], df["dst_ip"], df["src_port"], df["dst_port"], df["start_epoch"])


def label_nfstream(df: pd.DataFrame) -> np.ndarray:
    return apply_rules(df["src_ip"], df["dst_ip"], df["src_port"], df["dst_port"],
                       df["bidirectional_first_seen_ms"] / 1000.0)


def label_cic(df: pd.DataFrame) -> np.ndarray:
    epoch = pd.Timestamp("1970-01-01", tz="UTC")
    ts = (pd.to_datetime(df["Timestamp"]).dt.tz_localize("UTC") - epoch).dt.total_seconds()
    return apply_rules(df["Source IP"].str.strip(), df["Destination IP"].str.strip(),
                       df["Source Port"], df["Destination Port"], ts)
