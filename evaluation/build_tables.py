"""Assemble labelled feature tables for the three extractors.

Usage: python build_tables.py <tool> <out.parquet> <input files...>
  tool = flowlite | nfstream | cic

Every table carries: the tool's numeric feature columns, `label` (from the
shared rules in label.py), `day`, and the endpoint identifiers kept aside in
columns prefixed `id_` (never used as features). IP addresses, ports and
timestamps are excluded from all feature sets: they identify the testbed's
hosts rather than describe behaviour, and are a documented shortcut in
CIC-IDS2017 (Arp et al., USENIX Security 2022).
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import sys

import numpy as np
import pandas as pd

sys.path.insert(0, paths.HERE)
from label import label_cic, label_flowlite, label_nfstream  # noqa: E402

FL_IDENT = {"flow_id", "device", "capture_file", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol_name", "ip_version", "vlan_id", "start_time", "end_time", "start_epoch",
            "end_epoch", "expiry_reason"}
FL_CATEG = {"tcp_state", "src_scope", "dst_scope", "dst_asn", "dst_asn_org", "dst_country"}

NF_DROP_PREFIX = ("application_",)
NF_DROP = {"id", "expiration_id", "src_ip", "src_mac", "src_oui", "src_port", "dst_ip", "dst_mac",
           "dst_oui", "dst_port", "ip_version", "vlan_id", "tunnel_id", "requested_server_name",
           "client_fingerprint", "server_fingerprint", "user_agent", "content_type"}

CIC_DROP = {"Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp",
            "Label"}


def day_of(epoch: pd.Series) -> pd.Series:
    return pd.to_datetime(epoch, unit="s", utc=True).dt.strftime("%a")


def build_flowlite(files):
    frames = []
    for f in files:
        d = pd.read_csv(f, low_memory=False)
        frames.append(d)
    d = pd.concat(frames, ignore_index=True)
    feats = [c for c in d.columns if c not in FL_IDENT and c not in FL_CATEG]
    out = d[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float64)
    out["tcp_state"] = d["tcp_state"].astype(str)
    out["expiry_reason"] = d["expiry_reason"].astype(str)
    out["label"] = label_flowlite(d)
    out["day"] = day_of(d["start_epoch"])
    for c in ("src_ip", "dst_ip", "src_port", "dst_port", "start_epoch"):
        out["id_" + c] = d[c]
    return out


def build_nfstream(files):
    d = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)
    feats = [c for c in d.columns if c not in NF_DROP and not c.startswith(NF_DROP_PREFIX)
             and not c.endswith("_first_seen_ms") and not c.endswith("_last_seen_ms")]
    out = d[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float64)
    out["label"] = label_nfstream(d)
    out["day"] = day_of(d["bidirectional_first_seen_ms"] / 1000.0)
    for c in ("src_ip", "dst_ip", "src_port", "dst_port"):
        out["id_" + c] = d[c]
    out["id_start_epoch"] = d["bidirectional_first_seen_ms"] / 1000.0
    return out


def build_cic(files):
    frames = []
    for f in files:
        d = pd.read_parquet(f)
        d.columns = [c.strip() for c in d.columns]
        frames.append(d)
    d = pd.concat(frames, ignore_index=True)
    feats = [c for c in d.columns if c not in CIC_DROP]
    out = d[feats].apply(pd.to_numeric, errors="coerce").astype(np.float64)
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    out["label"] = label_cic(d)
    out["cic_label"] = d["Label"].str.strip().values
    epoch = pd.Timestamp("1970-01-01", tz="UTC")
    ts = (pd.to_datetime(d["Timestamp"]).dt.tz_localize("UTC") - epoch).dt.total_seconds()
    out["day"] = day_of(ts)
    for src, dst in (("Source IP", "src_ip"), ("Destination IP", "dst_ip"),
                     ("Source Port", "src_port"), ("Destination Port", "dst_port")):
        out["id_" + dst] = d[src].values
    out["id_start_epoch"] = ts.values
    return out


def main() -> None:
    tool, out_path, *files = sys.argv[1:]
    build = {"flowlite": build_flowlite, "nfstream": build_nfstream, "cic": build_cic}[tool]
    t = build(files)
    t.to_parquet(out_path, index=False)
    print(tool, t.shape)
    print(t.groupby(["day", "label"]).size().to_string())


if __name__ == "__main__":
    main()
