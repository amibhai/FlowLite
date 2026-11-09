"""Downstream detection experiments (RQ3).

Usage:
  python ml.py main     <out.json>   feature-set comparison, RF + ET, 5-fold CV
  python ml.py ablation <out.json>   FlowLite drop-one-group ablation, ET, 5-fold CV
  python ml.py importance <out.json> RF impurity importances on all FlowLite flows

All feature sets exclude endpoint identifiers (addresses, ports, timestamps).
Labels come from the shared rules in label.py, applied identically to every
extractor's flows. Folds are stratified and shuffled with a fixed seed.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedKFold

ROOT = paths.TABLES
NON_FEATURE = {"label", "day", "cic_label", "tcp_state", "expiry_reason"}

PROTO43 = [  # numeric part of the submitted version's 43-column prototype set
    "duration_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "fwd_iat_mean", "fwd_iat_std",
    "fwd_iat_max", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "fwd_pkt_len_mean",
    "fwd_pkt_len_std", "fwd_pkt_len_max", "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max",
    "pkt_len_var", "init_win_fwd", "init_win_bwd", "fwd_min_seg_size", "active_mean", "idle_mean",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio", "urg_ratio", "ttl_mean",
    "ttl_std", "protocol", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
]

# What a NetFlow v9 / IPFIX exporter reports from per-flow counters: volumes per
# direction, duration, protocol, cumulative TCP flags, TTL and packet-length
# extremes, and directional throughput. Approximates (does not reproduce) the
# NetFlow-based standard feature set of Sarhan et al.
NETFLOW_OBSERVABLE = [
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "duration_s", "protocol",
    "syn_seen", "fin_seen", "rst_seen", "psh_seen", "ack_seen", "urg_seen",
    "ttl_min", "ttl_max", "pkt_len_min", "pkt_len_max", "fwd_bytes_per_s", "bwd_bytes_per_s",
]

GROUPS = {
    "volume & rates": ["total_packets", "fwd_packets", "bwd_packets", "total_bytes", "fwd_bytes",
                       "bwd_bytes", "total_frame_bytes", "fwd_frame_bytes", "bwd_frame_bytes",
                       "packets_per_s", "bytes_per_s", "fwd_bytes_per_s", "bwd_bytes_per_s",
                       "down_up_byte_ratio", "fwd_bwd_packet_ratio", "byte_asymmetry"],
    "packet size": ["pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max", "pkt_len_var",
                    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min", "fwd_pkt_len_max",
                    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_min", "bwd_pkt_len_max"],
    "inter-arrival": ["duration_s", "flow_iat_mean", "flow_iat_std", "flow_iat_min", "flow_iat_max",
                      "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max", "bwd_iat_mean",
                      "bwd_iat_std", "bwd_iat_min", "bwd_iat_max"],
    "burst/idle": ["active_mean", "active_std", "active_max", "active_count", "idle_mean",
                   "idle_std", "idle_max", "idle_count"],
    "TCP flags": ["syn_count", "fin_count", "rst_count", "psh_count", "ack_count", "urg_count",
                  "ece_count", "cwr_count", "syn_ratio", "fin_ratio", "rst_ratio", "psh_ratio",
                  "ack_ratio", "urg_ratio"],
    "TCP handshake": ["init_win_fwd", "init_win_bwd", "fwd_min_seg_size", "tcp_handshake_ms"],
    "IP layer": ["ttl_mean", "ttl_std", "ttl_min", "ttl_max", "fragment_packets", "protocol"],
}


def load(tool: str) -> pd.DataFrame:
    return pd.read_parquet(os.path.join(ROOT, f"{tool}.parquet"))


def numeric_cols(df: pd.DataFrame):
    return [c for c in df.columns if c not in NON_FEATURE and not c.startswith("id_")
            and pd.api.types.is_numeric_dtype(df[c])]


def add_flag_presence(df: pd.DataFrame) -> pd.DataFrame:
    for f in ("syn", "fin", "rst", "psh", "ack", "urg"):
        df[f"{f}_seen"] = (df[f"{f}_count"] > 0).astype(np.float64)
    return df


def model(name: str, seed: int):
    common = dict(n_estimators=100, n_jobs=-1, random_state=seed)
    return RandomForestClassifier(**common) if name == "RF" else ExtraTreesClassifier(**common)


def cross_validate(X: np.ndarray, y: np.ndarray, model_name: str, folds: int = 5, seed: int = 0):
    labels = sorted(set(y))
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    per_fold = []
    for k, (tr, te) in enumerate(skf.split(X, y)):
        clf = model(model_name, seed + k)
        t0 = time.perf_counter()
        clf.fit(X[tr], y[tr])
        t_fit = time.perf_counter() - t0
        t0 = time.perf_counter()
        pred = clf.predict(X[te])
        t_pred = time.perf_counter() - t0
        yt = y[te]
        benign = yt == "BENIGN"
        per_fold.append({
            "macro_f1": f1_score(yt, pred, average="macro", labels=labels, zero_division=0),
            "weighted_f1": f1_score(yt, pred, average="weighted", labels=labels, zero_division=0),
            "accuracy": accuracy_score(yt, pred),
            "benign_fpr": float(np.mean(pred[benign] != "BENIGN")) if benign.any() else 0.0,
            "attack_dr": float(np.mean(pred[~benign] != "BENIGN")) if (~benign).any() else 0.0,
            "per_class_f1": dict(zip(labels, f1_score(yt, pred, average=None, labels=labels,
                                                      zero_division=0).tolist())),
            "fit_s": t_fit,
            "predict_s": t_pred,
        })
    agg = {}
    for key in ("macro_f1", "weighted_f1", "accuracy", "benign_fpr", "attack_dr", "fit_s", "predict_s"):
        vals = [f[key] for f in per_fold]
        agg[key] = {"mean": float(np.mean(vals)), "std": float(np.std(vals))}
    agg["per_class_f1"] = {c: float(np.mean([f["per_class_f1"][c] for f in per_fold])) for c in labels}
    agg["support"] = {c: int((y == c).sum()) for c in labels}
    return agg


def matrix(df: pd.DataFrame, cols):
    X = df[cols].to_numpy(dtype=np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=np.finfo(np.float32).max / 2, neginf=0.0)
    return X, df["label"].to_numpy(dtype=object)


def run_main(out: str) -> None:
    fl = add_flag_presence(load("flowlite"))
    fl_all = numeric_cols(fl)
    fl_all = [c for c in fl_all if not c.endswith("_seen")]
    sets = {
        "FlowLite (all)": (fl, fl_all),
        "FlowLite (no TTL)": (fl, [c for c in fl_all if not c.startswith("ttl_")]),
        "FlowLite prototype subset": (fl, PROTO43),
        "NetFlow-observable subset": (fl, NETFLOW_OBSERVABLE),
    }
    nf = load("nfstream")
    sets["NFStream (statistical)"] = (nf, numeric_cols(nf))
    cic = load("cic")
    sets["CICFlowMeter (CIC CSV)"] = (cic, numeric_cols(cic))
    results = {}
    for name, (df, cols) in sets.items():
        X, y = matrix(df, cols)
        for m in ("RF", "ET"):
            t0 = time.perf_counter()
            r = cross_validate(X, y, m)
            r["n_features"] = len(cols)
            r["n_flows"] = int(len(y))
            r["features"] = cols
            results[f"{name} | {m}"] = r
            print(f"{name:32s} {m}  macroF1={r['macro_f1']['mean']:.4f}±{r['macro_f1']['std']:.4f} "
                  f"FPR={r['benign_fpr']['mean']:.5f} n={len(y)} d={len(cols)} "
                  f"({time.perf_counter() - t0:.0f}s)", flush=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=1)
    # Robustness: exact duplicates (identical feature vector and label) inflate
    # cross-validated scores because copies land in both train and test folds.
    for name in ("FlowLite (all)", "NFStream (statistical)", "CICFlowMeter (CIC CSV)"):
        df, cols = sets[name]
        dd = df[cols + ["label"]].drop_duplicates()
        X, y = matrix(dd, cols)
        r = cross_validate(X, y, "RF")
        r["n_features"] = len(cols)
        r["n_flows"] = int(len(y))
        r["n_before_dedup"] = int(len(df))
        results[f"{name} dedup | RF"] = r
        print(f"{name:32s} dedup RF macroF1={r['macro_f1']['mean']:.4f} n={len(y)}/{len(df)}", flush=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1)
    # CIC features scored against CIC's own published labels, for reference.
    Xc, _ = matrix(cic, numeric_cols(cic))
    yc = cic["cic_label"].to_numpy(dtype=object)
    for m in ("RF",):
        r = cross_validate(Xc, yc, m)
        r["n_features"] = len(numeric_cols(cic))
        results[f"CICFlowMeter (CIC CSV, CIC labels) | {m}"] = r
        print(f"CIC with CIC labels {m} macroF1={r['macro_f1']['mean']:.4f}", flush=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)


def run_ablation(out: str) -> None:
    fl = load("flowlite")
    fl_all = numeric_cols(fl)
    results = {}
    X, y = matrix(fl, fl_all)
    results["all"] = cross_validate(X, y, "ET")
    print("all", results["all"]["macro_f1"], flush=True)
    for g, cols in GROUPS.items():
        keep = [c for c in fl_all if c not in set(cols)]
        X, y = matrix(fl, keep)
        r = cross_validate(X, y, "ET")
        r["dropped"] = cols
        results[f"without {g}"] = r
        print(f"without {g:16s} macroF1={r['macro_f1']['mean']:.4f}", flush=True)
        only = [c for c in cols if c in fl_all]
        X, y = matrix(fl, only)
        r2 = cross_validate(X, y, "ET")
        results[f"only {g}"] = r2
        print(f"only    {g:16s} macroF1={r2['macro_f1']['mean']:.4f}", flush=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1)


def run_importance(out: str) -> None:
    fl = load("flowlite")
    cols = numeric_cols(fl)
    X, y = matrix(fl, cols)
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=0).fit(X, y)
    imp = sorted(zip(cols, clf.feature_importances_.tolist()), key=lambda t: -t[1])
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(imp, fh, indent=1)
    for c, v in imp[:20]:
        print(f"{c:24s} {v:.4f}")


if __name__ == "__main__":
    {"main": run_main, "ablation": run_ablation, "importance": run_importance}[sys.argv[1]](sys.argv[2])
