"""
Batch script — runs once per hour.
Reads flows CSV + eapi_poll.csv + iface_counters.csv,
writes 60 rows (one per second-bucket) to network_ts.csv.
"""
import argparse
import sys
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats as sp_stats

warnings.filterwarnings("ignore")


def _find_config():
    for p in [Path("config.yaml"), Path("../config.yaml"), Path("/etc/nids/config.yaml")]:
        if p.exists():
            return str(p)
    return None


def _load_cfg(config_path):
    cfg_path = config_path or _find_config()
    if cfg_path is None:
        return None
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from utils.config_loader import load_config, ConfigError
    try:
        return load_config(cfg_path)
    except ConfigError:
        return None


def _read(path, log_warn=None) -> pd.DataFrame:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        if log_warn:
            log_warn(f"Missing or empty: {p}")
        return pd.DataFrame()
    try:
        return pd.read_csv(p, on_bad_lines="skip")
    except Exception as e:
        if log_warn:
            log_warn(f"Cannot read {p}: {e}")
        return pd.DataFrame()


def _dst_port_entropy(series: pd.Series) -> float:
    if series.empty:
        return 0.0
    vc = series.value_counts(normalize=True)
    return float(sp_stats.entropy(vc.values))


def _build_spine(hour_dt: datetime) -> pd.DataFrame:
    """60 rows for the target hour, one per minute."""
    start = hour_dt.replace(minute=0, second=0, microsecond=0)
    buckets = [start + timedelta(seconds=i * 60) for i in range(60)]
    return pd.DataFrame({"timestamp": buckets})


def build(cfg, hour_dt: datetime, flows_path: str, output_path: str,
          dry_run: bool, warn_fn):

    # ── Step A — load flows ─────────────────────────────────────────
    flows = _read(flows_path, warn_fn)
    if not flows.empty:
        if "ts_start" not in flows.columns:
            warn_fn("flows CSV missing ts_start column")
            flows = pd.DataFrame()
        else:
            flows["bucket_ts"] = (flows["ts_start"] // 60).astype(int) * 60
            flows["bucket_dt"] = pd.to_datetime(flows["bucket_ts"], unit="s", utc=True)
            flows["bucket_dt"] = flows["bucket_dt"].dt.tz_localize(None)

    # ── Step B — aggregate flows per 60s bucket ─────────────────────
    flow_agg = pd.DataFrame()
    if not flows.empty:
        groups = []
        for bucket, grp in flows.groupby("bucket_dt"):
            fwd = grp.get("n_fwd_bytes", pd.Series(dtype=float)).sum()
            bwd = grp.get("n_bwd_bytes", pd.Series(dtype=float)).sum()
            total = fwd + bwd
            n = len(grp)
            syn_no_ack = (
                (grp.get("syn_flag_ratio", pd.Series(0.0)) > 0.9)
                & (grp.get("ack_flag_ratio", pd.Series(0.0)) < 0.1)
            ).sum()

            groups.append({
                "timestamp":            bucket,
                "flows_per_sec":        n / 60.0,
                "bytes_per_sec":        total / 60.0,
                "tcp_ratio":            float((grp.get("ip_proto", pd.Series()) == 6).mean()) if n else 0.0,
                "udp_ratio":            float((grp.get("ip_proto", pd.Series()) == 17).mean()) if n else 0.0,
                "icmp_ratio":           float((grp.get("ip_proto", pd.Series()) == 1).mean()) if n else 0.0,
                "active_src_ips":       grp.get("src_ip", pd.Series()).nunique(),
                "active_dst_ips":       grp.get("dst_ip", pd.Series()).nunique(),
                "dst_port_entropy":     _dst_port_entropy(grp.get("dst_port", pd.Series())),
                "byte_asymmetry":       abs(fwd - bwd) / (total + 1e-9),
                "avg_flow_duration_s":  float(grp.get("flow_duration", pd.Series(0.0)).mean()),
                "syn_no_ack_rate":      syn_no_ack / 60.0,
                "avg_iat_std":          float(grp.get("flow_iat_std", pd.Series(0.0)).mean()),
                "high_rst_rate":        (grp.get("rst_flag_ratio", pd.Series(0.0)) > 0.5).sum() / 60.0,
            })
        flow_agg = pd.DataFrame(groups)

    # ── Step C — eAPI ───────────────────────────────────────────────
    eapi_agg = pd.DataFrame()
    if cfg is not None:
        eapi_df = _read(cfg.paths.eapi_out, warn_fn)
        if not eapi_df.empty and "timestamp" in eapi_df.columns:
            eapi_df["_dt"] = pd.to_datetime(eapi_df["timestamp"], errors="coerce", utc=True)
            eapi_df["_dt"] = eapi_df["_dt"].dt.tz_localize(None)
            eapi_df["_b"]  = eapi_df["_dt"].dt.floor("60s")
            grp = eapi_df.groupby("_b")
            eapi_agg = grp.agg(
                arp_changed_count_net = ("arp_changed_count", "sum"),
                mac_new_count_net     = ("mac_new_count",     "sum"),
                route_delta_max       = ("route_delta",       "max"),
                total_iface_errors    = ("total_iface_errors","sum"),
                total_iface_discards  = ("total_iface_discards","sum"),
                iface_down_count      = ("iface_down_count",  "max"),
            ).reset_index().rename(columns={"_b": "timestamp"})

    # ── Step D — sFlow iface counters ───────────────────────────────
    iface_agg = pd.DataFrame()
    if cfg is not None:
        iface_df = _read(cfg.paths.sflow_out, warn_fn)
        if not iface_df.empty and "timestamp" in iface_df.columns:
            iface_df["_dt"] = pd.to_datetime(iface_df["timestamp"], errors="coerce", utc=True)
            iface_df["_dt"] = iface_df["_dt"].dt.tz_localize(None)
            iface_df["_b"]  = iface_df["_dt"].dt.floor("60s")
            grp = iface_df.groupby("_b")
            iface_agg = grp.agg(
                total_in_bytes_net   = ("in_octets_delta",  "sum"),
                total_out_bytes_net  = ("out_octets_delta", "sum"),
            ).reset_index().rename(columns={"_b": "timestamp"})
            in_err  = iface_df.get("in_errors",  pd.Series(0))
            out_err = iface_df.get("out_errors", pd.Series(0))
            iface_df["_total_err"] = in_err.fillna(0) + out_err.fillna(0)
            err_agg = iface_df.groupby("_b")["_total_err"].sum().reset_index()
            err_agg.columns = ["timestamp", "total_iface_errors_net"]
            iface_agg = iface_agg.merge(err_agg, on="timestamp", how="left")

        # Entropy lookup
        entropy_path = Path(cfg.paths.sflow_out).parent / "entropy_lookup.csv"
        entropy_df = _read(entropy_path, None)
        if not entropy_df.empty and "timestamp" in entropy_df.columns:
            entropy_df["_dt"] = pd.to_datetime(entropy_df["timestamp"], errors="coerce", utc=True)
            entropy_df["_dt"] = entropy_df["_dt"].dt.tz_localize(None)
            entropy_df["_b"]  = entropy_df["_dt"].dt.floor("60s")
            ent_agg = (
                entropy_df.groupby("_b")["payload_entropy"]
                .mean()
                .reset_index()
                .rename(columns={"_b": "timestamp", "payload_entropy": "payload_entropy_mean"})
            )
            if not iface_agg.empty:
                iface_agg = iface_agg.merge(ent_agg, on="timestamp", how="left")
            else:
                iface_agg = ent_agg

    # ── Step E — time spine ─────────────────────────────────────────
    spine = _build_spine(hour_dt)

    def safe_merge(left, right, on="timestamp"):
        if right.empty:
            return left
        return left.merge(right, on=on, how="left")

    result = safe_merge(spine, flow_agg)
    result = safe_merge(result, eapi_agg)
    result = safe_merge(result, iface_agg)

    # Fill numeric NaN with 0
    num_cols = result.select_dtypes(include="number").columns
    result[num_cols] = result[num_cols].fillna(0)

    # ── Step F — append ─────────────────────────────────────────────
    if dry_run:
        print(f"DRY RUN: {len(result)} rows, {len(result.columns)} cols")
        print(result.to_string(max_rows=5))
        return result

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_header = not out.exists()
    result.to_csv(out, mode="a", header=write_header, index=False)
    print(f"network_ts: {len(result)} rows, {len(result.columns)} cols appended to {out}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Build network_ts.csv")
    parser.add_argument("--config",  default=None)
    parser.add_argument("--hour",    default=None,
                        help="YYYYMMDDHH (default: 1 hour ago)")
    parser.add_argument("--flows",   default=None)
    parser.add_argument("--output",  default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cfg = _load_cfg(args.config)

    if args.hour:
        hour_dt = datetime.strptime(args.hour, "%Y%m%d%H")
    else:
        hour_dt = datetime.utcnow() - timedelta(hours=1)

    if args.flows:
        flows_path = args.flows
    elif cfg:
        hour_str = hour_dt.strftime("%Y%m%d_%H00")
        flows_path = str(Path(cfg.paths.flows_dir) / f"{hour_str}_flows.csv")
    else:
        print("ERROR: provide --flows or a valid config.yaml", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = args.output
    elif cfg:
        output_path = cfg.paths.network_ts
    else:
        print("ERROR: provide --output or a valid config.yaml", file=sys.stderr)
        sys.exit(1)

    build(
        cfg=cfg,
        hour_dt=hour_dt,
        flows_path=flows_path,
        output_path=output_path,
        dry_run=args.dry_run,
        warn_fn=lambda m: print(f"WARN: {m}", file=sys.stderr),
    )


if __name__ == "__main__":
    main()
