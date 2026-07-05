from pathlib import Path

import numpy as np
import pandas as pd

from utils.csv_writer import append_rows


class HostProfileAggregator:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.window_min = cfg.aggregation.host_profile_window_min

    def aggregate(
        self, flows_df: pd.DataFrame, output_path: Path
    ) -> pd.DataFrame:
        if flows_df.empty:
            self.log.warning("Aggregator: empty flows DataFrame, skipping")
            return pd.DataFrame()

        df = flows_df.copy()
        df["ts"] = pd.to_datetime(df["ts_start"], unit="s")
        df["window"] = df["ts"].dt.floor(f"{self.window_min}min")

        window_totals = (
            df.groupby("window")
            .apply(
                lambda g: pd.Series({
                    "net_total_flows":  len(g),
                    "net_total_bytes":  int(g["n_fwd_bytes"].sum() + g["n_bwd_bytes"].sum()),
                    "net_unique_ports": g["dst_port"].nunique(),
                })
            )
            .reset_index()
        )

        profiles = []
        for (window, src_ip), grp in df.groupby(["window", "src_ip"]):
            n = len(grp)
            wt_rows = window_totals[window_totals["window"] == window]
            wt = wt_rows.iloc[0] if len(wt_rows) else None

            net_total_flows  = int(wt["net_total_flows"])  if wt is not None else 1
            net_total_bytes  = int(wt["net_total_bytes"])  if wt is not None else 1
            net_unique_ports = int(wt["net_unique_ports"]) if wt is not None else 1

            total_bytes_out = int(grp["n_fwd_bytes"].sum())
            total_bytes_in  = int(grp["n_bwd_bytes"].sum())
            total_bytes     = total_bytes_out + total_bytes_in
            this_ports      = grp["dst_port"].nunique()

            row = {
                "window_start":           window,
                "src_ip":                 src_ip,
                "n_flows":                n,
                "n_packets_fwd":          int(grp["n_fwd_pkts"].sum()),
                "n_packets_bwd":          int(grp["n_bwd_pkts"].sum()),
                "n_bytes_fwd":            total_bytes_out,
                "n_bytes_bwd":            total_bytes_in,
                "dir_ratio_bytes":        total_bytes_out / (total_bytes_in + 1e-9),
                "unique_dest_ip_count":   grp["dst_ip"].nunique(),
                "unique_dest_port_count": this_ports,
                "unique_dest_asn_count":  grp["dst_asn"].nunique(),
                "global_flow_share":      n / max(net_total_flows, 1),
                "global_byte_share":      total_bytes / max(net_total_bytes, 1),
                "global_port_share":      this_ports / max(net_unique_ports, 1),
                "tcp_ratio":              float((grp["ip_proto"] == 6).mean()),
                "udp_ratio":              float((grp["ip_proto"] == 17).mean()),
                "icmp_ratio":             float((grp["ip_proto"] == 1).mean()),
                "ttl_mean":               float(grp["ip_ttl_mean"].mean()),
                "ttl_std":                float(grp["ip_ttl_std"].mean()),
                "flow_iat_mean":          float(grp["flow_iat_mean"].mean()),
                "flow_iat_std":           float(grp["flow_iat_std"].mean()),
                "flow_iat_max":           float(grp["flow_iat_max"].max()),
                "fwd_iat_mean":           float(grp["fwd_iat_mean"].mean()),
                "fwd_iat_std":            float(grp["fwd_iat_std"].mean()),
                "fwd_iat_max":            float(grp["fwd_iat_max"].max()),
                "bwd_iat_mean":           float(grp["bwd_iat_mean"].mean()),
                "bwd_iat_std":            float(grp["bwd_iat_std"].mean()),
                "bwd_iat_max":            float(grp["bwd_iat_max"].max()),
                "fwd_pkt_len_mean":       float(grp["fwd_pkt_len_mean"].mean()),
                "fwd_pkt_len_std":        float(grp["fwd_pkt_len_std"].mean()),
                "fwd_pkt_len_max":        float(grp["fwd_pkt_len_max"].max()),
                "bwd_pkt_len_mean":       float(grp["bwd_pkt_len_mean"].mean()),
                "bwd_pkt_len_std":        float(grp["bwd_pkt_len_std"].mean()),
                "bwd_pkt_len_max":        float(grp["bwd_pkt_len_max"].max()),
                "pkt_len_variance":       float(grp["pkt_len_variance"].mean()),
                "init_win_bytes_fwd":     float(grp["init_win_bytes_fwd"].mean()),
                "init_win_bytes_bwd":     float(grp["init_win_bytes_bwd"].mean()),
                "min_seg_size_forward":   float(grp["min_seg_size_forward"].mean()),
                "flow_duration_mean":     float(grp["flow_duration"].mean()),
                "active_time_mean":       float(grp["active_time_mean"].mean()),
                "idle_time_mean":         float(grp["idle_time_mean"].mean()),
                "syn_flag_ratio":         float(grp["syn_flag_ratio"].mean()),
                "ack_flag_ratio":         float(grp["ack_flag_ratio"].mean()),
                "fin_flag_ratio":         float(grp["fin_flag_ratio"].mean()),
                "rst_flag_ratio":         float(grp["rst_flag_ratio"].mean()),
                "psh_flag_ratio":         float(grp["psh_flag_ratio"].mean()),
                "urg_flag_ratio":         float(grp["urg_flag_ratio"].mean()),
            }
            profiles.append(row)

        result = pd.DataFrame(profiles)
        result.replace([np.inf, -np.inf], 0.0, inplace=True)
        result.fillna(0.0, inplace=True)

        append_rows(
            output_path,
            result.to_dict("records"),
            list(result.columns),
        )
        self.log.info(
            "host_profiles: %d rows, %d cols → %s",
            len(result), len(result.columns), output_path,
        )
        return result
