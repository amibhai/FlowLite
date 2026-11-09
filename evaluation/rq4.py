"""RQ4: how extractor semantics shape the generated dataset.

1. Direction consistency: among flows the shared rules attribute to an attack,
   the share whose forward endpoint is the attack's initiator (the attacker for
   DoS/DDoS/scan/Heartbleed; the infected host for the botnet, which calls out
   to its C&C server). Measured for FlowLite and for CIC's CICFlowMeter flows.
2. CIC flows that CIC labels BENIGN but the rules attribute to an attack, and
   how many of them are direction-reversed.
3. TCP appendix suppression: segments absorbed by the teardown grace period,
   and records emitted with the grace period disabled.

Usage: python rq4.py <out.json>
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import json
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, paths.HERE)
from label import BOT_VICTIMS, NAT  # noqa: E402

TABLES = paths.TABLES
OUT = paths.OUT


def initiator_ok(label: pd.Series, src: pd.Series) -> np.ndarray:
    bot = label.to_numpy() == "Bot"
    s = src.to_numpy(dtype=object)
    return np.where(bot, np.isin(s, list(BOT_VICTIMS)), s == NAT)


def direction(df: pd.DataFrame, label_col: str = "label") -> dict:
    att = df[df[label_col] != "BENIGN"]
    ok = initiator_ok(att[label_col], att["id_src_ip"])
    per = {}
    for lab, g in att.assign(ok=ok).groupby(label_col):
        per[lab] = {"n": int(len(g)), "initiator_forward": float(g["ok"].mean())}
    return {"n": int(len(att)), "initiator_forward": float(ok.mean()), "per_class": per}


def main() -> None:
    out = sys.argv[1]
    res = {}
    fl = pd.read_parquet(os.path.join(TABLES, "flowlite.parquet"), columns=["label", "id_src_ip", "day"])
    cic = pd.read_parquet(os.path.join(TABLES, "cic.parquet"), columns=["label", "cic_label", "id_src_ip", "day"])
    res["flowlite_direction"] = direction(fl)
    res["cic_direction"] = direction(cic)

    disagree = cic[(cic["cic_label"] == "BENIGN") & (cic["label"] != "BENIGN")]
    rev = ~initiator_ok(disagree["label"], disagree["id_src_ip"])
    res["cic_benign_but_rule_attack"] = {
        "n": int(len(disagree)),
        "reversed": int(rev.sum()),
        "per_class": {lab: {"n": int(len(g)), "reversed": int((~initiator_ok(g["label"], g["id_src_ip"])).sum())}
                      for lab, g in disagree.groupby("label")},
    }
    res["cic_attack_but_rule_benign"] = int(((cic["cic_label"] != "BENIGN") & (cic["label"] == "BENIGN")).sum())

    app = {}
    for day in ("fri", "wed"):
        with_grace = json.load(open(os.path.join(OUT, f"fl_{day}.json"), encoding="utf-8"))
        without = json.load(open(os.path.join(OUT, f"fl_{day}_nograce.json"), encoding="utf-8"))
        app[day] = {
            "flows_with_grace": with_grace["flows"],
            "flows_without_grace": without["flows"],
            "absorbed_segments": with_grace["table_stats"]["absorbed_after_teardown"],
            "extra_records_without_grace": without["flows"] - with_grace["flows"],
            "teardown_records": with_grace["expiry_reasons"].get("teardown", 0),
        }
    res["appendix"] = app
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
