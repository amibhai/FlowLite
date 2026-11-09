"""Does absorbing teardown tails change detection? (RQ4)

Random forest on FlowLite's features extracted with the teardown grace period disabled,
with exactly the labels, features and protocol of `ml.py main` (stratified 5-fold CV,
seed 0), plus the same de-duplicated re-run. The with-grace results are in ml_main.json.

Usage: python ml_nograce.py <out.json>
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ml  # noqa: E402


def main(out: str) -> None:
    base = ml.add_flag_presence(ml.load("flowlite"))
    cols = [c for c in ml.numeric_cols(base) if not c.endswith("_seen")]  # the same 74 inputs
    del base
    df = ml.add_flag_presence(ml.load("flowlite_nograce"))
    results = {}
    X, y = ml.matrix(df, cols)
    r = ml.cross_validate(X, y, "RF")
    r.update(n_features=len(cols), n_flows=int(len(y)), features=cols)
    results["FlowLite (all), no grace | RF"] = r
    print("no grace RF macroF1=%.4f FPR=%.5f n=%d" % (r["macro_f1"]["mean"], r["benign_fpr"]["mean"], len(y)),
          flush=True)
    dd = df[cols + ["label"]].drop_duplicates()
    X, y = ml.matrix(dd, cols)
    r = ml.cross_validate(X, y, "RF")
    r.update(n_features=len(cols), n_flows=int(len(y)), n_before_dedup=int(len(df)))
    results["FlowLite (all), no grace dedup | RF"] = r
    print("no grace dedup RF macroF1=%.4f n=%d/%d" % (r["macro_f1"]["mean"], len(y), len(df)), flush=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
