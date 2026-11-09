"""Generate paper/numbers.tex from the measured results.

Every quantitative statement in the paper is a macro defined here, computed
from the JSON files the experiments wrote, so no number is transcribed by hand.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import glob
import json
import math
import os
import platform
import sys

import pandas as pd

sys.path.insert(0, paths.FLOWLITE_SRC)
from flowlite.flow.schema import FLOW_FIELDS  # noqa: E402

RES = paths.RESULTS
OUTD = paths.OUT
TEX = os.path.join(paths.PAPER, "numbers.tex")

macros: dict[str, str] = {}


def m(name: str, value) -> None:
    macros[name] = str(value)


def fmt_int(n: int) -> str:
    return f"{int(n):,}".replace(",", "{,}")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---- schema --------------------------------------------------------------- #
IDENT = {"flow_id", "device", "capture_file", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
         "protocol_name", "ip_version", "vlan_id", "start_time", "end_time", "start_epoch", "end_epoch",
         "expiry_reason"}
CATEG = {"tcp_state", "src_scope", "dst_scope", "dst_asn", "dst_asn_org", "dst_country"}
numeric = [c for c in FLOW_FIELDS if c not in IDENT and c not in CATEG]
m("FLcolumns", len(FLOW_FIELDS))
m("FLident", len(IDENT))
m("FLcateg", len(CATEG))
m("FLnumeric", len(numeric))
m("FLnumericPlusProto", len(numeric) + 1)
assert len(FLOW_FIELDS) == len(IDENT) + len(CATEG) + len(numeric)

# ---- environment ---------------------------------------------------------- #
import sklearn  # noqa: E402

m("SKversion", sklearn.__version__)
m("PYversion", platform.python_version())
m("CPUname", "Intel Core i9-12900H")
m("RAMgb", 16)

# ---- RQ1 ------------------------------------------------------------------ #
ref = load(os.path.join(RES, "refcheck.json"))
assert ref["comparisons"] == ref["within_tolerance"] and ref["only_ref"] == ref["only_flowlite"] == 0
m("RefValues", fmt_int(ref["comparisons"]))
m("RefFlows", fmt_int(ref["common_flows"]))
m("RefFeatures", ref["features_compared"])
m("RefPktsK", fmt_int(round(ref["flowlite_packets"] / 1000)))
m("RefPktsRaw", fmt_int(ref["ref_packets"]))
m("Ntests", load(os.path.join(RES, "tests.json"))["collected"])
enc = load(os.path.join(RES, "encap.json"))
assert all(v["same_flow_ids"] and v["differing_values"] == 0 for v in enc["framings"].values())
WORDS = {2: "two", 7: "seven", 9: "nine"}
link = [v for v in enc["framings"].values() if v["format"] == "pcap"]
m("EncapN", WORDS.get(len(enc["framings"]), len(enc["framings"])))
m("EncapLinkN", WORDS.get(len(link), len(link)))
m("EncapFmtN", WORDS.get(len(enc["framings"]) - len(link), len(enc["framings"]) - len(link)))
m("EncapFields", enc["fields_compared"])
m("EncapFlows", fmt_int(enc["flows"]))
m("EncapPktsK", fmt_int(round(enc["packets"] / 1000)))
m("FLbytesPerFlow", fmt_int(round(load(os.path.join(RES, "mem_per_flow.json"))["bytes_per_flow"])))
m("FLtableCapMB", round(250_000 * load(os.path.join(RES, "mem_per_flow.json"))["bytes_per_flow"] / 2**20))

# ---- datasets --------------------------------------------------------------- #
days = {"fri": "Friday-WorkingHours", "wed": "Wednesday-workingHours"}
ext = {d: load(os.path.join(RES, "fullday", f"fl_{d}.json")) for d in days}
tot_pkts = sum(e["packets_total"] for e in ext.values())
tot_bytes = sum(e["pcap_bytes"] for e in ext.values())
m("TotPktsM", f"{tot_pkts / 1e6:.1f}")
m("TotGB", f"{tot_bytes / 1e9:.1f}")
for d, e in ext.items():
    m(f"Pkts{d.capitalize()}", fmt_int(e["packets_total"]))
    m(f"Flows{d.capitalize()}", fmt_int(e["flows"]))

# ---- RQ2 ------------------------------------------------------------------ #
def best(path):
    d = load(path)
    ok = [r for r in d["runs"] if r["returncode"] == 0]
    if not ok:
        return None
    r = min(ok, key=lambda r: r["wall_s"])
    return {"wall": r["wall_s"], "peak": max(x["peak_rss_mb"] for x in ok), "child": r["child"],
            "pcap_bytes": d["pcap_bytes"]}


bench = {}
for p in glob.glob(os.path.join(RES, "bench", "*.json")):
    tool, run = os.path.basename(p)[:-5].split("__")
    bench[(tool, run)] = best(p)

LABEL = {"flowlite": "FlowLite 2.1 (CPython 3.14)", "flowlite_py312": "FlowLite 2.1 (CPython 3.12)",
         "prototype": "FlowLite prototype", "nfstream": "NFStream 6.6",
         "cicflowmeter_py": "CICFlowMeter port"}
SLICES = [("fri_250k", 250_000), ("fri_1000k", 1_000_000), ("fri_4000k", 4_000_000)]
FULL = [("full_Friday-WorkingHours", ext["fri"]["packets_total"]),
        ("full_Wednesday-workingHours", ext["wed"]["packets_total"])]


def cell(tool, run, pkts):
    b = bench.get((tool, run))
    if b is None:
        return ["--", "--"]
    if b["child"].get("flows", 1) == 0:
        # The prototype cannot read pcapng: it exits at once with no flows.
        return ["\\multicolumn{2}{c}{fails\\textsuperscript{a}}"]
    k = pkts / b["wall"] / 1e3
    # one decimal below 10 kpps, so ratios quoted in the text can be checked against the table
    return [f"{k:.1f}" if k < 10 else f"{k:.0f}", fmt_int(round(b["peak"]))]


head = ["\\begin{tabular}{@{}l" + "rr" * (len(SLICES) + len(FULL)) + "@{}}", "\\toprule"]
cols = [f"{n // 1000}k pkts" if n < 1e6 else f"{n / 1e6:g}M pkts" for _r, n in SLICES]
cols += ["Fri (full)", "Wed (full)"]
head.append(" & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{c}}}" for c in cols) + " \\\\")
head.append("".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(cols))))
head.append("Extractor & " + " & ".join(["kpps & MiB"] * len(cols)) + " \\\\")
head.append("\\midrule")
rows = []
LABEL["flowlite_pypy"] = "FlowLite 2.1 (PyPy 3.11)"
for tool in ("flowlite", "flowlite_py312", "flowlite_pypy", "prototype", "nfstream",
             "cicflowmeter_py"):
    vals = []
    for run, n in SLICES + FULL:
        vals.extend(cell(tool, run, n))
    rows.append(LABEL[tool] + " & " + " & ".join(vals) + " \\\\")
tail = ["\\bottomrule",
        "\\multicolumn{11}{@{}l}{\\textsuperscript{a}\\,reads classic pcap only; the CIC-IDS2017 "
        "captures are pcapng} \\\\",
        "\\end{tabular}"]
macros["PerfTable"] = "\n".join(head + rows + tail)

def kpps(tool, run, n):
    b = bench.get((tool, run))
    return n / b["wall"] / 1e3 if b else None


def peak(tool, run):
    b = bench.get((tool, run))
    return b["peak"] if b else None


for tool, tag in (("flowlite", "FL"), ("flowlite_py312", "FLtw"), ("flowlite_pypy", "PYPY"),
                  ("nfstream", "NF"), ("prototype", "PROTO")):
    v = kpps(tool, "fri_4000k", 4_000_000)
    if v:
        m(f"{tag}kppsFour", f"{v:.0f}")
        m(f"{tag}memFour", fmt_int(round(peak(tool, "fri_4000k"))))
v = kpps("cicflowmeter_py", "fri_1000k", 1_000_000)
if v:
    m("CICPYkppsOne", f"{v:.1f}")
    m("CICPYmemOne", fmt_int(round(peak("cicflowmeter_py", "fri_1000k"))))
    m("FLoverCICPY", f"{kpps('flowlite', 'fri_1000k', 1_000_000) / v:.0f}")
fl_mems = [peak("flowlite", r) for r, _n in SLICES + [("fri_500k", 0), ("fri_2000k", 0)] if peak("flowlite", r)]
if fl_mems:
    m("FLmemMin", f"{min(fl_mems):.0f}")
    m("FLmemMax", f"{max(fl_mems):.0f}")
if peak("prototype", "fri_4000k") and peak("flowlite", "fri_4000k"):
    m("PROTOoverFLmem", f"{peak('prototype', 'fri_4000k') / peak('flowlite', 'fri_4000k'):.0f}")
    m("NFoverFLmem", f"{peak('nfstream', 'fri_4000k') / peak('flowlite', 'fri_4000k'):.1f}")
par_path = os.path.join(RES, "parallel.json")
if os.path.exists(par_path):
    par = load(par_path)["runs"]
    best_par = max(par, key=lambda r: r["kpps"])
    m("ParBestKpps", f"{best_par['kpps']:.0f}")
    m("ParBestN", best_par["processes"])
    one = [r for r in par if r["processes"] == 1][0]
    eight = [r for r in par if r["processes"] == 8]
    if eight:
        m("ParEightKpps", f"{eight[0]['kpps']:.0f}")
        m("ParEightSpeedup", f"{eight[0]['kpps'] / one['kpps']:.1f}")
    rows = " & ".join(str(r["processes"]) for r in par)
    m("ParTable", rows)

for tool, tag in (("nfstream", "NF"), ("flowlite_pypy", "PYPY")):
    full = [bench.get((tool, r)) for r, _ in FULL]
    if all(full):
        rates = [n / b["wall"] / 1e3 for (_r, n), b in zip(FULL, full)]
        m(f"{tag}kppsFull", f"{min(rates):.0f}--{max(rates):.0f}")
        m(f"{tag}peakFullMax", fmt_int(round(max(b["peak"] for b in full))))
proto_full = bench.get(("prototype", "full_Friday-WorkingHours"))
if proto_full is not None:
    m("PROTOfullFlows", proto_full["child"].get("flows", 0))

# OS-recorded peak working set (psutil peak_wset) of the final-code full-day extractions;
# the benchmark's 20 ms sampling can miss short peaks.
wset = [load(os.path.join(RES, "fullday", f"final_fl_{d}.json"))["peak_mb"] for d in ("fri", "wed")]
m("FLwsetMax", str(math.ceil(max(wset))))  # an upper bound, so round up
# range over the CPython 3.14 cells of Table 3, so the text can be checked against the table
fl_rates = [kpps("flowlite", r, n) for r, n in SLICES + FULL if kpps("flowlite", r, n)]
m("FLkppsMin", f"{min(fl_rates):.0f}")
m("FLkppsMax", f"{max(fl_rates):.0f}")
nf_full = [kpps("nfstream", r, n) for r, n in FULL]
fl_full_rates = [kpps("flowlite", r, n) for r, n in FULL]
if all(nf_full) and all(fl_full_rates):
    ratios = [a / b for a, b in zip(nf_full, fl_full_rates)]
    m("NFoverFLfull", f"{min(ratios):.1f}--{max(ratios):.1f}")
m("FLvsNFfourPct",
  f"{100 * (1 - kpps('flowlite', 'fri_4000k', 4e6) / kpps('nfstream', 'fri_4000k', 4e6)):.0f}")

fl_full = [bench.get(("flowlite", r)) for r, _ in FULL]
if all(fl_full):
    rates_full = [n / b["wall"] / 1e3 for (_r, n), b in zip(FULL, fl_full)]
    m("FLkppsFull", f"{min(rates_full):.0f}--{max(rates_full):.0f}")
    m("FLpeakFullMax", f"{max(b['peak'] for b in fl_full):.0f}")

for tool, mac in (("flowlite", "FLcolsRun"), ("prototype", "PROTOcols"), ("nfstream", "NFcols"),
                  ("cicflowmeter_py", "CICPYcols")):
    b = bench.get((tool, "fri_250k"))
    if b is not None:
        m(mac, b["child"]["columns"])
cic_tab = pd.read_parquet(os.path.join(paths.TABLES, "cic.parquet"), columns=["label", "cic_label"])
m("CICcols", 85)  # TrafficLabelling CSV: Flow ID, 5-tuple, Timestamp, 77 features, Label
att = cic_tab[cic_tab["cic_label"] != "BENIGN"]
m("RuleRecall", f"{100 * (att['label'] == att['cic_label']).mean():.3f}")
m("CICflowsTot", fmt_int(len(cic_tab)))

flood = {}
for p in glob.glob(os.path.join(RES, "bench", "*__flood.json")):
    tool = os.path.basename(p).split("__")[0]
    d = load(p)
    r = d["runs"][0]
    flood[tool] = {"rc": r["returncode"], "peak": r["peak_rss_mb"], "wall": r["wall_s"], "child": r["child"]}
FLOOD_TAGS = {"flowlite_cap50k": "FLsmall", "flowlite_cap250k": "FLdefault", "nfstream": "NF",
              "prototype": "PROTO"}
for tool, rec in flood.items():
    tag = FLOOD_TAGS[tool]
    m(f"Flood{tag}Peak", fmt_int(round(rec["peak"])))
    m(f"Flood{tag}Kpps", f"{2_000_000 / rec['wall'] / 1e3:.1f}")
    m(f"Flood{tag}Wall", f"{rec['wall']:.0f}")
m("FloodPktsM", 2)
m("FloodCapK", 50)

# ---- RQ3 ------------------------------------------------------------------ #
ml_path = os.path.join(RES, "ml_main.json")
if os.path.exists(ml_path):
    ml = load(ml_path)
    SETS = [("FlowLite (all)", "FlowLite, all numeric"),
            ("FlowLite (no TTL)", "FlowLite, without TTL"),
            ("FlowLite prototype subset", "FlowLite, prototype subset"),
            ("NetFlow-observable subset", "FlowLite, NetFlow-observable"),
            ("NFStream (statistical)", "NFStream, statistical"),
            ("CICFlowMeter (CIC CSV)", "CICFlowMeter (CIC CSV)")]

    def mf(key):
        r = ml[key]["macro_f1"]
        return f"{r['mean']:.3f}", f"{r['std']:.3f}"

    def macro8(r):
        """Macro-F1 over the eight classes other than Heartbleed (5-12 flows).

        Equal to the fold mean of the per-fold 8-class macro-F1, because both
        are plain means over classes and folds."""
        pc = {c: v for c, v in r["per_class_f1"].items() if c != "Heartbleed"}
        return sum(pc.values()) / len(pc)

    lines = ["\\begin{tabular}{@{}lrrcccrr@{}}", "\\toprule",
             "& & & \\multicolumn{2}{c}{RF macro-F1} & ET & \\multicolumn{2}{c}{RF} \\\\",
             "\\cmidrule(lr){4-5}\\cmidrule(lr){7-8}",
             "Feature set & $d$ & Flows & 9 classes & 8 classes & 8 cl. & FPR & DR \\\\",
             "\\midrule"]
    for key, label in SETS:
        rf, et = ml[f"{key} | RF"], ml[f"{key} | ET"]
        lines.append(
            f"{label} & {rf['n_features']} & {rf['n_flows'] / 1e6:.2f}M & "
            f"{rf['macro_f1']['mean']:.3f}\\,$\\pm$\\,{rf['macro_f1']['std']:.3f} & "
            f"{macro8(rf):.4f} & {macro8(et):.4f} & "
            f"{100 * rf['benign_fpr']['mean']:.3f}\\,\\% & {100 * rf['attack_dr']['mean']:.2f}\\,\\% \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    macros["DetTable"] = "\n".join(lines)
    for key, tag in (("FlowLite (all) | RF", "FL"), ("CICFlowMeter (CIC CSV) | RF", "CIC"),
                     ("NFStream (statistical) | RF", "NF"), ("NetFlow-observable subset | RF", "NFO"),
                     ("FlowLite (no TTL) | RF", "FLnoTTL"), ("FlowLite prototype subset | RF", "PROTO"),
                     ("FlowLite (all) dedup | RF", "FLdedup"), ("CICFlowMeter (CIC CSV) dedup | RF", "CICdedup"),
                     ("NFStream (statistical) dedup | RF", "NFdedup"),
                     ("CICFlowMeter (CIC CSV, CIC labels) | RF", "CICown")):
        if key in ml:
            m(f"{tag}EightMacro", f"{macro8(ml[key]):.4f}")
    for key, tag in (("FlowLite (all) | RF", "FL"), ("CICFlowMeter (CIC CSV) | RF", "CIC"),
                     ("NFStream (statistical) | RF", "NF"), ("NetFlow-observable subset | RF", "NFO"),
                     ("CICFlowMeter (CIC CSV, CIC labels) | RF", "CICown")):
        m(f"{tag}BotFone", f"{ml[key]['per_class_f1']['Bot']:.3f}")
    def macro7(r):  # without Heartbleed and the botnet
        pc = {c: v for c, v in r["per_class_f1"].items() if c not in ("Heartbleed", "Bot")}
        return sum(pc.values()) / len(pc)

    seven = {}
    for key, tag in (("FlowLite (all) | RF", "FL"), ("CICFlowMeter (CIC CSV) | RF", "CIC"),
                     ("NFStream (statistical) | RF", "NF")):
        seven[tag] = macro7(ml[key])
        m(f"{tag}SevenMacro", f"{seven[tag]:.4f}")
    m("SevenSpread", f"{max(seven.values()) - min(seven.values()):.4f}")
    m("SevenLeadCIC", f"{seven['FL'] - seven['CIC']:.4f}")
    m("FLhbFlows", ml["FlowLite (all) | RF"]["support"]["Heartbleed"])
    m("CIChbFlows", ml["CICFlowMeter (CIC CSV) | RF"]["support"]["Heartbleed"])
    m("NFOn", ml["NetFlow-observable subset | RF"]["n_features"])
    m("NFnFeat", ml["NFStream (statistical) | RF"]["n_features"])
    m("CICnFeat", ml["CICFlowMeter (CIC CSV) | RF"]["n_features"])
    m("PROTOnFeat", ml["FlowLite prototype subset | RF"]["n_features"])
    for name, tag in (("FlowLite (all)", "FL"), ("NFStream (statistical)", "NF"),
                      ("CICFlowMeter (CIC CSV)", "CIC")):
        k = f"{name} dedup | RF"
        if k in ml:
            m(f"{tag}dedupMacro", f"{ml[k]['macro_f1']['mean']:.3f}")
            m(f"{tag}dedupKept", f"{100 * ml[k]['n_flows'] / ml[k]['n_before_dedup']:.1f}")
    for key, tag in (("FlowLite (all) | RF", "FL"), ("CICFlowMeter (CIC CSV) | RF", "CIC"),
                     ("NFStream (statistical) | RF", "NF"), ("NetFlow-observable subset | RF", "NFO"),
                     ("FlowLite (no TTL) | RF", "FLnoTTL")):
        m(f"{tag}rfStd", f"{ml[key]['macro_f1']['std']:.3f}")
        m(f"{tag}rfFPR", f"{100 * ml[key]['benign_fpr']['mean']:.3f}")
    for key, mac in (("FlowLite (all) | RF", "FLrfMacro"), ("CICFlowMeter (CIC CSV) | RF", "CICrfMacro"),
                     ("NFStream (statistical) | RF", "NFrfMacro"), ("NetFlow-observable subset | RF", "NFOrfMacro"),
                     ("FlowLite (no TTL) | RF", "FLnoTTLrfMacro"), ("FlowLite prototype subset | RF", "PROTOrfMacro"),
                     ("FlowLite (all) | ET", "FLetMacro")):
        m(mac, f"{ml[key]['macro_f1']['mean']:.3f}")
    ref_key = "CICFlowMeter (CIC CSV, CIC labels) | RF"
    if ref_key in ml:
        m("CICownLabelsMacro", f"{ml[ref_key]['macro_f1']['mean']:.3f}")
    # per-class F1 (RF)
    classes = list(ml["FlowLite (all) | RF"]["per_class_f1"].keys())
    pcs = [("FlowLite (all) | RF", "FlowLite"), ("NetFlow-observable subset | RF", "NetFlow-obs."),
           ("NFStream (statistical) | RF", "NFStream"), ("CICFlowMeter (CIC CSV) | RF", "CICFlowMeter")]
    pl = ["\\begin{tabular}{@{}l" + "rr" * len(pcs) + "@{}}", "\\toprule",
          "& " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{lab}}}" for _k, lab in pcs) + " \\\\",
          "".join(f"\\cmidrule(lr){{{2 + 2 * i}-{3 + 2 * i}}}" for i in range(len(pcs))),
          "Class & " + " & ".join(["flows & F1"] * len(pcs)) + " \\\\", "\\midrule"]
    for c in classes:
        cells = []
        for k, _lab in pcs:
            cells += [fmt_int(ml[k]["support"].get(c, 0)), f"{ml[k]['per_class_f1'].get(c, 0):.3f}"]
        pl.append(f"{c} & " + " & ".join(cells) + " \\\\")
    pl += ["\\bottomrule", "\\end{tabular}"]
    macros["ClassTable"] = "\n".join(pl)

# RQ4: detection with the teardown grace period disabled (ml_nograce.py)
ng_path = os.path.join(RES, "ml_nograce.json")
if os.path.exists(ng_path):
    ng = load(ng_path)

    def eight(r):  # macro-F1 over the eight classes other than Heartbleed
        pc = {c: v for c, v in r["per_class_f1"].items() if c != "Heartbleed"}
        return sum(pc.values()) / len(pc)

    r = ng["FlowLite (all), no grace | RF"]
    m("NoGraceEightMacro", f"{eight(r):.4f}")
    m("NoGraceFPR", f"{100 * r['benign_fpr']['mean']:.3f}")
    m("NoGraceBotFone", f"{r['per_class_f1']['Bot']:.3f}")
    m("NoGraceFlows", fmt_int(r["n_flows"]))
    rd = ng["FlowLite (all), no grace dedup | RF"]
    m("NoGraceDedupEightMacro", f"{eight(rd):.4f}")
    m("NoGraceDedupKept", f"{100 * rd['n_flows'] / rd['n_before_dedup']:.1f}")

abl_path = os.path.join(RES, "ml_ablation.json")
if os.path.exists(abl_path):
    ab = load(abl_path)

    def m8(r):
        pc = {c: v for c, v in r["per_class_f1"].items() if c != "Heartbleed"}
        return sum(pc.values()) / len(pc)

    base8 = m8(ab["all"])
    m("AblEightAll", f"{base8:.4f}")
    drops = {k[len("without "):]: base8 - m8(v) for k, v in ab.items() if k.startswith("without ")}
    m("AblMaxDrop", f"{max(drops.values()):.4f}")
    m("AblMaxDropGroup", max(drops, key=drops.get))
    for g, tag in (("volume & rates", "Volume"), ("inter-arrival", "IAT"), ("TCP handshake", "Hs"),
                   ("packet size", "Size"), ("burst/idle", "Burst"), ("TCP flags", "Flags"),
                   ("IP layer", "IP")):
        m(f"AblOnly{tag}", f"{m8(ab[f'only {g}']):.3f}")
    m("AblIPBot", f"{ab['only IP layer']['per_class_f1']['Bot']:.3f}")
    m("AblIPSlowloris", f"{ab['only IP layer']['per_class_f1']['DoS slowloris']:.3f}")
    m("AblIATSlowhttp", f"{ab['only inter-arrival']['per_class_f1']['DoS Slowhttptest']:.3f}")
    m("AblSizeSlowhttp", f"{ab['only packet size']['per_class_f1']['DoS Slowhttptest']:.3f}")
    m("AblAll", f"{ab['all']['macro_f1']['mean']:.3f}")
    for k, v in ab.items():
        if k == "all":
            continue
        tag = "".join(w.capitalize() for w in k.replace("&", "and").replace("/", " ").split())
        m("Abl" + "".join(ch for ch in tag if ch.isalpha()), f"{v['macro_f1']['mean']:.3f}")

rq4_path = os.path.join(RES, "rq4.json")
if os.path.exists(rq4_path):
    r4 = load(rq4_path)
    m("FLdirOK", f"{100 * r4['flowlite_direction']['initiator_forward']:.1f}")
    m("CICdirOK", f"{100 * r4['cic_direction']['initiator_forward']:.1f}")
    cb = r4["cic_benign_but_rule_attack"]
    m("CICbenignRuleAttack", fmt_int(cb["n"]))
    m("CICbenignRuleAttackReversed", fmt_int(cb["reversed"]))
    m("CICbenignRuleAttackReversedPct", f"{100 * cb['reversed'] / cb['n']:.1f}")
    ddos = cb["per_class"].get("DDoS", {"n": 0, "reversed": 0})
    m("CICddosBenign", fmt_int(ddos["n"]))
    m("CICddosBenignReversed", fmt_int(ddos["reversed"]))
    for cls, mac in (("DDoS", "CICdirDDoS"), ("Bot", "CICdirBot"), ("DoS Slowhttptest", "FLdirSlowhttp")):
        src = r4["flowlite_direction"] if mac.startswith("FL") else r4["cic_direction"]
        m(mac, f"{100 * src['per_class'][cls]['initiator_forward']:.1f}")
    m("FLbotFlows", fmt_int(r4["flowlite_direction"]["per_class"]["Bot"]["n"]))
    sys.path.insert(0, paths.HERE)
    from rq4 import initiator_ok  # noqa: E402

    flt = pd.read_parquet(os.path.join(paths.TABLES, "flowlite.parquet"),
                          columns=["label", "id_src_ip", "syn_count"])
    att = flt[flt["label"] != "BENIGN"]
    rev = att[~initiator_ok(att["label"], att["id_src_ip"])]
    m("FLdirBadN", fmt_int(len(rev)))
    m("FLdirBadSynPct", f"{100 * (rev['syn_count'] > 0).mean():.0f}")
    top = rev["label"].value_counts()
    m("FLdirBadHulkDDoSPct", f"{100 * (top.get('DoS Hulk', 0) + top.get('DDoS', 0)) / len(rev):.0f}")
    # syn_count counts every SYN-flagged packet, SYN-ACKs included: >= 2 means the
    # record holds both handshake packets.
    m("FLdirBadHandshakePct", f"{100 * (rev['syn_count'] >= 2).mean():.0f}")
    fb = pd.read_parquet(os.path.join(paths.TABLES, "flowlite.parquet"),
                         columns=["label", "id_start_epoch", "total_bytes", "total_packets",
                                  "syn_count", "rst_count"])
    bot = fb[fb["label"] == "Bot"]
    cic_bot = pd.read_parquet(os.path.join(paths.TABLES, "cic.parquet"),
                              columns=["cic_label", "id_start_epoch"])
    last_cic_bot = cic_bot.loc[cic_bot["cic_label"] == "Bot", "id_start_epoch"].max()
    late = bot[bot["id_start_epoch"] > last_cic_bot + 60]  # CIC stamps have minute resolution
    m("FLbotLate", fmt_int(len(late)))
    m("FLbotLatePct", f"{100 * len(late) / len(bot):.0f}")
    m("FLbotLateNoPayloadPct", f"{100 * (late['total_bytes'] == 0).mean():.0f}")
    refused = bot[(bot["total_packets"] == 2) & (bot["syn_count"] >= 1) & (bot["rst_count"] >= 1)]
    m("FLbotRefusedPct", f"{100 * len(refused) / len(bot):.0f}")
    nf_tab = pd.read_parquet(os.path.join(paths.TABLES, "nfstream.parquet"), columns=["label"])
    m("NFbotFlows", fmt_int(int((nf_tab["label"] == "Bot").sum())))
    m("NFflowsTot", fmt_int(len(nf_tab)))
    app = r4["appendix"]
    m("AppWedExtraPct", f"{100 * app['wed']['extra_records_without_grace'] / app['wed']['flows_with_grace']:.1f}")
    m("AppFriExtraPct", f"{100 * app['fri']['extra_records_without_grace'] / app['fri']['flows_with_grace']:.1f}")
    m("AppWedTeardown", fmt_int(app["wed"]["teardown_records"]))
    m("AppWedExtra", fmt_int(app["wed"]["extra_records_without_grace"]))
    absorbed = sum(v["absorbed_segments"] for v in app.values())
    extra = sum(v["extra_records_without_grace"] for v in app.values())
    with_g = sum(v["flows_with_grace"] for v in app.values())
    m("AppAbsorbed", fmt_int(absorbed))
    m("AppExtra", fmt_int(extra))
    m("AppExtraPct", f"{100 * extra / with_g:.1f}")
    m("FlowsTot", fmt_int(with_g))

# ---- write ------------------------------------------------------------------ #
os.makedirs(os.path.dirname(TEX), exist_ok=True)  # paper/ is not shipped with the code
with open(TEX, "w", encoding="utf-8") as fh:
    fh.write("% Generated by make_numbers.py from the measured results. Do not edit.\n")
    for k, v in macros.items():
        fh.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(f"wrote {len(macros)} macros to {TEX}")
