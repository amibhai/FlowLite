"""Paper figures from measured results (vector PDF, greyscale-safe, >= 6 pt text).

  python figures.py memory   -> paper/figures/memory.pdf   (RQ2)
  python figures.py ablation -> paper/figures/ablation.pdf (RQ3)

Series identity is carried by marker shape, line style and direct labels as
well as by colour, so the figures read in black and white. Colours are the
validated categorical palette, assigned per tool in a fixed order.
"""

from __future__ import annotations

import os  # noqa: F401
import sys  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402

import glob
import json
import os
import sys

import matplotlib

matplotlib.use("pdf")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator  # noqa: E402

RES = paths.RESULTS
FIG = os.path.join(paths.PAPER, "figures")
os.makedirs(FIG, exist_ok=True)  # paper/ is not shipped with the code
MM = 1 / 25.4
INK, MUTED, GRID = "#1f1f1e", "#5e5d58", "#d9d8d2"

# tool -> (label, colour, marker, linestyle); colour follows the tool everywhere.
TOOLS = {
    "flowlite": ("FlowLite 2.1, CPython 3.14", "#2a78d6", "o", "-"),
    "flowlite_pypy": ("FlowLite 2.1, PyPy 3.11", "#e87ba4", "v", (0, (1, 1.2))),
    "nfstream": ("NFStream", "#eb6834", "s", "--"),
    "cicflowmeter_py": ("CICFlowMeter port", "#1baf7a", "^", "-."),
    "prototype": ("FlowLite prototype", "#eda100", "D", ":"),
}

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7,
    "axes.labelsize": 7,
    "axes.titlesize": 7.5,
    "xtick.labelsize": 6.5,
    "ytick.labelsize": 6.5,
    "legend.fontsize": 6.5,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.linewidth": 0.6,
    "pdf.fonttype": 42,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def load_bench():
    """{tool: {packets: (best_wall_s, peak_mb, packets)}} from the slice runs."""
    data = {}
    for path in glob.glob(os.path.join(RES, "bench", "*__fri_*.json")):
        tool = os.path.basename(path).split("__")[0]
        d = json.load(open(path, encoding="utf-8"))
        ok = [r for r in d["runs"] if r["returncode"] == 0]
        if not ok:
            continue
        best = min(ok, key=lambda r: r["wall_s"])
        pk = int(os.path.basename(path).split("__fri_")[1].split("k")[0]) * 1000
        data.setdefault(tool, {})[pk] = (best["wall_s"], max(r["peak_rss_mb"] for r in ok), pk)
    return data


def human_packets(x, _pos=None):
    return f"{x / 1e6:g}M" if x >= 1e6 else f"{x / 1e3:g}k"


def style(ax):
    ax.grid(True, which="major", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.xaxis.set_major_locator(FixedLocator([250e3, 500e3, 1e6, 2e6, 4e6]))
    ax.xaxis.set_major_formatter(FuncFormatter(human_packets))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xlabel("packets processed (Friday prefix)")


def fig_memory():
    data = load_bench()
    fig, (a, b) = plt.subplots(1, 2, figsize=(122 * MM, 42 * MM), constrained_layout=True)
    for tool, (label, colour, marker, ls) in TOOLS.items():
        if tool not in data:
            continue
        xs = sorted(data[tool])
        mem = [data[tool][x][1] for x in xs]
        kpps = [x / data[tool][x][0] / 1e3 for x in xs]
        kw = dict(color=colour, marker=marker, linestyle=ls, linewidth=1.4, markersize=4.2,
                  markeredgecolor="white", markeredgewidth=0.6, label=label)
        a.plot(xs, mem, **kw)
        b.plot(xs, kpps, **kw)
        # direct label at the series end, in ink colour (identity comes from the mark)
        a.annotate(label, (xs[-1], mem[-1]), xytext=(4, 0), textcoords="offset points",
                   va="center", fontsize=6, color=INK)
    style(a)
    style(b)
    a.set_ylabel("peak working set (MiB)")
    b.set_ylabel("throughput (kpps)")
    a.set_title("(a) peak memory", loc="left", color=INK)
    b.set_title("(b) throughput", loc="left", color=INK)
    for ax in (a, b):
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:g}"))
        ax.set_xlim(200e3, 5e6)
    a.set_xlim(200e3, 16e6)
    handles, labels = a.get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside lower center", ncol=3, frameon=False)
    fig.savefig(os.path.join(FIG, "memory.pdf"))
    print("wrote memory.pdf")


# ml.py's group keys -> the group names of the paper's Table 2
TABLE2_NAME = {"volume & rates": "Volume and rates", "packet size": "Packet size",
               "inter-arrival": "Timing", "burst/idle": "Active/idle", "TCP flags": "TCP flags",
               "TCP handshake": "TCP handshake", "IP layer": "IP layer"}


def fig_ablation():
    d = json.load(open(os.path.join(RES, "ml_ablation.json"), encoding="utf-8"))

    def macro8(r):  # macro-F1 over the eight classes other than Heartbleed (5 flows)
        pc = {c: v for c, v in r["per_class_f1"].items() if c != "Heartbleed"}
        return sum(pc.values()) / len(pc)

    base = macro8(d["all"])
    groups = [k[len("without "):] for k in d if k.startswith("without ")]
    without = [macro8(d[f"without {g}"]) for g in groups]
    only = [macro8(d[f"only {g}"]) for g in groups]
    order = sorted(range(len(groups)), key=lambda i: only[i])
    groups = [groups[i] for i in order]
    without = [without[i] for i in order]
    only = [only[i] for i in order]
    # Bars stay unlabelled (they are too thin to carry text); the exact values sit in a
    # two-column table to the right of the plot, in ink colour.
    fig = plt.figure(figsize=(122 * MM, 42 * MM))
    ax = fig.add_axes([0.16, 0.30, 0.62, 0.62])
    y = range(len(groups))
    h = 0.38
    ax.barh([i + h / 2 + 0.02 for i in y], without, height=h, color="#2a78d6",
            label="group removed", edgecolor="white", linewidth=0.6)
    ax.barh([i - h / 2 - 0.02 for i in y], only, height=h, color="#eb6834", hatch="////",
            label="group alone", edgecolor="white", linewidth=0.6)
    ax.axvline(base, color=INK, linestyle="--", linewidth=0.8)
    ax.text(base - 0.003, len(groups) - 0.42, f"all features {base:.4f}", ha="right",
            va="bottom", fontsize=6, color=INK)
    ax.set_yticks(list(y))
    ax.set_yticklabels([TABLE2_NAME.get(g, g) for g in groups])
    lo = min(only + without)
    ax.set_xlim(max(0.0, lo - 0.02), 1.0)
    ax.set_ylim(-0.6, len(groups) - 0.4)
    ax.set_xlabel("macro-F1, eight classes other than Heartbleed\n(extra-trees, 5-fold CV)")
    ax.grid(True, axis="x", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    # value table in axes-fraction x, data y
    tx = ax.get_yaxis_transform()
    ax.text(1.06, len(groups) - 0.45, "removed", transform=tx, ha="left", va="bottom",
            fontsize=6.5, color=INK, fontweight="bold")
    ax.text(1.26, len(groups) - 0.45, "alone", transform=tx, ha="left", va="bottom",
            fontsize=6.5, color=INK, fontweight="bold")
    for i in y:
        ax.text(1.06, i, f"{without[i]:.4f}", transform=tx, ha="left", va="center",
                fontsize=6.5, color=INK)
        ax.text(1.26, i, f"{only[i]:.4f}", transform=tx, ha="left", va="center",
                fontsize=6.5, color=INK)
    fig.legend(*ax.get_legend_handles_labels(), loc="lower right", ncol=1, frameon=False,
               bbox_to_anchor=(1.0, 0.02))
    fig.savefig(os.path.join(FIG, "ablation.pdf"))
    print("wrote ablation.pdf")


if __name__ == "__main__":
    {"memory": fig_memory, "ablation": fig_ablation}[sys.argv[1]]()
