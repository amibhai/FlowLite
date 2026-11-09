"""Locations used by the evaluation scripts; override with environment variables.

FLOWLITE_EVAL_DATA  directory with pcap/ (CIC-IDS2017 captures), slices/ and labels/
FLOWLITE_EVAL_OUT   directory for extracted flow CSVs and generated captures
BASELINE_PYTHON     interpreter with nfstream, cicflowmeter, dpkt, numpy, pandas installed
PYPY                PyPy interpreter for the PyPy runs
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FLOWLITE_SRC = os.path.join(REPO, "src")
PAPER = os.path.join(REPO, "paper")
PROTOTYPE = os.path.join(HERE, "prototype")
DATA = os.environ.get("FLOWLITE_EVAL_DATA", os.path.join(HERE, "data"))
OUT = os.environ.get("FLOWLITE_EVAL_OUT", os.path.join(HERE, "out"))
BENCH_OUT = os.path.join(OUT, "bench")
TABLES = os.path.join(OUT, "tables")
RESULTS = os.path.join(HERE, "results")
BASELINE_PYTHON = os.environ.get("BASELINE_PYTHON", "python")
PYPY = os.environ.get("PYPY", "pypy3")
