# Evaluation of FlowLite 2.1 (ISEA-ISAP 2027 paper)

Everything needed to reproduce the paper's numbers: the labelling rules, the reference
implementation, the benchmark drivers, the classifier experiments and the scripts that turn the
results into the paper's figures and `paper/numbers.tex`. The measured results are in
`results/` (with `results/fullday/` for the full-day extraction summaries and `results/pilot/` for
the pilot runs); `paper/numbers.tex` is generated from them. The few measured values typed into
the paper by hand, the CICFlowMeter port's 13,193 and 14,391 flows (Sect. 5.5), come from
`results/bench/cicflowmeter_py__fri_250k.json` and `results/pilot/cicflowmeter_py.json`.
`make_numbers.py` also needs the labelled parquet tables that `build_tables.py` writes (not shipped:
about 370 MB).

## Data

CIC-IDS2017 [Sharafaldin et al., ICISSP 2018], Wednesday and Friday captures. Both files are
pcapng despite their `.pcap` extension.

| File | Bytes | SHA-256 |
|---|---|---|
| `Wednesday-workingHours.pcap` | 13,420,789,612 | `cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186` |
| `Friday-WorkingHours.pcap` | 8,839,309,056 | `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` |

Obtain them from the dataset authors (https://www.unb.ca/cic/datasets/ids-2017.html) and check
the digests. CIC's own labelled CICFlowMeter flows (the `TrafficLabelling` CSV files) are needed
for the CICFlowMeter comparison.

Set `FLOWLITE_EVAL_DATA` to a directory containing `pcap/` (the two captures), `slices/`
(prefixes made with `editcap -F pcap -r <capture> fri_<N>k.pcap 1-<N>`) and `labels/`, and
`FLOWLITE_EVAL_OUT` to a scratch directory. `BASELINE_PYTHON` names an interpreter with
`nfstream==6.6.0`, `cicflowmeter==0.5.0`, `dpkt`, `numpy`, `pandas` and `psutil`; `PYPY` names a
PyPy 3.11 interpreter. The analysis scripts need `pandas`, `pyarrow`, `scikit-learn` and
`matplotlib`.

## Scripts

| Script | Purpose | Paper |
|---|---|---|
| `label.py` | Rule-based ground truth from the published attack schedule (UTC windows, attacker/victim pairs in either direction, service ports) | Sect. 5.1 |
| `reference_check.py` | Two-pass dpkt + NumPy reference; compares every feature of every flow | RQ1 |
| `encap_check.py` | Re-frames a capture under seven link-layer framings and two further file formats (pcapng, gzip) and compares the output | RQ1 |
| `mem_per_flow.py` | Heap bytes per in-progress flow (tracemalloc) | Sect. 3.3 |
| `run_bench.py`, `drv_*.py` | Runs one extractor on one capture and measures wall time and peak memory of its process tree | RQ2 |
| `make_flood.py` | Writes the SYN flood in which every packet opens a new flow | RQ2 |
| `parallel_scale.py` | N FlowLite processes at once, each reading the given capture (the paper uses the 1M-packet prefix as a stand-in for N rotated files) | RQ2 |
| `extract.py` | Full-day FlowLite extraction with the shipped defaults (`--teardown-grace 0` for RQ4) | RQ3, RQ4 |
| `build_tables.py` | Labelled feature tables for FlowLite, NFStream and CIC's CICFlowMeter CSVs | RQ3 |
| `ml.py` | Random forest / extra-trees, stratified 5-fold CV, de-duplicated runs, group ablation | RQ3 |
| `rq4.py` | Direction consistency, CIC label/direction analysis, teardown-tail counts | RQ4 |
| `figures.py`, `make_numbers.py` | Figures 2-3 and `paper/numbers.tex`; `make_numbers.py` also reads the parquet tables written by `build_tables.py` (RQ4 macros), so run it last | all |
| `prototype/` | The earlier dpkt-based prototype, restored from git history, used as a baseline | RQ2 |

The paper's LaTeX sources are not part of this repository. `make_numbers.py` and `figures.py`
write `paper/numbers.tex` and `paper/figures/*.pdf` next to `evaluation/`, creating the folder
if needed.

## Order of the runs

1. `label.py`, then `extract.py` for both days (with and without `--teardown-grace 0`).
2. `reference_check.py`, `encap_check.py`, `mem_per_flow.py` (RQ1, Sect. 3.3).
3. `run_bench.py` for every extractor and capture, `make_flood.py` + `run_bench.py` on the flood,
   `parallel_scale.py` (RQ2).
4. `build_tables.py`, then `ml.py main`, `ml.py ablation` and `rq4.py` (RQ3, RQ4).
5. `figures.py memory`, `figures.py ablation` and `make_numbers.py`.

## Notes on the measurements

* One extractor at a time, on an otherwise idle machine (Intel Core i9-12900H, 16 GB RAM,
  Windows 11). Memory is the peak working set of the process tree sampled every 20 ms.
* On Windows the CICFlowMeter port needs `tcpdump` to filter files; `drv_cicflowmeter.py`
  applies the identical filter in Python. NFStream needs Npcap's DLL directory, which
  `drv_nfstream.py` adds. Nothing else in either tool is changed.
* The CICFlowMeter port's flow count varies between runs on the same file: its garbage
  collector expires flows against the wall clock (`flow_session.garbage_collect(time.time())`).
