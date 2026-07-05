# NIDS — Network Intrusion Detection System Pipeline

An automated data pipeline that streams live packet capture from an Arista EOS
switch, extracts ~45 per-flow features using pure Python (dpkt only), aggregates
behavioral profiles per host, polls switch telemetry via eAPI, and listens for
sFlow UDP datagrams — all running continuously with a single command.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [GeoIP Setup](#geoip-setup)
6. [Switch Setup (Arista EOS)](#switch-setup-arista-eos)
7. [Running the Pipeline](#running-the-pipeline)
8. [Command-Line Options](#command-line-options)
9. [Output Files](#output-files)
10. [Feature Reference](#feature-reference)
11. [Module Reference](#module-reference)
12. [Logs](#logs)
13. [Retention and Cleanup](#retention-and-cleanup)
14. [Troubleshooting](#troubleshooting)
15. [Extending the Pipeline](#extending-the-pipeline)

---

## Architecture Overview

```
Arista EOS Switch
      │
      ├─── SSH (paramiko) ──────────────────────► capture/streamer.py
      │         tcpdump -i mirror0 -w -               │ one .pcap/hour
      │                                               │
      ├─── HTTPS eAPI (requests) ──────────────► collectors/poll_eapi.py
      │         show arp / mac / routes / ifaces       │ every 30 s
      │                                               │
      └─── sFlow v5 UDP (socket) ──────────────► collectors/sflow_listener.py
                port 6343                             │ every 60 s
                                                      │
                                    ┌─────────────────┘
                                    │
                            pipeline/watcher.py
                            (consumes pcap queue)
                                    │
                     ┌──────────────┼──────────────┐
                     │              │              │
             sasplite/          pipeline/    collectors/
             extractor.py    aggregator.py  build_network_ts.py
             (45 features)   (55 cols/host)  (30 cols/60 s)
                     │              │              │
                     ▼              ▼              ▼
               flows.csv   host_profiles.csv  network_ts.csv

                         pipeline/dashboard.py
                         (live terminal view, 30 s refresh)
```

All components run as threads inside one Python process. `start_nids.py` is the
single entry point.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.9+ | Standard library only for core parsing |
| pip packages | see below | No system binaries needed |
| Arista EOS switch | any modern | eAPI must be enabled; mirror/SPAN interface required |
| GeoLite2 databases | optional | ASN and City `.mmdb` files from MaxMind |

**Zero system binary dependencies.** No `apt install` required beyond Python.
No Zeek, tshark, NFStream, sflowtool, or nfdump.

---

## Installation

```bash
# 1. Clone or copy the nids/ directory to your machine
cd nids

# 2. (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS/WSL
# or on Windows:
# .venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt
```

### requirements.txt contents

```
dpkt>=1.9.8          # pcap parsing — the ONLY packet library used
paramiko>=3.4.0      # SSH to Arista switch for tcpdump stream
requests>=2.31.0     # eAPI HTTPS polling
PyYAML>=6.0.1        # config.yaml parsing
pandas>=2.1.0        # DataFrames for features and aggregation
numpy>=1.26.0        # vectorised feature computation
scipy>=1.11.0        # entropy calculation in network_ts
geoip2>=4.7.0        # MaxMind GeoLite2 ASN/City lookup
psutil>=5.9.0        # process/resource monitoring
```

---

## Configuration

All settings live in `config.yaml`. **Nothing is hardcoded.**

```bash
cp config.yaml config.yaml.bak   # keep a backup
nano config.yaml                  # or your preferred editor
```

### Minimum required fields

```yaml
switch:
  host: "192.168.1.1"    # management IP of your Arista switch
  user: "admin"          # eAPI + SSH username
  pass: "your_password"  # password (plain text; restrict file permissions)
```

The pipeline refuses to start if any of these three are empty.

### Full config reference

```yaml
# ── Switch ─────────────────────────────────────────────────────────
switch:
  host: ""               # Arista switch management IP
  user: ""               # eAPI + SSH username
  pass: ""               # password
  interface: "mirror0"   # SPAN/mirror interface name (tcpdump runs here)
  ssh_port: 22           # SSH port (default 22)
  verify_ssl: false      # EOS uses self-signed certs — keep false

# ── Capture ────────────────────────────────────────────────────────
capture:
  duration_sec: 3600     # seconds per pcap file (3600 = 1 hour)
  retry_wait_sec: 15     # wait before retrying a failed capture
  base_dir: ""           # where to save pcap files
                         # Windows example: C:\Users\You\Desktop\captures
                         # Linux/WSL example: /data/pcaps
                         # Windows paths are auto-converted to WSL /mnt/c/...

# ── Feature extraction ─────────────────────────────────────────────
sasplite:
  geoip_asn_db:  "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
  geoip_city_db: "/usr/share/GeoIP/GeoLite2-City.mmdb"
  subflow_gap_s: 1.0     # inter-packet silence > this value ends an active burst

# ── Aggregation ────────────────────────────────────────────────────
aggregation:
  host_profile_window_min: 10   # group flows into N-minute windows per host
  business_hours_start: 8       # used for future anomaly context (hour 0-23)
  business_hours_end: 20

# ── eAPI polling ───────────────────────────────────────────────────
eapi:
  poll_interval_s: 30    # how often to poll the switch (seconds)
  timeout_s: 5           # HTTP request timeout

# ── sFlow listener ─────────────────────────────────────────────────
sflow:
  listen_port: 6343      # UDP port to bind (standard sFlow port)
  parse_interval_s: 60   # how often to flush received datagrams to CSV

# ── Output paths ───────────────────────────────────────────────────
paths:
  output_base:  "/data/nids/output"           # root for all per-hour dirs
  flows_dir:    "/data/nids/output/flows"     # per-hour flows CSVs
  profiles_dir: "/data/nids/output/host_profiles"
  network_ts:   "/data/nids/output/network_ts.csv"   # rolling append
  eapi_out:     "/data/nids/collectors/eapi_poll.csv"
  sflow_out:    "/data/nids/collectors/iface_counters.csv"
  logs:         "/var/log/nids"

# ── Retention ──────────────────────────────────────────────────────
retention:
  keep_pcaps_days: 7     # delete pcap files older than N days
  keep_csvs_days:  30    # delete CSV files older than N days

# ── Process control ────────────────────────────────────────────────
daemons:
  capture: true    # set false to disable SSH capture (replay mode)
  eapi:    true    # set false to disable eAPI polling
  sflow:   true    # set false to disable sFlow listener

# ── Timeouts ───────────────────────────────────────────────────────
timeouts:
  extractor_s:  3600   # max seconds for feature extraction per pcap
  aggregator_s: 300    # max seconds for host profile aggregation
  build_ts_s:   300    # max seconds for network_ts build subprocess
```

### Securing the config

```bash
chmod 600 config.yaml   # restrict read access to owner only
```

---

## GeoIP Setup

The pipeline uses MaxMind GeoLite2 databases for ASN enrichment of destination
IPs. This is optional — the pipeline runs without them, but `dst_asn` fields
will show `"UNKNOWN"`.

### Download GeoLite2 databases

1. Create a free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Download **GeoLite2-ASN.mmdb** and **GeoLite2-City.mmdb**
3. Place them at the paths set in `config.yaml`:

```bash
# Default paths (change in config.yaml if needed)
sudo mkdir -p /usr/share/GeoIP
sudo cp GeoLite2-ASN.mmdb  /usr/share/GeoIP/
sudo cp GeoLite2-City.mmdb /usr/share/GeoIP/
```

Private IPs (RFC 1918: `10.x`, `172.16-31.x`, `192.168.x`, `127.x`) always
return `"PRIVATE"` without a database lookup.

---

## Switch Setup (Arista EOS)

### 1. Enable eAPI

```eos
management api http-commands
   protocol https
   no shutdown
```

Verify:
```eos
show management api http-commands
```

### 2. Create a SPAN/mirror session

```eos
monitor session 1 source interface Ethernet1 - Ethernet48
monitor session 1 destination interface mirror0
```

Replace `Ethernet1 - Ethernet48` with the interfaces you want to mirror.
`mirror0` must match `config.yaml → switch.interface`.

### 3. Create a dedicated user (recommended)

```eos
username nids privilege 15 secret <password>
```

### 4. Enable sFlow (optional)

```eos
sflow sample 1024
sflow polling-interval 30
sflow destination <your_machine_ip> 6343
sflow source-interface Management0
sflow run
```

Replace `<your_machine_ip>` with the IP of the machine running NIDS, and
`6343` with `config.yaml → sflow.listen_port`.

---

## Running the Pipeline

### Basic start

```bash
python3 start_nids.py
```

The pipeline starts all daemons and shows a live dashboard in the terminal.
Press **Ctrl+C** to stop cleanly (finishes the current operation first).

### Validate config without connecting

```bash
python3 start_nids.py --dry-run
```

Output example:
```
DRY RUN — would start:
  Capture:  SSH to 192.168.1.1:22  iface=mirror0
  eAPI:     polling 192.168.1.1 every 30s
  sFlow:    listening UDP port 6343
  Watcher:  processing pcaps → /data/nids/output
```

### Selective daemon control

```bash
# Only run eAPI polling and sFlow (no SSH capture)
python3 start_nids.py --no-capture

# Run capture + watcher only (no switch telemetry)
python3 start_nids.py --no-eapi --no-sflow

# Process existing pcap files without live capture
# (drop pcap paths into the queue manually via the watcher)
python3 start_nids.py --no-capture --no-eapi --no-sflow
```

You can also permanently disable any daemon in `config.yaml`:
```yaml
daemons:
  capture: false   # never SSH to the switch
  eapi:    true
  sflow:   false
```

### Use an alternate config file

```bash
python3 start_nids.py --config /path/to/other_config.yaml
```

### Run in background (Linux/WSL)

```bash
nohup python3 start_nids.py > /var/log/nids/stdout.log 2>&1 &
echo $! > /var/run/nids.pid
```

Stop it:
```bash
kill $(cat /var/run/nids.pid)
```

### Run as a systemd service

```ini
# /etc/systemd/system/nids.service
[Unit]
Description=NIDS Data Pipeline
After=network.target

[Service]
Type=simple
User=nids
WorkingDirectory=/opt/nids
ExecStart=/opt/nids/.venv/bin/python3 start_nids.py --config /etc/nids/config.yaml
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable nids
sudo systemctl start nids
sudo journalctl -u nids -f
```

---

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--config PATH` | auto-discover | Path to `config.yaml` |
| `--no-capture` | off | Disable SSH tcpdump capture thread |
| `--no-eapi` | off | Disable eAPI polling thread |
| `--no-sflow` | off | Disable sFlow UDP listener thread |
| `--dry-run` | off | Print what would start, then exit cleanly |

Config auto-discovery order: `./config.yaml` → `../config.yaml` → `/etc/nids/config.yaml`

---

## Output Files

All output paths are configurable in `config.yaml → paths`.

### flows.csv (per-flow features)

Written per hour to `flows_dir/YYYYMMDD_HHMM_flows.csv`.
One row per TCP/UDP/ICMP flow. Millions of rows for busy networks.

| Column | Type | Description |
|--------|------|-------------|
| `src_ip` | str | Source IP address |
| `dst_ip` | str | Destination IP address |
| `src_port` | int | Source port (0 for ICMP) |
| `dst_port` | int | Destination port (0 for ICMP) |
| `proto` | int | IP protocol number (6=TCP, 17=UDP, 1=ICMP) |
| `ts_start` | float | Unix timestamp of first packet |
| `ts_end` | float | Unix timestamp of last packet |
| `flow_duration` | float | Duration in seconds |
| `flow_iat_mean` | float | Mean inter-arrival time across all packets |
| `flow_iat_std` | float | Std dev of inter-arrival times |
| `flow_iat_max` | float | Max inter-arrival time |
| `fwd_iat_mean` | float | Mean IAT for forward direction packets |
| `fwd_iat_std` | float | Std dev of forward IATs |
| `fwd_iat_max` | float | Max forward IAT |
| `bwd_iat_mean` | float | Mean IAT for backward direction packets |
| `bwd_iat_std` | float | Std dev of backward IATs |
| `bwd_iat_max` | float | Max backward IAT |
| `fwd_pkt_len_mean` | float | Mean forward payload size (bytes) |
| `fwd_pkt_len_std` | float | Std dev of forward payload sizes |
| `fwd_pkt_len_max` | float | Max forward payload size |
| `bwd_pkt_len_mean` | float | Mean backward payload size |
| `bwd_pkt_len_std` | float | Std dev of backward payload sizes |
| `bwd_pkt_len_max` | float | Max backward payload size |
| `pkt_len_variance` | float | Variance of all payload sizes in flow |
| `init_win_bytes_fwd` | int | TCP window size in first SYN (forward) |
| `init_win_bytes_bwd` | int | TCP window size in first SYN-ACK (backward) |
| `min_seg_size_forward` | int | Minimum non-zero forward payload size |
| `active_time_mean` | float | Mean duration of active packet bursts |
| `idle_time_mean` | float | Mean duration of idle gaps between bursts |
| `syn_flag_ratio` | float | Fraction of packets with SYN flag set |
| `ack_flag_ratio` | float | Fraction of packets with ACK flag set |
| `fin_flag_ratio` | float | Fraction of packets with FIN flag set |
| `rst_flag_ratio` | float | Fraction of packets with RST flag set |
| `psh_flag_ratio` | float | Fraction of packets with PSH flag set |
| `urg_flag_ratio` | float | Fraction of packets with URG flag set |
| `ip_ttl_mean` | float | Mean TTL across all packets |
| `ip_ttl_std` | float | Std dev of TTL values |
| `ip_proto` | int | IP protocol (same as `proto`, for grouping) |
| `n_fwd_pkts` | int | Count of forward packets |
| `n_bwd_pkts` | int | Count of backward packets |
| `n_fwd_bytes` | int | Total forward payload bytes |
| `n_bwd_bytes` | int | Total backward payload bytes |
| `dst_asn` | str | Destination ASN (e.g. `AS15169`) or `PRIVATE`/`UNKNOWN` |

### host_profiles.csv (per-host behavioral profiles)

Written per hour to `output_base/YYYYMMDD_HHMM/host_profiles.csv`.
One row per `(src_ip, 10-minute window)`. ~55 columns.

Key columns beyond the flow features:

| Column | Description |
|--------|-------------|
| `window_start` | Start of the 10-minute window (datetime) |
| `src_ip` | Host IP address |
| `n_flows` | Number of flows in this window |
| `dir_ratio_bytes` | Bytes sent / bytes received (upload/download ratio) |
| `unique_dest_ip_count` | Number of distinct destination IPs contacted |
| `unique_dest_port_count` | Number of distinct destination ports used |
| `unique_dest_asn_count` | Number of distinct destination ASNs |
| `global_flow_share` | This host's flows as fraction of all network flows |
| `global_byte_share` | This host's bytes as fraction of all network bytes |
| `global_port_share` | This host's unique ports as fraction of network-wide unique ports |
| `tcp_ratio` | Fraction of flows using TCP |
| `udp_ratio` | Fraction of flows using UDP |
| `icmp_ratio` | Fraction of flows using ICMP |

### network_ts.csv (network-wide time series)

Rolling append at `paths.network_ts`. One row per 60-second bucket,
60 rows added per hour. Merges flows, eAPI, and sFlow data.

| Column | Source | Description |
|--------|--------|-------------|
| `timestamp` | derived | 60-second bucket start time |
| `flows_per_sec` | flows | Flow count / 60 |
| `bytes_per_sec` | flows | Total bytes / 60 |
| `tcp_ratio` | flows | Fraction of TCP flows in bucket |
| `udp_ratio` | flows | Fraction of UDP flows in bucket |
| `icmp_ratio` | flows | Fraction of ICMP flows in bucket |
| `active_src_ips` | flows | Unique source IPs in bucket |
| `active_dst_ips` | flows | Unique destination IPs in bucket |
| `dst_port_entropy` | flows | Shannon entropy of destination port distribution |
| `byte_asymmetry` | flows | `|fwd - bwd| / total` — asymmetry indicator |
| `avg_flow_duration_s` | flows | Mean flow duration |
| `syn_no_ack_rate` | flows | Flows with high SYN + low ACK ratio per second |
| `avg_iat_std` | flows | Mean of per-flow IAT standard deviations |
| `high_rst_rate` | flows | Flows with RST ratio > 0.5 per second |
| `arp_changed_count_net` | eAPI | ARP entries that changed MAC in this bucket |
| `mac_new_count_net` | eAPI | New MACs appearing in MAC table |
| `route_delta_max` | eAPI | Max change in route table size |
| `total_iface_errors` | eAPI | Total interface errors from switch |
| `total_iface_discards` | eAPI | Total interface discards from switch |
| `iface_down_count` | eAPI | Number of interfaces in non-connected state |
| `total_in_bytes_net` | sFlow | Sum of in-octets deltas across all interfaces |
| `total_out_bytes_net` | sFlow | Sum of out-octets deltas |
| `total_iface_errors_net` | sFlow | Sum of in+out errors from sFlow counters |
| `payload_entropy_mean` | sFlow | Mean Shannon entropy of sampled packet payloads |

### eapi_poll.csv

Written to `paths.eapi_out` every 30 seconds. One row per poll.

| Column | Description |
|--------|-------------|
| `timestamp` | Poll time (UTC ISO 8601) |
| `switch_ip` | Switch management IP |
| `arp_table_size` | Total ARP table entries |
| `arp_changed_count` | Entries whose MAC changed since last poll |
| `arp_new_count` | New IPs appearing in ARP table |
| `mac_table_size` | Total MAC table unicast entries |
| `mac_new_count` | New MACs since last poll |
| `mac_lost_count` | MACs that disappeared since last poll |
| `route_count` | Total routes in default VRF |
| `route_delta` | Change in route count since last poll |
| `total_iface_errors` | Total interface input errors (delta) |
| `total_iface_discards` | Total interface discards |
| `iface_down_count` | Interfaces not in "connected" state |

### iface_counters.csv

Written to `paths.sflow_out` every 60 seconds by the sFlow listener.

| Column | Description |
|--------|-------------|
| `timestamp` | Flush time (UTC ISO 8601) |
| `agent_ip` | IP of the sFlow agent (switch) |
| `if_index` | Interface index (SNMP ifIndex) |
| `in_octets` | Cumulative inbound octets |
| `out_octets` | Cumulative outbound octets |
| `in_discards` | Inbound discards |
| `out_discards` | Outbound discards |
| `in_errors` | Inbound errors |
| `out_errors` | Outbound errors |
| `in_octets_delta` | Inbound octets since last flush |
| `out_octets_delta` | Outbound octets since last flush |

---

## Feature Reference

### How flows are identified

A flow is a 5-tuple: `(src_ip, src_port, dst_ip, dst_port, proto)`.
Direction is assigned by whichever endpoint sent the first packet —
that endpoint is always "forward" (fwd), the other is "backward" (bwd).
All packets in a pcap file with the same 5-tuple (or its reverse) belong
to the same flow record.

### Active/idle burst detection

The `subflow_gap_s` setting (default 1.0 second) controls burst boundaries.
Consecutive packets separated by less than `subflow_gap_s` are in the same
active burst. A gap larger than `subflow_gap_s` ends the burst and starts an
idle period.

- `active_time_mean` — mean duration of active bursts across the flow
- `idle_time_mean`   — mean duration of idle gaps across the flow

### TCP handshake features

- `init_win_bytes_fwd` — window size advertised in the first SYN packet
- `init_win_bytes_bwd` — window size advertised in the first SYN-ACK packet

These are 0 for UDP and ICMP flows.

### ASN enrichment

`dst_asn` is populated from MaxMind GeoLite2-ASN for each unique destination
IP. Lookups are cached in memory to avoid repeated disk reads. Private IPs
return `"PRIVATE"`. Missing database returns `"UNKNOWN"`.

---

## Module Reference

```
nids/
├── start_nids.py               Entry point — starts all threads
│
├── config.yaml                 All settings (never hardcoded elsewhere)
├── requirements.txt            pip dependencies
│
├── capture/
│   └── streamer.py             SSH to switch → tcpdump stdout → local .pcap
│                               Functions: capture_one(), run()
│                               Helpers:   windows_to_wsl(), make_save_path()
│
├── sasplite/
│   ├── extractor.py            dpkt pcap reader → flows DataFrame (45 cols)
│   │                           Classes: FlowExtractor, FlowState
│   │                           Functions: _process_packet(), _aggregate_flow()
│   └── geoip.py                MaxMind GeoLite2 wrapper with RFC1918 check
│                               Class: GeoIPLookup
│
├── pipeline/
│   ├── watcher.py              Queue consumer: pcap → extract → aggregate → ts
│   │                           Function: run()
│   ├── aggregator.py           Flows → per-host 10-min profiles (55 cols)
│   │                           Class: HostProfileAggregator
│   └── dashboard.py            ANSI terminal live status (30 s refresh)
│                               Function: run()
│
├── collectors/
│   ├── poll_eapi.py            Arista eAPI HTTPS poller (every 30 s)
│   │                           Function: run()
│   ├── sflow_listener.py       Pure Python sFlow v5 UDP parser + CSV writer
│   │                           Function: run()
│   └── build_network_ts.py     Hourly batch: merge 4 sources → network_ts.csv
│                               Can also be run standalone (see below)
│
└── utils/
    ├── config_loader.py        YAML → SimpleNamespace, validates required fields
    │                           Functions: load_config(), get()
    ├── logger.py               Rotating file + stdout logging
    │                           Function: get_logger()
    └── csv_writer.py           Thread-safe atomic CSV append
                                Functions: append_rows(), read_csv(), tail_rows()
```

### Running build_network_ts.py standalone

```bash
# Build network_ts for the previous hour (default)
python3 -m collectors.build_network_ts

# Build for a specific hour
python3 -m collectors.build_network_ts --hour 2025052609

# Use custom flows CSV and output path
python3 -m collectors.build_network_ts \
    --flows /data/nids/output/flows/20250526_0900_flows.csv \
    --output /data/nids/output/network_ts.csv

# Preview without writing
python3 -m collectors.build_network_ts --dry-run
```

---

## Logs

Log files are written to `config.yaml → paths.logs` (default `/var/log/nids`).

| File | Contains |
|------|----------|
| `nids.log` | Main pipeline — startup, shutdown, summary per hour |
| Rotated as | `nids.log.1`, `nids.log.2`, … up to 5 backups, 10 MB each |

Log format:
```
2025-05-26 09:00:15  nids                 INFO      NIDS Pipeline starting — 5 threads
2025-05-26 09:00:15  nids                 INFO      Started thread: capture
2025-05-26 10:00:42  nids                 INFO      Extracted 142847 flows, 45 cols from 09_00_to_10_00.pcap
2025-05-26 10:04:38  nids                 INFO      Pipeline 20250526_0900 — OK — flows=142847 profiles=1204 (238.1s)
```

To tail logs while running:
```bash
tail -f /var/log/nids/nids.log
```

---

## Retention and Cleanup

The watcher automatically deletes old files after each successful hour:

| Setting | Default | What gets deleted |
|---------|---------|-------------------|
| `retention.keep_pcaps_days` | 7 | `.pcap` files older than N days |
| `retention.keep_csvs_days` | 30 | `.csv` files in output dirs older than N days |

`network_ts.csv` and `eapi_poll.csv` are excluded from cleanup (they roll up
forever). Delete them manually if needed.

---

## Troubleshooting

### "Config error: switch.host must be a non-empty string"

Edit `config.yaml` and fill in the three required fields:
```yaml
switch:
  host: "192.168.1.1"
  user: "admin"
  pass: "yourpassword"
```

### SSH capture fails immediately

Check:
1. Switch IP is reachable: `ping 192.168.1.1`
2. SSH works manually: `ssh admin@192.168.1.1`
3. `mirror0` interface exists on the switch: `show interfaces mirror0`
4. The user has privilege 15 (needed to run tcpdump)
5. `capture.base_dir` in config.yaml is set and writable

### eAPI returns 401 Unauthorized

The user must have eAPI access. On EOS:
```eos
management api http-commands
   no shutdown
```
Also confirm `switch.user` and `switch.pass` match exactly.

### eAPI SSL error

Set `verify_ssl: false` in config.yaml (already default). EOS uses
self-signed certificates.

### sFlow datagrams not received

1. Confirm the switch is sending to this machine's IP on port 6343
2. Check firewall: `sudo ufw allow 6343/udp`
3. The listener logs "sFlow listener bound to UDP port 6343" on startup —
   if you don't see that, check for port conflicts: `ss -ulnp | grep 6343`

### "No flows extracted from pcap"

Possible causes:
- The pcap file is empty (capture stopped early — check SSH logs)
- All traffic on `mirror0` is non-IP (VLAN tags, raw L2 frames)
- dpkt could not parse the link-layer type — check `pcap.datalink()`

### network_ts.csv is missing rows

`build_network_ts.py` runs as a subprocess after each hour. If it fails,
the watcher logs `build_network_ts failed` with the last 500 chars of stderr.
Run it manually to see the full error:
```bash
python3 -m collectors.build_network_ts --hour 2025052609 --dry-run
```

### Dashboard is garbled

The dashboard uses ANSI escape codes to overwrite its own output.
It requires a terminal that supports ANSI (any modern terminal does).
In non-interactive environments (cron, systemd), redirect stdout:
```bash
python3 start_nids.py > /var/log/nids/stdout.log 2>&1
```

---

## Extending the Pipeline

### Add a new flow feature

1. Open [sasplite/extractor.py](sasplite/extractor.py)
2. Compute the value in `_aggregate_flow()` using `pkts`, `fwd`, `bwd` arrays
3. Add it to the returned dict
4. Add the column name to `HostProfileAggregator.aggregate()` in
   [pipeline/aggregator.py](pipeline/aggregator.py) if you want it in profiles

### Add a new host profile feature

1. Open [pipeline/aggregator.py](pipeline/aggregator.py)
2. Compute it inside the `for (window, src_ip), grp in df.groupby(...)` loop
3. Add it to the `row` dict

### Add a new network_ts metric

1. Open [collectors/build_network_ts.py](collectors/build_network_ts.py)
2. Add computation in Step B, C, or D
3. The time-spine join in Step E picks it up automatically

### Replay existing pcap files

```python
# Drop a path directly into the watcher queue from Python
import queue, threading
from utils.config_loader import load_config
from sasplite.geoip import GeoIPLookup
from pipeline.watcher import run as run_watcher

cfg      = load_config()
geoip    = GeoIPLookup(cfg.sasplite.geoip_asn_db, cfg.sasplite.geoip_city_db)
q        = queue.Queue()
stop     = threading.Event()
status   = []

q.put("/path/to/existing.pcap")
stop_after_one = threading.Timer(5, stop.set)
stop_after_one.start()

run_watcher(q, cfg, stop, print, geoip, status)
geoip.close()
```

Or use the standalone extractor directly:
```python
from pathlib import Path
from utils.config_loader import load_config
from sasplite.geoip import GeoIPLookup
from sasplite.extractor import FlowExtractor
import logging

cfg     = load_config()
geoip   = GeoIPLookup(cfg.sasplite.geoip_asn_db, cfg.sasplite.geoip_city_db)
log     = logging.getLogger("test")
ex      = FlowExtractor(cfg, geoip, log)
df      = ex.extract(Path("capture.pcap"))
print(df.head())
geoip.close()
```
