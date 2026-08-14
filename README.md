<div align="center">

# FlowLite

**Vendor-neutral network flow telemetry. Any switch, any router, any capture file.**

FlowLite turns packets and device counters into analysis-ready CSV: 95 per-flow features,
per-host behavioural profiles, and a network-wide time series — from a single command.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-298%20passing-brightgreen)](tests/)
[![Dependencies](https://img.shields.io/badge/required%20dependencies-none-brightgreen)](#installation)

</div>

---

## What it does

```
  ┌──────────────────────── inputs: use any, all, or none ─────────────────────────┐
  │                                                                                │
  │   packet capture              device telemetry           flow export           │
  │   ───────────────             ────────────────           ───────────           │
  │   • a watched folder          • SNMP  (any device)       • sFlow v5            │
  │   • a local mirror NIC        • RESTCONF (RFC 8040)      • NetFlow v5          │
  │   • SSH to the device         • Arista eAPI              • NetFlow v9          │
  │                               • Cisco NX-API             • IPFIX               │
  │                               • any CLI + your regex                           │
  └────────────────────────────────────┬───────────────────────────────────────────┘
                                       ▼
                      ┌────────────────────────────────────┐
                      │   pcap/pcapng decode → flow table  │
                      │   constant memory per flow         │
                      └────────────────┬───────────────────┘
                                       ▼
       ┌───────────────────┬───────────────────────┬────────────────────────┐
       ▼                   ▼                       ▼                        ▼
   flows.csv        host_profiles.csv       network_ts.csv         device_telemetry.csv
   95 columns         48 columns              45 columns               27 columns
   one row/flow    one row/host/window    one row/time bucket        one row/poll
```

Every input is optional and every input produces the same normalised output. A switch you
can only reach by SNMP, a router that exports IPFIX, and a folder of pcap files from an
incident response all flow into the same schema.

## Why it exists

Most flow tooling assumes a specific vendor, a specific capture method, or a stack of
system packages (Zeek, tshark, nfdump, sflowtool). FlowLite assumes none of that:

| | |
|---|---|
| **Runs anywhere** | The entire core is Python standard library. No compiler, no `apt install`, no root. Optional extras add SSH password auth and GeoIP. |
| **Works with any device** | SNMP IF-MIB covers essentially every managed device ever shipped. Vendor APIs are drivers, not assumptions. |
| **Never assumes a format** | Its own pcap **and pcapng** reader, handling Ethernet, VLAN/QinQ, MPLS, Linux cooked capture, raw IP, PPP and 802.11. |
| **Bounded by design** | Constant memory per flow, an LRU-capped flow table, bounded collector queues. It cannot be made to exhaust RAM by traffic volume. |
| **Fails loudly, degrades safely** | Missing config keys use defaults; unreachable devices are *recorded as unreachable*, never as zeros; a bad capture file fails that file alone. |
| **Provable** | `flowlite selftest` exercises the whole pipeline on generated data — no switch, no mirror port, no privileges. |

---

## Installation

```bash
git clone https://github.com/Swastik-Dubey/FlowLite.git
cd FlowLite
pip install -e .
```

That is a complete, working installation. Optional extras:

```bash
pip install -e '.[yaml]'    # PyYAML — full YAML support (a subset parser is built in)
pip install -e '.[ssh]'     # paramiko — SSH capture with password authentication
pip install -e '.[geoip]'   # geoip2 — ASN, organisation and country enrichment
pip install -e '.[full]'    # everything above
```

Verify the install end to end:

```bash
flowlite selftest
```

```
FlowLite 2.0.0 self-test

  [ok]  generate synthetic capture  -- 372 packets
  [ok]  read pcap  -- pcap, 372 packets
  [ok]  read pcapng  -- pcapng, 372 packets
  [ok]  flow extraction  -- 33 flows, 33 host profiles, 1 time buckets
  [ok]  TCP state tracking  -- 25/25 TCP flows
  [ok]  IPv6 decoding  -- 1 IPv6 flow(s)
  ...
16/16 checks passed
Self-test PASSED. FlowLite works correctly on this machine.
```

---

## Quick start

### Analyse capture files you already have

No configuration, no device, no privileges:

```bash
flowlite process capture.pcapng
flowlite process /data/captures/          # a whole directory
```

```
capture.pcapng: 14,208 flows, 1,204 host profiles, 60 time buckets in 3.1s
  flows CSV: data/flows/20260810T140000Z_capture_flows.csv

host profiles: data/host_profiles/host_profiles.csv
network series: data/network_ts.csv
```

### Monitor a live device

```bash
flowlite init --profile generic-snmp   # or arista-eos, cisco-nxos, juniper-junos, ...
$EDITOR flowlite.yaml                  # set device.host and credentials
flowlite doctor                        # check environment and reach the device
flowlite run                           # start the pipeline
```

`flowlite doctor` is the first thing to run when anything looks wrong. It checks the
Python environment, optional dependencies, external tools, config validity, path
writability, free disk space, and then actually contacts the device:

```
Capture driver
  [ok]  ssh 192.0.2.10:22 -- tcpdump found, interface Ethernet49 exists

Telemetry driver
  [ok]  snmp 192.0.2.10:161 -- 48 interfaces, sysName=core-sw-1
```

---

## Supported devices

FlowLite is device-agnostic by construction: it speaks standard protocols, and vendor
APIs are optional accelerators. Ready-made profiles live in [`configs/profiles/`](configs/profiles/).

| Platform | Capture | Telemetry | Flow export | Profile |
|---|---|---|---|---|
| **Any managed device** | folder / SPAN → local NIC | SNMP v1/v2c | — | [`generic-snmp.yaml`](configs/profiles/generic-snmp.yaml) |
| Arista EOS | SSH (`bash -c tcpdump`) | eAPI or SNMP | sFlow | [`arista-eos.yaml`](configs/profiles/arista-eos.yaml) |
| Cisco NX-OS | SPAN → local NIC | NX-API or SNMP | NetFlow | [`cisco-nxos.yaml`](configs/profiles/cisco-nxos.yaml) |
| Cisco IOS-XE | SPAN → local NIC | RESTCONF or SNMP | NetFlow v9 | [`cisco-ios-xe.yaml`](configs/profiles/cisco-ios-xe.yaml) |
| Juniper Junos | SSH (`start shell`) | SNMP | IPFIX | [`juniper-junos.yaml`](configs/profiles/juniper-junos.yaml) |
| MikroTik RouterOS | folder | SNMP | NetFlow v9 | [`mikrotik-routeros.yaml`](configs/profiles/mikrotik-routeros.yaml) |
| Linux host / router | local tcpdump | `/proc/net/dev` over SSH | — | [`linux-host.yaml`](configs/profiles/linux-host.yaml) |
| Offline / forensics | folder | — | — | [`offline-analysis.yaml`](configs/profiles/offline-analysis.yaml) |

**Your platform isn't listed?** Start from `generic-snmp`. If it is a managed device it
speaks SNMP IF-MIB. If it can export sFlow or NetFlow, enable the collector. If you can
get a capture file off it by any means, drop that file in the watch folder.

See [docs/DEVICES.md](docs/DEVICES.md) for per-platform setup, including the switch-side
configuration commands.

---

## Output

Four tidy CSVs, all UTC, all schema-locked. Full column reference in
[docs/SCHEMA.md](docs/SCHEMA.md).

### `flows.csv` — 95 columns, one row per bidirectional flow

Identity, timing, volume, packet-size and inter-arrival statistics in both directions,
burst structure, the full TCP flag set, handshake RTT, connection state, TTL statistics
and address enrichment.

```csv
src_ip,dst_ip,dst_port,protocol_name,duration_s,total_packets,total_bytes,tcp_state,tcp_handshake_ms,dst_scope,dst_asn
10.0.4.17,140.82.121.4,443,TCP,12.482,184,148302,closed,24.117,public,AS36459
10.0.4.17,10.0.0.53,53,UDP,0.031,2,241,n/a,0.0,private,
```

### `host_profiles.csv` — 48 columns, one row per host per window

Behavioural profile of each host: bytes and flows in both directions, peer and port
cardinality, destination-port entropy, fan-out ratio, failed-handshake ratio, protocol
mix, and each host's share of its window.

### `network_ts.csv` — 45 columns, one row per time bucket

A regular time series with gaps filled and *flagged*, joining flow statistics with device
telemetry and sFlow/NetFlow counters onto one spine.

### `device_telemetry.csv` / `interface_counters.csv` — 27 + 25 columns

Per-poll device state and per-interface counters with correct deltas, rates and
utilisation — normalised identically whether they came from SNMP, RESTCONF, eAPI,
NX-API, a CLI regex, or sFlow counter samples.

---

## Commands

| Command | Purpose |
|---|---|
| `flowlite run` | Run the live pipeline (capture + telemetry + collectors + analysis) |
| `flowlite process <path>` | Analyse existing capture files or a directory |
| `flowlite doctor` | Diagnose environment, configuration and device reachability |
| `flowlite selftest` | Prove the whole pipeline works on generated data |
| `flowlite decode <file>` | Inspect a capture file: format, link type, packets, flows |
| `flowlite init [--profile P]` | Write a starter configuration |
| `flowlite config [--json]` | Show the effective configuration, secrets redacted |

Useful flags: `--set key.path=value` overrides any setting; `--no-capture`,
`--no-telemetry` and `--no-flowproto` disable components; `--strict` turns unknown config
keys into errors.

---

## Configuration

One YAML file, merged over a complete set of defaults, so **no key is ever missing** and
an omission can never raise `AttributeError` inside a worker thread. Secrets come from the
environment:

```yaml
device:
  name: "core-sw-1"
  host: "192.0.2.10"

credentials:
  snmp_community: "${FLOWLITE_SNMP}"     # ${VAR} or ${VAR:-fallback}

capture:
  source: folder                          # folder | local | ssh | none

telemetry:
  driver: snmp                            # snmp | restconf | eapi | nxapi | ssh_cli | none
  interval_s: 60

flowproto:
  enabled: true
  sflow: { enabled: true, port: 6343 }
```

Validation reports **every** problem at once, with the exact key path:

```
error: Configuration is invalid (flowlite.yaml)
  - capture.source: 'banana' is not one of folder, ssh, local, none
  - telemetry.interval_s: 1 is below the minimum of 5
  - telemetry.snmp.community (or credentials.snmp_community) must be set for SNMP v1/v2c
```

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md), annotated example:
[`configs/flowlite.example.yaml`](configs/flowlite.example.yaml).

---

## Running as a service

```ini
# /etc/systemd/system/flowlite.service
[Unit]
Description=FlowLite network telemetry pipeline
After=network-online.target

[Service]
Type=simple
User=flowlite
WorkingDirectory=/opt/flowlite
Environment=FLOWLITE_SNMP=your-community
ExecStart=/opt/flowlite/.venv/bin/flowlite run --config /etc/flowlite/flowlite.yaml
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
```

Set `runtime.health_file` and any monitoring system can read component state directly:

```json
{
  "status": "ok",
  "uptime_s": 86412.3,
  "queue_depth": 0,
  "threads": {
    "capture":   {"alive": true, "restarts": 0},
    "pipeline":  {"alive": true, "restarts": 0},
    "telemetry": {"alive": true, "restarts": 0}
  }
}
```

---

## Architecture

Supervised threads with independent failure domains, connected by one bounded queue:

```
  capture driver ──► queue(bounded) ──► pipeline worker ──► CSV sinks
        │                                     ▲
        │                                     │  join on time
  telemetry poller ──────────────────────────►│
  sFlow / NetFlow collectors ────────────────►┘

  supervisor: restart with backoff · fatal-vs-transient · health file · ordered shutdown
```

Design decisions worth knowing about:

- **Streaming statistics.** Mean, variance, min, max and sum are maintained incrementally
  with Welford's algorithm. A flow costs a fixed number of floats regardless of packet
  count, and variance stays numerically stable at epoch-scale timestamps where the naive
  formula collapses.
- **Real flow expiry.** Active timeout, idle timeout, TCP teardown detection and an LRU
  capacity ceiling — the same model hardware exporters use.
- **True-append CSV with a locked schema.** Writes cost time proportional to the rows
  being written, never to the file already on disk. If a column set ever changes, the old
  file is rotated aside so every CSV on disk stays parseable by a single header.
- **Per-exporter NetFlow templates, persisted.** Template caches are keyed by exporter and
  observation domain, and survive restarts, so a collector restart does not blackhole data
  until the next template refresh.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Development

```bash
pip install -e '.[dev]'
pytest                       # 298 tests
pytest --cov=flowlite        # with coverage
ruff check src tests         # lint
ruff format src tests        # format
```

The test suite runs entirely offline. Devices, switches and network traffic are
synthesised in-process: `flowlite.synth` builds valid pcap/pcapng files, sFlow datagrams,
NetFlow v5/v9 and IPFIX exports, and `tests/test_telemetry.py` runs a real in-process SNMP
agent so the SNMP driver is tested against actual wire-format BER.

Decoders are fuzzed against random and truncated input — a malformed datagram from a
misconfigured device must never take down a collector.

---

## Relationship to the previous version

FlowLite 2.0 is a ground-up rewrite of an Arista-EOS-specific pipeline. Beyond going
vendor-neutral, it fixes defects that made the original unsuitable for production,
including: CSV appends that rewrote the entire file every 30 seconds; capture files queued
under a path that did not exist on the running platform; unbounded per-packet buffering
that exhausted memory within an hour; pcapng files rejected outright; a time-series spine
derived from the wall clock rather than the data, which zeroed every joined column;
telemetry failures written as rows of zeros indistinguishable from real zeros; and a
collector whose socket bind failure left it reporting itself healthy while receiving
nothing. Each of those now has a regression test.

## Licence

MIT — see [LICENSE](LICENSE).
