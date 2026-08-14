# Architecture

FlowLite is a set of independent producers feeding one analysis stage through a bounded
queue, all under a supervisor that owns restart policy and shutdown.

```
   ┌─────────────────┐
   │ capture driver  │  folder | local | ssh | none
   │  (1 thread)     │
   └────────┬────────┘
            │  CaptureArtifact (a complete, valid capture file)
            ▼
    ┌───────────────┐        bounded: back-pressure, never unbounded growth
    │ queue(maxsize)│
    └───────┬───────┘
            ▼
   ┌─────────────────┐      ┌──────────────────┐      ┌───────────────────┐
   │ pipeline worker │─────►│ flows/*.csv      │      │ telemetry poller  │
   │  (1 thread)     │      │ host_profiles.csv│      │  (1 thread)       │
   │                 │      │ network_ts.csv   │◄─────┤                   │
   └─────────────────┘      └──────────────────┘      └───────────────────┘
            ▲                        ▲
            │                        │  joined on the time spine
            │               ┌────────┴──────────┐
            │               │ sFlow / NetFlow   │
            │               │ collectors        │
            │               │  (1 thread each)  │
            │               └───────────────────┘
            │
   ┌────────┴────────────────────────────────────────────────────────┐
   │ supervisor: restart with backoff · fatal vs transient ·          │
   │ health file · ordered shutdown · PID file                        │
   └──────────────────────────────────────────────────────────────────┘
```

Every component is optional. A deployment can be capture-only, telemetry-only,
collector-only, or all three.

---

## Module map

```
src/flowlite/
├── cli.py                  Command line: run, process, doctor, selftest, decode, init, config
├── config.py               Schema, defaults, merging, coercion, validation
├── _miniyaml.py            Strict YAML subset parser used when PyYAML is absent
├── errors.py               Exception hierarchy (fatal vs transient)
├── logging_setup.py        Rotating file + console + in-memory ring buffer
├── runtime.py              Supervisor, ManagedThread, ServiceState, health
├── pipeline.py             The analysis stage and retention
├── synth.py                Synthetic packets, capture files and export datagrams
│
├── pcap/
│   ├── reader.py           pcap + pcapng + gzip/bzip2, truncation-tolerant
│   └── decode.py           Link layers, IPv4/IPv6, TCP/UDP/ICMP/SCTP/GRE
│
├── flow/
│   ├── stats.py            Welford streaming statistics
│   ├── table.py            Bidirectional flow assembly with bounded memory
│   └── schema.py           The 95-column flow row (single source of truth)
│
├── analytics/
│   ├── host_profiles.py    Per-host behavioural windows
│   └── network_ts.py       Time series with external joins
│
├── capture/
│   ├── base.py             CaptureSource, CaptureArtifact, PreflightReport
│   ├── folder.py           Watch a directory (default; universal)
│   ├── local.py            Capture from a local NIC via tcpdump/dumpcap/tshark
│   ├── ssh.py              Run a capture tool on the device, stream it back
│   ├── streaming.py        Shared rotation engine for live streams
│   └── splitter.py         Lossless pcap/pcapng stream splitting
│
├── telemetry/
│   ├── base.py             DeviceSnapshot, InterfaceCounters, CounterTracker
│   ├── snmp.py             Pure-Python SNMP v1/v2c (BER codec + client)
│   ├── httpapi.py          RESTCONF, Arista eAPI, Cisco NX-API
│   ├── ssh_cli.py          Arbitrary CLI commands parsed with operator regexes
│   └── collector.py        Poll loop, rate computation, CSV output
│
├── flowproto/
│   ├── sflow.py            sFlow v5 decoder (standard + expanded samples)
│   ├── netflow.py          NetFlow v5/v9 + IPFIX with a persistent template cache
│   └── server.py           UDP collectors with bounded queues
│
├── enrich/
│   ├── addresses.py        RFC-based address classification
│   └── geoip.py            Optional MaxMind ASN/country enrichment
│
├── storage/
│   ├── csvsink.py          True-append CSV with a locked schema
│   └── atomic.py           Atomic replace for state files
│
└── ui/dashboard.py         Live terminal dashboard
```

---

## The flow engine

### Constant memory per flow

Every statistic is maintained incrementally with
[Welford's algorithm](https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance).
A flow costs a fixed number of floats no matter how many packets it carries.

This is not only a memory question. The naive "sum of squares minus square of sums"
variance formula loses all precision at epoch-scale magnitudes and can return a negative
variance for timestamps near 1.7 × 10⁹. Welford stays stable, and there is a regression
test for exactly that case.

### Bounded flow count

Flows live in an LRU-ordered map with four exits:

| Exit | Trigger | `expiry_reason` |
|---|---|---|
| Teardown | TCP FIN both ways, or RST | `teardown` |
| Idle timeout | No packet for `idle_timeout_s` of capture time | `idle-timeout` |
| Active timeout | Flow older than `active_timeout_s` | `active-timeout` |
| Packet cap | Flow reaches `max_packets_per_flow` | `packet-cap` |
| Capacity | Table at `max_flows_in_memory`; least-recently-updated evicted | `capacity` |
| End of capture | File exhausted | `end-of-capture` |

Because the map is LRU-ordered, the idle sweep stops at the first flow that is still
fresh — cost is proportional to what actually expires, not to the table size.

A scan producing 3,000 distinct flows against a table capped at 100 still emits all 3,000
records; it just never holds more than 100 at once. There is a test for that.

### Direction is decided once

The endpoint that sent the first packet is *forward* for the flow's whole life. Initial
TCP windows are recorded from the first packet observed **in each direction**, so a
capture that begins mid-connection cannot attribute the responder's window to the
initiator — a real bug in the previous implementation.

### Untrusted timestamps

Merged or reordered captures produce negative inter-arrival times. Those are clamped to
zero rather than being allowed to poison every downstream mean and standard deviation.

---

## Capture

All three live drivers share one rotation engine (`streaming.py`) and one stream splitter
(`splitter.py`).

**The splitter is the interesting part.** A capture tool writes one continuous pcap or
pcapng stream; FlowLite must cut it into hourly files. Cutting at an arbitrary byte offset
produces a truncated record at the end of one file and a headerless fragment at the start
of the next. The splitter instead parses record boundaries as bytes arrive and only ever
rotates *between* records, re-emitting the file header (pcap) or the section and interface
blocks (pcapng) into each new file. Every produced file is independently valid, and no
packet is lost at a boundary. Tests feed a stream one byte at a time and assert the packet
count across rotations is exactly conserved.

The splitter also inspects the first bytes of the stream. When a device answers with
`% Invalid input detected at '^' marker` or `tcpdump: Operation not permitted` instead of
a capture header, that text is surfaced as the error — rather than a confusing "not a pcap
file" message about bytes the operator never asked for.

---

## Telemetry

Every driver returns the same `DeviceSnapshot`. Downstream code never learns which vendor
produced the numbers, so supporting a new platform means writing one `collect()` method.

```
DeviceSnapshot
├── reachable, error, poll_ms          ← always populated, even on failure
├── system_name, system_description, uptime_s
├── cpu_percent, memory_percent
├── arp_entries, mac_entries, route_entries
└── interfaces: [InterfaceCounters]
        index, name, alias, admin_status, oper_status, speed_bps,
        in/out octets, packets, errors, discards
```

### Failures are recorded as failures

A failed poll writes `reachable=0` with a populated `error` and **empty** metric cells. It
is never written as a row of zeros: an unreachable switch and a genuinely idle switch must
not produce byte-identical output.

### Counter arithmetic

`CounterTracker` turns raw counters into deltas and rates, distinguishing two cases that
look similar:

- **Wrap.** A 32-bit counter passing 2³² is corrected by adding the modulus.
- **Reset.** A reboot or counter clear. Detected by asking whether the implied rate is
  physically possible at the interface speed. If a "wrap" would require more bytes than
  the link can carry in the elapsed time, it is a reset: the delta is suppressed and
  `counter_reset` is flagged, rather than reporting a fabricated traffic spike.

The first sample for any interface yields no rate at all, because there is nothing to
compare against.

### SNMP without a dependency

`telemetry/snmp.py` is a complete SNMP v1/v2c implementation: BER encoder/decoder,
GET/GETNEXT/GETBULK, subtree-bounded walks, retries with per-request IDs. It prefers
64-bit `ifXTable` counters and falls back to 32-bit `ifTable` when a device does not
support them.

This exists because SNMP IF-MIB is the one management interface essentially every managed
device supports, and requiring `pysnmp` would have made the most portable path the hardest
one to install. The test suite runs a real in-process SNMP agent, so the codec is verified
against actual wire-format BER rather than mocks.

---

## Flow protocols

### Templates are the hard part of NetFlow

NetFlow v9 and IPFIX send data records whose layout is defined by templates sent
separately, on a timer that is commonly 10–30 minutes. Three decisions matter:

1. **Templates are keyed by `(exporter, observation domain, template id)`.** Different
   devices reuse the same template ids for different layouts; a global cache silently
   decodes one device's records with another device's schema. There is a test asserting
   two exporters using template 256 with different layouts both decode correctly.
2. **The cache is persisted to disk.** Without this, a collector restart blackholes every
   data record until the next template refresh.
3. **Data arriving before its template is counted, not silently dropped.** After 50 such
   records with nothing decoded, FlowLite logs an explanation, so "no output" is
   diagnosable instead of mysterious.

### Collectors cannot lie about being healthy

A bind failure raises before any thread starts. The predecessor swallowed it: the receive
thread died, the writer thread blocked forever on a join, and the process reported the
collector as running while receiving nothing, indefinitely.

Queues are bounded and overflow is counted and logged. A slow disk causes visible,
measured loss rather than unbounded memory growth.

---

## Storage

`CsvSink` appends. Cost is proportional to the rows being written, never to the file
already on disk.

The schema is locked at the header. If a writer ever presents a different column set, the
existing file is rotated aside and a new one started, so **every CSV on disk is parseable
with a single header**. The alternative — appending rows of a different width, which the
previous implementation did whenever an optional data source was absent for an hour —
produces a file no CSV parser can read.

Values are sanitised on the way out: `NaN` and infinity become empty cells rather than
tokens that break downstream parsers, and cells beginning `=`, `+`, `-` or `@` are prefixed
so spreadsheet software does not execute flow data as a formula.

---

## Runtime

`ManagedThread` classifies failures:

- **Fatal** — `ConfigError`, `DependencyError`, `DriverNotFound`, socket bind failures.
  These will fail identically on every retry. Restarting only fills logs and hides the
  real problem, so the worker stops. If it was marked critical, FlowLite exits non-zero.
- **Transient** — everything else. Restarted with the backoff schedule in
  `runtime.restart_backoff_s`.

`runtime.health_file` receives a JSON document every ten seconds with per-thread liveness,
restart counts, queue depth and last errors, so external monitoring never has to parse
logs.

Shutdown is ordered: capture stops first so no new work arrives, the queue drains, then
the analysis stage finishes its current file, then collectors flush. Threads that overrun
`runtime.shutdown_grace_s` are abandoned with a warning rather than hanging the process.

---

## Testing

The suite runs entirely offline — no network, no privileges, no devices.

`flowlite.synth` generates valid pcap and pcapng files (both byte orders, microsecond and
nanosecond), sFlow v5 datagrams in both standard and expanded form, and NetFlow v5, v9 and
IPFIX exports. `tests/test_telemetry.py` runs a real in-process SNMP agent.

Every decoder is fuzzed against random and truncated input, because a malformed datagram
from one misconfigured device must never take down a collector serving others.

Where a test exists for a specific historical defect, its docstring says so — for example
`test_protected_files_are_never_deleted` and
`test_bind_failure_raises_instead_of_dying_silently`.
