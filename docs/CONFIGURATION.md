# Configuration reference

FlowLite merges your file over a complete set of defaults. Anything you omit keeps its
default value, so a partial file is always valid and a missing key can never raise an
error inside a worker thread.

- Annotated template: [`configs/flowlite.example.yaml`](../configs/flowlite.example.yaml)
- Ready-made device profiles: [`configs/profiles/`](../configs/profiles/)
- See the effective result: `flowlite config` (secrets redacted)
- Validate without running: `flowlite doctor`

---

## Where the config comes from

In order, first match wins:

1. `--config PATH`
2. `$FLOWLITE_CONFIG`
3. `./flowlite.yaml`, `./flowlite.yml`, `./flowlite.json`
4. `./configs/flowlite.yaml`
5. `~/.config/flowlite/flowlite.yaml`
6. `/etc/flowlite/flowlite.yaml`

No file at all is valid: FlowLite runs on defaults and warns. JSON is accepted anywhere
YAML is. A top-level `flowlite:` wrapper key is optional and unwrapped automatically.

### Overrides from the command line

```bash
flowlite run --set telemetry.interval_s=30 --set device.host=10.0.0.1
```

Values are parsed as JSON when possible, otherwise as strings.

### Secrets from the environment

Any string may reference the environment:

```yaml
credentials:
  password: "${FLOWLITE_PASS}"            # error if unset
  snmp_community: "${FLOWLITE_SNMP:-public}"   # falls back
```

Referencing an unset variable **without** a fallback is a configuration error, not a
silent empty string. `flowlite config` redacts every credential-shaped value.

---

## Validation

Every problem is reported at once, with the exact key path:

```
error: Configuration is invalid (flowlite.yaml)
  - capture.source: 'banana' is not one of folder, ssh, local, none
  - telemetry.interval_s: 1 is below the minimum of 5
  - telemetry.snmp.community (or credentials.snmp_community) must be set for SNMP v1/v2c
```

Types are coerced where the intent is unambiguous — `port: "6343"` from a templating
system becomes an integer, `enabled: "no"` becomes a boolean, `patterns: "*.pcap, *.cap"`
becomes a list. Unknown keys are reported as warnings so typos are visible; `--strict`
turns them into errors.

---

## `device`

Descriptive, except that `host` is inherited by every driver that does not set its own.

| Key | Default | Notes |
|---|---|---|
| `name` | `""` | Written into every output row. Defaults to `host`, then `instance`. |
| `host` | `""` | Management IP or hostname. |
| `vendor` | `generic` | Free text, for your own records. |
| `description` | `""` | Free text. |

## `credentials`

Shared credentials, inherited by drivers that do not override them.

| Key | Notes |
|---|---|
| `username` / `password` | SSH and HTTP API authentication. |
| `ssh_key_file` | Private key path. Preferred over passwords. |
| `ssh_key_passphrase` | Passphrase for the key, if it has one. |
| `snmp_community` | SNMP v1/v2c community string. |

---

## `capture`

| Key | Default | Notes |
|---|---|---|
| `source` | `folder` | `folder`, `local`, `ssh` or `none`. |
| `rotate_seconds` | `3600` | Start a new capture file this often. |
| `max_file_mb` | `4096` | ...or at this size, whichever comes first. |
| `queue_depth` | `64` | Files awaiting analysis before capture applies back-pressure. |
| `retry_initial_s` / `retry_max_s` | `5` / `300` | Reconnect backoff bounds. |

### `capture.source: folder` — the universal option

Watches a directory for capture files. Works with anything that can produce a pcap: a
scheduled export from the device, `scp` from a jump host, a colleague's incident capture.

| Key | Default | Notes |
|---|---|---|
| `watch_dir` | `<data_dir>/incoming` | Directory to watch. |
| `patterns` | `*.pcap, *.pcapng, *.pcap.gz, *.pcapng.gz` | Globs to match. |
| `poll_interval_s` | `5` | How often to scan. |
| `stable_seconds` | `10` | A file must stop changing for this long before it is taken — this is what prevents reading a half-written upload. |
| `recursive` | `true` | Descend into subdirectories. |
| `delete_after_processing` | `false` | Remove the source file once analysed. |
| `reprocess_existing` | `true` | Process files already present at startup. `false` adopts them silently. |

Files are checkpointed by path, size and modification time, so a restart does not
reprocess work already done — but replacing a file's *contents* under the same name does
queue it again. Temporary and hidden files (`.tmp`, `.part`, leading dot) are ignored.

### `capture.source: local`

Captures from a NIC on this machine, typically one patched into a SPAN, mirror or TAP port.

| Key | Default | Notes |
|---|---|---|
| `interface` | `""` | **Required.** The local NIC. `flowlite doctor` lists what it can find. |
| `tool` | `auto` | `auto`, `tcpdump`, `dumpcap` or `tshark`. |
| `bpf_filter` | `""` | e.g. `not port 22` to exclude your own SSH session. |
| `snaplen` | `0` | 0 captures whole packets. |
| `extra_args` | `[]` | Appended verbatim to the capture command. |

Capturing usually needs elevated privileges. On Linux, grant them without running FlowLite
as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
```

### `capture.source: ssh`

Runs a capture tool on the device and streams the result back.

| Key | Default | Notes |
|---|---|---|
| `host` / `port` | `device.host` / `22` | |
| `username` / `password` / `key_file` | from `credentials` | Passwords require `paramiko`. Key auth works with the system `ssh` binary. |
| `host_key_policy` | `accept-new` | `strict`, `accept-new` or `ignore`. |
| `known_hosts_file` | `""` | Defaults to the system file. |
| `interface` | `any` | The interface name **on the device**. |
| `bpf_filter` / `snaplen` | `""` / `0` | |
| `capture_tool` | `tcpdump` | `tcpdump`, `tshark` or `dumpcap`. |
| `sudo` | `false` | Prefix with `sudo -n`. |
| `command` | `""` | Full override. Placeholders: `{interface}`, `{filter}`, `{snaplen}`. |
| `connect_timeout_s` / `read_timeout_s` | `30` / `30` | |

`command` is what makes this work across platforms whose SSH session is a CLI rather than
a shell:

```yaml
# Arista EOS — SSH lands in the CLI, so wrap in bash
command: "bash -c 'tcpdump -i {interface} -U -w - -n'"

# Juniper Junos
command: "start shell command \"tcpdump -i {interface} -U -w - -n\""
```

> `host_key_policy: ignore` disables host key verification and permits man-in-the-middle
> interception. FlowLite warns when it is set. Use `accept-new` or `strict` in production.

---

## `telemetry`

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | |
| `driver` | `none` | `snmp`, `restconf`, `eapi`, `nxapi`, `ssh_cli` or `none`. |
| `interval_s` | `60` | Poll interval. Minimum 5. |
| `timeout_s` | `10` | Per-request timeout. |

Whichever driver you choose, the output schema is identical.

### `telemetry.snmp` — works with almost any device

| Key | Default | Notes |
|---|---|---|
| `host` / `port` | `device.host` / `161` | |
| `version` | `2c` | `1` or `2c`. |
| `community` | from `credentials` | |
| `max_repetitions` | `25` | GETBULK repetitions. Lower it for devices with small buffers. |
| `retries` | `2` | Retries per request. |
| `collect_interface_names` | `true` | Walk `ifName`/`ifAlias`. Costs two extra walks. |
| `collect_high_capacity` | `true` | Prefer 64-bit `ifXTable` counters; falls back automatically. |
| `tables` | `[]` | Extra walks: `arp`, `mac`, `routes`. Each costs a walk. |

> Leave `collect_high_capacity: true` on any link faster than 100 Mbit/s. A 32-bit octet
> counter wraps in under six minutes on a gigabit link, so a 60-second poll cannot tell a
> wrap from a reset reliably.

### `telemetry.http` — RESTCONF, eAPI and NX-API

| Key | Default | Notes |
|---|---|---|
| `host` | `device.host` | |
| `scheme` | `https` | |
| `port` | `0` | 0 uses the scheme default. |
| `verify_tls` | `true` | |
| `ca_bundle` | `""` | Path to the device certificate or its CA. |
| `base_path` | `""` | Override the API root. |
| `username` / `password` | from `credentials` | |

> Network devices ship self-signed certificates, so `verify_tls: false` is common — and
> FlowLite warns when it is set, because it removes authentication of the device. The
> better answer is to export the device certificate and point `ca_bundle` at it.

### `telemetry.ssh_cli` — any device with a CLI

Runs commands over SSH and extracts named groups from your regexes. The escape hatch for
platforms with no usable API.

```yaml
telemetry:
  driver: ssh_cli
  ssh_cli:
    commands:
      - name: interfaces
        command: "cat /proc/net/dev"
        scope: interface        # one row per regex match
        regex: '^\s*(?P<if_name>[\w.@-]+):\s*(?P<in_octets>\d+)\s+(?P<in_packets>\d+)'
      - name: cpu
        command: "show system resources"
        scope: device           # one row for the device
        regex: 'CPU states:\s+(?P<cpu_percent>[\d.]+)%'
```

`scope: interface` recognises the group names `if_name`, `if_index`, `if_alias`,
`admin_status`, `oper_status`, `speed_bps`, `in_octets`, `out_octets`, `in_packets`,
`out_packets`, `in_errors`, `out_errors`, `in_discards`, `out_discards`.

`scope: device` recognises `cpu_percent`, `memory_percent`, `uptime_s`, `arp_entries`,
`mac_entries`, `route_entries`, `system_name`, `system_description`.

Regexes are compiled and validated at configuration load, so a mistake is caught by
`flowlite doctor` rather than at 3 a.m.

---

## `flowproto`

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | Master switch. |
| `flush_interval_s` | `60` | How often buffered records are written. |
| `max_queue` | `200000` | Bounded. Overflow is counted and logged. |
| `recv_buffer_bytes` | `4194304` | `SO_RCVBUF`. Raise it for high sampling rates. |
| `sflow.enabled` / `sflow.bind` / `sflow.port` | `false` / `0.0.0.0` / `6343` | |
| `sflow.sample_csv` | `true` | Write individual samples, not only counters. |
| `netflow.enabled` / `netflow.bind` / `netflow.port` | `false` / `0.0.0.0` / `2055` | v5, v9 and IPFIX are auto-detected. |
| `netflow.template_ttl_s` | `3600` | Templates older than this are discarded. |

Firewall the collector ports on the receiving host:

```bash
sudo ufw allow 6343/udp
sudo ufw allow 2055/udp
```

---

## `analytics`

### `analytics.flow`

| Key | Default | Notes |
|---|---|---|
| `active_timeout_s` | `300` | Cut long-lived flows into records of this length. |
| `idle_timeout_s` | `60` | Close a flow after this much silence. |
| `burst_gap_s` | `1.0` | Gap that separates an active burst from idle time. |
| `max_flows_in_memory` | `250000` | Hard ceiling. Excess is evicted, not dropped. |
| `max_packets_per_flow` | `20000` | Cut a flow record at this many packets. |
| `min_packets_per_flow` | `1` | Discard flows below this size. |

For **offline analysis**, raise the timeouts so flows stay whole:

```yaml
analytics:
  flow:
    active_timeout_s: 86400
    idle_timeout_s: 3600
```

For **live monitoring**, the defaults match what hardware exporters do.

### `analytics.host_profiles` and `analytics.network_ts`

| Key | Default | Notes |
|---|---|---|
| `host_profiles.enabled` | `true` | |
| `host_profiles.window_minutes` | `10` | Profile window length. |
| `network_ts.enabled` | `true` | |
| `network_ts.bucket_seconds` | `60` | Time-series resolution. |

---

## `enrich`

| Key | Default | Notes |
|---|---|---|
| `classify_addresses` | `true` | Fills `src_scope`/`dst_scope`. No dependencies. |
| `geoip.enabled` | `false` | Requires `pip install 'flowlite[geoip]'`. |
| `geoip.asn_db` | `""` | Path to `GeoLite2-ASN.mmdb`. |
| `geoip.city_db` | `""` | Path to `GeoLite2-City.mmdb`. |

Databases are free from [MaxMind](https://www.maxmind.com/en/geolite2/signup) after
registration. Missing or unreadable databases produce a warning and empty enrichment
columns — never a failure.

---

## `paths`

`data_dir` is the only one you normally set; leave the rest empty to derive them.

| Key | Derived as |
|---|---|
| `data_dir` | `./data` |
| `incoming_dir` | `<data_dir>/incoming` |
| `pcap_dir` | `<data_dir>/pcap` |
| `flows_dir` | `<data_dir>/flows` |
| `profiles_dir` | `<data_dir>/host_profiles` |
| `network_ts` | `<data_dir>/network_ts.csv` |
| `telemetry_csv` | `<data_dir>/telemetry/device_telemetry.csv` |
| `interfaces_csv` | `<data_dir>/telemetry/interface_counters.csv` |
| `sflow_csv` | `<data_dir>/flowproto/sflow_samples.csv` |
| `netflow_csv` | `<data_dir>/flowproto/netflow_records.csv` |
| `logs_dir` | `<data_dir>/logs` |
| `state_dir` | `<data_dir>/state` |

`~` and environment variables are expanded.

---

## `retention`

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | |
| `pcap_days` | `7` | Delete capture files older than this. 0 disables. |
| `csv_days` | `30` | Delete per-file flow CSVs older than this. 0 disables. |
| `max_data_dir_gb` | `0.0` | 0 means no cap. Otherwise the oldest captures are deleted until the directory fits. |
| `protect` | `["network_ts.csv"]` | Never deleted. |

`network_ts.csv`, `device_telemetry.csv` and `interface_counters.csv` are protected
automatically — they are rolling files meant to accumulate.

> Retention never walks a path that is empty, `.` or `/`. An unset path means "nothing to
> sweep", not "sweep the working directory".

---

## `runtime`

| Key | Default | Notes |
|---|---|---|
| `dashboard` | `auto` | `auto` shows it only on an interactive terminal. |
| `restart_backoff_s` | `[5, 15, 60, 300]` | Backoff schedule for crashed workers. |
| `max_restarts` | `0` | 0 is unlimited. |
| `health_file` | `""` | JSON health document, refreshed every 10 s. |
| `pid_file` | `""` | Refuses to start if a live instance already holds it. |
| `shutdown_grace_s` | `30` | How long to wait for threads on shutdown. |

## `logging`

| Key | Default | Notes |
|---|---|---|
| `level` | `INFO` | Console level. Raised to WARNING while the dashboard owns the terminal. |
| `file_level` | `DEBUG` | Level for `<logs_dir>/flowlite.log`. |
| `console` | `true` | |
| `max_bytes` / `backups` | `10485760` / `5` | Rotation. |
| `format` | `text` | `text` or `json` for log shipping. |

An unwritable log directory is not fatal: FlowLite warns and continues with console
logging.
