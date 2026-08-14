# Device setup

FlowLite speaks standard protocols, so vendor support is a matter of configuration rather
than code. This page covers the device side.

**If your platform is not listed**, work through the decision guide below. Every managed
network device made in the last two decades satisfies at least one of these paths.

---

## Decision guide

### 1. How will you get packets?

| Situation | Use |
|---|---|
| You can plug a NIC into a SPAN, mirror or TAP port | `capture.source: local` |
| The device has a usable shell and `tcpdump` | `capture.source: ssh` |
| You can get capture files off the device by any means | `capture.source: folder` |
| You cannot capture packets at all | `capture.source: none` — use flow export and telemetry |

Packet capture is optional. A device that only exports NetFlow still produces useful
output.

### 2. How will you get device counters?

| Situation | Use |
|---|---|
| It is a managed device | `telemetry.driver: snmp` — the safe default |
| It supports RESTCONF (RFC 8040) | `telemetry.driver: restconf` |
| Arista EOS | `telemetry.driver: eapi` |
| Cisco NX-OS | `telemetry.driver: nxapi` |
| It has a CLI but no API | `telemetry.driver: ssh_cli` with your own regexes |
| You do not need counters | `telemetry.driver: none` |

### 3. Can it export flows?

If the device supports sFlow, NetFlow v5/v9 or IPFIX, enable the collector and point the
device at this host. This gives you flow visibility across the whole device, not just the
ports you can mirror.

---

## Generic: any managed switch or router

The most portable configuration FlowLite has. Start here.

```bash
flowlite init --profile generic-snmp
```

On the device, enable SNMP read-only access. The exact syntax varies, but the shape does
not:

```
snmp-server community <community> ro
snmp-server host <collector-ip>
```

Verify from the collector:

```bash
flowlite doctor
```

```
Telemetry driver
  [ok]  snmp 192.0.2.20:161 -- 48 interfaces, sysName=switch-1
```

If that works, you have working telemetry. Add packet capture separately when you can.

> **Use a read-only community.** FlowLite only reads, and SNMP v1/v2c sends the community
> string in clear text. Restrict it by source address on the device, and prefer an
> out-of-band management network.

---

## Arista EOS

[`configs/profiles/arista-eos.yaml`](../configs/profiles/arista-eos.yaml)

```eos
! A dedicated read-only account
username flowlite privilege 15 role network-admin secret <password>

! eAPI over HTTPS
management api http-commands
   protocol https
   no shutdown

! Mirror the ports you care about to a spare interface
monitor session 1 source interface Ethernet1-48
monitor session 1 destination interface Ethernet49

! sFlow to the collector
sflow sample 16384
sflow polling-interval 30
sflow destination <collector-ip> 6343
sflow source-interface Management1
sflow run
```

EOS drops SSH sessions into the CLI rather than a shell, so the capture command needs a
wrapper — the profile sets this for you:

```yaml
capture:
  source: ssh
  ssh:
    interface: "Ethernet49"
    command: "bash -c 'tcpdump -i {interface} -U -w - -n'"
```

EOS uses a self-signed certificate. Either export it and set `telemetry.http.ca_bundle`,
or accept the risk with `verify_tls: false`.

---

## Cisco NX-OS (Nexus)

[`configs/profiles/cisco-nxos.yaml`](../configs/profiles/cisco-nxos.yaml)

```nxos
feature nxapi
feature netflow

monitor session 1
  source interface Ethernet1/1-48 both
  destination interface Ethernet1/49
  no shut

flow exporter FLOWLITE
  destination <collector-ip>
  transport udp 2055
  version 9
```

NX-OS has an on-box `ethanalyzer`, but it is rate-limited to protect the supervisor and is
not suitable for bulk capture. Mirror to a collector NIC and use `capture.source: local`.

---

## Cisco IOS-XE (Catalyst, ISR, ASR)

[`configs/profiles/cisco-ios-xe.yaml`](../configs/profiles/cisco-ios-xe.yaml)

```ios
ip http secure-server
restconf

flow record FLOWLITE-RECORD
  match ipv4 source address
  match ipv4 destination address
  match transport source-port
  match transport destination-port
  match ipv4 protocol
  collect counter bytes
  collect counter packets

flow exporter FLOWLITE
  destination <collector-ip>
  transport udp 2055
  export-protocol netflow-v9

flow monitor FLOWLITE-MONITOR
  exporter FLOWLITE
  record FLOWLITE-RECORD

interface GigabitEthernet0/0/0
  ip flow monitor FLOWLITE-MONITOR input
```

IOS-XE cannot usefully stream a packet capture over SSH, so pair NetFlow export with
either a SPAN port into this host or no packet capture at all.

---

## Juniper Junos

[`configs/profiles/juniper-junos.yaml`](../configs/profiles/juniper-junos.yaml)

```junos
set snmp community <community> authorization read-only
set snmp community <community> clients <collector-ip>/32

set services flow-monitoring version-ipfix template FLOWLITE ipv4-template
set forwarding-options sampling instance FLOWLITE family inet output flow-server <collector-ip> port 2055
set forwarding-options sampling instance FLOWLITE family inet output flow-server <collector-ip> version-ipfix template FLOWLITE
```

Junos provides a real shell via `start shell`, and `tcpdump` is present on most platforms,
so SSH capture works directly:

```yaml
capture:
  source: ssh
  ssh:
    interface: "em0"
    command: "start shell command \"tcpdump -i {interface} -U -w - -n\""
```

Junos exports IPFIX; FlowLite detects the version automatically on the NetFlow port.

---

## MikroTik RouterOS

[`configs/profiles/mikrotik-routeros.yaml`](../configs/profiles/mikrotik-routeros.yaml)

```routeros
/snmp set enabled=yes
/snmp community set [find default=yes] name=<community> addresses=<collector-ip>/32

/ip traffic-flow set enabled=yes
/ip traffic-flow target add dst-address=<collector-ip> port=2055 version=9
```

RouterOS has no `tcpdump`. Use flow export plus SNMP, and drop capture files into the
watch folder if you take them another way.

---

## Linux hosts, routers and virtual appliances

[`configs/profiles/linux-host.yaml`](../configs/profiles/linux-host.yaml)

Capture locally and read counters from `/proc/net/dev` over SSH — nothing to install on
the target beyond an SSH server.

```bash
# On the target: allow capture without root
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)

# A dedicated monitoring account with key-only access
sudo useradd -m -s /bin/bash monitor
sudo -u monitor mkdir -p ~monitor/.ssh
```

The profile's `ssh_cli` regex parses `/proc/net/dev` directly, which is a good template
for any device whose counters you can print but cannot query.

---

## Offline and forensic analysis

[`configs/profiles/offline-analysis.yaml`](../configs/profiles/offline-analysis.yaml)

No device, no credentials, no privileges:

```bash
flowlite process incident.pcapng
flowlite process /evidence/captures/
```

Or run continuously against a drop folder:

```bash
flowlite init --profile offline-analysis
flowlite run
cp *.pcapng data/incoming/
```

The profile raises flow timeouts so flows stay whole rather than being cut at an
exporter-style active timeout, and narrows the time-series bucket to 10 seconds for finer
resolution.

---

## Troubleshooting

Start with `flowlite doctor`. It checks the environment, the config, path writability,
disk space, and then contacts the device.

### No IP packets decoded

```bash
flowlite decode suspect.pcap
```

```
link type     Linux cooked v1 (113)
packets       48,102 read, 0 IP, 48,102 non-IP or undecodable
```

A link type FlowLite reports but cannot decode into IP usually means the mirror is
delivering an encapsulation not yet handled. If the capture genuinely contains only ARP,
LLDP or STP, that is the mirror configuration rather than a FlowLite problem.

### SSH capture fails immediately

`flowlite doctor` prints the device's own error text. The usual causes:

- The SSH session lands in a CLI, not a shell → set `capture.ssh.command` with a wrapper.
- The account lacks capture privileges → use a privileged role, or set `sudo: true`.
- The interface name does not exist on the device → check with `show interfaces`.

### SNMP times out

- Confirm the community is read-only and permits the collector's source address.
- Some devices restrict SNMP to the management VRF or a specific interface.
- Try `telemetry.snmp.max_repetitions: 10` for devices with small response buffers.

### No sFlow or NetFlow data arriving

```bash
ss -ulnp | grep -E '6343|2055'      # is FlowLite listening?
sudo tcpdump -ni any port 6343      # is anything arriving?
sudo ufw allow 6343/udp
```

For NetFlow v9 and IPFIX specifically, records cannot be decoded until their template
arrives. Exporters resend templates every 10–30 minutes, so the first records after a
start may be buffered. FlowLite logs an explanation once it has seen enough undecodable
records.

### Counters look wrong after a device reboot

That is a counter reset, and it is flagged rather than reported as a spike: check
`counter_reset` in `interface_counters.csv` and `counter_resets` in
`device_telemetry.csv`.

### Telemetry rows show `reachable=0`

The device did not answer. The `error` column has the reason. Metric cells are left empty
on purpose so a failed poll is never mistaken for an idle device.
