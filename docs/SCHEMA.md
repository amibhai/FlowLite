# Output schema

Every FlowLite CSV is schema-locked: the header is written once and the shape never
changes within a file. All timestamps are UTC. An empty cell means *not measured*,
which is deliberately distinct from `0`.

This page is generated from the field definitions in the code, so it cannot drift from
what FlowLite actually writes.

| File | Columns | Granularity |
|---|---|---|
| `flows/*_flows.csv` | 95 | one row per bidirectional flow |
| `host_profiles/host_profiles.csv` | 48 | one row per host per window |
| `network_ts.csv` | 45 | one row per time bucket |
| `telemetry/device_telemetry.csv` | 27 | one row per poll |
| `telemetry/interface_counters.csv` | 25 | one row per interface per poll |
| `flowproto/sflow_samples.csv` | 24 | one row per sampled packet |
| `flowproto/netflow_records.csv` | 26 | one row per exported flow record |

---

## flows.csv (95 columns)

A *flow* is a bidirectional conversation keyed on
`(src_ip, src_port, dst_ip, dst_port, protocol, vlan)`. The endpoint that sent the
first packet is **forward** (`fwd`) for the whole life of the flow; the other is
**backward** (`bwd`). ICMP carries no ports, so type and code occupy the port fields.

Records are emitted when a flow ends through TCP teardown, goes idle, exceeds the
active timeout, hits the packet cap, or the capture ends. `expiry_reason` records which.

| Column | Description |
|---|---|
| `flow_id` | Stable identifier: 5-tuple plus start time. |
| `device` | Device name from `device.name`. |
| `capture_file` | Source capture file name. |
| `src_ip` | Initiator address (the endpoint that sent the first packet). |
| `src_port` | Initiator port. ICMP type for ICMP flows. |
| `dst_ip` | Responder address. |
| `dst_port` | Responder port. ICMP code for ICMP flows. |
| `protocol` | IP protocol number. |
| `protocol_name` | TCP, UDP, ICMP, ICMPv6, SCTP, GRE, ESP, AH, or the number. |
| `ip_version` | 4 or 6. |
| `vlan_id` | Outermost 802.1Q VLAN id, 0 if untagged. |
| `start_time` | First packet, UTC ISO-8601 with milliseconds. |
| `end_time` | Last packet, UTC ISO-8601. |
| `start_epoch` | First packet as a Unix timestamp. |
| `end_epoch` | Last packet as a Unix timestamp. |
| `duration_s` | end_epoch minus start_epoch. |
| `expiry_reason` | Why the record was emitted: `end-of-capture`, `idle-timeout`, `active-timeout`, `teardown`, `packet-cap` or `capacity`. |
| `total_packets` | Packets in both directions. |
| `fwd_packets` | Packets initiator to responder. |
| `bwd_packets` | Packets responder to initiator. |
| `total_bytes` | L4 payload bytes, both directions. |
| `fwd_bytes` | L4 payload bytes forward. |
| `bwd_bytes` | L4 payload bytes backward. |
| `total_frame_bytes` | On-the-wire frame bytes, both directions. |
| `fwd_frame_bytes` | Frame bytes forward. |
| `bwd_frame_bytes` | Frame bytes backward. |
| `packets_per_s` | total_packets / duration (0 when the flow is instantaneous). |
| `bytes_per_s` | total_bytes / duration. |
| `fwd_bytes_per_s` | fwd_bytes / duration. |
| `bwd_bytes_per_s` | bwd_bytes / duration. |
| `pkt_len_mean` | Mean payload size across all packets. |
| `pkt_len_std` | Population standard deviation of payload size. |
| `pkt_len_min` | Smallest payload. |
| `pkt_len_max` | Largest payload. |
| `pkt_len_var` | Variance of payload size. |
| `fwd_pkt_len_mean` | Mean forward payload size. |
| `fwd_pkt_len_std` | Standard deviation, forward. |
| `fwd_pkt_len_min` | Minimum forward payload. |
| `fwd_pkt_len_max` | Maximum forward payload. |
| `bwd_pkt_len_mean` | Mean backward payload size. |
| `bwd_pkt_len_std` | Standard deviation, backward. |
| `bwd_pkt_len_min` | Minimum backward payload. |
| `bwd_pkt_len_max` | Maximum backward payload. |
| `flow_iat_mean` | Mean inter-arrival time across all packets. |
| `flow_iat_std` | Standard deviation of inter-arrival times. |
| `flow_iat_min` | Smallest gap between consecutive packets. |
| `flow_iat_max` | Largest gap between consecutive packets. |
| `fwd_iat_mean` | Mean gap between forward packets. |
| `fwd_iat_std` | Standard deviation of forward gaps. |
| `fwd_iat_min` | Minimum forward gap. |
| `fwd_iat_max` | Maximum forward gap. |
| `bwd_iat_mean` | Mean gap between backward packets. |
| `bwd_iat_std` | Standard deviation of backward gaps. |
| `bwd_iat_min` | Minimum backward gap. |
| `bwd_iat_max` | Maximum backward gap. |
| `active_mean` | Mean duration of active bursts (gaps below `burst_gap_s`). |
| `active_std` | Standard deviation of burst durations. |
| `active_max` | Longest active burst. |
| `active_count` | Number of active bursts. |
| `idle_mean` | Mean idle gap between bursts. |
| `idle_std` | Standard deviation of idle gaps. |
| `idle_max` | Longest idle gap. |
| `idle_count` | Number of idle gaps. |
| `syn_count` | Packets with SYN set. |
| `fin_count` | Packets with FIN set. |
| `rst_count` | Packets with RST set. |
| `psh_count` | Packets with PSH set. |
| `ack_count` | Packets with ACK set. |
| `urg_count` | Packets with URG set. |
| `ece_count` | Packets with ECE set. |
| `cwr_count` | Packets with CWR set. |
| `syn_ratio` | syn_count / total_packets. |
| `fin_ratio` | fin_count / total_packets. |
| `rst_ratio` | rst_count / total_packets. |
| `psh_ratio` | psh_count / total_packets. |
| `ack_ratio` | ack_count / total_packets. |
| `urg_ratio` | urg_count / total_packets. |
| `init_win_fwd` | TCP window advertised in the first forward packet. |
| `init_win_bwd` | TCP window advertised in the first backward packet. |
| `fwd_min_seg_size` | Smallest non-zero forward payload. |
| `tcp_handshake_ms` | SYN to SYN-ACK time in milliseconds, 0 when not observed. |
| `tcp_state` | `syn-sent`, `established`, `closing`, `closed`, `reset`, `ongoing` or `n/a`. |
| `ttl_mean` | Mean IPv4 TTL or IPv6 hop limit. |
| `ttl_std` | Standard deviation of TTL. |
| `ttl_min` | Minimum TTL. |
| `ttl_max` | Maximum TTL. |
| `fragment_packets` | Packets that were IP fragments. |
| `down_up_byte_ratio` | bwd_bytes / fwd_bytes. |
| `fwd_bwd_packet_ratio` | fwd_packets / bwd_packets. |
| `byte_asymmetry` | abs(fwd_bytes - bwd_bytes) / total_bytes. |
| `src_scope` | Address class of the source: private, public, loopback, link-local, cgnat, multicast, broadcast or reserved. |
| `dst_scope` | Address class of the destination. |
| `dst_asn` | Destination ASN. Requires GeoIP. |
| `dst_asn_org` | Destination AS organisation. Requires GeoIP. |
| `dst_country` | Destination country ISO code. Requires GeoIP. |

---

## host_profiles.csv (48 columns)

Every host is profiled in **both roles**: it is credited with what it sent and with
what reached it, so a machine that only receives traffic still appears. One row per
`(host, window)`, where the window length is `analytics.host_profiles.window_minutes`.

| Column | Description |
|---|---|
| `window_start` | Window start, UTC ISO-8601. |
| `window_end` | Window end, UTC ISO-8601. |
| `device` | Device name. |
| `host_ip` | The profiled host. |
| `host_scope` | Address class of the host: private, public, cgnat, and so on. |
| `flows_out` | Flows this host initiated. |
| `flows_in` | Flows initiated towards this host. |
| `flows_total` | Flows involving this host in either role. |
| `packets_sent` | Packets sent by this host. |
| `packets_received` | Packets received by this host. |
| `bytes_sent` | Payload bytes sent. |
| `bytes_received` | Payload bytes received. |
| `bytes_total` | Sum of bytes sent and received. |
| `frame_bytes_sent` | On-the-wire bytes sent, including headers. |
| `frame_bytes_received` | On-the-wire bytes received. |
| `bytes_per_s_sent` | Send rate across the window. |
| `bytes_per_s_received` | Receive rate across the window. |
| `unique_dst_ips` | Distinct destinations this host contacted. |
| `unique_dst_ports` | Distinct destination ports this host used. |
| `unique_dst_asns` | Distinct destination ASNs. Requires GeoIP. |
| `unique_dst_countries` | Distinct destination countries. Requires GeoIP. |
| `unique_peer_sources` | Distinct hosts that contacted this host. |
| `unique_listening_ports` | Distinct local ports on which this host received connections. |
| `dst_port_entropy` | Shannon entropy of the destination-port distribution. High entropy together with high fan-out is the classic port-scan signature. |
| `dst_ip_entropy` | Shannon entropy of the destination-address distribution. |
| `fan_out_ratio` | unique_dst_ips / flows_out. Near 1.0 means almost every flow went somewhere new. |
| `public_dst_ratio` | Share of this host's outbound flows that targeted a public address. |
| `tcp_ratio` | Share of this host's flows that were TCP. |
| `udp_ratio` | Share that were UDP. |
| `icmp_ratio` | Share that were ICMP. |
| `other_proto_ratio` | Share that used another protocol. |
| `syn_ratio` | Mean per-flow SYN ratio across this host's flows. |
| `rst_ratio` | Mean per-flow RST ratio. |
| `fin_ratio` | Mean per-flow FIN ratio. |
| `failed_handshake_ratio` | Share of TCP flows left in `syn-sent`, meaning never answered. A strong scan and outage indicator. |
| `short_flow_ratio` | Share of flows carrying very few packets, typical of scans and probes. |
| `mean_flow_duration_s` | Mean flow duration. |
| `max_flow_duration_s` | Longest flow in the window. |
| `mean_pkt_len` | Mean packet size across this host's flows. |
| `mean_flow_iat_s` | Mean of the per-flow mean inter-arrival times. |
| `mean_active_s` | Mean active-burst duration. |
| `mean_idle_s` | Mean idle gap between bursts. |
| `mean_ttl` | Mean TTL observed for this host. |
| `down_up_byte_ratio` | bytes_received / bytes_sent. Low values suggest a sender role or exfiltration. |
| `share_of_window_flows` | This host's share of all flows in the window. |
| `share_of_window_bytes` | This host's share of all bytes in the window. |
| `share_of_window_dst_ports` | This host's share of all distinct destination ports seen in the window. |
| `cardinality_truncated` | 1 if a cardinality set hit its per-host ceiling, meaning the `unique_*` values are lower bounds. Memory stays bounded even against a host contacting millions of addresses. |

---

## network_ts.csv (45 columns)

A regular time series on a spine derived **from the timestamps in the data**, bucketed
at `analytics.network_ts.bucket_seconds`. Quiet buckets are emitted with zero counts
and `flow_samples = 0`, so a genuinely idle minute stays distinguishable from a minute
that was never measured.

| Column | Description |
|---|---|
| `timestamp` | Bucket start, UTC ISO-8601. |
| `epoch` | Bucket start as a Unix timestamp. |
| `device` | Device name. |
| `bucket_seconds` | Bucket width in seconds. |
| `flow_samples` | Flows starting in this bucket. `0` means measured and quiet. |
| `flows_per_s` | flow_samples / bucket_seconds. |
| `packets_per_s` | Packets per second. |
| `bytes_per_s` | Payload bytes per second. |
| `tcp_ratio` | Share of flows that were TCP. |
| `udp_ratio` | Share that were UDP. |
| `icmp_ratio` | Share that were ICMP. |
| `active_src_ips` | Distinct source addresses. |
| `active_dst_ips` | Distinct destination addresses. |
| `active_dst_ports` | Distinct destination ports. |
| `dst_port_entropy` | Shannon entropy of destination ports across the bucket. |
| `dst_ip_entropy` | Shannon entropy of destination addresses. |
| `byte_asymmetry` | Directional imbalance across the bucket. |
| `mean_flow_duration_s` | Mean flow duration in the bucket. |
| `mean_flow_iat_s` | Mean inter-arrival time. |
| `mean_pkt_len` | Mean packet size. |
| `syn_no_ack_per_s` | Unanswered TCP handshakes per second. The clearest single scan and outage signal. |
| `rst_flows_per_s` | Flows ending in RST per second. |
| `short_flows_ratio` | Share of flows carrying very few packets. |
| `public_dst_ratio` | Share of flows targeting a public address. |
| `ipv6_ratio` | Share of flows carried over IPv6. |
| `new_flows_per_s` | Newly started flows per second. |
| `telemetry_samples` | Device telemetry polls joined into this bucket. `0` means none. |
| `iface_in_bytes_per_s` | Device-reported inbound bytes per second. |
| `iface_out_bytes_per_s` | Device-reported outbound bytes per second. |
| `iface_errors` | Device-reported interface errors during the bucket. |
| `iface_discards` | Device-reported discards during the bucket. |
| `ifaces_total` | Interfaces reported by the device. |
| `ifaces_down` | Interfaces operationally down. |
| `arp_entries` | ARP or neighbour table size, when the driver reports it. |
| `mac_entries` | MAC address table size, when reported. |
| `route_entries` | Routing table size, when reported. |
| `device_cpu_pct` | Device CPU utilisation, when reported. |
| `device_mem_pct` | Device memory utilisation, when reported. |
| `sflow_samples` | sFlow samples joined into this bucket. |
| `sflow_frames_per_s` | Sampled frames per second, before scaling by the sampling rate. |
| `sflow_bytes_per_s` | Bytes per second implied by sFlow samples. |
| `sflow_payload_entropy` | Mean payload entropy of sampled packets. Sustained high entropy suggests encryption or tunnelling. |
| `netflow_samples` | NetFlow or IPFIX records joined into this bucket. |
| `netflow_flows_per_s` | Flows per second reported by the exporter. |
| `netflow_bytes_per_s` | Bytes per second reported by the exporter. |

---

## device_telemetry.csv (27 columns)

One row per poll, identical in shape no matter which driver produced it.

> A failed poll is written with `reachable = 0`, a populated `error`, and its metric
> cells left **empty**. It is never written as a row of zeros: an unreachable device
> and a genuinely idle device must not be indistinguishable.

| Column | Description |
|---|---|
| `timestamp` | Poll time, UTC ISO-8601. |
| `epoch` | Poll time as a Unix timestamp. |
| `device` | Device name. |
| `driver` | Driver that produced the row: snmp, restconf, eapi, nxapi or ssh_cli. |
| `reachable` | 1 if the poll succeeded, 0 if it failed. |
| `poll_ms` | How long the poll took, in milliseconds. |
| `error` | Failure reason when `reachable` is 0. |
| `interfaces_total` | Interfaces discovered. |
| `interfaces_up` | Interfaces operationally up. |
| `interfaces_down` | Interfaces operationally down. |
| `in_bytes_per_s` | Total inbound bytes per second across all interfaces. |
| `out_bytes_per_s` | Total outbound bytes per second. |
| `in_packets_per_s` | Total inbound packets per second. |
| `out_packets_per_s` | Total outbound packets per second. |
| `in_errors_delta` | Inbound errors since the previous poll. |
| `out_errors_delta` | Outbound errors since the previous poll. |
| `in_discards_delta` | Inbound discards since the previous poll. |
| `out_discards_delta` | Outbound discards since the previous poll. |
| `counter_resets` | Interfaces whose counters reset since the previous poll. |
| `arp_entries` | ARP or neighbour table size, when available. |
| `mac_entries` | MAC address table size, when available. |
| `route_entries` | Routing table size, when available. |
| `cpu_percent` | CPU utilisation, when the driver reports it. |
| `memory_percent` | Memory utilisation, when reported. |
| `uptime_s` | Device uptime in seconds. |
| `system_name` | Device hostname as the device reports it. |
| `system_description` | Device description string, typically model and OS version. |

---

## interface_counters.csv (25 columns)

One row per interface per poll. sFlow counter samples are written here too, in exactly
this shape, so an sFlow-only deployment produces the same interface data as an SNMP one.

> Counter deltas are wrap-aware. A 32-bit counter wrap is corrected. A *reset*, from a
> reboot or a counter clear, is detected by testing whether the implied rate is
> physically possible at the interface speed; it is flagged in `counter_reset` and the
> delta is suppressed rather than reported as a fabricated spike.

| Column | Description |
|---|---|
| `timestamp` | Sample time, UTC ISO-8601. |
| `epoch` | Sample time as a Unix timestamp. |
| `device` | Device name, or the sFlow agent address. |
| `if_index` | SNMP ifIndex. |
| `if_name` | Interface name. |
| `if_alias` | Interface description or alias. |
| `admin_status` | up or down. |
| `oper_status` | up or down. |
| `speed_bps` | Interface speed in bits per second. |
| `in_octets` | Raw inbound octet counter. |
| `out_octets` | Raw outbound octet counter. |
| `in_packets` | Raw inbound packet counter. |
| `out_packets` | Raw outbound packet counter. |
| `in_errors` | Raw inbound error counter. |
| `out_errors` | Raw outbound error counter. |
| `in_discards` | Raw inbound discard counter. |
| `out_discards` | Raw outbound discard counter. |
| `interval_s` | Seconds since the previous sample for this interface. |
| `in_octets_delta` | Inbound octets since the previous sample. |
| `out_octets_delta` | Outbound octets since the previous sample. |
| `in_bytes_per_s` | Inbound bytes per second. |
| `out_bytes_per_s` | Outbound bytes per second. |
| `utilisation_in_pct` | Inbound utilisation against `speed_bps`. |
| `utilisation_out_pct` | Outbound utilisation against `speed_bps`. |
| `counter_reset` | 1 if the counter reset since the previous sample. |

---

## sflow_samples.csv (24 columns)

One row per sampled packet header. Standard and expanded sample formats produce
identical rows.

| Column | Description |
|---|---|
| `timestamp` | Receive time, UTC ISO-8601. |
| `epoch` | Receive time as a Unix timestamp. |
| `agent_ip` | sFlow agent address. |
| `sub_agent_id` | Agent sub-agent id. |
| `sequence` | Sample sequence number. Gaps indicate datagrams lost in transit. |
| `sampling_rate` | 1-in-N sampling rate. Multiply counts by this to estimate totals. |
| `sample_pool` | Total packets the agent could have sampled. |
| `drops` | Samples the agent itself dropped. |
| `input_if` | Ingress ifIndex. |
| `output_if` | Egress ifIndex. |
| `frame_length` | Original frame length on the wire. |
| `stripped` | Bytes stripped by the agent before sampling. |
| `header_bytes` | Header bytes actually captured in the sample. |
| `payload_entropy` | Shannon entropy of the captured header bytes, 0 to 8. |
| `ip_version` | 4 or 6. |
| `src_ip` | Source address from the sampled header. |
| `dst_ip` | Destination address from the sampled header. |
| `src_port` | Source port. |
| `dst_port` | Destination port. |
| `protocol` | IP protocol number. |
| `protocol_name` | Protocol name. |
| `tcp_flags` | TCP flag bits from the sampled packet. |
| `vlan_id` | 802.1Q VLAN id. |
| `ttl` | IPv4 TTL or IPv6 hop limit from the sampled header. |

---

## netflow_records.csv (26 columns)

One row per exported flow record. NetFlow v5, NetFlow v9 and IPFIX all normalise to
this schema; `version` records which produced the row.

| Column | Description |
|---|---|
| `timestamp` | Export time, UTC ISO-8601. |
| `epoch` | Export time as a Unix timestamp. |
| `exporter` | Source address of the exporting device. |
| `version` | 5, 9 or 10 (IPFIX). |
| `observation_domain` | Observation domain or source id. |
| `template_id` | Template that decoded this record. 0 for v5. |
| `src_ip` | Source address. |
| `dst_ip` | Destination address. |
| `src_port` | Source port. |
| `dst_port` | Destination port. |
| `protocol` | IP protocol number. |
| `protocol_name` | Protocol name. |
| `tcp_flags` | Cumulative TCP flags for the flow. |
| `ip_version` | 4 or 6. |
| `packets` | Packets in the flow. |
| `bytes` | Bytes in the flow. |
| `first_switched` | Flow start as a Unix timestamp. |
| `last_switched` | Flow end as a Unix timestamp. |
| `duration_s` | Flow duration. |
| `input_if` | Ingress ifIndex. |
| `output_if` | Egress ifIndex. |
| `src_vlan` | Source VLAN. |
| `tos` | IP type of service. |
| `src_asn` | Source ASN as reported by the exporter. |
| `dst_asn` | Destination ASN as reported by the exporter. |
| `sampling_rate` | Exporter sampling rate. 1 when unsampled. |

