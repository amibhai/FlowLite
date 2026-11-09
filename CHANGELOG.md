# Changelog

## 2.1.0 (2026-11-09)

Flow-record semantics are now fully deterministic, and several decoder defects are fixed.
Records produced by 2.1.0 differ from 2.0.0 where noted.

### Flow engine

- **Idle timeout is checked per packet.** A packet arriving more than `idle_timeout_s`
  after its flow's previous packet starts a new flow. 2.0.0 enforced the idle timeout
  only in a sweep every 8,192 packets, so on sparse captures flows separated by long
  silences were merged. Flow boundaries now depend only on the packet sequence; a test
  checks that the sweep interval cannot change any record.
- **No TCP appendix records.** After a teardown, segments on the same connection that
  arrive within `teardown_grace_s` (new key, default 5 s) and do not open a new
  connection are absorbed and counted (`absorbed_after_teardown`) instead of becoming
  one- or two-packet flows.
- **Direction survives record cuts.** A conversation cut at the active timeout or the
  packet cap keeps its original initiator as the forward endpoint in the continuation
  record.
- **Expiry reasons no longer depend on the sweep.** A flow still in the table at the end of
  a capture that had already been silent for longer than the idle timeout is labelled
  `idle-timeout`, exactly as if a sweep had expired it; a test checks that whole rows,
  `expiry_reason` included, are identical whatever the sweep interval.
- **ICMP query/reply pairing.** Echo, timestamp, information and address-mask replies
  (and ICMPv6 echo replies) are keyed with their request's slots mirrored, so a request
  and its reply form one bidirectional flow.

### Decoder and reader

- Payload length is taken from the IP header's length field even when the capture was
  taken with a snap length, so length features are correct on header-only traces.
- 802.11 and radiotap: Frame Control is parsed in its native little-endian order. 2.0.0
  rejected ordinary data frames.
- 802.1ah (PBB) nesting is bounded, so a crafted frame cannot exhaust the recursion limit.
- A gzip or bzip2 capture cut short now yields its complete packets and is flagged as
  truncated, as uncompressed captures already were.

### Storage

- If a CSV whose header no longer matches cannot be rotated aside (on Windows, another
  process such as a spreadsheet holds it open), the sink now raises instead of appending
  rows that do not match the file's header.

### Collectors

- A NetFlow v9 or IPFIX template whose fields are all zero-length no longer sends the
  decoder into an infinite loop (one crafted datagram could stall the collector).

### Tests and documentation

- 25 new regression tests (323 in total); a degenerate statistics test that failed on
  Python 3.9 and 3.11 is fixed, and tests no longer rely on CPython's reference counting to
  close files, so the suite also passes on PyPy.
- `docs/SCHEMA.md`, `docs/ARCHITECTURE.md` and `docs/CONFIGURATION.md` describe the flow
  semantics precisely: timeouts, teardown handling, ICMP keying, payload and frame
  lengths, fragments, and how unobserved statistics are written.
