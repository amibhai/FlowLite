"""UDP collectors for sFlow and NetFlow/IPFIX.

The predecessor's listener had a failure mode worth naming: if the socket bind
failed, the receive thread died with the exception swallowed, the writer thread
then blocked forever on a join, and the process reported the collector as
running while receiving nothing, indefinitely. Here a bind failure is raised
before any thread starts, and the supervisor decides what to do about it.

Other properties:

* **Bounded queues.** A slow disk cannot make an unbounded in-memory deque grow
  until the process is killed. Overflow is counted and logged, so loss is
  visible rather than silent.
* **A large receive buffer.** ``SO_RCVBUF`` is raised because the default is far
  too small for a switch bursting sFlow at line-rate sampling, and kernel-level
  drops never appear in application logs.
* **Decode failures are isolated.** One malformed datagram cannot stop the
  collector; it is counted and dropped.
"""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from ..storage.csvsink import CsvSink
from ..telemetry.base import INTERFACE_FIELDS, CounterTracker, counter_rate, utilisation_pct
from .netflow import NETFLOW_FIELDS, NetFlowDecoder, TemplateCache
from .sflow import SFLOW_SAMPLE_FIELDS, decode_sflow

__all__ = ["UdpCollector", "SFlowCollector", "NetFlowCollector", "build_collectors"]


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class UdpCollector:
    """A UDP listener with a bounded queue and a periodic CSV flush."""

    name = "udp"

    def __init__(
        self,
        bind: str,
        port: int,
        *,
        logger,
        flush_interval_s: float = 60.0,
        max_queue: int = 200000,
        recv_buffer_bytes: int = 4 << 20,
        status: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.bind = bind
        self.port = int(port)
        self.log = logger
        self.flush_interval = float(flush_interval_s)
        self.max_queue = int(max_queue)
        self.recv_buffer_bytes = int(recv_buffer_bytes)
        self.status: Dict[str, Any] = status if status is not None else {}

        self._queue: Deque[Dict[str, Any]] = deque(maxlen=self.max_queue)
        self._lock = threading.Lock()
        self._socket: Optional[socket.socket] = None
        self.datagrams = 0
        self.rows_queued = 0
        self.rows_written = 0
        self.dropped = 0
        self.decode_errors = 0
        self.last_datagram_at: Optional[float] = None

    # -- socket ------------------------------------------------------------ #

    def bind_socket(self) -> socket.socket:
        """Create and bind the listening socket. Raises on failure, by design."""
        family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buffer_bytes)
        except OSError:
            pass
        try:
            sock.bind((self.bind, self.port))
        except OSError as exc:
            sock.close()
            hint = ""
            if getattr(exc, "errno", None) in (13, 10013):
                hint = f" Ports below 1024 need elevated privileges; {self.port} may be restricted."
            elif getattr(exc, "errno", None) in (98, 10048):
                hint = (
                    f" Another process is already listening on {self.bind}:{self.port}"
                    f" (check with: ss -ulnp | grep {self.port})."
                )
            raise OSError(
                f"{self.name} collector cannot bind {self.bind}:{self.port}: {exc}.{hint}"
            ) from exc

        effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.settimeout(1.0)
        self._socket = sock
        self.log.info(
            "%s collector listening on %s:%d (receive buffer %d KiB)",
            self.name,
            self.bind,
            self.port,
            effective // 1024,
        )
        self.status.update({"running": True, "port": self.port, "bind": self.bind})
        return sock

    # -- subclass hooks ---------------------------------------------------- #

    def handle(self, data: bytes, source_ip: str, epoch: float) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def flush(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self.status["running"] = False

    # -- queue -------------------------------------------------------------- #

    def _enqueue(self, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        with self._lock:
            space = self.max_queue - len(self._queue)
            if space <= 0:
                self.dropped += len(rows)
                return
            if len(rows) > space:
                self.dropped += len(rows) - space
                rows = rows[:space]
            self._queue.extend(rows)
            self.rows_queued += len(rows)

    def _drain(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = list(self._queue)
            self._queue.clear()
        return rows

    # -- main loop ---------------------------------------------------------- #

    def run(self, stop_event: threading.Event) -> None:
        sock = self._socket or self.bind_socket()
        last_flush = time.monotonic()
        last_drop_warning = 0.0

        try:
            while not stop_event.is_set():
                try:
                    data, address = sock.recvfrom(65535)
                except (socket.timeout, TimeoutError):
                    data = None
                    address = None
                except OSError as exc:
                    if stop_event.is_set():
                        break
                    self.log.warning("%s collector receive error: %s", self.name, exc)
                    time.sleep(0.2)
                    data = None
                    address = None

                if data:
                    now = time.time()
                    self.datagrams += 1
                    self.last_datagram_at = now
                    try:
                        self._enqueue(self.handle(data, address[0] if address else "", now))
                    except Exception as exc:
                        self.decode_errors += 1
                        self.log.debug("%s decode error from %s: %s", self.name, address, exc)

                    if self.dropped and time.monotonic() - last_drop_warning > 60:
                        last_drop_warning = time.monotonic()
                        self.log.warning(
                            "%s collector dropped %d record(s): the queue of %d is full. "
                            "Lower flowproto.flush_interval_s or raise flowproto.max_queue.",
                            self.name,
                            self.dropped,
                            self.max_queue,
                        )

                if time.monotonic() - last_flush >= self.flush_interval:
                    last_flush = time.monotonic()
                    self._safe_flush()
                    self._update_status()

            self._safe_flush()
            self._update_status()
        finally:
            self.close()
            self.log.info(
                "%s collector stopped: %d datagram(s), %d row(s) written, %d dropped",
                self.name,
                self.datagrams,
                self.rows_written,
                self.dropped,
            )

    def _safe_flush(self) -> None:
        try:
            self.rows_written += self.flush()
        except Exception as exc:
            self.log.error("%s collector flush failed: %s", self.name, exc, exc_info=True)

    def _update_status(self) -> None:
        self.status.update(
            {
                "datagrams": self.datagrams,
                "rows": self.rows_written,
                "dropped": self.dropped,
                "errors": self.decode_errors,
                "last_datagram": self.last_datagram_at,
                "queued": len(self._queue),
            }
        )


class SFlowCollector(UdpCollector):
    """Receive sFlow v5, writing flow samples and interface counters."""

    name = "sflow"

    def __init__(self, cfg, logger, status=None) -> None:
        fp = cfg.flowproto
        super().__init__(
            fp.sflow.bind,
            fp.sflow.port,
            logger=logger,
            flush_interval_s=fp.flush_interval_s,
            max_queue=fp.max_queue,
            recv_buffer_bytes=fp.recv_buffer_bytes,
            status=status,
        )
        self.write_samples = bool(fp.sflow.sample_csv)
        self.sample_sink = CsvSink(Path(cfg.paths.sflow_csv), SFLOW_SAMPLE_FIELDS)
        self.interface_sink = CsvSink(Path(cfg.paths.interfaces_csv), INTERFACE_FIELDS)
        self.tracker = CounterTracker()
        self._counter_rows: List[Dict[str, Any]] = []
        self._counter_lock = threading.Lock()

    def handle(self, data: bytes, source_ip: str, epoch: float) -> List[Dict[str, Any]]:
        datagram = decode_sflow(data, epoch)
        if datagram.errors:
            self.decode_errors += 1
            self.log.debug("sFlow from %s: %s", source_ip, "; ".join(datagram.errors[:3]))
        agent = datagram.agent_ip or source_ip

        if datagram.counter_samples:
            self._absorb_counters(datagram.counter_samples, agent, epoch)

        if not self.write_samples:
            return []

        rows: List[Dict[str, Any]] = []
        for sample in datagram.flow_samples:
            row = dict.fromkeys(SFLOW_SAMPLE_FIELDS, "")
            row.update(
                {
                    "timestamp": _iso(epoch),
                    "epoch": round(epoch, 3),
                    "agent_ip": agent,
                    "sub_agent_id": datagram.sub_agent_id,
                }
            )
            row.update({k: v for k, v in sample.items() if k in row})
            rows.append(row)
        return rows

    def _absorb_counters(self, samples: List[Dict[str, Any]], agent: str, epoch: float) -> None:
        rows: List[Dict[str, Any]] = []
        for sample in samples:
            index = int(sample.get("if_index", 0))
            speed = int(sample.get("speed_bps", 0) or 0)
            deltas = self.tracker.update(
                f"sflow|{agent}|{index}",
                {
                    "in_octets": sample.get("in_octets"),
                    "out_octets": sample.get("out_octets"),
                    "in_packets": sample.get("in_packets"),
                    "out_packets": sample.get("out_packets"),
                    "in_errors": sample.get("in_errors"),
                    "out_errors": sample.get("out_errors"),
                    "in_discards": sample.get("in_discards"),
                    "out_discards": sample.get("out_discards"),
                },
                epoch,
                speed_bps=speed,
            )
            interval = float(deltas.get("interval_s", 0.0) or 0.0)
            in_rate = counter_rate(deltas, "in_octets", interval)
            out_rate = counter_rate(deltas, "out_octets", interval)
            status_word = int(sample.get("status", 0) or 0)
            rows.append(
                {
                    "timestamp": _iso(epoch),
                    "epoch": round(epoch, 3),
                    "device": agent,
                    "if_index": index,
                    "if_name": f"ifIndex{index}",
                    "if_alias": "",
                    # ifStatus packs admin state in bit 0 and oper state in bit 1.
                    "admin_status": "up" if status_word & 1 else "down",
                    "oper_status": "up" if status_word & 2 else "down",
                    "speed_bps": speed,
                    "in_octets": sample.get("in_octets", ""),
                    "out_octets": sample.get("out_octets", ""),
                    "in_packets": sample.get("in_packets", ""),
                    "out_packets": sample.get("out_packets", ""),
                    "in_errors": sample.get("in_errors", ""),
                    "out_errors": sample.get("out_errors", ""),
                    "in_discards": sample.get("in_discards", ""),
                    "out_discards": sample.get("out_discards", ""),
                    "interval_s": interval if interval else "",
                    "in_octets_delta": deltas.get("in_octets_delta", ""),
                    "out_octets_delta": deltas.get("out_octets_delta", ""),
                    "in_bytes_per_s": in_rate,
                    "out_bytes_per_s": out_rate,
                    "utilisation_in_pct": utilisation_pct(in_rate, speed),
                    "utilisation_out_pct": utilisation_pct(out_rate, speed),
                    "counter_reset": deltas.get("counter_reset", 0),
                }
            )
        if rows:
            with self._counter_lock:
                # Keep the pending buffer bounded even if flushing stalls.
                overflow = len(self._counter_rows) + len(rows) - self.max_queue
                if overflow > 0:
                    del self._counter_rows[:overflow]
                    self.dropped += overflow
                self._counter_rows.extend(rows)

    def flush(self) -> int:
        written = 0
        rows = self._drain()
        if rows:
            written += self.sample_sink.write_rows(rows)
        with self._counter_lock:
            counters = self._counter_rows
            self._counter_rows = []
        if counters:
            written += self.interface_sink.write_rows(counters)
        return written

    def close(self) -> None:
        super().close()
        for sink in (self.sample_sink, self.interface_sink):
            try:
                sink.close()
            except Exception:
                pass


class NetFlowCollector(UdpCollector):
    """Receive NetFlow v5/v9 and IPFIX."""

    name = "netflow"

    def __init__(self, cfg, logger, status=None) -> None:
        fp = cfg.flowproto
        super().__init__(
            fp.netflow.bind,
            fp.netflow.port,
            logger=logger,
            flush_interval_s=fp.flush_interval_s,
            max_queue=fp.max_queue,
            recv_buffer_bytes=fp.recv_buffer_bytes,
            status=status,
        )
        cache = TemplateCache(
            Path(cfg.paths.state_dir) / "netflow_templates.json",
            ttl_s=float(fp.netflow.template_ttl_s),
        )
        self.decoder = NetFlowDecoder(cache, logger)
        self.sink = CsvSink(Path(cfg.paths.netflow_csv), NETFLOW_FIELDS)
        self._warned_templates = False

    def handle(self, data: bytes, source_ip: str, epoch: float) -> List[Dict[str, Any]]:
        rows = self.decoder.decode(data, source_ip, epoch)
        if (
            not self._warned_templates
            and self.decoder.records_awaiting_template > 50
            and self.decoder.records_decoded == 0
        ):
            self._warned_templates = True
            self.log.warning(
                "Received %d NetFlow data set(s) with no matching template yet. Exporters resend "
                "templates periodically (often every 10-30 minutes); records will decode once a "
                "template arrives.",
                self.decoder.records_awaiting_template,
            )
        for row in rows:
            row["timestamp"] = _iso(row.get("epoch", epoch))
        return rows

    def flush(self) -> int:
        rows = self._drain()
        return self.sink.write_rows(rows) if rows else 0

    def close(self) -> None:
        super().close()
        try:
            self.decoder.cache.save()
        except Exception:
            pass
        try:
            self.sink.close()
        except Exception:
            pass


def build_collectors(cfg, logger, status: Optional[Dict[str, Any]] = None) -> List[UdpCollector]:
    """Instantiate every enabled flow-protocol collector."""
    collectors: List[UdpCollector] = []
    if not cfg.flowproto.enabled:
        return collectors
    shared = status if status is not None else {}
    if cfg.flowproto.sflow.enabled:
        collectors.append(SFlowCollector(cfg, logger, shared.setdefault("sflow", {})))
    if cfg.flowproto.netflow.enabled:
        collectors.append(NetFlowCollector(cfg, logger, shared.setdefault("netflow", {})))
    return collectors
