"""Thread supervision, health reporting and orderly shutdown.

The previous entry point started threads and then blocked on ``Thread.join()``
with no timeout. A thread that died took its function with it silently: capture
would stop while the process kept running, apparently healthy, forever. There
was also no way for an operator to tell the difference from outside.

This supervisor:

* **Restarts crashed workers** with exponential backoff, up to an optional cap.
* **Distinguishes fatal from transient.** A configuration or bind error that
  will fail identically on every retry stops the service instead of spinning.
* **Publishes health.** A JSON health file is written continuously, so systemd,
  Kubernetes, Nagios or a shell script can see component state without parsing
  logs.
* **Shuts down in order** on SIGINT/SIGTERM: capture first so no new work
  arrives, then drain the queue, then the analysis stage, then collectors.
"""

from __future__ import annotations

import os
import queue
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .errors import FlowLiteError
from .storage.atomic import atomic_write_json

__all__ = ["Supervisor", "ManagedThread", "ServiceState"]


def _process_alive(pid: int) -> bool:
    """Best-effort liveness check for a process id."""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # type: ignore[attr-defined]
            if not handle:
                return False
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@dataclass
class ServiceState:
    """Live state shared with the dashboard and the health file."""

    started_at: float = field(default_factory=time.time)
    instance: str = "flowlite"
    device: str = ""
    capture: Dict[str, Any] = field(default_factory=dict)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    flowproto: Dict[str, Any] = field(default_factory=dict)
    pipeline: Dict[str, Any] = field(default_factory=dict)
    threads: Dict[str, Any] = field(default_factory=dict)
    queue_depth: int = 0
    stopping: bool = False

    @property
    def uptime_s(self) -> float:
        return max(0.0, time.time() - self.started_at)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance": self.instance,
            "device": self.device,
            "started_at": self.started_at,
            "uptime_s": round(self.uptime_s, 1),
            "stopping": self.stopping,
            "queue_depth": self.queue_depth,
            "capture": self.capture,
            "telemetry": self.telemetry,
            "flowproto": self.flowproto,
            "pipeline": self.pipeline,
            "threads": self.threads,
        }


class ManagedThread:
    """One supervised worker."""

    def __init__(
        self,
        name: str,
        target: Callable[[threading.Event], None],
        *,
        restart: bool = True,
        critical: bool = False,
        backoff: Optional[List[float]] = None,
        max_restarts: int = 0,
    ) -> None:
        self.name = name
        self.target = target
        self.restart = restart
        self.critical = critical
        self.backoff = list(backoff or [5.0, 15.0, 60.0, 300.0])
        self.max_restarts = int(max_restarts)

        self.thread: Optional[threading.Thread] = None
        self.restarts = 0
        self.started_at = 0.0
        self.last_error = ""
        self.fatal = False
        self.finished = False
        self._next_attempt = 0.0

    @property
    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def status(self) -> Dict[str, Any]:
        return {
            "alive": self.alive,
            "restarts": self.restarts,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else 0.0,
            "last_error": self.last_error,
            "fatal": self.fatal,
            "finished": self.finished,
        }

    def start(self, stop_event: threading.Event, logger) -> None:
        def wrapper() -> None:
            try:
                self.target(stop_event)
                self.finished = True
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                # Errors that will recur identically on every restart are fatal:
                # spinning on them fills logs and hides the real problem.
                from .errors import ConfigError, DependencyError, DriverNotFound

                if isinstance(exc, (ConfigError, DependencyError, DriverNotFound)):
                    self.fatal = True
                    logger.error("Thread %s failed fatally: %s", self.name, exc)
                elif isinstance(exc, OSError) and "bind" in str(exc).lower():
                    self.fatal = True
                    logger.error("Thread %s cannot start: %s", self.name, exc)
                else:
                    logger.error("Thread %s crashed: %s", self.name, exc, exc_info=True)

        self.thread = threading.Thread(target=wrapper, name=self.name, daemon=True)
        self.started_at = time.time()
        self.thread.start()

    def should_restart(self, now: float) -> bool:
        if not self.restart or self.fatal or self.finished:
            return False
        if self.max_restarts and self.restarts >= self.max_restarts:
            return False
        return now >= self._next_attempt

    def schedule_restart(self, now: float) -> float:
        delay = self.backoff[min(self.restarts, len(self.backoff) - 1)]
        self._next_attempt = now + delay
        self.restarts += 1
        return delay


class Supervisor:
    """Owns the worker threads, the shutdown protocol and the health file."""

    def __init__(self, cfg, logger, state: Optional[ServiceState] = None) -> None:
        self.cfg = cfg
        self.log = logger
        self.state = state or ServiceState(
            instance=cfg.instance, device=cfg.device.name or cfg.device.host
        )
        self.stop_event = threading.Event()
        self.workers: List[ManagedThread] = []
        self.queue: queue.Queue[Any] = queue.Queue(maxsize=int(cfg.capture.queue_depth))
        self.health_path = Path(cfg.runtime.health_file) if cfg.runtime.health_file else None
        self.pid_path = Path(cfg.runtime.pid_file) if cfg.runtime.pid_file else None
        self.shutdown_grace = float(cfg.runtime.shutdown_grace_s)
        self._exit_code = 0
        self._signals_installed = False
        self._pid_written = False

    # -- registration ------------------------------------------------------- #

    def add(
        self,
        name: str,
        target: Callable[[threading.Event], None],
        *,
        restart: bool = True,
        critical: bool = False,
    ) -> ManagedThread:
        worker = ManagedThread(
            name,
            target,
            restart=restart,
            critical=critical,
            backoff=list(self.cfg.runtime.restart_backoff_s),
            max_restarts=int(self.cfg.runtime.max_restarts),
        )
        self.workers.append(worker)
        return worker

    # -- signals ------------------------------------------------------------ #

    def install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            if self.stop_event.is_set():
                self.log.warning("Second signal received; exiting immediately")
                raise SystemExit(130)
            self.log.info("Signal %s received; shutting down gracefully", signum)
            self.request_stop()

        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                signal.signal(sig, handler)
                self._signals_installed = True
            except (ValueError, OSError):
                # Not the main thread, or unsupported on this platform.
                continue

    def request_stop(self) -> None:
        self.state.stopping = True
        self.stop_event.set()

    # -- lifecycle ---------------------------------------------------------- #

    def write_pid_file(self) -> None:
        """Record this process id, refusing to clobber a live instance."""
        if self.pid_path is None:
            return
        existing = self._read_pid()
        if existing is not None and existing != os.getpid() and _process_alive(existing):
            raise FlowLiteError(
                f"Another FlowLite instance appears to be running as PID {existing} "
                f"(from {self.pid_path}). Stop it first, or use a different runtime.pid_file."
            )
        try:
            self.pid_path.parent.mkdir(parents=True, exist_ok=True)
            self.pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
            self._pid_written = True
        except OSError as exc:
            self.log.warning("Cannot write PID file %s: %s", self.pid_path, exc)

    def _read_pid(self) -> Optional[int]:
        if self.pid_path is None or not self.pid_path.exists():
            return None
        try:
            return int(self.pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def remove_pid_file(self) -> None:
        if self.pid_path is None or not self._pid_written:
            return
        try:
            self.pid_path.unlink()
        except OSError:
            pass
        self._pid_written = False

    def run(self) -> int:
        self.install_signal_handlers()
        self.write_pid_file()
        for worker in self.workers:
            worker.start(self.stop_event, self.log)
            self.log.info("Started %s", worker.name)

        try:
            self._supervise()
        except KeyboardInterrupt:
            self.log.info("Interrupted; shutting down")
            self.request_stop()
        finally:
            self._shutdown()
        return self._exit_code

    def _supervise(self) -> None:
        last_health = 0.0
        while not self.stop_event.is_set():
            now = time.time()
            self.state.queue_depth = self.queue.qsize()

            for worker in self.workers:
                self.state.threads[worker.name] = worker.status()
                if worker.alive or worker.finished:
                    continue
                if worker.fatal:
                    if worker.critical:
                        self.log.error(
                            "Critical component %s cannot run; stopping FlowLite", worker.name
                        )
                        self._exit_code = 1
                        self.request_stop()
                    continue
                if worker.should_restart(now):
                    delay = worker.schedule_restart(now)
                    self.log.warning(
                        "Restarting %s (attempt %d, next backoff %.0fs)",
                        worker.name,
                        worker.restarts,
                        delay,
                    )
                    worker.start(self.stop_event, self.log)
                elif worker.max_restarts and worker.restarts >= worker.max_restarts:
                    if worker.critical:
                        self.log.error(
                            "%s exceeded runtime.max_restarts (%d); stopping FlowLite",
                            worker.name,
                            worker.max_restarts,
                        )
                        self._exit_code = 1
                        self.request_stop()

            if self.health_path is not None and time.monotonic() - last_health > 10:
                last_health = time.monotonic()
                self.write_health()

            self.stop_event.wait(timeout=1.0)

    def _shutdown(self) -> None:
        self.state.stopping = True
        self.stop_event.set()
        deadline = time.monotonic() + self.shutdown_grace

        for worker in self.workers:
            if worker.thread is None:
                continue
            remaining = max(0.1, deadline - time.monotonic())
            worker.thread.join(timeout=remaining)
            if worker.thread.is_alive():
                self.log.warning(
                    "%s did not stop within the %.0fs grace period; abandoning it",
                    worker.name,
                    self.shutdown_grace,
                )

        if self.health_path is not None:
            self.state.threads = {w.name: w.status() for w in self.workers}
            self.write_health(final=True)
        self.remove_pid_file()

    # -- health ------------------------------------------------------------- #

    def health(self) -> Dict[str, Any]:
        payload = self.state.to_dict()
        unhealthy = [
            name
            for name, info in payload["threads"].items()
            if not info.get("alive") and not info.get("finished")
        ]
        payload["status"] = (
            "stopping" if self.state.stopping else ("degraded" if unhealthy else "ok")
        )
        payload["unhealthy"] = unhealthy
        payload["generated_at"] = time.time()
        return payload

    def write_health(self, final: bool = False) -> None:
        if self.health_path is None:
            return
        try:
            payload = self.health()
            if final:
                payload["status"] = "stopped"
            atomic_write_json(self.health_path, payload, fsync=False)
        except OSError as exc:
            self.log.debug("Cannot write health file %s: %s", self.health_path, exc)
