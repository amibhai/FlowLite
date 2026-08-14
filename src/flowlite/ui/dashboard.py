"""Live terminal dashboard.

The previous dashboard printed a variable number of lines but always moved the
cursor up by a fixed count, so the display drifted and overwrote itself into
noise within a minute. It also emitted ANSI escapes unconditionally, filling
systemd journals and cron mail with control characters, and rendered status
fields that nothing ever wrote -- capture and the watcher were permanently shown
as stopped even while running.

This one tracks exactly how many lines it drew, refuses to draw at all unless
stdout is an interactive terminal, enables VT processing on Windows consoles,
and renders only state the workers actually publish.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from ..logging_setup import ring_buffer

__all__ = ["Dashboard", "supports_ansi"]

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


def supports_ansi(stream=None) -> bool:
    """True when it is safe to emit ANSI escapes to ``stream``."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


def _enable_windows_vt() -> bool:
    """Turn on virtual terminal processing for the Windows console."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds:02d}s"


def _ago(epoch: Optional[float]) -> str:
    if not epoch:
        return "never"
    delta = time.time() - float(epoch)
    if delta < 0:
        return "just now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    return f"{int(delta // 3600)}h ago"


def _human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return f"{value:,.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


class Dashboard:
    """Renders :class:`~flowlite.runtime.ServiceState` to a terminal."""

    def __init__(
        self, state, supervisor=None, refresh_s: float = 2.0, colour: Optional[bool] = None
    ) -> None:
        self.state = state
        self.supervisor = supervisor
        self.refresh_s = max(0.5, float(refresh_s))
        self.colour = supports_ansi() if colour is None else bool(colour)
        self._lines_drawn = 0
        self._lock = threading.Lock()

    # -- styling ------------------------------------------------------------ #

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.colour else text

    def _mark(self, ok: bool, warn: bool = False) -> str:
        if warn:
            return self._c("!", _YELLOW)
        return self._c("+", _GREEN) if ok else self._c("x", _RED)

    # -- rendering ----------------------------------------------------------- #

    def render(self) -> List[str]:
        width = max(60, min(shutil.get_terminal_size((100, 30)).columns, 120))
        rule = "-" * width
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

        lines: List[str] = []
        title = f" FlowLite -- {self.state.instance}"
        if self.state.device:
            title += f" / {self.state.device}"
        lines.append(self._c(title.ljust(width - 24) + now.rjust(24), _BOLD))
        lines.append(rule)
        lines.append(
            f"  uptime {_duration(self.state.uptime_s):<16}"
            f"queue {self.state.queue_depth:<8}"
            f"{'STOPPING' if self.state.stopping else ''}"
        )
        lines.append("")

        capture = self.state.capture or {}
        if capture:
            running = bool(capture.get("running"))
            detail = capture.get("mode", "")
            if capture.get("current_file"):
                detail += f"  {capture['current_file']} ({capture.get('current_mb', 0)} MB)"
            elif capture.get("watch_dir"):
                detail += f"  {capture['watch_dir']}"
            lines.append(
                f"  {self._mark(running)} capture     "
                f"{('running' if running else 'stopped'):<10}"
                f"files {int(capture.get('files_produced', 0)):<8}{detail}"
            )
            if capture.get("last_file"):
                lines.append(
                    f"      last: {capture['last_file']} ({capture.get('last_file_mb', 0)} MB)"
                )

        pipeline = self.state.pipeline or {}
        if pipeline:
            busy = bool(pipeline.get("busy"))
            failed = int(pipeline.get("failed", 0))
            lines.append(
                f"  {self._mark(bool(pipeline.get('running')), warn=failed > 0)} pipeline    "
                f"{('busy' if busy else 'idle'):<10}"
                f"done {int(pipeline.get('processed', 0)):<9}"
                f"failed {failed:<6}{pipeline.get('current', '')}"
            )
            if pipeline.get("last_result"):
                lines.append(f"      {self._c(str(pipeline['last_result'])[: width - 8], _DIM)}")

        telemetry = self.state.telemetry or {}
        if telemetry:
            reachable = bool(telemetry.get("reachable"))
            lines.append(
                f"  {self._mark(reachable)} telemetry   "
                f"{telemetry.get('driver', '-'):<10}"
                f"polls {int(telemetry.get('polls', 0)):<8}"
                f"fails {int(telemetry.get('failures', 0)):<7}"
                f"last {_ago(telemetry.get('last_poll'))}"
            )
            if telemetry.get("last_error"):
                lines.append(f"      {self._c(str(telemetry['last_error'])[: width - 8], _RED)}")

        for name, info in (self.state.flowproto or {}).items():
            if not info:
                continue
            lines.append(
                f"  {self._mark(bool(info.get('running')), warn=bool(info.get('dropped')))} "
                f"{name:<11}"
                f"port {info.get('port', '-'):<6}"
                f"datagrams {int(info.get('datagrams', 0)):<9}"
                f"rows {int(info.get('rows', 0)):<8}"
                f"last {_ago(info.get('last_datagram'))}"
            )
            dropped = int(info.get("dropped", 0))
            if dropped:
                warning = f"dropped {dropped} record(s) - the queue is full"
                lines.append(f"      {self._c(warning, _YELLOW)}")

        threads = self.state.threads or {}
        unhealthy = [
            name
            for name, info in threads.items()
            if not info.get("alive") and not info.get("finished")
        ]
        if unhealthy:
            lines.append("")
            lines.append(self._c(f"  ! not running: {', '.join(unhealthy)}", _RED))

        events = ring_buffer().snapshot(6)
        if events:
            lines.append("")
            lines.append(self._c("  recent events", _CYAN))
            for entry in events:
                stamp = datetime.fromtimestamp(entry["time"], tz=timezone.utc).strftime("%H:%M:%S")
                level = entry["level"]
                colour = (
                    _RED
                    if level in ("ERROR", "CRITICAL")
                    else (_YELLOW if level == "WARNING" else _DIM)
                )
                message = entry["message"].replace("\n", " ")[: width - 22]
                lines.append(f"   {stamp} {self._c(f'{level:<8}', colour)} {message}")

        lines.append("")
        lines.append(self._c(rule, _DIM))
        lines.append(self._c("  Ctrl+C to stop", _DIM))
        return lines

    # -- output -------------------------------------------------------------- #

    def draw(self) -> None:
        """Repaint in place, moving up by exactly the number of lines last drawn."""
        with self._lock:
            lines = self.render()
            out = sys.stdout
            if self.colour and self._lines_drawn:
                out.write(f"\033[{self._lines_drawn}A")
            for line in lines:
                out.write(("\033[2K" if self.colour else "") + line + "\n")
            # If this frame is shorter than the last, clear the leftover rows.
            for _ in range(max(0, self._lines_drawn - len(lines))):
                out.write(("\033[2K" if self.colour else "") + "\n")
            drawn = max(len(lines), self._lines_drawn)
            out.flush()
            self._lines_drawn = drawn

    def run(self, stop_event: threading.Event) -> None:
        if not self.colour:
            # Not a terminal: the log stream already carries everything.
            stop_event.wait()
            return
        while not stop_event.is_set():
            try:
                self.draw()
            except Exception:
                # A rendering bug must never take down the service.
                return
            stop_event.wait(timeout=self.refresh_s)

    def snapshot(self) -> str:
        """One rendered frame as plain text, for ``flowlite status``."""
        previous = self.colour
        self.colour = False
        try:
            return "\n".join(self.render())
        finally:
            self.colour = previous
