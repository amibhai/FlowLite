import time
from datetime import datetime
from threading import Event
from typing import Dict

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

_WIDTH = 62


def _fmt_uptime(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m:02d}m"


def _tick(running: bool) -> str:
    return f"{_GREEN}✓{_RESET}" if running else f"{_RED}✗{_RESET}"


def _print_dashboard(status: Dict) -> None:
    now     = datetime.now()
    started = datetime.fromtimestamp(status.get("start_time", time.time()))
    uptime  = (now - started).total_seconds()

    cap   = status.get("capture", {})
    eapi  = status.get("eapi",    {})
    sflow = status.get("sflow",   {})
    watch = status.get("watcher", {})
    hours = status.get("recent_hours", [])
    cfg   = status.get("config", None)

    lines = []
    lines.append(f"{_BOLD}╔{'═' * _WIDTH}╗{_RESET}")
    lines.append(f"{_BOLD}║{'NIDS Pipeline — Live Status':^{_WIDTH}}║{_RESET}")
    lines.append(f"{_BOLD}╚{'═' * _WIDTH}╝{_RESET}")
    lines.append("")
    lines.append(
        f"  Started:   {started.strftime('%Y-%m-%d %H:%M:%S')}   "
        f"Uptime: {_fmt_uptime(uptime)}"
    )
    lines.append("")

    # Capture
    cap_run  = cap.get("running", False)
    cap_cyc  = cap.get("cycle", 0)
    cap_file = cap.get("current_file", "—")
    cap_mb   = cap.get("mb", 0.0)
    lines.append(
        f"  Capture    {_tick(cap_run)} {'running' if cap_run else 'stopped':<8} "
        f"cycle #{cap_cyc:<3} {cap_file}   {cap_mb:.1f} MB"
    )

    # eAPI
    host      = getattr(getattr(cfg, "switch", None), "host", "?") if cfg else "?"
    eapi_run  = eapi.get("running", False)
    eapi_last = eapi.get("last_poll", "never")
    lines.append(
        f"  eAPI       {_tick(eapi_run)} {'running' if eapi_run else 'stopped':<8} "
        f"last poll  {eapi_last}   switch: {host}"
    )

    # sFlow
    sflow_run  = sflow.get("running", False)
    sflow_last = sflow.get("last_pkt", "never")
    sflow_port = getattr(getattr(cfg, "sflow", None), "listen_port", 6343) if cfg else 6343
    lines.append(
        f"  sFlow      {_tick(sflow_run)} {'running' if sflow_run else 'stopped':<8} "
        f"last pkt   {sflow_last}   port: {sflow_port}"
    )

    # Watcher
    watch_run   = watch.get("running", False)
    watch_qdep  = watch.get("queue_depth", 0)
    watch_last  = watch.get("last_run", "never")
    lines.append(
        f"  Watcher    {_tick(watch_run)} {'idle' if not watch_run else 'busy':<8} "
        f"queue: {watch_qdep}   last run:  {watch_last}"
    )

    lines.append("")
    lines.append(f"  {_CYAN}── Completed hours {'─' * 42}{_RESET}")

    if not hours:
        lines.append("  (none yet)")
    else:
        for h in hours[-6:]:
            ok      = h["status"] == "OK"
            sym     = f"{_GREEN}✓{_RESET}" if ok else f"{_RED}✗{_RESET}"
            status_ = f"{_GREEN}OK{_RESET}" if ok else f"{_RED}FAILED{_RESET}"
            dur     = f"{h['duration_s']:.0f}s"
            err     = f"  {h['error']}" if h["error"] else ""
            lines.append(
                f"  {h['hour']}  {sym} {status_:<6} "
                f" flows {h['flows']:>8,}  profiles {h['profiles']:>6,}  {dur}{err}"
            )

    lines.append("")
    out_path = getattr(getattr(cfg, "paths", None), "output_base", "/data/nids/output") if cfg else "?"
    log_path = getattr(getattr(cfg, "paths", None), "logs", "/var/log/nids") if cfg else "?"
    lines.append(f"  Output: {out_path}")
    lines.append(f"  Logs:   {log_path}")
    lines.append("")
    lines.append(f"  Press {_BOLD}Ctrl+C{_RESET} to stop cleanly.")
    lines.append(f"{'─' * (_WIDTH + 2)}")

    # Move cursor up by however many lines we printed last time, then reprint
    n = len(lines)
    print(f"\033[{n}A", end="", flush=True)
    for line in lines:
        print(f"\033[K{line}")


def _initial_print(status: Dict) -> None:
    """Print blank placeholder lines so the first update can overwrite them."""
    now     = datetime.now()
    started = datetime.fromtimestamp(status.get("start_time", time.time()))
    uptime  = (now - started).total_seconds()
    cfg     = status.get("config", None)
    hours   = status.get("recent_hours", [])

    n_lines = 20 + min(len(hours), 6)
    for _ in range(n_lines):
        print()


def run(status: Dict, stop_event: Event, log) -> None:
    _initial_print(status)
    while not stop_event.is_set():
        try:
            _print_dashboard(status)
        except Exception as e:
            log.debug("Dashboard render error: %s", e)
        stop_event.wait(timeout=30)
