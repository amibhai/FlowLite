import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue
from threading import Event
from typing import Optional

import paramiko


def windows_to_wsl(path: str) -> str:
    if path.startswith("/"):
        return path
    # Handle C:\... or C:/...
    p = path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        rest = p[2:].lstrip("/")
        return f"/mnt/{drive}/{rest}"
    return path


def time_bucket(dt: datetime) -> str:
    h = dt.hour
    if h < 12:
        return "Morning"
    elif h < 15:
        return "Afternoon"
    return "Evening"


def date_folder(dt: datetime) -> str:
    return f"{dt.day}_{dt.strftime('%B')[:3]}_{dt.strftime('%y')}"


def make_save_path(base_dir: str, start: datetime, fname: str) -> Path:
    folder = Path(base_dir) / date_folder(start) / time_bucket(start)
    folder.mkdir(parents=True, exist_ok=True)
    return folder / fname


def capture_one(cfg, stop_event: Event, log) -> Optional[Path]:
    start = datetime.now()
    end   = start + timedelta(seconds=cfg.capture.duration_sec)
    fname = f"{start.strftime('%H_%M')}_to_{end.strftime('%H_%M')}.pcap"
    local_path = make_save_path(cfg.capture.base_dir, start, fname)

    remote_cmd = (
        f"bash timeout {cfg.capture.duration_sec} "
        f"tcpdump -i {cfg.switch.interface} -w - -Z root 2>/dev/null"
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=cfg.switch.host,
            port=cfg.switch.ssh_port,
            username=cfg.switch.user,
            password=getattr(cfg.switch, "pass"),
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        log.error("SSH connect failed: %s", e)
        return None

    channel = client.get_transport().open_session()
    channel.exec_command(remote_cmd)
    channel.settimeout(2)

    state = {"bytes": 0, "done": False, "error": None}

    def _stream():
        try:
            with open(local_path, "wb") as f:
                while not stop_event.is_set():
                    try:
                        chunk = channel.recv(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        state["bytes"] += len(chunk)
                    except Exception:
                        if channel.exit_status_ready():
                            break
                        time.sleep(0.05)
        except Exception as e:
            state["error"] = e
        finally:
            state["done"] = True

    t = threading.Thread(target=_stream, daemon=True)
    t.start()

    tick = 0
    while not state["done"] and not stop_event.is_set():
        if tick % 60 == 0:
            mb = state["bytes"] / (1024 * 1024)
            log.info(
                "Capture %s — %dm elapsed — %.1f MB received",
                fname, tick // 60, mb,
            )
        time.sleep(1)
        tick += 1

    t.join(timeout=30)
    channel.close()
    client.close()

    if state["error"]:
        log.error("Stream error: %s", state["error"])
        return None

    if not local_path.exists() or local_path.stat().st_size == 0:
        log.error("Empty file — tcpdump may have failed on switch")
        return None

    mb = local_path.stat().st_size / (1024 * 1024)
    log.info("Capture complete: %s (%.1f MB)", local_path, mb)
    return local_path


def run(queue: Queue, cfg, stop_event: Event, log):
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        log.info("Capture cycle #%d starting", cycle)
        try:
            path = capture_one(cfg, stop_event, log)
            if path is not None:
                wsl_path = windows_to_wsl(str(path))
                queue.put(wsl_path)
                log.info("Queued for processing: %s", wsl_path)
            else:
                log.warning(
                    "Cycle #%d failed, retrying in %ds",
                    cycle, cfg.capture.retry_wait_sec,
                )
                stop_event.wait(timeout=cfg.capture.retry_wait_sec)
        except Exception as e:
            log.error("Unexpected error in cycle #%d: %s", cycle, e)
            stop_event.wait(timeout=cfg.capture.retry_wait_sec)
