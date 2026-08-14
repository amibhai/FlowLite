"""Telemetry from arbitrary CLI commands over SSH.

The universal escape hatch. When a device has no SNMP agent, no REST API and no
vendor SDK -- an old access switch, an appliance, a lab box -- it still has a
CLI. Configure the commands and the regular expressions that pull numbers out of
their output, and the results land in exactly the same normalised CSV as every
other driver.

Configuration example::

    telemetry:
      driver: ssh_cli
      ssh_cli:
        commands:
          - name: interfaces
            command: "show interface counters"
            regex: '^(?P<if_name>\\S+)\\s+(?P<in_octets>\\d+)\\s+(?P<out_octets>\\d+)'
            scope: interface
          - name: cpu
            command: "show processes cpu | include CPU"
            regex: 'one minute: (?P<cpu_percent>[\\d.]+)%'
            scope: device

Named capture groups map onto snapshot fields. ``scope: interface`` produces one
interface row per regex match; ``scope: device`` sets device-level fields from
the first match.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from ..errors import TelemetryError, TransientTelemetryError
from .base import DeviceSnapshot, InterfaceCounters, PreflightReport, TelemetryDriver

__all__ = ["SshCliDriver"]

_INTERFACE_FIELDS = {
    "if_name",
    "if_index",
    "if_alias",
    "admin_status",
    "oper_status",
    "speed_bps",
    "in_octets",
    "out_octets",
    "in_packets",
    "out_packets",
    "in_errors",
    "out_errors",
    "in_discards",
    "out_discards",
}

_DEVICE_FIELDS = {
    "arp_entries",
    "mac_entries",
    "route_entries",
    "cpu_percent",
    "memory_percent",
    "uptime_s",
    "system_name",
    "system_description",
}


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


class SshCliDriver(TelemetryDriver):
    """Run configured commands over SSH and parse their output with regexes."""

    name = "ssh_cli"

    def __init__(self, cfg, logger) -> None:
        super().__init__(cfg, logger)
        ssh = cfg.telemetry.ssh_cli
        self.host = ssh.host
        self.port = int(ssh.port)
        self.username = ssh.username
        self.password = ssh.password
        self.key_file = ssh.key_file
        self.policy = ssh.host_key_policy
        self.commands: List[Dict[str, Any]] = []
        for item in ssh.commands:
            entry = dict(item) if isinstance(item, dict) else {}
            pattern = str(entry.get("regex", "") or "")
            entry["_compiled"] = re.compile(pattern, re.MULTILINE) if pattern else None
            self.commands.append(entry)

    def describe(self) -> str:
        return f"ssh_cli {self.username}@{self.host}:{self.port} ({len(self.commands)} command(s))"

    # -- transport --------------------------------------------------------- #

    def _run_all(self) -> Dict[str, str]:
        try:
            import paramiko  # type: ignore

            return self._run_paramiko(paramiko)
        except ImportError:
            if shutil.which("ssh"):
                return self._run_openssh()
            raise TelemetryError(
                "The ssh_cli driver needs paramiko (pip install 'flowlite[ssh]') or an OpenSSH "
                "client on PATH."
            ) from None

    def _run_paramiko(self, paramiko) -> Dict[str, str]:
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        policy = paramiko.RejectPolicy() if self.policy == "strict" else paramiko.AutoAddPolicy()
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None,
                key_filename=self.key_file or None,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=bool(self.key_file) or not self.password,
                allow_agent=not self.password,
            )
        except Exception as exc:
            client.close()
            raise TransientTelemetryError(f"SSH connection to {self.host} failed: {exc}") from exc

        outputs: Dict[str, str] = {}
        try:
            for entry in self.commands:
                name = str(entry.get("name", ""))
                command = str(entry.get("command", ""))
                try:
                    _stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
                    outputs[name] = stdout.read().decode("utf-8", "replace")
                    error = stderr.read().decode("utf-8", "replace").strip()
                    if error:
                        self.log.debug("Command %r stderr: %s", command, error[:300])
                except Exception as exc:
                    self.log.warning("Command %r failed: %s", command, exc)
                    outputs[name] = ""
        finally:
            client.close()
        return outputs

    def _run_openssh(self) -> Dict[str, str]:
        outputs: Dict[str, str] = {}
        base = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={int(self.timeout)}",
        ]
        if self.policy == "ignore":
            base += ["-o", "StrictHostKeyChecking=no"]
        elif self.policy == "accept-new":
            base += ["-o", "StrictHostKeyChecking=accept-new"]
        if self.key_file:
            base += ["-i", self.key_file]
        target = f"{self.username}@{self.host}" if self.username else self.host

        for entry in self.commands:
            name = str(entry.get("name", ""))
            command = str(entry.get("command", ""))
            try:
                result = subprocess.run(
                    base + [target, command],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 5,
                    check=False,
                )
                outputs[name] = result.stdout
                if result.returncode != 0 and result.stderr.strip():
                    self.log.warning("Command %r failed: %s", command, result.stderr.strip()[:300])
            except (OSError, subprocess.SubprocessError) as exc:
                self.log.warning("Command %r failed: %s", command, exc)
                outputs[name] = ""
        return outputs

    # -- parsing ----------------------------------------------------------- #

    def preflight(self) -> PreflightReport:
        if not self.commands:
            return PreflightReport(
                ok=False, driver=self.name, detail="telemetry.ssh_cli.commands is empty"
            )
        try:
            outputs = self._run_all()
        except Exception as exc:
            return PreflightReport(ok=False, driver=self.name, detail=str(exc))
        empty = [name for name, text in outputs.items() if not text.strip()]
        hints = []
        if empty:
            hints.append(f"These commands returned nothing: {', '.join(empty)}")
        for entry in self.commands:
            compiled = entry.get("_compiled")
            text = outputs.get(str(entry.get("name", "")), "")
            if compiled is not None and text and not compiled.search(text):
                hints.append(
                    f"The regex for {entry.get('name')!r} matched none of the command output; "
                    f"run the command manually and adjust the pattern"
                )
        return PreflightReport(
            ok=True,
            driver=self.name,
            detail=f"{len(outputs)} command(s) executed on {self.host}",
            hints=hints,
        )

    def collect(self) -> DeviceSnapshot:
        started = time.monotonic()
        try:
            outputs = self._run_all()
            snapshot = DeviceSnapshot(device=self.device, driver=self.name, epoch=time.time())
            interfaces: Dict[str, InterfaceCounters] = {}

            for entry in self.commands:
                compiled = entry.get("_compiled")
                if compiled is None:
                    continue
                text = outputs.get(str(entry.get("name", "")), "")
                if not text:
                    continue
                scope = str(entry.get("scope", "interface")).lower()
                for match in compiled.finditer(text):
                    groups = {k: v for k, v in match.groupdict().items() if v is not None}
                    if scope == "device":
                        self._apply_device(snapshot, groups)
                        break
                    self._apply_interface(interfaces, groups)

            snapshot.interfaces = list(interfaces.values())
            snapshot.poll_ms = (time.monotonic() - started) * 1000.0
            if not snapshot.interfaces and snapshot.cpu_percent is None:
                snapshot.error = "no configured pattern matched any command output"
            return snapshot
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}", started)

    @staticmethod
    def _apply_device(snapshot: DeviceSnapshot, groups: Dict[str, str]) -> None:
        for key, value in groups.items():
            if key not in _DEVICE_FIELDS:
                continue
            if key in ("system_name", "system_description"):
                setattr(snapshot, key, value.strip())
            elif key in ("cpu_percent", "memory_percent", "uptime_s"):
                setattr(snapshot, key, _to_float(value))
            else:
                setattr(snapshot, key, _to_int(value))

    @staticmethod
    def _apply_interface(store: Dict[str, InterfaceCounters], groups: Dict[str, str]) -> None:
        name = groups.get("if_name", "").strip()
        if not name:
            return
        counters = store.get(name)
        if counters is None:
            counters = InterfaceCounters(index=len(store) + 1, name=name)
            store[name] = counters
        for key, value in groups.items():
            if key not in _INTERFACE_FIELDS or key == "if_name":
                continue
            if key in ("if_alias", "admin_status", "oper_status"):
                setattr(counters, key, value.strip())
            elif key == "if_index":
                counters.index = _to_int(value) or counters.index
            elif key == "speed_bps":
                counters.speed_bps = _to_int(value) or 0
            else:
                setattr(counters, key, _to_int(value))
