"""Capture from a local interface using whichever tool is installed.

This is the driver for the common physical arrangement: a SPAN, mirror or TAP
port from the switch is patched into a NIC on the collector. The switch needs no
credentials, no API and no on-box capture support -- it only has to mirror, which
every managed switch on the market can do.

``tcpdump``, ``dumpcap`` and ``tshark`` are all supported and auto-detected;
whichever is present is used.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from typing import List, Optional

from ..errors import CaptureError
from .base import PreflightResult
from .ssh import _process_handle
from .streaming import StreamHandle, StreamingCaptureSource

__all__ = ["LocalCaptureSource", "detect_capture_tool", "list_local_interfaces"]

_TOOL_ORDER = ("dumpcap", "tcpdump", "tshark")


def detect_capture_tool(preferred: str = "auto") -> Optional[str]:
    """Return the first usable capture tool, honouring an explicit preference."""
    if preferred and preferred != "auto":
        return preferred if shutil.which(preferred) else None
    for tool in _TOOL_ORDER:
        if shutil.which(tool):
            return tool
    return None


def list_local_interfaces() -> List[str]:
    """Best-effort list of capture-capable interfaces on this host."""
    names: List[str] = []
    try:
        import socket

        if hasattr(socket, "if_nameindex"):
            names = [name for _index, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        names = []
    if names:
        return names
    tool = detect_capture_tool()
    if not tool:
        return []
    try:
        flag = "-D" if tool in ("tcpdump", "dumpcap") else "-D"
        result = subprocess.run(
            [tool, flag], capture_output=True, text=True, timeout=15, check=False
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # "1.eth0 [Up, Running]" or "1. eth0"
            token = line.split()[0]
            token = token.split(".", 1)[-1] if token[:1].isdigit() else token
            if token:
                names.append(token)
    except (OSError, subprocess.SubprocessError):
        return []
    return names


class LocalCaptureSource(StreamingCaptureSource):
    """Capture from a NIC on this machine."""

    name = "local"

    def __init__(self, cfg, logger, status=None) -> None:
        super().__init__(cfg, logger, status)
        local = cfg.capture.local
        self.interface = local.interface
        self.requested_tool = local.tool
        self.bpf_filter = local.bpf_filter
        self.snaplen = int(local.snaplen)
        self.extra_args = [str(a) for a in local.extra_args]
        self.tool = detect_capture_tool(self.requested_tool)

    def _argv(self) -> List[str]:
        if not self.tool:
            raise CaptureError(
                "No local capture tool found. Install one of: dumpcap (Wireshark), tcpdump, tshark."
            )
        argv = [self.tool, "-i", self.interface, "-w", "-"]
        if self.tool == "tcpdump":
            argv += ["-U", "-n"]
            if self.snaplen:
                argv += ["-s", str(self.snaplen)]
            if self.bpf_filter:
                argv += shlex.split(self.bpf_filter)
        else:
            argv += ["-q"]
            if self.tool == "tshark":
                argv += ["-F", "pcap"]
            if self.tool == "dumpcap":
                argv += ["-P"]
            if self.snaplen:
                argv += ["-s", str(self.snaplen)]
            if self.bpf_filter:
                argv += ["-f", self.bpf_filter]
        argv += self.extra_args
        return argv

    def command_line(self) -> str:
        try:
            return " ".join(shlex.quote(a) for a in self._argv())
        except CaptureError as exc:
            return str(exc)

    def describe(self) -> str:
        return f"local: {self.command_line()}"

    def preflight(self) -> PreflightResult:
        if not self.tool:
            return PreflightResult(
                ok=False,
                driver=self.name,
                detail=f"capture tool {self.requested_tool!r} is not on PATH",
                hints=[
                    "Install Wireshark (provides dumpcap/tshark) or tcpdump",
                    "Or switch to capture.source: folder and drop capture files in yourself",
                ],
            )
        hints: List[str] = []
        interfaces = list_local_interfaces()
        if interfaces and self.interface not in interfaces:
            hints.append(
                f"Interface {self.interface!r} was not found. "
                f"Available: {', '.join(interfaces[:20])}"
            )
        try:
            probe = subprocess.run(
                [self.tool, "-D"], capture_output=True, text=True, timeout=15, check=False
            )
            if probe.returncode != 0 and "permission" in (probe.stderr or "").lower():
                hints.append(
                    "Packet capture needs elevated privileges: run as root, grant "
                    "CAP_NET_RAW (setcap cap_net_raw,cap_net_admin+eip), or add this user to the "
                    "wireshark group."
                )
        except (OSError, subprocess.SubprocessError):
            pass
        return PreflightResult(
            ok=True,
            driver=self.name,
            detail=f"{self.tool} on interface {self.interface}",
            hints=hints,
            facts={"tool": self.tool, "interfaces_found": len(interfaces)},
        )

    def open_stream(self) -> StreamHandle:
        argv = self._argv()
        try:
            process = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
            )
        except OSError as exc:
            raise CaptureError(f"Cannot launch {argv[0]}: {exc}") from exc
        return _process_handle(process, " ".join(shlex.quote(a) for a in argv))
