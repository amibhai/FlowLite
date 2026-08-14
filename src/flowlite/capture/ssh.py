"""Capture over SSH from any device that can run a packet capture tool.

Nothing here is vendor-specific. The command sent to the device is a template,
so the same driver captures from an Arista switch, a Cumulus or SONiC box, a
Juniper in shell mode, a MikroTik, a Linux router or a plain server -- the
difference is one line of configuration, and ready-made lines ship in
``configs/profiles/``.

Two transports are supported and chosen automatically:

* **paramiko**, when installed. Supports password authentication.
* **the system ``ssh`` binary**, otherwise. Key-based authentication only, but
  needs no Python dependency at all and inherits the operator's existing
  ``~/.ssh/config``.

Host key policy is explicit. The predecessor used ``AutoAddPolicy``, silently
trusting whatever key the far end presented on every connection -- indefinitely
accepting a man-in-the-middle. The default here is ``accept-new``: trust on
first use, then pin.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from typing import List, Optional

from ..errors import CaptureError
from .base import PreflightResult
from .streaming import StreamHandle, StreamingCaptureSource

__all__ = ["SshCaptureSource", "build_capture_command"]

# Templates are deliberately plain and POSIX-ish; devices that need a shell
# wrapper (Arista EOS, some Junos modes) set capture.ssh.command explicitly.
_TOOL_TEMPLATES = {
    "tcpdump": "tcpdump -i {interface} -U -w - -n{snaplen}{filter}",
    "tshark": "tshark -i {interface} -w - -F pcap -q{snaplen}{filter}",
    "dumpcap": "dumpcap -i {interface} -w - -P -q{snaplen}{filter}",
}


def build_capture_command(
    tool: str,
    interface: str,
    bpf_filter: str = "",
    snaplen: int = 0,
    sudo: bool = False,
    template: str = "",
) -> str:
    """Render the remote capture command.

    ``template`` wins when supplied and may use ``{interface}``, ``{filter}``
    and ``{snaplen}`` placeholders.
    """
    interface = interface.strip() or "any"
    if template.strip():
        command = template.format(
            interface=interface,
            filter=bpf_filter.strip(),
            snaplen=str(snaplen or ""),
        )
    else:
        base = _TOOL_TEMPLATES.get(tool, _TOOL_TEMPLATES["tcpdump"])
        snap_part = ""
        if snaplen and tool == "tcpdump" or snaplen and tool in ("tshark", "dumpcap"):
            snap_part = f" -s {int(snaplen)}"
        filter_part = f" {shlex.quote(bpf_filter.strip())}" if bpf_filter.strip() else ""
        if tool in ("tshark", "dumpcap") and bpf_filter.strip():
            filter_part = f" -f {shlex.quote(bpf_filter.strip())}"
        command = base.format(
            interface=shlex.quote(interface), snaplen=snap_part, filter=filter_part
        )

    if sudo and not command.startswith("sudo "):
        command = f"sudo -n {command}"
    return command


class SshCaptureSource(StreamingCaptureSource):
    """Stream a remote capture over SSH."""

    name = "ssh"

    def __init__(self, cfg, logger, status=None) -> None:
        super().__init__(cfg, logger, status)
        ssh = cfg.capture.ssh
        self.host = ssh.host
        self.port = int(ssh.port)
        self.username = ssh.username
        self.password = ssh.password
        self.key_file = ssh.key_file
        self.key_passphrase = cfg.credentials.ssh_key_passphrase
        self.policy = ssh.host_key_policy
        self.known_hosts = ssh.known_hosts_file
        self.connect_timeout = float(ssh.connect_timeout_s)
        self.read_timeout = float(ssh.read_timeout_s)
        self.command = build_capture_command(
            tool=ssh.capture_tool,
            interface=ssh.interface,
            bpf_filter=ssh.bpf_filter,
            snaplen=int(ssh.snaplen),
            sudo=bool(ssh.sudo),
            template=ssh.command,
        )

    def command_line(self) -> str:
        return f"ssh {self.username}@{self.host}:{self.port} -- {self.command}"

    def describe(self) -> str:
        return f"ssh: {self.username}@{self.host}:{self.port} running `{self.command}`"

    # -- preflight --------------------------------------------------------- #

    def preflight(self) -> PreflightResult:
        hints: List[str] = []
        transport = "paramiko" if _has_paramiko() else ("openssh" if _has_openssh() else "")
        if not transport:
            return PreflightResult(
                ok=False,
                driver=self.name,
                detail="no SSH transport available",
                hints=[
                    "Install paramiko (pip install 'flowlite[ssh]') for password authentication",
                    "or install an OpenSSH client and configure key-based authentication",
                ],
            )
        if transport == "openssh" and self.password and not self.key_file:
            hints.append(
                "Password authentication needs paramiko; the OpenSSH fallback uses keys only. "
                "Install paramiko or set capture.ssh.key_file."
            )
        if not self.username:
            hints.append(
                "capture.ssh.username is empty; the SSH client will use the local user name"
            )
        if self.policy == "ignore":
            hints.append("host_key_policy=ignore disables host key verification")
        return PreflightResult(
            ok=True,
            driver=self.name,
            detail=f"{transport} -> {self.username or '<local user>'}@{self.host}:{self.port}",
            hints=hints,
            facts={"transport": transport, "command": self.command},
        )

    # -- transport --------------------------------------------------------- #

    def open_stream(self) -> StreamHandle:
        if _has_paramiko():
            return self._open_paramiko()
        if _has_openssh():
            return self._open_openssh()
        raise CaptureError(
            "SSH capture requires either the paramiko package (pip install 'flowlite[ssh]') "
            "or an OpenSSH client on PATH."
        )

    def _open_paramiko(self) -> StreamHandle:
        import paramiko  # type: ignore

        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        if self.known_hosts:
            try:
                client.load_host_keys(self.known_hosts)
            except OSError as exc:
                self.log.warning("Cannot read known_hosts file %s: %s", self.known_hosts, exc)

        if self.policy == "strict":
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif self.policy == "ignore":
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:  # accept-new: trust on first use, then pin
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None,
                key_filename=self.key_file or None,
                passphrase=self.key_passphrase or None,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                look_for_keys=bool(self.key_file) or not self.password,
                allow_agent=not self.password,
            )
        except Exception as exc:
            try:
                client.close()
            except Exception:
                pass
            raise CaptureError(f"SSH connection to {self.host}:{self.port} failed: {exc}") from exc

        if self.policy == "accept-new" and self.known_hosts:
            try:
                client.save_host_keys(self.known_hosts)
            except OSError:
                pass

        transport = client.get_transport()
        if transport is None:  # pragma: no cover - paramiko internal state
            client.close()
            raise CaptureError("SSH transport was not established")
        transport.set_keepalive(30)

        channel = transport.open_session()
        channel.settimeout(self.read_timeout)
        channel.exec_command(self.command)

        stderr_chunks: List[bytes] = []
        stderr_lock = threading.Lock()

        def drain_stderr() -> None:
            while True:
                try:
                    if channel.recv_stderr_ready():
                        data = channel.recv_stderr(65536)
                        if not data:
                            break
                        with stderr_lock:
                            if sum(len(c) for c in stderr_chunks) < 262144:
                                stderr_chunks.append(data)
                    elif channel.exit_status_ready() and not channel.recv_stderr_ready():
                        break
                    else:
                        import time as _time

                        _time.sleep(0.1)
                except Exception:
                    break

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True, name="ssh-stderr")
        stderr_thread.start()

        def read(size: int) -> bytes:
            if channel.exit_status_ready() and not channel.recv_ready():
                return b""
            return channel.recv(size)

        def close() -> None:
            try:
                channel.close()
            finally:
                client.close()

        def stderr_text() -> str:
            with stderr_lock:
                return b"".join(stderr_chunks).decode("utf-8", "replace")

        def exit_status() -> Optional[int]:
            return channel.recv_exit_status() if channel.exit_status_ready() else None

        return StreamHandle(read, close, stderr_text, exit_status, self.describe())

    def _open_openssh(self) -> StreamHandle:
        argv = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={int(self.connect_timeout)}",
            "-o",
            "ServerAliveInterval=30",
        ]
        if self.policy == "ignore":
            argv += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        elif self.policy == "accept-new":
            argv += ["-o", "StrictHostKeyChecking=accept-new"]
        else:
            argv += ["-o", "StrictHostKeyChecking=yes"]
        if self.known_hosts:
            argv += ["-o", f"UserKnownHostsFile={self.known_hosts}"]
        if self.key_file:
            argv += ["-i", self.key_file]
        target = f"{self.username}@{self.host}" if self.username else self.host
        argv += [target, self.command]

        try:
            process = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
            )
        except OSError as exc:
            raise CaptureError(f"Cannot launch ssh: {exc}") from exc

        return _process_handle(process, " ".join(shlex.quote(a) for a in argv))


def _process_handle(process: subprocess.Popen[bytes], description: str) -> StreamHandle:
    """Wrap a subprocess as a :class:`StreamHandle`, draining stderr safely."""
    stderr_chunks: List[bytes] = []
    lock = threading.Lock()

    def drain() -> None:
        if process.stderr is None:
            return
        for line in iter(process.stderr.readline, b""):
            with lock:
                if sum(len(c) for c in stderr_chunks) < 262144:
                    stderr_chunks.append(line)

    thread = threading.Thread(target=drain, daemon=True, name="capture-stderr")
    thread.start()

    def read(size: int) -> bytes:
        if process.stdout is None:
            return b""
        return (
            process.stdout.read1(size)
            if hasattr(process.stdout, "read1")
            else process.stdout.read(size)
        )

    def close() -> None:
        for stream in (process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    def stderr_text() -> str:
        with lock:
            return b"".join(stderr_chunks).decode("utf-8", "replace")

    return StreamHandle(read, close, stderr_text, process.poll, description)


def _has_paramiko() -> bool:
    try:
        import paramiko  # type: ignore # noqa: F401

        return True
    except ImportError:
        return False


def _has_openssh() -> bool:
    return shutil.which("ssh") is not None
