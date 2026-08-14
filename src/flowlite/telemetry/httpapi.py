"""HTTP/JSON device APIs: RESTCONF, Arista eAPI and Cisco NX-API.

All three speak JSON over HTTPS with basic authentication, so they share one
transport built on ``urllib`` -- no ``requests`` dependency in the core.

TLS is verified by default. The predecessor disabled certificate verification
globally and suppressed the resulting warnings, which silently accepted any
certificate from anyone for the life of the process. Here, verification is on
unless the operator turns it off, ``ca_bundle`` lets a self-signed device
certificate be verified properly, and disabling verification produces a warning
at startup rather than being hidden.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from ..errors import TelemetryError, TransientTelemetryError
from .base import DeviceSnapshot, InterfaceCounters, PreflightReport, TelemetryDriver

__all__ = ["HttpJsonClient", "RestconfDriver", "EapiDriver", "NxapiDriver"]

_DEFAULT_PORTS = {"http": 80, "https": 443}


class HttpJsonClient:
    """Minimal JSON-over-HTTP client with explicit TLS control."""

    def __init__(
        self,
        host: str,
        scheme: str = "https",
        port: int = 0,
        username: str = "",
        password: str = "",
        verify_tls: bool = True,
        ca_bundle: str = "",
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.scheme = scheme
        self.port = int(port) or _DEFAULT_PORTS.get(scheme, 443)
        self.username = username
        self.password = password
        self.timeout = float(timeout)
        self._context: Optional[ssl.SSLContext] = None
        if scheme == "https":
            if verify_tls:
                self._context = ssl.create_default_context(cafile=ca_bundle or None)
            else:
                self._context = ssl._create_unverified_context()  # noqa: S323 - operator opt-in

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def request(
        self,
        path: str,
        method: str = "GET",
        payload: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Perform a request and decode a JSON response."""
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        body = None
        request_headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        if self.username:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            request_headers["Authorization"] = f"Basic {token}"

        request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._context
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            if exc.code in (401, 403):
                raise TelemetryError(
                    f"{url} rejected the credentials (HTTP {exc.code}). Check "
                    f"credentials.username / credentials.password and that the API is "
                    f"authorised for this user. {detail}"
                ) from exc
            if exc.code == 404:
                raise TelemetryError(
                    f"{url} returned HTTP 404. The API path is wrong for this platform; set "
                    f"telemetry.http.base_path to the correct root. {detail}"
                ) from exc
            raise TransientTelemetryError(f"{url} returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError):
                raise TelemetryError(
                    f"TLS verification failed for {url}: {reason}. Point "
                    f"telemetry.http.ca_bundle at the device certificate, or set "
                    f"telemetry.http.verify_tls to false if you accept the risk."
                ) from exc
            raise TransientTelemetryError(f"cannot reach {url}: {reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise TransientTelemetryError(f"cannot reach {url}: {exc}") from exc

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            preview = raw[:200].decode("utf-8", "replace")
            raise TelemetryError(
                f"{url} did not return JSON (got {preview!r}). This usually means the API is "
                f"disabled or the path belongs to a different platform."
            ) from exc


def _num(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


class _HttpDriver(TelemetryDriver):
    """Shared construction for the HTTP-based drivers."""

    def __init__(self, cfg, logger) -> None:
        super().__init__(cfg, logger)
        http = cfg.telemetry.http
        self.base_path = http.base_path
        self.client = HttpJsonClient(
            host=http.host,
            scheme=http.scheme,
            port=int(http.port),
            username=http.username,
            password=http.password,
            verify_tls=bool(http.verify_tls),
            ca_bundle=http.ca_bundle,
            timeout=self.timeout,
        )

    def describe(self) -> str:
        return f"{self.name} {self.client.base_url}"


class RestconfDriver(_HttpDriver):
    """RFC 8040 RESTCONF using the standard ietf-interfaces YANG model.

    Works on any platform with a standards-compliant RESTCONF implementation --
    IOS-XE, IOS-XR, Junos, Nokia SR OS, SONiC and others -- because the data
    model is an IETF standard rather than a vendor schema.
    """

    name = "restconf"

    def _root(self) -> str:
        return self.base_path.rstrip("/") if self.base_path else "/restconf/data"

    def preflight(self) -> PreflightReport:
        try:
            self.client.request(f"{self._root()}/ietf-interfaces:interfaces-state")
        except Exception as exc:
            return PreflightReport(
                ok=False,
                driver=self.name,
                detail=str(exc),
                hints=[
                    "Confirm RESTCONF is enabled (on IOS-XE: `restconf` in global config)",
                    "Set telemetry.http.base_path if this platform roots RESTCONF elsewhere",
                ],
            )
        return PreflightReport(
            ok=True, driver=self.name, detail=f"RESTCONF reachable at {self.client.base_url}"
        )

    def collect(self) -> DeviceSnapshot:
        started = time.monotonic()
        try:
            data = self.client.request(f"{self._root()}/ietf-interfaces:interfaces-state")
            snapshot = DeviceSnapshot(device=self.device, driver=self.name, epoch=time.time())
            container = (data or {}).get("ietf-interfaces:interfaces-state", data or {})
            entries = container.get("interface", []) if isinstance(container, dict) else []

            for index, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    continue
                stats = entry.get("statistics", {}) or {}
                snapshot.interfaces.append(
                    InterfaceCounters(
                        index=_num(entry.get("if-index")) or index,
                        name=str(entry.get("name", f"if{index}")),
                        alias=str(entry.get("description", "") or ""),
                        admin_status=str(entry.get("admin-status", "") or ""),
                        oper_status=str(entry.get("oper-status", "") or ""),
                        speed_bps=_num(entry.get("speed")) or 0,
                        in_octets=_num(stats.get("in-octets")),
                        out_octets=_num(stats.get("out-octets")),
                        in_packets=_num(stats.get("in-unicast-pkts")),
                        out_packets=_num(stats.get("out-unicast-pkts")),
                        in_errors=_num(stats.get("in-errors")),
                        out_errors=_num(stats.get("out-errors")),
                        in_discards=_num(stats.get("in-discards")),
                        out_discards=_num(stats.get("out-discards")),
                        high_capacity=True,
                    )
                )
            snapshot.poll_ms = (time.monotonic() - started) * 1000.0
            return snapshot
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}", started)


class _JsonRpcDriver(_HttpDriver):
    """Shared JSON-RPC ``runCmds`` behaviour for eAPI and NX-API."""

    endpoint = "/command-api"
    commands: List[str] = []

    def _run(self, commands: List[str]) -> List[Any]:
        payload = {
            "jsonrpc": "2.0",
            "method": "runCmds",
            "params": {"version": 1, "cmds": commands, "format": "json"},
            "id": "flowlite",
        }
        response = self.client.request(
            self.base_path or self.endpoint, method="POST", payload=payload
        )
        if not isinstance(response, dict):
            raise TelemetryError("device returned an unexpected JSON-RPC envelope")
        if "error" in response:
            error = response["error"]
            message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
            raise TelemetryError(f"device rejected the commands: {message}")
        result = response.get("result")
        if not isinstance(result, list):
            raise TelemetryError("device response contained no result list")
        # Never index blindly: a device that answers fewer commands than asked
        # previously produced an IndexError swallowed into a row of zeros.
        while len(result) < len(commands):
            result.append({})
        return result

    def preflight(self) -> PreflightReport:
        try:
            self._run(self.commands[:1])
        except Exception as exc:
            return PreflightReport(ok=False, driver=self.name, detail=str(exc), hints=self._hints())
        return PreflightReport(
            ok=True, driver=self.name, detail=f"reachable at {self.client.base_url}"
        )

    def _hints(self) -> List[str]:  # pragma: no cover - overridden
        return []


class EapiDriver(_JsonRpcDriver):
    """Arista EOS eAPI."""

    name = "eapi"
    endpoint = "/command-api"
    commands = ["show interfaces", "show version"]

    def _hints(self) -> List[str]:
        return [
            "Enable eAPI on the switch: `management api http-commands` then `no shutdown`",
            "The user needs privilege 15 and an eAPI-permitted role",
        ]

    def collect(self) -> DeviceSnapshot:
        started = time.monotonic()
        try:
            interfaces_result, version_result = self._run(self.commands)
            snapshot = DeviceSnapshot(device=self.device, driver=self.name, epoch=time.time())

            entries = (interfaces_result or {}).get("interfaces", {})
            if isinstance(entries, dict):
                for name, entry in entries.items():
                    if not isinstance(entry, dict):
                        continue
                    counters = entry.get("interfaceCounters", {}) or {}
                    snapshot.interfaces.append(
                        InterfaceCounters(
                            index=_num(entry.get("interfaceMembership"))
                            or len(snapshot.interfaces) + 1,
                            name=str(name),
                            alias=str(entry.get("description", "") or ""),
                            admin_status=str(entry.get("interfaceStatus", "") or ""),
                            oper_status=str(entry.get("lineProtocolStatus", "") or ""),
                            speed_bps=int(float(entry.get("bandwidth", 0) or 0)),
                            in_octets=_num(counters.get("inOctets")),
                            out_octets=_num(counters.get("outOctets")),
                            in_packets=_num(counters.get("inUcastPkts")),
                            out_packets=_num(counters.get("outUcastPkts")),
                            in_errors=_num(counters.get("totalInErrors")),
                            out_errors=_num(counters.get("totalOutErrors")),
                            in_discards=_num(counters.get("inDiscards")),
                            out_discards=_num(counters.get("outDiscards")),
                            high_capacity=True,
                        )
                    )

            if isinstance(version_result, dict):
                snapshot.system_description = str(version_result.get("modelName", ""))
                snapshot.uptime_s = (
                    float(version_result["uptime"]) if _num(version_result.get("uptime")) else None
                )
                memory_total = _num(version_result.get("memTotal"))
                memory_free = _num(version_result.get("memFree"))
                if memory_total:
                    snapshot.memory_percent = round(
                        100.0 * (memory_total - (memory_free or 0)) / memory_total, 2
                    )

            snapshot.poll_ms = (time.monotonic() - started) * 1000.0
            return snapshot
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}", started)


class NxapiDriver(_JsonRpcDriver):
    """Cisco NX-OS NX-API."""

    name = "nxapi"
    endpoint = "/ins"
    commands = ["show interface"]

    def _run(self, commands: List[str]) -> List[Any]:
        payload = {
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": " ;".join(commands),
                "output_format": "json",
            }
        }
        response = self.client.request(
            self.base_path or self.endpoint, method="POST", payload=payload
        )
        if not isinstance(response, dict):
            raise TelemetryError("NX-API returned an unexpected envelope")
        outputs = response.get("ins_api", {}).get("outputs", {}).get("output", {})
        if isinstance(outputs, dict):
            outputs = [outputs]
        results = []
        for item in outputs or []:
            if str(item.get("code", "200")) != "200":
                raise TelemetryError(f"NX-API error: {item.get('msg', 'unknown')}")
            results.append(item.get("body", {}))
        while len(results) < len(commands):
            results.append({})
        return results

    def _hints(self) -> List[str]:
        return [
            "Enable NX-API on the switch: `feature nxapi`",
            "Confirm the HTTPS port (default 443) and that the user has network-operator rights",
        ]

    def collect(self) -> DeviceSnapshot:
        started = time.monotonic()
        try:
            (body,) = self._run(self.commands)
            snapshot = DeviceSnapshot(device=self.device, driver=self.name, epoch=time.time())
            rows = (
                body.get("TABLE_interface", {}).get("ROW_interface", [])
                if isinstance(body, dict)
                else []
            )
            if isinstance(rows, dict):
                rows = [rows]
            for index, entry in enumerate(rows or [], start=1):
                if not isinstance(entry, dict):
                    continue
                snapshot.interfaces.append(
                    InterfaceCounters(
                        index=index,
                        name=str(entry.get("interface", f"if{index}")),
                        alias=str(entry.get("desc", "") or ""),
                        admin_status=str(entry.get("admin_state", "") or ""),
                        oper_status=str(entry.get("state", "") or ""),
                        speed_bps=(_num(entry.get("eth_speed")) or 0),
                        in_octets=_num(entry.get("eth_inbytes")),
                        out_octets=_num(entry.get("eth_outbytes")),
                        in_packets=_num(entry.get("eth_inpkts")),
                        out_packets=_num(entry.get("eth_outpkts")),
                        in_errors=_num(entry.get("eth_inerr")),
                        out_errors=_num(entry.get("eth_outerr")),
                        in_discards=_num(entry.get("eth_indiscard")),
                        out_discards=_num(entry.get("eth_outdiscard")),
                        high_capacity=True,
                    )
                )
            snapshot.poll_ms = (time.monotonic() - started) * 1000.0
            return snapshot
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}", started)
