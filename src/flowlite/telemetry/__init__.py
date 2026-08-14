"""Device telemetry drivers and the registry that resolves them by name."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from ..errors import DriverNotFound
from .base import (
    DEVICE_TELEMETRY_FIELDS,
    INTERFACE_FIELDS,
    CounterTracker,
    DeviceSnapshot,
    InterfaceCounters,
    PreflightReport,
    TelemetryDriver,
)
from .collector import TelemetryCollector, snapshot_to_rows
from .httpapi import EapiDriver, HttpJsonClient, NxapiDriver, RestconfDriver
from .snmp import OID, SnmpClient, SnmpTelemetryDriver
from .ssh_cli import SshCliDriver

__all__ = [
    "TelemetryDriver",
    "DeviceSnapshot",
    "InterfaceCounters",
    "CounterTracker",
    "PreflightReport",
    "DEVICE_TELEMETRY_FIELDS",
    "INTERFACE_FIELDS",
    "TelemetryCollector",
    "snapshot_to_rows",
    "SnmpClient",
    "SnmpTelemetryDriver",
    "OID",
    "HttpJsonClient",
    "RestconfDriver",
    "EapiDriver",
    "NxapiDriver",
    "SshCliDriver",
    "TELEMETRY_DRIVERS",
    "build_telemetry_driver",
    "available_drivers",
]

TELEMETRY_DRIVERS: Dict[str, Type[TelemetryDriver]] = {
    "snmp": SnmpTelemetryDriver,
    "restconf": RestconfDriver,
    "eapi": EapiDriver,
    "nxapi": NxapiDriver,
    "ssh_cli": SshCliDriver,
}


def build_telemetry_driver(cfg, logger) -> Optional[TelemetryDriver]:
    """Instantiate the configured telemetry driver, or ``None`` when disabled."""
    if not cfg.telemetry.enabled:
        return None
    name = cfg.telemetry.driver
    if name == "none":
        return None
    driver = TELEMETRY_DRIVERS.get(name)
    if driver is None:
        raise DriverNotFound("telemetry", name, list(TELEMETRY_DRIVERS) + ["none"])
    return driver(cfg, logger)


def available_drivers() -> List[str]:
    return sorted(TELEMETRY_DRIVERS) + ["none"]
