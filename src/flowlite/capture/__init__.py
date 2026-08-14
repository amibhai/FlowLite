"""Capture drivers and the registry that resolves them by name."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from ..errors import DriverNotFound
from .base import CaptureArtifact, CaptureSource, PreflightResult
from .folder import FolderCaptureSource
from .local import LocalCaptureSource, detect_capture_tool, list_local_interfaces
from .ssh import SshCaptureSource, build_capture_command

__all__ = [
    "CaptureArtifact",
    "CaptureSource",
    "PreflightResult",
    "FolderCaptureSource",
    "SshCaptureSource",
    "LocalCaptureSource",
    "build_capture_command",
    "detect_capture_tool",
    "list_local_interfaces",
    "CAPTURE_DRIVERS",
    "build_capture_source",
]

CAPTURE_DRIVERS: Dict[str, Type[CaptureSource]] = {
    "folder": FolderCaptureSource,
    "ssh": SshCaptureSource,
    "local": LocalCaptureSource,
}


def build_capture_source(cfg, logger, status=None) -> Optional[CaptureSource]:
    """Instantiate the configured capture driver, or ``None`` when disabled."""
    name = cfg.capture.source
    if name == "none":
        return None
    driver = CAPTURE_DRIVERS.get(name)
    if driver is None:
        raise DriverNotFound("capture", name, list(CAPTURE_DRIVERS) + ["none"])
    return driver(cfg, logger, status)


def available_drivers() -> List[str]:
    return sorted(CAPTURE_DRIVERS) + ["none"]
