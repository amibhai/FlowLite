"""Exception hierarchy for FlowLite.

Every error FlowLite raises deliberately derives from :class:`FlowLiteError`, so
supervisors can distinguish "the operator needs to fix something" from "a
dependency blew up unexpectedly".
"""

from __future__ import annotations

__all__ = [
    "FlowLiteError",
    "ConfigError",
    "DependencyError",
    "CaptureError",
    "TransientCaptureError",
    "ParseError",
    "TelemetryError",
    "TransientTelemetryError",
    "DriverNotFound",
]


class FlowLiteError(Exception):
    """Base class for all FlowLite errors."""


class ConfigError(FlowLiteError):
    """Configuration is missing, malformed or internally inconsistent.

    Carries every problem found in one pass so the operator can fix them all at
    once instead of playing whack-a-mole one restart at a time.
    """

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        self.problems = list(problems or [])
        if self.problems:
            detail = "\n".join(f"  - {p}" for p in self.problems)
            message = f"{message}\n{detail}"
        super().__init__(message)


class DependencyError(FlowLiteError):
    """An optional dependency is required for the selected feature but absent."""

    def __init__(self, feature: str, package: str, extra: str = "") -> None:
        self.feature = feature
        self.package = package
        hint = f"pip install 'flowlite[{extra}]'" if extra else f"pip install {package}"
        super().__init__(
            f"{feature} requires the optional package '{package}', which is not installed. "
            f"Install it with: {hint}"
        )


class ParseError(FlowLiteError):
    """A wire format or file format could not be decoded."""


class CaptureError(FlowLiteError):
    """Packet capture failed in a way that will not fix itself."""


class TransientCaptureError(CaptureError):
    """Packet capture failed for a reason that a retry may resolve."""


class TelemetryError(FlowLiteError):
    """Device telemetry collection failed in a way that will not fix itself."""


class TransientTelemetryError(TelemetryError):
    """Device telemetry failed for a reason that a retry may resolve."""


class DriverNotFound(FlowLiteError):
    """A capture or telemetry driver name does not resolve to an implementation."""

    def __init__(self, kind: str, name: str, available: list[str]) -> None:
        super().__init__(
            f"Unknown {kind} driver {name!r}. Available: {', '.join(sorted(available))}"
        )
