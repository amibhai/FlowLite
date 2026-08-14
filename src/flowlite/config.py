"""Configuration loading, merging, validation and normalisation.

Design rules, all of which exist because the previous generation of this tool
violated one of them:

1. **Every key always exists.** A complete default tree is merged under the
   operator's file, so no code path can ever raise ``AttributeError`` for a key
   the operator forgot. Missing configuration degrades; it does not crash.
2. **All problems are reported at once.** Validation collects every error before
   raising, so fixing a config is one edit, not one edit per restart.
3. **Typos are visible.** Keys that are not in the schema are reported as
   warnings, because a silently ignored ``intreval_s`` is a config that quietly
   does the wrong thing forever.
4. **Secrets never reach disk or logs.** Values may reference environment
   variables, and :meth:`Config.redacted` masks credentials for display.
5. **Types are coerced, not assumed.** ``port: "6343"`` from a templating system
   is accepted and normalised rather than exploding inside a socket call.
"""

from __future__ import annotations

import copy
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import ConfigError

__all__ = ["Config", "Section", "load_config", "default_config", "DEFAULTS", "CONFIG_SEARCH_PATH"]


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

DEFAULTS: Dict[str, Any] = {
    "instance": "flowlite",
    "device": {
        "name": "",
        "host": "",
        "vendor": "generic",
        "description": "",
    },
    "credentials": {
        "username": "",
        "password": "",
        "ssh_key_file": "",
        "ssh_key_passphrase": "",
        "snmp_community": "",
    },
    "capture": {
        "source": "folder",
        "rotate_seconds": 3600,
        "max_file_mb": 4096,
        "queue_depth": 64,
        "retry_initial_s": 5,
        "retry_max_s": 300,
        "folder": {
            "watch_dir": "",
            "patterns": ["*.pcap", "*.pcapng", "*.pcap.gz", "*.pcapng.gz"],
            "poll_interval_s": 5,
            "stable_seconds": 10,
            "recursive": True,
            "delete_after_processing": False,
            "reprocess_existing": True,
        },
        "ssh": {
            "host": "",
            "port": 22,
            "username": "",
            "password": "",
            "key_file": "",
            "host_key_policy": "accept-new",
            "known_hosts_file": "",
            "interface": "any",
            "bpf_filter": "",
            "snaplen": 0,
            "capture_tool": "tcpdump",
            "command": "",
            "sudo": False,
            "connect_timeout_s": 30,
            "read_timeout_s": 30,
        },
        "local": {
            "interface": "",
            "tool": "auto",
            "bpf_filter": "",
            "snaplen": 0,
            "extra_args": [],
        },
    },
    "telemetry": {
        "enabled": True,
        "driver": "none",
        "interval_s": 60,
        "timeout_s": 10,
        "snmp": {
            "host": "",
            "port": 161,
            "version": "2c",
            "community": "",
            "max_repetitions": 25,
            "retries": 2,
            "collect_interface_names": True,
            "collect_high_capacity": True,
            "tables": [],
        },
        "http": {
            "host": "",
            "scheme": "https",
            "port": 0,
            "verify_tls": True,
            "ca_bundle": "",
            "base_path": "",
            "username": "",
            "password": "",
        },
        "ssh_cli": {
            "host": "",
            "port": 22,
            "username": "",
            "password": "",
            "key_file": "",
            "host_key_policy": "accept-new",
            "commands": [],
        },
    },
    "flowproto": {
        "enabled": False,
        "flush_interval_s": 60,
        "max_queue": 200000,
        "recv_buffer_bytes": 4194304,
        "sflow": {
            "enabled": False,
            "bind": "0.0.0.0",
            "port": 6343,
            "sample_csv": True,
        },
        "netflow": {
            "enabled": False,
            "bind": "0.0.0.0",
            "port": 2055,
            "template_ttl_s": 3600,
        },
    },
    "analytics": {
        "flow": {
            "active_timeout_s": 300,
            "idle_timeout_s": 60,
            "burst_gap_s": 1.0,
            "max_flows_in_memory": 250000,
            "max_packets_per_flow": 20000,
            "min_packets_per_flow": 1,
        },
        "host_profiles": {
            "enabled": True,
            "window_minutes": 10,
        },
        "network_ts": {
            "enabled": True,
            "bucket_seconds": 60,
        },
    },
    "enrich": {
        "geoip": {
            "enabled": False,
            "asn_db": "",
            "city_db": "",
        },
        "classify_addresses": True,
    },
    "paths": {
        "data_dir": "./data",
        "incoming_dir": "",
        "pcap_dir": "",
        "flows_dir": "",
        "profiles_dir": "",
        "network_ts": "",
        "telemetry_csv": "",
        "interfaces_csv": "",
        "sflow_csv": "",
        "netflow_csv": "",
        "logs_dir": "",
        "state_dir": "",
    },
    "retention": {
        "enabled": True,
        "pcap_days": 7,
        "csv_days": 30,
        # Float so fractional caps ("half a gigabyte") are expressible.
        "max_data_dir_gb": 0.0,
        "protect": ["network_ts.csv"],
    },
    "runtime": {
        "dashboard": "auto",
        "restart_backoff_s": [5, 15, 60, 300],
        "max_restarts": 0,
        "health_file": "",
        "shutdown_grace_s": 30,
        "pid_file": "",
    },
    "logging": {
        "level": "INFO",
        "file_level": "DEBUG",
        "console": True,
        "max_bytes": 10485760,
        "backups": 5,
        "format": "text",
    },
}

CONFIG_SEARCH_PATH: Tuple[str, ...] = (
    "flowlite.yaml",
    "flowlite.yml",
    "flowlite.json",
    "configs/flowlite.yaml",
    "~/.config/flowlite/flowlite.yaml",
    "/etc/flowlite/flowlite.yaml",
)

_SECRET_KEYS = frozenset(
    {
        "password",
        "snmp_community",
        "community",
        "api_token",
        "ssh_key_passphrase",
        "token",
        "secret",
    }
)

_ENUMS: Dict[str, Sequence[str]] = {
    "capture.source": ("folder", "ssh", "local", "none"),
    "capture.ssh.host_key_policy": ("strict", "accept-new", "ignore"),
    "capture.ssh.capture_tool": ("tcpdump", "tshark", "dumpcap"),
    "capture.local.tool": ("auto", "tcpdump", "dumpcap", "tshark"),
    "telemetry.driver": ("none", "snmp", "restconf", "eapi", "nxapi", "ssh_cli"),
    "telemetry.snmp.version": ("1", "2c"),
    "telemetry.http.scheme": ("http", "https"),
    "telemetry.ssh_cli.host_key_policy": ("strict", "accept-new", "ignore"),
    "runtime.dashboard": ("auto", "on", "off"),
    "logging.level": ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    "logging.file_level": ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    "logging.format": ("text", "json"),
}

# Ranges are (minimum, maximum) inclusive; ``None`` means unbounded.
_RANGES: Dict[str, Tuple[Optional[float], Optional[float]]] = {
    "capture.rotate_seconds": (10, 86400),
    "capture.max_file_mb": (1, None),
    "capture.queue_depth": (1, 100000),
    "capture.retry_initial_s": (1, 3600),
    "capture.retry_max_s": (1, 86400),
    "capture.folder.poll_interval_s": (1, 3600),
    "capture.folder.stable_seconds": (0, 3600),
    "capture.ssh.port": (1, 65535),
    "capture.ssh.snaplen": (0, 262144),
    "capture.ssh.connect_timeout_s": (1, 600),
    "capture.ssh.read_timeout_s": (1, 3600),
    "capture.local.snaplen": (0, 262144),
    "telemetry.interval_s": (5, 86400),
    "telemetry.timeout_s": (1, 600),
    "telemetry.snmp.port": (1, 65535),
    "telemetry.snmp.max_repetitions": (1, 255),
    "telemetry.snmp.retries": (0, 10),
    "telemetry.http.port": (0, 65535),
    "telemetry.ssh_cli.port": (1, 65535),
    "flowproto.flush_interval_s": (1, 3600),
    "flowproto.max_queue": (100, 10000000),
    "flowproto.recv_buffer_bytes": (65536, 268435456),
    "flowproto.sflow.port": (1, 65535),
    "flowproto.netflow.port": (1, 65535),
    "flowproto.netflow.template_ttl_s": (60, 86400),
    "analytics.flow.active_timeout_s": (1, 86400),
    "analytics.flow.idle_timeout_s": (1, 86400),
    "analytics.flow.burst_gap_s": (0.001, 3600),
    "analytics.flow.max_flows_in_memory": (100, 50000000),
    "analytics.flow.max_packets_per_flow": (2, 10000000),
    "analytics.flow.min_packets_per_flow": (1, 1000),
    "analytics.host_profiles.window_minutes": (1, 1440),
    "analytics.network_ts.bucket_seconds": (1, 3600),
    "retention.pcap_days": (0, 3650),
    "retention.csv_days": (0, 3650),
    "retention.max_data_dir_gb": (0, 1000000),
    "runtime.max_restarts": (0, 100000),
    "runtime.shutdown_grace_s": (1, 3600),
    "logging.max_bytes": (4096, 1073741824),
    "logging.backups": (0, 100),
}

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


# --------------------------------------------------------------------------- #
# Section / Config objects
# --------------------------------------------------------------------------- #


class Section(Mapping):
    """Read-only mapping with attribute access and helpful failure messages."""

    __slots__ = ("_data", "_path")

    def __init__(self, data: Mapping[str, Any], path: str = "") -> None:
        object.__setattr__(self, "_data", dict(data))
        object.__setattr__(self, "_path", path)

    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        if name in data:
            return data[name]
        prefix = object.__getattribute__(self, "_path")
        full = f"{prefix}.{name}" if prefix else name
        raise ConfigError(
            f"No such configuration key: {full!r}. "
            f"Known keys here: {', '.join(sorted(data)) or '(none)'}"
        )

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover - guard
        raise ConfigError("Configuration is read-only at runtime")

    def __getitem__(self, key: str) -> Any:
        return object.__getattribute__(self, "_data")[key]

    def __iter__(self):
        return iter(object.__getattribute__(self, "_data"))

    def __len__(self) -> int:
        return len(object.__getattribute__(self, "_data"))

    def __contains__(self, key: object) -> bool:
        return key in object.__getattribute__(self, "_data")

    def __repr__(self) -> str:
        path = object.__getattribute__(self, "_path")
        return f"<Section {path or 'root'}: {', '.join(sorted(self))}>"

    def to_dict(self) -> Dict[str, Any]:
        return _unwrap(self)


class Config(Section):
    """The fully-merged, validated configuration tree."""

    __slots__ = ("source_path", "warnings")

    def __init__(
        self,
        data: Mapping[str, Any],
        source_path: Optional[Path] = None,
        warnings: Optional[List[str]] = None,
    ) -> None:
        super().__init__(data, "")
        object.__setattr__(self, "source_path", source_path)
        object.__setattr__(self, "warnings", list(warnings or []))

    def get(self, dotted: str, default: Any = None) -> Any:
        """Fetch ``a.b.c``; return ``default`` when any segment is missing."""
        node: Any = self
        for part in dotted.split("."):
            if (
                isinstance(node, Section)
                and part in node
                or isinstance(node, Mapping)
                and part in node
            ):
                node = node[part]
            else:
                return default
        return node

    def redacted(self) -> Dict[str, Any]:
        """A plain dict safe to log: every credential-shaped value is masked."""
        return _redact(self.to_dict())

    def dump(self, indent: int = 2) -> str:
        return json.dumps(self.redacted(), indent=indent, sort_keys=True, default=str)


def _wrap(value: Any, path: str = "") -> Any:
    if isinstance(value, Mapping):
        return Section({k: _wrap(v, f"{path}.{k}" if path else k) for k, v in value.items()}, path)
    if isinstance(value, list):
        return [_wrap(v, path) for v in value]
    return value


def _unwrap(value: Any) -> Any:
    if isinstance(value, Section):
        return {k: _unwrap(value[k]) for k in value}
    if isinstance(value, Mapping):
        return {k: _unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unwrap(v) for v in value]
    return value


def _redact(value: Any, key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if key in _SECRET_KEYS and isinstance(value, str) and value:
        return "***redacted***"
    return value


# --------------------------------------------------------------------------- #
# Loading helpers
# --------------------------------------------------------------------------- #


def _read_structured(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc

    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc

    try:
        import yaml  # type: ignore
    except ImportError:
        from . import _miniyaml

        try:
            return _miniyaml.safe_load(text)
        except ConfigError as exc:
            raise ConfigError(f"Cannot parse {path}: {exc}") from exc
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError and friends
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc


def _expand_env(value: Any, problems: List[str], path: str = "") -> Any:
    """Substitute ``${VAR}`` / ``${VAR:-default}`` inside every string."""
    if isinstance(value, dict):
        return {
            k: _expand_env(v, problems, f"{path}.{k}" if path else str(k)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_expand_env(v, problems, path) for v in value]
    if not isinstance(value, str) or "${" not in value:
        return value

    def repl(match: re.Match[str]) -> str:
        name, fallback = match.group(1), match.group(2)
        env = os.environ.get(name)
        if env is not None:
            return env
        if fallback is not None:
            return fallback
        problems.append(
            f"{path or 'config'}: environment variable ${{{name}}} is referenced but not set "
            f"(use ${{{name}:-fallback}} to allow a default)"
        )
        return ""

    return _ENV_PATTERN.sub(repl, value)


def _deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            value is None
            and key in result
            and isinstance(result[key], (dict, list, str, int, float, bool))
        ):
            # An explicit `key:` with no value means "leave the default alone"
            # rather than "set this to null and crash later".
            continue
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _collect_unknown(
    user: Mapping[str, Any], schema: Mapping[str, Any], prefix: str = ""
) -> List[str]:
    unknown: List[str] = []
    for key, value in user.items():
        full = f"{prefix}.{key}" if prefix else str(key)
        if key not in schema:
            unknown.append(full)
            continue
        if isinstance(value, Mapping) and isinstance(schema[key], Mapping):
            unknown.extend(_collect_unknown(value, schema[key], full))
    return unknown


def _coerce(value: Any, template: Any, dotted: str, problems: List[str]) -> Any:
    """Coerce ``value`` to the type of ``template``, or record a clear problem."""
    if isinstance(template, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "yes", "on", "1"):
                return True
            if low in ("false", "no", "off", "0"):
                return False
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        problems.append(f"{dotted}: expected a boolean, got {value!r}")
        return template
    if isinstance(template, int) and not isinstance(template, bool):
        if isinstance(value, bool):
            problems.append(f"{dotted}: expected an integer, got a boolean")
            return template
        if isinstance(value, int):
            return value
        if isinstance(value, float) and float(value).is_integer():
            return int(value)
        if isinstance(value, str):
            try:
                return int(value.strip(), 0)
            except ValueError:
                pass
        problems.append(f"{dotted}: expected an integer, got {value!r}")
        return template
    if isinstance(template, float):
        if isinstance(value, bool):
            problems.append(f"{dotted}: expected a number, got a boolean")
            return template
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                pass
        problems.append(f"{dotted}: expected a number, got {value!r}")
        return template
    if isinstance(template, str):
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        problems.append(f"{dotted}: expected a string, got {value!r}")
        return template
    if isinstance(template, list):
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            # Accept "a,b,c" for list-valued keys; templating systems love this.
            return [part.strip() for part in value.split(",") if part.strip()]
        problems.append(f"{dotted}: expected a list, got {value!r}")
        return list(template)
    return value


def _coerce_tree(
    merged: Dict[str, Any], schema: Mapping[str, Any], problems: List[str], prefix: str = ""
) -> Dict[str, Any]:
    for key, template in schema.items():
        dotted = f"{prefix}.{key}" if prefix else key
        if key not in merged:
            merged[key] = copy.deepcopy(template)
            continue
        value = merged[key]
        if isinstance(template, Mapping):
            if isinstance(value, Mapping):
                merged[key] = _coerce_tree(dict(value), template, problems, dotted)
            else:
                problems.append(f"{dotted}: expected a mapping of settings, got {value!r}")
                merged[key] = copy.deepcopy(template)
            continue
        merged[key] = _coerce(value, template, dotted, problems)
    return merged


# --------------------------------------------------------------------------- #
# Normalisation and validation
# --------------------------------------------------------------------------- #


def _expand_path(value: str) -> str:
    return str(Path(os.path.expandvars(os.path.expanduser(value))))


def _derive_paths(cfg: Dict[str, Any]) -> None:
    paths = cfg["paths"]
    data_dir = Path(_expand_path(paths["data_dir"] or "./data"))
    paths["data_dir"] = str(data_dir)

    derived = {
        "incoming_dir": data_dir / "incoming",
        "pcap_dir": data_dir / "pcap",
        "flows_dir": data_dir / "flows",
        "profiles_dir": data_dir / "host_profiles",
        "network_ts": data_dir / "network_ts.csv",
        "telemetry_csv": data_dir / "telemetry" / "device_telemetry.csv",
        "interfaces_csv": data_dir / "telemetry" / "interface_counters.csv",
        "sflow_csv": data_dir / "flowproto" / "sflow_samples.csv",
        "netflow_csv": data_dir / "flowproto" / "netflow_records.csv",
        "logs_dir": data_dir / "logs",
        "state_dir": data_dir / "state",
    }
    for key, fallback in derived.items():
        current = str(paths.get(key) or "").strip()
        paths[key] = _expand_path(current) if current else str(fallback)

    folder = cfg["capture"]["folder"]
    folder["watch_dir"] = (
        _expand_path(folder["watch_dir"]) if folder["watch_dir"].strip() else paths["incoming_dir"]
    )

    for section, key in (
        (cfg["capture"]["ssh"], "key_file"),
        (cfg["capture"]["ssh"], "known_hosts_file"),
        (cfg["telemetry"]["ssh_cli"], "key_file"),
        (cfg["telemetry"]["http"], "ca_bundle"),
        (cfg["credentials"], "ssh_key_file"),
        (cfg["enrich"]["geoip"], "asn_db"),
        (cfg["enrich"]["geoip"], "city_db"),
        (cfg["runtime"], "health_file"),
        (cfg["runtime"], "pid_file"),
    ):
        if section.get(key):
            section[key] = _expand_path(section[key])


def _inherit_credentials(cfg: Dict[str, Any]) -> None:
    """Let per-driver settings fall back to the shared device/credential block."""
    device_host = cfg["device"]["host"].strip()
    creds = cfg["credentials"]

    for section in (cfg["capture"]["ssh"], cfg["telemetry"]["ssh_cli"]):
        section["host"] = section["host"].strip() or device_host
        section["username"] = section["username"].strip() or creds["username"]
        section["password"] = section["password"] or creds["password"]
        section["key_file"] = section["key_file"].strip() or creds["ssh_key_file"]

    snmp = cfg["telemetry"]["snmp"]
    snmp["host"] = snmp["host"].strip() or device_host
    snmp["community"] = snmp["community"].strip() or creds["snmp_community"]

    http = cfg["telemetry"]["http"]
    http["host"] = http["host"].strip() or device_host
    http["username"] = http["username"].strip() or creds["username"]
    http["password"] = http["password"] or creds["password"]

    if not cfg["device"]["name"].strip():
        cfg["device"]["name"] = device_host or cfg["instance"]


def _validate(cfg: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    def value_at(dotted: str) -> Any:
        node: Any = cfg
        for part in dotted.split("."):
            node = node[part]
        return node

    for dotted, allowed in _ENUMS.items():
        raw = value_at(dotted)
        if isinstance(raw, str) and raw not in allowed:
            lowered = raw.strip().lower()
            match = next((a for a in allowed if a.lower() == lowered), None)
            if match is not None:
                node = cfg
                parts = dotted.split(".")
                for part in parts[:-1]:
                    node = node[part]
                node[parts[-1]] = match
            else:
                errors.append(f"{dotted}: {raw!r} is not one of {', '.join(allowed)}")

    for dotted, (low, high) in _RANGES.items():
        raw = value_at(dotted)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            continue
        if low is not None and raw < low:
            errors.append(f"{dotted}: {raw} is below the minimum of {low}")
        if high is not None and raw > high:
            errors.append(f"{dotted}: {raw} is above the maximum of {high}")

    source = cfg["capture"]["source"]
    if source == "ssh" and not cfg["capture"]["ssh"]["host"].strip():
        errors.append("capture.ssh.host (or device.host) must be set when capture.source is 'ssh'")
    if source == "local" and not cfg["capture"]["local"]["interface"].strip():
        errors.append(
            "capture.local.interface must name a local interface when capture.source is 'local'"
        )

    driver = cfg["telemetry"]["driver"]
    if cfg["telemetry"]["enabled"] and driver != "none":
        if driver == "snmp":
            snmp = cfg["telemetry"]["snmp"]
            if not snmp["host"].strip():
                errors.append(
                    "telemetry.snmp.host (or device.host) must be set for the snmp driver"
                )
            if not snmp["community"].strip():
                errors.append(
                    "telemetry.snmp.community (or credentials.snmp_community) must be set "
                    "for SNMP v1/v2c"
                )
        elif driver in ("restconf", "eapi", "nxapi"):
            http = cfg["telemetry"]["http"]
            if not http["host"].strip():
                errors.append(
                    f"telemetry.http.host (or device.host) must be set for the {driver} driver"
                )
            if not http["username"].strip():
                warnings.append(
                    f"telemetry.http.username is empty; the {driver} driver will attempt an "
                    f"unauthenticated request"
                )
            if http["scheme"] == "https" and not http["verify_tls"]:
                warnings.append(
                    "telemetry.http.verify_tls is false -- TLS certificates will not be checked. "
                    "Set telemetry.http.ca_bundle to the device certificate to verify properly."
                )
        elif driver == "ssh_cli":
            ssh = cfg["telemetry"]["ssh_cli"]
            if not ssh["host"].strip():
                errors.append("telemetry.ssh_cli.host (or device.host) must be set")
            if not ssh["commands"]:
                errors.append("telemetry.ssh_cli.commands must list at least one command to run")
            for i, item in enumerate(ssh["commands"]):
                if not isinstance(item, Mapping):
                    errors.append(f"telemetry.ssh_cli.commands[{i}]: expected a mapping")
                    continue
                for field in ("name", "command"):
                    if not str(item.get(field, "")).strip():
                        errors.append(f"telemetry.ssh_cli.commands[{i}].{field} is required")
                pattern = item.get("regex")
                if pattern:
                    try:
                        re.compile(str(pattern))
                    except re.error as exc:
                        errors.append(
                            f"telemetry.ssh_cli.commands[{i}].regex is not a valid regular "
                            f"expression: {exc}"
                        )

    for policy_path in ("capture.ssh.host_key_policy", "telemetry.ssh_cli.host_key_policy"):
        if value_at(policy_path) == "ignore":
            warnings.append(
                f"{policy_path} is 'ignore' -- SSH host keys are not verified, which permits "
                f"man-in-the-middle interception. Use 'accept-new' or 'strict' in production."
            )

    fp = cfg["flowproto"]
    if fp["enabled"] and not (fp["sflow"]["enabled"] or fp["netflow"]["enabled"]):
        warnings.append(
            "flowproto.enabled is true but neither flowproto.sflow.enabled nor "
            "flowproto.netflow.enabled is set; no collector will start"
        )
    both_collectors_on = fp["sflow"]["enabled"] and fp["netflow"]["enabled"]
    same_socket = (fp["sflow"]["port"], fp["sflow"]["bind"]) == (
        fp["netflow"]["port"],
        fp["netflow"]["bind"],
    )
    if both_collectors_on and same_socket:
        errors.append("flowproto.sflow and flowproto.netflow cannot bind the same address and port")

    geoip = cfg["enrich"]["geoip"]
    if geoip["enabled"]:
        if not geoip["asn_db"] and not geoip["city_db"]:
            warnings.append(
                "enrich.geoip.enabled is true but no database path is configured; "
                "ASN enrichment will report UNKNOWN"
            )
        for key in ("asn_db", "city_db"):
            path = geoip[key]
            if path and not Path(path).exists():
                warnings.append(
                    f"enrich.geoip.{key}: {path} does not exist; lookups will be skipped"
                )

    flow = cfg["analytics"]["flow"]
    if flow["idle_timeout_s"] > flow["active_timeout_s"]:
        warnings.append(
            "analytics.flow.idle_timeout_s exceeds active_timeout_s, so the idle timeout can "
            "never fire; flows will only be evicted by the active timeout"
        )

    backoff = cfg["runtime"]["restart_backoff_s"]
    cleaned = [
        x for x in backoff if isinstance(x, (int, float)) and not isinstance(x, bool) and x > 0
    ]
    if not cleaned:
        warnings.append(
            "runtime.restart_backoff_s had no usable values; falling back to [5, 15, 60, 300]"
        )
        cleaned = [5, 15, 60, 300]
    cfg["runtime"]["restart_backoff_s"] = [float(x) for x in cleaned]

    if cfg["capture"]["retry_max_s"] < cfg["capture"]["retry_initial_s"]:
        warnings.append("capture.retry_max_s is below capture.retry_initial_s; raising it to match")
        cfg["capture"]["retry_max_s"] = cfg["capture"]["retry_initial_s"]

    patterns = cfg["capture"]["folder"]["patterns"]
    cfg["capture"]["folder"]["patterns"] = [str(p) for p in patterns if str(p).strip()]
    if source == "folder" and not cfg["capture"]["folder"]["patterns"]:
        errors.append("capture.folder.patterns must contain at least one glob pattern")

    return errors, warnings


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _find_config(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(_expand_path(explicit))
        if not path.exists():
            raise ConfigError(f"Configuration file not found: {path}")
        return path
    env_path = os.environ.get("FLOWLITE_CONFIG")
    if env_path:
        path = Path(_expand_path(env_path))
        if not path.exists():
            raise ConfigError(f"FLOWLITE_CONFIG points at a missing file: {path}")
        return path
    for candidate in CONFIG_SEARCH_PATH:
        path = Path(_expand_path(candidate))
        if path.exists():
            return path
    return None


def _apply_overrides(data: Dict[str, Any], overrides: Iterable[str], problems: List[str]) -> None:
    """Apply ``--set a.b.c=value`` style overrides onto the raw user tree."""
    for item in overrides:
        if "=" not in item:
            problems.append(f"override {item!r} is not of the form key.path=value")
            continue
        dotted, _, raw = item.partition("=")
        parts = [p for p in dotted.strip().split(".") if p]
        if not parts:
            problems.append(f"override {item!r} has an empty key path")
            continue
        node = data
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        try:
            node[parts[-1]] = json.loads(raw)
        except ValueError:
            node[parts[-1]] = raw


def default_config() -> Config:
    """A fully-populated configuration using nothing but defaults."""
    return load_config(path=None, allow_missing=True, _skip_search=True)


def load_config(
    path: Optional[str] = None,
    overrides: Optional[Iterable[str]] = None,
    allow_missing: bool = True,
    strict_unknown: bool = False,
    _skip_search: bool = False,
) -> Config:
    """Load, merge, coerce and validate a FlowLite configuration.

    Args:
        path: Explicit config file. When ``None``, ``$FLOWLITE_CONFIG`` and then
            :data:`CONFIG_SEARCH_PATH` are consulted.
        overrides: ``key.path=value`` strings applied on top of the file.
        allow_missing: When true (the default) a missing config file yields the
            default configuration plus a warning, so FlowLite is usable with no
            file at all. When false, a missing file is an error.
        strict_unknown: Treat unrecognised keys as errors instead of warnings.

    Raises:
        ConfigError: with every problem found, not just the first.
    """
    warnings: List[str] = []
    problems: List[str] = []

    found = None if _skip_search else _find_config(path)
    raw: Any = {}
    if found is not None:
        raw = _read_structured(found)
        if raw is None:
            raw = {}
            warnings.append(f"{found} is empty; using defaults for every setting")
        elif not isinstance(raw, Mapping):
            raise ConfigError(
                f"{found} must contain a mapping at the top level, not {type(raw).__name__}"
            )
    elif not allow_missing:
        raise ConfigError(
            "No configuration file found. Searched: "
            + ", ".join(CONFIG_SEARCH_PATH)
            + ". Create one with: flowlite init"
        )
    else:
        warnings.append(
            "No configuration file found; running entirely on defaults. "
            "Create one with: flowlite init"
        )

    user: Dict[str, Any] = dict(raw)
    # `flowlite:` is accepted as an optional top-level wrapper.
    if len(user) == 1 and isinstance(user.get("flowlite"), Mapping):
        user = dict(user["flowlite"])

    if overrides:
        _apply_overrides(user, overrides, problems)

    user = _expand_env(user, problems)

    unknown = _collect_unknown(user, DEFAULTS)
    for key in unknown:
        message = f"unknown configuration key {key!r} (ignored)"
        if strict_unknown:
            problems.append(message)
        else:
            warnings.append(message)

    merged = _deep_merge(DEFAULTS, user)
    merged = _coerce_tree(merged, DEFAULTS, problems)

    _derive_paths(merged)
    _inherit_credentials(merged)

    errors, more_warnings = _validate(merged)
    problems.extend(errors)
    warnings.extend(more_warnings)

    if problems:
        where = str(found) if found else "(defaults)"
        raise ConfigError(f"Configuration is invalid ({where})", problems)

    return Config(_wrap(merged), found, warnings)
