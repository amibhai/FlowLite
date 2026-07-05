import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import yaml


class ConfigError(Exception):
    pass


def _to_namespace(obj: Any) -> Any:
    if isinstance(obj, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return [_to_namespace(i) for i in obj]
    return obj


def load_config(path: Optional[str] = None) -> SimpleNamespace:
    search = []
    if path:
        search = [Path(path)]
    else:
        search = [
            Path("config.yaml"),
            Path("../config.yaml"),
            Path("/etc/nids/config.yaml"),
        ]

    found = None
    for p in search:
        if p.exists():
            found = p
            break

    if found is None:
        raise ConfigError(
            f"config.yaml not found. Searched: {[str(p) for p in search]}"
        )

    try:
        with open(found, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        raise ConfigError(f"Failed to parse {found}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"{found} did not parse to a mapping")

    cfg = _to_namespace(raw)

    # Validate required non-empty string fields
    required = [
        ("switch", "host"),
        ("switch", "user"),
        ("switch", "pass"),
    ]
    for section, field in required:
        section_obj = getattr(cfg, section, None)
        if section_obj is None:
            raise ConfigError(f"Missing config section: {section}")
        val = getattr(section_obj, field, None)
        if not isinstance(val, str) or not val.strip():
            raise ConfigError(
                f"config.yaml: {section}.{field} must be a non-empty string. "
                f"Edit config.yaml and fill in your switch credentials."
            )

    return cfg


def get(cfg: SimpleNamespace, dotted_key: str, default: Any = None) -> Any:
    parts = dotted_key.split(".")
    obj = cfg
    for part in parts:
        if not isinstance(obj, SimpleNamespace):
            return default
        obj = getattr(obj, part, None)
        if obj is None:
            return default
    return obj
