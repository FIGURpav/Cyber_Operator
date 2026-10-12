"""Resolve local paths without personal-machine defaults or implicit repo storage."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path


def configured_path(key: str, environment: str, leaf: str) -> Path:
    value = os.environ.get(environment)
    if value is None and os.environ.get("CYBER_CONFIG"):
        path = Path(os.environ["CYBER_CONFIG"]).expanduser()
        with path.open("rb") as stream:
            config = tomllib.load(stream)
        value = config.get("paths", {}).get(key)
    if value is None:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
        return base / "cyber-operator" / leaf
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{key} must be an absolute path")
    return path


def workspace_root() -> Path:
    return configured_path("workspace_root", "CYBER_WORKSPACE_ROOT", "workspaces")


def source_root(*, readonly: bool = True) -> Path:
    return configured_path(
        "source_ro" if readonly else "source_rw",
        "CYBER_SOURCE_RO" if readonly else "CYBER_SOURCE_RW",
        "source-ro" if readonly else "source",
    )
