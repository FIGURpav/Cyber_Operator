"""Manage operator-approved standing authorization for controlled-engagement workspaces."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import stat
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import artifact_handling, operational_profile, workspace_lifecycle
    from . import operational_trace as trace
else:
    import artifact_handling  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import operational_trace as trace  # type: ignore[no-redef]
    import workspace_lifecycle  # type: ignore[no-redef]

STANDING_AUTHORIZATION_LEDGER = "standing_authorizations.jsonl"
SECRET_DISPLAY_LEDGER = "engagement_secret_display.jsonl"
STANDING_ID_RE = re.compile(r"^SAUTH-\d{8}T\d{12}Z$")
STANDING_EVENT_ID_RE = re.compile(r"^SAE-\d{8}T\d{12}Z$")
SECRET_DISPLAY_EVENT_ID_RE = re.compile(r"^SDE-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

EVENTS = {"activated", "revoked", "closed"}
PRESETS = {"custom"}
HOST_SCOPES = {"canonical-current", "canonical-current-and-future"}
CREDENTIAL_OPERATIONS = {"none", "dump-reuse", "dump-reuse-spray"}
PERSISTENCE_MODES = {"none", "single", "risk-adaptive", "dual"}
SECRET_DISPLAY_EVENTS = {"enabled", "disabled"}
SECRET_DISPLAY_SURFACES = ("chat", "screenshot", "private-report")

SECRET_DISPLAY_FIELDS = (
    "schema_version",
    "secret_display_event_id",
    "created_at_utc",
    "standing_authorization_id",
    "event",
    "surfaces",
    "reason",
)

TECHNIQUE_FAMILY_CATEGORIES = {
    "initial-access": {"initial-access"},
    "privilege-escalation": {"identity-switch", "privilege-escalation"},
    "persistence": {"access-control", "configuration", "persistence", "service"},
    "security-control-change": {"access-control", "configuration", "service"},
    "credential-access": {"access-control", "data", "filesystem"},
    "credential-reuse": {"identity-switch", "initial-access", "lateral-movement"},
    "credential-spraying": {"initial-access", "lateral-movement"},
    "pivot-tunnel": {"external-callback", "network", "pivot", "tunnel"},
    "lateral-movement": {"lateral-movement"},
    "filesystem-data": {"data", "filesystem"},
    "bulk-data-access": {"bulk-data-access", "data"},
    "destructive-mutation": {"configuration", "data", "destructive", "filesystem"},
    "cloud-control": {"cloud"},
    "container-control": {"container"},
    "kubernetes-control": {"kubernetes"},
    "model-control": {"model"},
}


STANDING_FIELDS = (
    "schema_version",
    "standing_event_id",
    "created_at_utc",
    "standing_authorization_id",
    "event",
    "preset",
    "host_scope",
    "host_ids",
    "maximum_impact",
    "categories",
    "technique_families",
    "credential_operations",
    "persistence_mode",
    "allow_security_control_changes",
    "allow_destructive",
    "allow_bulk_data",
    "callback_cidrs",
    "callback_port_ranges",
    "expires_at_utc",
    "exclusions",
    "source",
    "summary",
    "note",
)


class EngagementPolicyError(RuntimeError):
    """A deterministic standing-authorization policy failure."""


def _validate_artifact_handling(root: Path) -> str:
    """Fail closed when the independent workspace artifact mode is invalid."""
    try:
        return artifact_handling.workspace_mode(root)
    except artifact_handling.ArtifactHandlingError as exc:
        raise EngagementPolicyError(str(exc)) from exc


def _timestamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, now: datetime) -> str:
    return now.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _parse_timestamp(value: str, label: str) -> datetime:
    if TIMESTAMP_RE.fullmatch(value) is None:
        raise EngagementPolicyError(f"{label} must use canonical UTC format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EngagementPolicyError(f"invalid {label}") from exc


def _text(value: str, label: str, maximum: int = 1024) -> str:
    normalized = value.strip()
    if not normalized:
        raise EngagementPolicyError(f"{label} must not be empty")
    if len(normalized) > maximum:
        raise EngagementPolicyError(f"{label} is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise EngagementPolicyError(f"{label} must not contain control characters")
    return normalized


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _categories_for(families: Iterable[str]) -> list[str]:
    categories: set[str] = set()
    for family in families:
        if family not in TECHNIQUE_FAMILY_CATEGORIES:
            raise EngagementPolicyError(f"unsupported technique family: {family}")
        categories.update(TECHNIQUE_FAMILY_CATEGORIES[family])
    categories.discard("denial-of-service")
    categories.discard("other")
    return sorted(categories)


def _normalize_cidrs(values: Iterable[str]) -> list[str]:
    networks: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise EngagementPolicyError(f"invalid callback CIDR: {value!r}") from exc
        networks.append(str(network))
    return sorted(set(networks))


def _parse_port_range(value: str) -> tuple[int, int]:
    parts = value.split("-", 1)
    try:
        start = int(parts[0])
        end = int(parts[1]) if len(parts) == 2 else start
    except ValueError as exc:
        raise EngagementPolicyError(f"invalid callback port range: {value!r}") from exc
    if not 1 <= start <= end <= 65535:
        raise EngagementPolicyError(f"invalid callback port range: {value!r}")
    return start, end


def _normalize_port_ranges(values: Iterable[str]) -> list[str]:
    ranges = {_parse_port_range(value) for value in values}
    return [str(start) if start == end else f"{start}-{end}" for start, end in sorted(ranges)]


def _validate_record(record: dict[str, Any], source: str) -> None:
    missing = [field for field in STANDING_FIELDS if field not in record]
    extra = [field for field in record if field not in STANDING_FIELDS]
    if missing or extra:
        detail = "missing " + ", ".join(missing) if missing else "unexpected " + ", ".join(extra)
        raise EngagementPolicyError(f"{source} has {detail}")
    if record["schema_version"] != "1.0":
        raise EngagementPolicyError(f"{source} has unsupported schema_version")
    if not isinstance(record["standing_event_id"], str) or STANDING_EVENT_ID_RE.fullmatch(record["standing_event_id"]) is None:
        raise EngagementPolicyError(f"{source} has malformed standing_event_id")
    if not isinstance(record["standing_authorization_id"], str) or STANDING_ID_RE.fullmatch(record["standing_authorization_id"]) is None:
        raise EngagementPolicyError(f"{source} has malformed standing_authorization_id")
    created = record["created_at_utc"]
    if not isinstance(created, str):
        raise EngagementPolicyError(f"{source} has malformed created_at_utc")
    created_at = _parse_timestamp(created, "created_at_utc")
    expected_event = _identifier("SAE", created_at)
    if record["standing_event_id"] != expected_event:
        raise EngagementPolicyError(f"{source} event identifier and timestamp do not match")
    if record["event"] not in EVENTS or record["preset"] not in PRESETS:
        raise EngagementPolicyError(f"{source} has unsupported lifecycle state")
    if record["host_scope"] not in HOST_SCOPES:
        raise EngagementPolicyError(f"{source} has unsupported host_scope")
    if not isinstance(record["host_ids"], list) or any(not isinstance(value, str) or trace.HOST_ID_RE.fullmatch(value) is None for value in record["host_ids"]):
        raise EngagementPolicyError(f"{source} has invalid host_ids")
    if len(record["host_ids"]) != len(set(record["host_ids"])):
        raise EngagementPolicyError(f"{source} has duplicate host_ids")
    if record["maximum_impact"] not in trace.IMPACT_LEVELS:
        raise EngagementPolicyError(f"{source} has unsupported maximum_impact")
    if not isinstance(record["categories"], list) or not record["categories"]:
        raise EngagementPolicyError(f"{source} categories must be a non-empty list")
    if any(value not in trace.AUTHORIZATION_CATEGORIES for value in record["categories"]):
        raise EngagementPolicyError(f"{source} has unsupported categories")
    families = record["technique_families"]
    if not isinstance(families, list) or not families or any(value not in TECHNIQUE_FAMILY_CATEGORIES for value in families):
        raise EngagementPolicyError(f"{source} has unsupported technique_families")
    if record["credential_operations"] not in CREDENTIAL_OPERATIONS:
        raise EngagementPolicyError(f"{source} has unsupported credential_operations")
    if record["persistence_mode"] not in PERSISTENCE_MODES:
        raise EngagementPolicyError(f"{source} has unsupported persistence_mode")
    for field in ("allow_security_control_changes", "allow_destructive", "allow_bulk_data"):
        if not isinstance(record[field], bool):
            raise EngagementPolicyError(f"{source} {field} must be boolean")
    _normalize_cidrs(record["callback_cidrs"])
    _normalize_port_ranges(record["callback_port_ranges"])
    if record["expires_at_utc"] is not None:
        if not isinstance(record["expires_at_utc"], str):
            raise EngagementPolicyError(f"{source} has malformed expires_at_utc")
        _parse_timestamp(record["expires_at_utc"], "expires_at_utc")
    for field in ("exclusions",):
        if not isinstance(record[field], list) or any(not isinstance(value, str) for value in record[field]):
            raise EngagementPolicyError(f"{source} {field} must be a string list")
    for field in ("source", "summary", "note"):
        if not isinstance(record[field], str):
            raise EngagementPolicyError(f"{source} {field} must be text")


def _ledger_path(workspace: Path) -> Path:
    return workspace / STANDING_AUTHORIZATION_LEDGER


def _read_records(workspace: Path) -> list[dict[str, Any]]:
    path = _ledger_path(workspace)
    if not path.exists():
        return []
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EngagementPolicyError(f"cannot inspect {path.name}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EngagementPolicyError(f"{path.name} must be a real non-symlink regular file")
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise EngagementPolicyError(f"cannot read {path.name}: {exc}") from exc
    records: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if not line.endswith("\n"):
            raise EngagementPolicyError(f"{path.name} line {number} is not newline terminated")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EngagementPolicyError(f"invalid JSON in {path.name} line {number}") from exc
        if not isinstance(record, dict):
            raise EngagementPolicyError(f"{path.name} line {number} must be an object")
        _validate_record(record, f"{path.name} line {number}")
        records.append(record)
    return records


def load_standing_authorizations(workspace: str | Path) -> list[dict[str, Any]]:
    root = trace.validate_workspace(workspace)
    records = _read_records(root)
    events: set[str] = set()
    histories: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record["standing_event_id"] in events:
            raise EngagementPolicyError("standing authorization ledger duplicates an event ID")
        events.add(record["standing_event_id"])
        history = histories.setdefault(record["standing_authorization_id"], [])
        if not history:
            if record["event"] != "activated":
                raise EngagementPolicyError("standing authorization must begin with activated")
            activation_time = _parse_timestamp(record["created_at_utc"], "created_at_utc")
            if record["standing_authorization_id"] != _identifier("SAUTH", activation_time):
                raise EngagementPolicyError("standing authorization ID and activation time do not match")
        else:
            if history[-1]["event"] != "activated":
                raise EngagementPolicyError("standing authorization lifecycle is already terminal")
            stable = set(STANDING_FIELDS) - {"schema_version", "standing_event_id", "created_at_utc", "event", "note"}
            if any(record[field] != history[0][field] for field in stable):
                raise EngagementPolicyError("standing authorization lifecycle changed stable fields")
        history.append(record)
    return records


def active_standing_authorization(workspace: str | Path, now: datetime | None = None) -> dict[str, Any] | None:
    if __package__:
        from . import engagement_config, restore_checkpoint
    else:
        import engagement_config
        import restore_checkpoint
    if engagement_config.is_managed(Path(workspace)):
        engagement_config.load(Path(workspace))
        return None
    records = load_standing_authorizations(workspace)
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        latest[record["standing_authorization_id"]] = record
    moment = now or datetime.now(UTC)
    active = [
        record
        for record in latest.values()
        if record["event"] == "activated"
        and workspace_lifecycle.authorization_is_current(workspace, record)
        and not restore_checkpoint.historical_authorization(Path(workspace), record["standing_authorization_id"])
        and (
            record["expires_at_utc"] is None
            or moment < _parse_timestamp(record["expires_at_utc"], "expires_at_utc")
        )
    ]
    if not active:
        return None
    if len(active) > 1:
        raise EngagementPolicyError("workspace contains multiple active standing authorizations")
    record = active[0]
    return record


def _secret_display_path(workspace: Path) -> Path:
    return workspace / SECRET_DISPLAY_LEDGER


def _validate_secret_display_record(record: dict[str, Any], source: str) -> None:
    missing = [field for field in SECRET_DISPLAY_FIELDS if field not in record]
    extra = [field for field in record if field not in SECRET_DISPLAY_FIELDS]
    if missing or extra:
        detail = (
            "missing " + ", ".join(missing)
            if missing
            else "unexpected " + ", ".join(extra)
        )
        raise EngagementPolicyError(f"{source} has {detail}")
    if record["schema_version"] != "1.0":
        raise EngagementPolicyError(f"{source} has unsupported schema_version")
    event_id = record["secret_display_event_id"]
    if (
        not isinstance(event_id, str)
        or SECRET_DISPLAY_EVENT_ID_RE.fullmatch(event_id) is None
    ):
        raise EngagementPolicyError(f"{source} has malformed secret_display_event_id")
    created = record["created_at_utc"]
    if not isinstance(created, str):
        raise EngagementPolicyError(f"{source} has malformed created_at_utc")
    created_at = _parse_timestamp(created, "created_at_utc")
    if event_id != _identifier("SDE", created_at):
        raise EngagementPolicyError(f"{source} event identifier and timestamp do not match")
    if (
        not isinstance(record["standing_authorization_id"], str)
        or STANDING_ID_RE.fullmatch(record["standing_authorization_id"]) is None
    ):
        raise EngagementPolicyError(f"{source} has malformed standing_authorization_id")
    if record["event"] not in SECRET_DISPLAY_EVENTS:
        raise EngagementPolicyError(f"{source} has unsupported lifecycle state")
    if record["surfaces"] != list(SECRET_DISPLAY_SURFACES):
        raise EngagementPolicyError(f"{source} has unsupported secret-display surfaces")
    if not isinstance(record["reason"], str):
        raise EngagementPolicyError(f"{source} reason must be text")
    _text(record["reason"], "reason")


def load_secret_display_events(workspace: str | Path) -> list[dict[str, Any]]:
    root = trace.validate_workspace(workspace)
    path = _secret_display_path(root)
    if not path.exists():
        if path.is_symlink():
            raise EngagementPolicyError(
                f"{path.name} must be a real non-symlink regular file"
            )
        return []
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EngagementPolicyError(f"cannot inspect {path.name}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EngagementPolicyError(f"{path.name} must be a real non-symlink regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise EngagementPolicyError(f"{path.name} permissions must not expose private policy data")
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise EngagementPolicyError(f"cannot read {path.name}: {exc}") from exc
    standing_ids = {
        record["standing_authorization_id"]
        for record in load_standing_authorizations(root)
        if record["event"] == "activated"
    }
    records: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    latest: dict[str, str] = {}
    for number, line in enumerate(lines, start=1):
        if not line.endswith("\n"):
            raise EngagementPolicyError(f"{path.name} line {number} is not newline terminated")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EngagementPolicyError(f"invalid JSON in {path.name} line {number}") from exc
        if not isinstance(record, dict):
            raise EngagementPolicyError(f"{path.name} line {number} must be an object")
        _validate_secret_display_record(record, f"{path.name} line {number}")
        event_id = record["secret_display_event_id"]
        standing_id = record["standing_authorization_id"]
        if event_id in event_ids:
            raise EngagementPolicyError("secret-display ledger duplicates an event ID")
        if standing_id not in standing_ids:
            raise EngagementPolicyError("secret-display event references unknown standing authorization")
        if latest.get(standing_id) == record["event"]:
            raise EngagementPolicyError("secret-display ledger repeats the effective state")
        event_ids.add(event_id)
        latest[standing_id] = record["event"]
        records.append(record)
    return records


def secret_display_enabled(
    workspace: str | Path, now: datetime | None = None
) -> bool:
    root = trace.validate_workspace(workspace)
    policy = active_standing_authorization(root, now)
    if policy is None:
        return False
    matching = [
        record
        for record in load_secret_display_events(root)
        if record["standing_authorization_id"]
        == policy["standing_authorization_id"]
    ]
    return bool(matching and matching[-1]["event"] == "enabled")


def _append_secret_display_locked(
    workspace: Path, record: dict[str, Any], validation_time: datetime
) -> None:
    path = _secret_display_path(workspace)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EngagementPolicyError(f"{path.name} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise EngagementPolicyError(
                f"{path.name} permissions must not expose private policy data"
            )
        events = load_secret_display_events(workspace)
        current = active_standing_authorization(workspace, validation_time)
        if (
            current is None
            or current["standing_authorization_id"]
            != record["standing_authorization_id"]
        ):
            raise EngagementPolicyError("standing authorization is no longer active")
        matching = [
            item
            for item in events
            if item["standing_authorization_id"]
            == record["standing_authorization_id"]
        ]
        if matching and matching[-1]["event"] == record["event"]:
            raise EngagementPolicyError("secret-display switch already has that state")
        current_path = path.lstat()
        if (
            current_path.st_dev != metadata.st_dev
            or current_path.st_ino != metadata.st_ino
            or stat.S_ISLNK(current_path.st_mode)
        ):
            raise EngagementPolicyError("secret-display ledger changed during append")
        encoded = (
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode()
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def set_secret_display(
    *,
    workspace: str | Path,
    enabled: bool,
    reason: str,
    acknowledged: bool,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = trace.validate_workspace(workspace)
    if enabled:
        _validate_artifact_handling(root)
    try:
        operational_profile.workspace_profile(root)
    except operational_profile.OperationalProfileError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    policy = active_standing_authorization(root, now)
    if policy is None:
        raise EngagementPolicyError("workspace has no active standing authorization")
    if apply and enabled and not acknowledged:
        raise EngagementPolicyError(
            "enable apply requires explicit acknowledgement: --ack-secret-display"
        )
    moment = now or datetime.now(UTC)
    normalized_reason = _text(reason, "reason")
    try:
        trace._reject_secret_content(root, [normalized_reason])
    except trace.TraceError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    matching_events = [
        event
        for event in load_secret_display_events(root)
        if event["standing_authorization_id"]
        == policy["standing_authorization_id"]
    ]
    current_enabled = bool(
        matching_events and matching_events[-1]["event"] == "enabled"
    )
    if current_enabled == enabled:
        state = "enabled" if enabled else "disabled"
        raise EngagementPolicyError(f"secret-display switch is already {state}")
    record = {
        "schema_version": "1.0",
        "secret_display_event_id": _identifier("SDE", moment),
        "created_at_utc": _timestamp(moment),
        "standing_authorization_id": policy["standing_authorization_id"],
        "event": "enabled" if enabled else "disabled",
        "surfaces": list(SECRET_DISPLAY_SURFACES),
        "reason": normalized_reason,
    }
    _validate_secret_display_record(record, "secret-display event")
    if apply:
        with _shared_policy_lock(root):
            current = active_standing_authorization(root, now)
            if (
                current is None
                or current["standing_authorization_id"]
                != policy["standing_authorization_id"]
            ):
                raise EngagementPolicyError("standing authorization is no longer active")
            _append_secret_display_locked(root, record, moment)
    return root, record


def _append_locked(
    workspace: Path, record: dict[str, Any], validation_time: datetime
) -> None:
    path = _ledger_path(workspace)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EngagementPolicyError(f"{path.name} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise EngagementPolicyError(f"{path.name} permissions must not expose private policy data")
        load_standing_authorizations(workspace)
        active = active_standing_authorization(workspace, validation_time)
        if record["event"] == "activated":
            if active is not None:
                raise EngagementPolicyError(
                    "workspace already has an active standing authorization"
                )
        elif active is None or active["standing_authorization_id"] != record[
            "standing_authorization_id"
        ]:
            raise EngagementPolicyError("standing authorization is no longer active")
        current = path.lstat()
        if (
            current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or stat.S_ISLNK(current.st_mode)
        ):
            raise EngagementPolicyError("standing authorization ledger changed during append")
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _shared_policy_lock(workspace: Path) -> Iterable[None]:
    path = _ledger_path(workspace)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
        ):
            raise EngagementPolicyError("standing authorization ledger changed during permit")
        yield
        current = path.lstat()
        if current.st_dev != metadata.st_dev or current.st_ino != metadata.st_ino:
            raise EngagementPolicyError("standing authorization ledger changed during permit")
    finally:
        os.close(descriptor)


def preset_configuration(preset: str) -> dict[str, Any]:
    raise EngagementPolicyError("an explicit engagement configuration is required; no takeover presets exist")


def build_activation(
    *,
    workspace: str | Path,
    preset: str,
    host_scope: str,
    callback_cidrs: list[str],
    callback_port_ranges: list[str],
    expires_at_utc: str | None,
    source: str,
    summary: str,
    configuration: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = trace.validate_workspace(workspace)
    _reject_managed_grant(root)
    try:
        workspace_lifecycle.assert_target_actions_open(root)
    except workspace_lifecycle.WorkspaceLifecycleError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    _validate_artifact_handling(root)
    try:
        operational_profile.workspace_profile(root)
    except operational_profile.OperationalProfileError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    if preset not in PRESETS or host_scope not in HOST_SCOPES:
        raise EngagementPolicyError("unsupported standing authorization preset or host scope")
    if active_standing_authorization(root, now) is not None:
        raise EngagementPolicyError("workspace already has an active standing authorization")
    config = dict(configuration) if configuration is not None else preset_configuration(preset)
    required = {
        "maximum_impact", "technique_families", "categories", "credential_operations",
        "persistence_mode", "allow_security_control_changes", "allow_destructive", "allow_bulk_data",
    }
    if set(config) != required:
        raise EngagementPolicyError("standing authorization flag matrix is incomplete")
    families = sorted(set(config["technique_families"]))
    categories = sorted(set(config["categories"]))
    expected_categories = set(_categories_for(families))
    if not set(categories) <= expected_categories:
        raise EngagementPolicyError("categories exceed the selected technique families")
    if "denial-of-service" in categories or "other" in categories:
        raise EngagementPolicyError("DoS and unclassified operations cannot use standing authorization")
    cidrs = _normalize_cidrs(callback_cidrs)
    ports = _normalize_port_ranges(callback_port_ranges)
    if "external-callback" in categories and (not cidrs or not ports):
        raise EngagementPolicyError("external callbacks require CIDR and port allowlists")
    expires = None
    moment = now or datetime.now(UTC)
    if expires_at_utc is not None:
        expiry = _parse_timestamp(expires_at_utc, "expires_at_utc")
        if expiry <= moment:
            raise EngagementPolicyError("expires_at_utc must be in the future")
        expires = _timestamp(expiry)
    known_hosts = sorted(
        trace.discover_active_host_ids(root), key=lambda value: int(value[1:])
    )
    if host_scope == "canonical-current" and not known_hosts:
        raise EngagementPolicyError("canonical-current scope requires at least one registered host")
    standing_id = _identifier("SAUTH", moment)
    record = {
        "schema_version": "1.0",
        "standing_event_id": _identifier("SAE", moment),
        "created_at_utc": _timestamp(moment),
        "standing_authorization_id": standing_id,
        "event": "activated",
        "preset": preset,
        "host_scope": host_scope,
        "host_ids": known_hosts if host_scope == "canonical-current" else [],
        "maximum_impact": config["maximum_impact"],
        "categories": categories,
        "technique_families": families,
        "credential_operations": config["credential_operations"],
        "persistence_mode": config["persistence_mode"],
        "allow_security_control_changes": config["allow_security_control_changes"],
        "allow_destructive": config["allow_destructive"],
        "allow_bulk_data": config["allow_bulk_data"],
        "callback_cidrs": cidrs,
        "callback_port_ranges": ports,
        "expires_at_utc": expires,
        "exclusions": ["denial-of-service", "systems outside this canonical workspace"],
        "source": _text(source, "source", 128),
        "summary": _text(summary, "summary"),
        "note": "",
    }
    _validate_record(record, "activation")
    trace._reject_secret_content(root, [record["source"], record["summary"]])
    return root, record


def apply_activation(workspace: Path, record: dict[str, Any]) -> None:
    root = trace.validate_workspace(workspace)
    _reject_managed_grant(root)
    try:
        workspace_lifecycle.assert_target_actions_open(root)
    except workspace_lifecycle.WorkspaceLifecycleError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    _validate_artifact_handling(root)
    _validate_record(record, "activation apply")
    _append_locked(
        root,
        record,
        _parse_timestamp(record["created_at_utc"], "created_at_utc"),
    )


def _reject_managed_grant(root: Path) -> None:
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    try:
        engagement_config.reject_legacy_mutation(root)
    except (ValueError, RuntimeError, OSError) as exc:
        raise EngagementPolicyError(str(exc)) from exc


def _callback_allowed(record: dict[str, Any], callback: str | None) -> bool:
    if callback is None:
        return False
    host: str
    port_text: str
    if callback.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", callback)
        if match is None:
            raise EngagementPolicyError("invalid callback endpoint")
        host, port_text = match.groups()
    else:
        try:
            host, port_text = callback.rsplit(":", 1)
        except ValueError as exc:
            raise EngagementPolicyError("invalid callback endpoint") from exc
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as exc:
        raise EngagementPolicyError("invalid callback endpoint") from exc
    network_ok = any(address in ipaddress.ip_network(value) for value in record["callback_cidrs"])
    port_ok = any(start <= port <= end for start, end in map(_parse_port_range, record["callback_port_ranges"]))
    return network_ok and port_ok


def permit_operation(
    *,
    workspace: str | Path,
    host_ids: list[str],
    category: str,
    impact_level: str,
    technique_family: str,
    technique: str,
    callback: str | None,
    summary: str,
    apply: bool,
    review_reference: str | None = None,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any] | None, dict[str, Any]]:
    if apply and not review_reference:
        raise EngagementPolicyError("recording an authorization requires an explicit operator review reference")
    if review_reference is not None:
        review_reference = _text(review_reference, "review_reference", 96)
    root = trace.validate_workspace(workspace)
    try:
        workspace_lifecycle.assert_target_actions_open(root)
    except workspace_lifecycle.WorkspaceLifecycleError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    _validate_artifact_handling(root)
    try:
        if operational_profile.workspace_profile(root) != operational_profile.CONTROLLED_ENGAGEMENT:
            raise EngagementPolicyError("permit requires operational profile controlled-engagement")
    except operational_profile.OperationalProfileError as exc:
        raise EngagementPolicyError(str(exc)) from exc
    policy = active_standing_authorization(root, now)
    if policy is None:
        raise EngagementPolicyError("workspace has no active standing authorization")
    if category == "denial-of-service" or category == "other":
        raise EngagementPolicyError("DoS and unclassified operations require separate authorization")
    if technique_family not in policy["technique_families"]:
        raise EngagementPolicyError("technique family is outside standing authorization")
    if category not in TECHNIQUE_FAMILY_CATEGORIES[technique_family] or category not in policy["categories"]:
        raise EngagementPolicyError("category is outside the selected technique family")
    if trace.IMPACT_RANK[impact_level] > trace.IMPACT_RANK[policy["maximum_impact"]]:
        raise EngagementPolicyError("operation impact exceeds standing authorization")
    known = trace.discover_active_host_ids(root)
    normalized_hosts = _unique(host_ids)
    if not normalized_hosts or any(host_id not in known for host_id in normalized_hosts):
        raise EngagementPolicyError("permit requires registered canonical host IDs")
    if policy["host_scope"] == "canonical-current" and any(host_id not in policy["host_ids"] for host_id in normalized_hosts):
        raise EngagementPolicyError("host is outside the activation-time scope")
    if technique_family == "security-control-change" and not policy["allow_security_control_changes"]:
        raise EngagementPolicyError("security-control changes are disabled")
    if technique_family == "destructive-mutation" and not policy["allow_destructive"]:
        raise EngagementPolicyError("destructive mutation is disabled")
    if technique_family == "bulk-data-access" and not policy["allow_bulk_data"]:
        raise EngagementPolicyError("bulk data access is disabled")
    if technique_family == "credential-spraying" and policy["credential_operations"] != "dump-reuse-spray":
        raise EngagementPolicyError("credential spraying is disabled")
    if technique_family in {"credential-access", "credential-reuse"} and policy["credential_operations"] == "none":
        raise EngagementPolicyError("credential operations are disabled")
    if category == "external-callback" and not _callback_allowed(policy, callback):
        raise EngagementPolicyError("callback endpoint is outside the standing allowlist")
    concrete = _text(technique, "technique", 240)
    description = _text(summary, "summary")
    authorization = None
    if apply:
        with _shared_policy_lock(root):
            current = active_standing_authorization(root, now)
            if current is None or current["standing_authorization_id"] != policy[
                "standing_authorization_id"
            ]:
                raise EngagementPolicyError("standing authorization is no longer active")
            _, authorization = trace.log_authorization(
                workspace=root,
                host_ids=normalized_hosts,
                categories=[category],
                maximum_impact=impact_level,
                techniques=[concrete],
                exclusions=policy["exclusions"],
                source=f"operator-review:{review_reference}",
                summary=description,
                standing_authorization_id=policy["standing_authorization_id"],
                now=now,
            )
    return root, authorization, policy


def end_policy(
    *, workspace: str | Path, event: str, note: str, apply: bool, now: datetime | None = None
) -> tuple[Path, dict[str, Any]]:
    if event != "revoked":
        raise EngagementPolicyError(
            "standing authorization supports only revoke; use cyber-workspace close "
            "with an operator-acknowledged close plan"
        )
    root = trace.validate_workspace(workspace)
    policy = active_standing_authorization(root, now)
    if policy is None:
        raise EngagementPolicyError("workspace has no active standing authorization")
    moment = now or datetime.now(UTC)
    record = dict(policy)
    record.update(
        standing_event_id=_identifier("SAE", moment),
        created_at_utc=_timestamp(moment),
        event=event,
        note=_text(note, "note"),
    )
    _validate_record(record, event)
    trace._reject_secret_content(root, [record["note"]])
    if apply:
        _append_locked(root, record, moment)
    return root, record


def _custom_configuration(args: argparse.Namespace) -> dict[str, Any]:
    if not args.technique_family or not args.category or args.maximum_impact is None:
        raise EngagementPolicyError("custom preset requires impact, categories, and technique families")
    if args.credential_operations is None or args.persistence_mode is None:
        raise EngagementPolicyError("custom preset requires credential and persistence modes")
    return {
        "maximum_impact": args.maximum_impact,
        "technique_families": args.technique_family,
        "categories": args.category,
        "credential_operations": args.credential_operations,
        "persistence_mode": args.persistence_mode,
        "allow_security_control_changes": args.allow_security_control_changes,
        "allow_destructive": args.allow_destructive,
        "allow_bulk_data": args.allow_bulk_data,
    }


def _print_matrix(record: dict[str, Any]) -> None:
    print(f"standing_authorization_id: {record['standing_authorization_id']}")
    print(f"preset: {record['preset']}")
    print(f"host_scope: {record['host_scope']}")
    print(f"maximum_impact: {record['maximum_impact']}")
    print(f"credential_operations: {record['credential_operations']}")
    print(f"persistence_mode: {record['persistence_mode']}")
    for field in ("allow_security_control_changes", "allow_destructive", "allow_bulk_data"):
        print(f"{field}: {'ON' if record[field] else 'OFF'}")
    print("denial_of_service: OFF")
    print(f"callback_cidrs: {','.join(record['callback_cidrs']) or 'none'}")
    print(f"callback_port_ranges: {','.join(record['callback_port_ranges']) or 'none'}")
    print(f"expires_at_utc: {record['expires_at_utc'] or 'revoke-or-close'}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cyber-policy")
    sub = root.add_subparsers(dest="command", required=True)
    activate = sub.add_parser("activate", help="preview or activate standing authorization")
    activate.add_argument("--workspace", required=True)
    activate.add_argument("--preset", choices=sorted(PRESETS), required=True)
    activate.add_argument("--host-scope", choices=sorted(HOST_SCOPES), default="canonical-current-and-future")
    activate.add_argument("--callback-cidr", action="append", default=[])
    activate.add_argument("--callback-port-range", action="append", default=[])
    activate.add_argument("--expires-at")
    activate.add_argument("--source", default="operator-cli")
    activate.add_argument("--summary", required=True)
    activate.add_argument("--maximum-impact", choices=trace.IMPACT_LEVELS)
    activate.add_argument("--technique-family", action="append", choices=sorted(TECHNIQUE_FAMILY_CATEGORIES))
    activate.add_argument("--category", action="append", choices=sorted(trace.AUTHORIZATION_CATEGORIES))
    activate.add_argument("--credential-operations", choices=sorted(CREDENTIAL_OPERATIONS))
    activate.add_argument("--persistence-mode", choices=sorted(PERSISTENCE_MODES))
    activate.add_argument("--allow-security-control-changes", action="store_true")
    activate.add_argument("--allow-destructive", action="store_true")
    activate.add_argument("--allow-bulk-data", action="store_true")
    activate.add_argument("--ack-critical-impact", action="store_true")
    activate.add_argument("--ack-security-control-changes", action="store_true")
    activate.add_argument("--ack-destructive", action="store_true")
    activate.add_argument("--ack-bulk-data", action="store_true")
    activate.add_argument("--apply", action="store_true")

    permit = sub.add_parser("permit", help="derive one exact authorization")
    permit.add_argument("--workspace", required=True)
    permit.add_argument("--host-id", action="append", required=True)
    permit.add_argument("--category", choices=sorted(trace.AUTHORIZATION_CATEGORIES), required=True)
    permit.add_argument("--impact-level", choices=trace.IMPACT_LEVELS, required=True)
    permit.add_argument("--technique-family", choices=sorted(TECHNIQUE_FAMILY_CATEGORIES), required=True)
    permit.add_argument("--technique", required=True)
    permit.add_argument("--callback")
    permit.add_argument("--summary", required=True)
    permit.add_argument("--review-reference", help="reference to the human review of this exact action")
    permit.add_argument("--apply", action="store_true")

    status = sub.add_parser("status", help="show standing authorization state")
    status.add_argument("--workspace", required=True)
    secret_display = sub.add_parser(
        "secret-display",
        help="preview or change the controlled-engagement secret-display switch",
    )
    secret_display.add_argument("action", choices=("enable", "disable"))
    secret_display.add_argument("--workspace", required=True)
    secret_display.add_argument("--reason", required=True)
    secret_display.add_argument("--ack-secret-display", action="store_true")
    secret_display.add_argument("--apply", action="store_true")
    revoke = sub.add_parser("revoke", help="preview or revoke standing authorization")
    revoke.add_argument("--workspace", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--apply", action="store_true")
    close = sub.add_parser("close", help="compatibility frontend for workspace target-action closure")
    close.add_argument("--workspace", required=True)
    close.add_argument("--reason", required=True)
    close.add_argument("--close-plan-sha256")
    close.add_argument("--ack-operator-requested-close", action="store_true")
    close.add_argument("--ack-retain-active-state", action="store_true")
    close.add_argument("--apply", action="store_true")
    return root


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "activate":
            configuration = _custom_configuration(args) if args.preset == "custom" else None
            workspace, record = build_activation(
                workspace=args.workspace,
                preset=args.preset,
                host_scope=args.host_scope,
                callback_cidrs=args.callback_cidr,
                callback_port_ranges=args.callback_port_range,
                expires_at_utc=args.expires_at,
                source=args.source,
                summary=args.summary,
                configuration=configuration,
                now=now,
            )
            if args.apply:
                required = [
                    (record["maximum_impact"] == "critical", args.ack_critical_impact, "--ack-critical-impact"),
                    (record["allow_security_control_changes"], args.ack_security_control_changes, "--ack-security-control-changes"),
                    (record["allow_destructive"], args.ack_destructive, "--ack-destructive"),
                    (record["allow_bulk_data"], args.ack_bulk_data, "--ack-bulk-data"),
                ]
                missing = [flag for enabled, acknowledged, flag in required if enabled and not acknowledged]
                if missing:
                    raise EngagementPolicyError("apply requires explicit acknowledgements: " + ", ".join(missing))
                apply_activation(workspace, record)
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            _print_matrix(record)
            return 0
        if args.command == "permit":
            _, authorization, policy = permit_operation(
                workspace=args.workspace,
                host_ids=args.host_id,
                category=args.category,
                impact_level=args.impact_level,
                technique_family=args.technique_family,
                technique=args.technique,
                callback=args.callback,
                summary=args.summary,
                apply=args.apply,
                review_reference=args.review_reference,
                now=now,
            )
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"standing_authorization_id: {policy['standing_authorization_id']}")
            print(f"authorization_id: {authorization['authorization_id'] if authorization else 'pending'}")
            return 0
        if args.command == "status":
            root = trace.validate_workspace(args.workspace)
            artifact_mode = artifact_handling.workspace_mode(root)
            policy = active_standing_authorization(root, now)
            print(f"status: {'active' if policy else 'inactive'}")
            print(
                "workspace_target_actions: "
                f"{'closed' if workspace_lifecycle.is_closed(root) else 'open'}"
            )
            print(f"artifact_handling: {artifact_mode}")
            if policy:
                _print_matrix(policy)
            display_enabled = secret_display_enabled(root, now)
            print(
                "allow_secret_display: "
                f"{'ON' if display_enabled else 'OFF'}"
            )
            print(
                "secret_display_surfaces: "
                + (
                    ",".join(SECRET_DISPLAY_SURFACES)
                    if display_enabled
                    else "none"
                )
            )
            print(f"path: {STANDING_AUTHORIZATION_LEDGER}")
            print(f"secret_display_path: {SECRET_DISPLAY_LEDGER}")
            return 0
        if args.command == "secret-display":
            _, record = set_secret_display(
                workspace=args.workspace,
                enabled=args.action == "enable",
                reason=args.reason,
                acknowledged=args.ack_secret_display,
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            print(
                f"standing_authorization_id: {record['standing_authorization_id']}"
            )
            print(
                "allow_secret_display: "
                f"{'ON' if record['event'] == 'enabled' else 'OFF'}"
            )
            print("secret_display_surfaces: " + ",".join(record["surfaces"]))
            print(f"path: {SECRET_DISPLAY_LEDGER}")
            return 0
        if args.command == "close":
            plan = workspace_lifecycle.build_close_plan(args.workspace)
            if args.apply:
                workspace_lifecycle.apply_close(
                    plan,
                    supplied_plan_sha256=args.close_plan_sha256 or "",
                    operator_acknowledged=args.ack_operator_requested_close,
                    retain_active_state=args.ack_retain_active_state,
                    reason=args.reason,
                    now=now,
                )
            workspace_lifecycle.print_close_plan(plan, apply=args.apply)
            return 0
        if args.command == "revoke":
            _, record = end_policy(
                workspace=args.workspace,
                event="revoked",
                note=args.reason,
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"standing_authorization_id: {record['standing_authorization_id']}")
            print(f"event: {record['event']}")
            return 0
        raise EngagementPolicyError("unsupported command")
    except (
        artifact_handling.ArtifactHandlingError,
        EngagementPolicyError,
        workspace_lifecycle.WorkspaceLifecycleError,
        trace.TraceError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
