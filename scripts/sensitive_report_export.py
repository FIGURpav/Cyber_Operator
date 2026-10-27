#!/usr/bin/env python3
"""Render explicitly authorized plaintext-secret engagement report bundles."""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import shlex
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

if __package__:
    from . import (
        credential_intake,
        engagement_policy,
        operational_profile,
        report_contract,
    )
    from . import operational_trace as trace
else:
    import credential_intake  # type: ignore[no-redef]
    import engagement_policy  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import operational_trace as trace  # type: ignore[no-redef]
    import report_contract  # type: ignore[no-redef]

POLICY_LEDGER = "plaintext_report_policy.jsonl"
EXPORT_LEDGER = "plaintext_report_exports.jsonl"
REPORT_NAME = "STEPS_TO_REPRODUCTION_PRIVATE.md"
MANIFEST_NAME = "EXPORT_MANIFEST.json"
DISPOSAL_NAME = "DISPOSAL.md"

MAX_TEMPLATE_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
MAX_TOTAL_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_RENDERED_BYTES = 32 * 1024 * 1024

POLICY_EVENT_RE = re.compile(r"^SRPE-\d{8}T\d{12}Z$")
EXPORT_EVENT_RE = re.compile(r"^SRXE-\d{8}T\d{12}Z$")
EXPORT_ID_RE = re.compile(r"^SRX-\d{8}T\d{12}Z$")
LOOT_ID_RE = re.compile(r"^LOOT-\d{8}T\d{12}Z$")
PLACEHOLDER_RE = re.compile(
    r"\{\{CRED:"
    r"(CRED-\d{8}T\d{12}Z):"
    r"(secret|username|host_id|service|secret_type|url|realm):"
    r"(raw|shell|json|powershell|url|base64-raw|base64-shell)"
    r"\}\}"
)
LOOT_PLACEHOLDER_RE = re.compile(
    r"\{\{LOOT:"
    r"(LOOT-\d{8}T\d{12}Z):"
    r"(value_text|username|host_id|category|label|source):"
    r"(raw|shell|json|powershell|url|base64-raw|base64-shell)"
    r"\}\}"
)

POLICY_FIELDS = (
    "schema_version",
    "policy_event_id",
    "created_at_utc",
    "standing_authorization_id",
    "event",
    "destination_root",
    "reason",
)
EXPORT_FIELDS = (
    "schema_version",
    "export_event_id",
    "created_at_utc",
    "export_id",
    "event",
    "standing_authorization_id",
    "destination",
    "template",
    "credential_ids",
    "loot_ids",
    "report_sha256",
    "payloads",
    "contains_plaintext_secrets",
    "note",
)
BLOCKED_SYNC_NAMES = {
    "dropbox",
    "onedrive",
    "google drive",
    "google drive streaming",
    "icloud drive",
}


class SensitiveReportError(RuntimeError):
    """A deterministic error that must never reproduce a secret value."""


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise SensitiveReportError("ledger contains an invalid timestamp") from exc


def _text(value: str, label: str, maximum: int = 1024) -> str:
    normalized = value.strip()
    if not normalized:
        raise SensitiveReportError(f"{label} must not be empty")
    if len(normalized) > maximum:
        raise SensitiveReportError(f"{label} is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise SensitiveReportError(f"{label} contains a prohibited control character")
    return normalized


def _is_within(candidate: Path, boundary: Path) -> bool:
    try:
        candidate.relative_to(boundary)
        return True
    except ValueError:
        return False


def _existing_chain(path: Path) -> list[Path]:
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    chain.reverse()
    return chain


def _inspect_path_chain(path: Path, *, allow_missing_leaf: bool) -> None:
    chain = _existing_chain(path)
    missing_seen = False
    for index, component in enumerate(chain):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and index == len(chain) - 1:
                missing_seen = True
                continue
            raise SensitiveReportError("destination path has a missing ancestor") from None
        if missing_seen:
            raise SensitiveReportError("destination path changed during validation")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SensitiveReportError(
                "destination path components must be real non-symlink directories"
            )


def _git_boundary(path: Path) -> Path | None:
    current = path
    while True:
        marker = current / ".git"
        if marker.exists() or marker.is_symlink():
            return current
        if current.parent == current:
            return None
        current = current.parent


def validate_destination_root(
    workspace: Path, destination_text: str, *, allow_create: bool
) -> tuple[Path, bool]:
    supplied = Path(destination_text).expanduser()
    if not supplied.is_absolute() or ".." in supplied.parts:
        raise SensitiveReportError("destination root must be an absolute path without '..'")
    destination = supplied.absolute()
    repository = Path(__file__).resolve().parents[1]
    if (
        _is_within(destination, workspace)
        or _is_within(workspace, destination)
        or _is_within(destination, repository)
        or _is_within(repository, destination)
    ):
        raise SensitiveReportError(
            "destination root must be separate from the canonical workspace and reusable repository"
        )
    if any(component.casefold() in BLOCKED_SYNC_NAMES for component in destination.parts):
        raise SensitiveReportError("destination root must not use a known cloud-sync path")
    exists = destination.exists() or destination.is_symlink()
    _inspect_path_chain(destination, allow_missing_leaf=allow_create and not exists)
    if exists:
        metadata = destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SensitiveReportError("destination root must be a real directory")
        if metadata.st_uid != os.geteuid():
            raise SensitiveReportError("destination root must be owned by the effective user")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SensitiveReportError("destination root must use mode 0700")
    elif not allow_create:
        raise SensitiveReportError("destination root does not exist")
    else:
        parent = destination.parent
        metadata = parent.lstat()
        if metadata.st_uid != os.geteuid():
            raise SensitiveReportError("destination parent must be owned by the effective user")
    boundary = _git_boundary(destination if exists else destination.parent)
    if boundary is not None:
        raise SensitiveReportError("destination root must not be inside a Git work tree")
    return destination, exists


def _validate_private_ledger(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SensitiveReportError(f"{path.name} must be a real regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid():
        raise SensitiveReportError(f"{path.name} must be owner-only mode 0600")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    _validate_private_ledger(path)
    if not path.exists():
        return []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SensitiveReportError(f"cannot read {path.name}") from exc
    if raw and not raw.endswith(b"\n"):
        raise SensitiveReportError(f"{path.name} is not newline terminated")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SensitiveReportError(
                f"{path.name} line {number} contains invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise SensitiveReportError(f"{path.name} line {number} must be an object")
        records.append(value)
    return records


def _validate_policy_record(record: dict[str, Any], source: str) -> None:
    if tuple(record) != POLICY_FIELDS:
        raise SensitiveReportError(f"{source} has incorrect fields")
    if record["schema_version"] != "1.0":
        raise SensitiveReportError(f"{source} has unsupported schema version")
    created = _parse_timestamp(record["created_at_utc"])
    if record["policy_event_id"] != _identifier("SRPE", created):
        raise SensitiveReportError(f"{source} has malformed event identity")
    if POLICY_EVENT_RE.fullmatch(record["policy_event_id"]) is None:
        raise SensitiveReportError(f"{source} has malformed event identity")
    if engagement_policy.STANDING_ID_RE.fullmatch(record["standing_authorization_id"]) is None:
        raise SensitiveReportError(f"{source} has malformed standing authorization")
    if record["event"] not in {"enabled", "disabled"}:
        raise SensitiveReportError(f"{source} has unsupported lifecycle state")
    if not isinstance(record["destination_root"], str):
        raise SensitiveReportError(f"{source} has invalid destination root")
    _text(record["reason"], "reason")


def load_policy_events(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / POLICY_LEDGER
    records = _read_jsonl(path)
    standing_ids = {
        item["standing_authorization_id"]
        for item in engagement_policy.load_standing_authorizations(workspace)
        if item["event"] == "activated"
    }
    seen: set[str] = set()
    latest: dict[str, dict[str, Any]] = {}
    for number, record in enumerate(records, start=1):
        _validate_policy_record(record, f"{path.name} line {number}")
        event_id = record["policy_event_id"]
        standing_id = record["standing_authorization_id"]
        if event_id in seen:
            raise SensitiveReportError("plaintext-report policy duplicates an event ID")
        if standing_id not in standing_ids:
            raise SensitiveReportError(
                "plaintext-report policy references an unknown standing authorization"
            )
        previous = latest.get(standing_id)
        if previous is None and record["event"] != "enabled":
            raise SensitiveReportError("plaintext-report policy must begin with enabled")
        if previous is not None:
            if previous["event"] == record["event"]:
                raise SensitiveReportError("plaintext-report policy repeats effective state")
            if previous["destination_root"] != record["destination_root"]:
                raise SensitiveReportError("plaintext-report policy changed destination root")
        seen.add(event_id)
        latest[standing_id] = record
    return records


def active_policy(
    workspace: Path, now: datetime | None = None
) -> dict[str, Any] | None:
    standing = engagement_policy.active_standing_authorization(workspace, now)
    if standing is None:
        return None
    matching = [
        record
        for record in load_policy_events(workspace)
        if record["standing_authorization_id"]
        == standing["standing_authorization_id"]
    ]
    if not matching or matching[-1]["event"] != "enabled":
        return None
    return matching[-1]


def _append_record(path: Path, record: dict[str, Any]) -> None:
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SensitiveReportError(f"{path.name} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid():
            raise SensitiveReportError(f"{path.name} must be owner-only mode 0600")
        encoded = (
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode()
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def set_policy(
    *,
    workspace: str | Path,
    enabled: bool,
    destination_root: str | None,
    reason: str,
    acknowledged_plaintext: bool,
    acknowledged_duplication: bool,
    acknowledged_retention: bool,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], bool]:
    try:
        root = trace.validate_workspace(workspace)
        operational_profile.workspace_profile(root)
    except (trace.TraceError, operational_profile.OperationalProfileError) as exc:
        raise SensitiveReportError(str(exc)) from exc
    standing = engagement_policy.active_standing_authorization(root, now)
    if standing is None:
        raise SensitiveReportError("workspace has no active standing authorization")
    if not engagement_policy.secret_display_enabled(root, now):
        raise SensitiveReportError("plaintext report export requires secret-display ON")
    previous = [
        record
        for record in load_policy_events(root)
        if record["standing_authorization_id"]
        == standing["standing_authorization_id"]
    ]
    current_enabled = bool(previous and previous[-1]["event"] == "enabled")
    if current_enabled == enabled:
        raise SensitiveReportError(
            "plaintext-report policy is already " + ("enabled" if enabled else "disabled")
        )
    if enabled:
        if destination_root is None:
            raise SensitiveReportError("enable requires --destination-root")
        destination, existed = validate_destination_root(
            root, destination_root, allow_create=True
        )
        if apply and not all(
            (acknowledged_plaintext, acknowledged_duplication, acknowledged_retention)
        ):
            raise SensitiveReportError(
                "enable apply requires --ack-plaintext-report, "
                "--ack-credential-duplication and --ack-local-retention"
            )
    else:
        if destination_root is not None:
            raise SensitiveReportError("disable does not accept --destination-root")
        if not previous:
            raise SensitiveReportError("plaintext-report policy has no active history")
        destination = Path(previous[-1]["destination_root"])
        existed = True
    normalized_reason = _text(reason, "reason")
    try:
        trace._reject_secret_content(root, [normalized_reason, str(destination)])
    except trace.TraceError as exc:
        raise SensitiveReportError(str(exc)) from exc
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    record = {
        "schema_version": "1.0",
        "policy_event_id": _identifier("SRPE", moment),
        "created_at_utc": _timestamp(moment),
        "standing_authorization_id": standing["standing_authorization_id"],
        "event": "enabled" if enabled else "disabled",
        "destination_root": str(destination),
        "reason": normalized_reason,
    }
    _validate_policy_record(record, "plaintext-report policy event")
    created_root = False
    if apply:
        try:
            if enabled and not existed:
                destination.mkdir(mode=0o700)
                created_root = True
            validate_destination_root(root, str(destination), allow_create=False)
            with engagement_policy._shared_policy_lock(root):
                current_standing = engagement_policy.active_standing_authorization(root, now)
                if (
                    current_standing is None
                    or current_standing["standing_authorization_id"]
                    != standing["standing_authorization_id"]
                    or not engagement_policy.secret_display_enabled(root, now)
                ):
                    raise SensitiveReportError(
                        "standing authorization or secret-display is no longer active"
                    )
                current = active_policy(root, now)
                if enabled and current is not None:
                    raise SensitiveReportError(
                        "plaintext-report policy became enabled concurrently"
                    )
                if not enabled and current is None:
                    raise SensitiveReportError("plaintext-report policy is no longer active")
                _append_record(root / POLICY_LEDGER, record)
                load_policy_events(root)
        except BaseException:
            if created_root:
                try:
                    destination.rmdir()
                except OSError:
                    pass
            raise
    return root, record, created_root


def _credentials(workspace: Path) -> dict[str, dict[str, Any]]:
    handles = credential_intake._open_workspace(str(workspace))
    try:
        hosts = credential_intake._discover_hosts(handles.workspace_fd)
        snapshot = credential_intake._read_ledger(
            handles.credentials_fd, credential_intake._known_host_ids(hosts)
        )
        return {record["credential_id"]: record for record in snapshot.records}
    except credential_intake.CredentialIntakeError as exc:
        raise SensitiveReportError(str(exc)) from exc
    finally:
        handles.close()


def _loot(workspace: Path) -> dict[str, dict[str, Any]]:
    path = workspace / "loot.jsonl"
    records = _read_jsonl(path)
    known_hosts = trace.discover_host_ids(workspace)
    result: dict[str, dict[str, Any]] = {}
    expected_fields = (
        "schema_version",
        "loot_id",
        "timestamp_utc",
        "host_id",
        "category",
        "label",
        "source",
        "username",
        "value_sha256",
        "value_text",
    )
    for number, record in enumerate(records, start=1):
        if tuple(record) != expected_fields:
            raise SensitiveReportError(f"loot.jsonl line {number} has incorrect fields")
        loot_id = record["loot_id"]
        if not isinstance(loot_id, str) or LOOT_ID_RE.fullmatch(loot_id) is None:
            raise SensitiveReportError(f"loot.jsonl line {number} has malformed identity")
        if loot_id in result:
            raise SensitiveReportError("loot ledger contains a duplicate ID")
        if record["schema_version"] != "1.0" or record["host_id"] not in known_hosts:
            raise SensitiveReportError(f"loot.jsonl line {number} has invalid scope")
        value = record["value_text"]
        digest = record["value_sha256"]
        if (
            not isinstance(value, str)
            or not isinstance(digest, str)
            or hashlib.sha256(value.encode()).hexdigest() != digest
        ):
            raise SensitiveReportError(f"loot.jsonl line {number} has invalid value integrity")
        result[loot_id] = record
    return result


def _real_input_file(workspace: Path, supplied: str, *, maximum: int) -> tuple[Path, bytes]:
    path = Path(supplied).expanduser()
    path = path if path.is_absolute() else Path.cwd() / path
    path = path.absolute()
    if ".." in Path(supplied).parts or not _is_within(path, workspace):
        raise SensitiveReportError("input files must remain inside the canonical workspace")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SensitiveReportError("input file does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SensitiveReportError("input files must be real non-symlink regular files")
    if metadata.st_size > maximum:
        raise SensitiveReportError("input file exceeds its size limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SensitiveReportError("cannot read input file") from exc
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SensitiveReportError("input file changed during verified read")
    return path, raw


def _decode_base64(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise SensitiveReportError("base64 credential value is not canonical UTF-8 data") from exc


def _render_value(value: str, renderer: str) -> str:
    if renderer.startswith("base64-"):
        value = _decode_base64(value)
        renderer = renderer.removeprefix("base64-")
    if renderer == "raw":
        return value
    if renderer == "shell":
        return shlex.quote(value)
    if renderer == "json":
        return json.dumps(value, ensure_ascii=False)
    if renderer == "powershell":
        return "'" + value.replace("'", "''") + "'"
    if renderer == "url":
        return quote(value, safe="")
    raise SensitiveReportError("template uses an unsupported renderer")


def _parse_template(
    workspace: Path, template_raw: bytes
) -> tuple[
    str,
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    list[str],
    list[str],
]:
    try:
        template = template_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SensitiveReportError("template must be UTF-8") from exc
    credential_slots = [match.groups() for match in PLACEHOLDER_RE.finditer(template)]
    loot_slots = [match.groups() for match in LOOT_PLACEHOLDER_RE.finditer(template)]
    if not credential_slots and not loot_slots:
        raise SensitiveReportError(
            "template must contain at least one typed CRED or LOOT placeholder"
        )
    remainder = PLACEHOLDER_RE.sub("", template)
    remainder = LOOT_PLACEHOLDER_RE.sub("", remainder)
    if "{{CRED:" in remainder or "{{LOOT:" in remainder:
        raise SensitiveReportError("template contains a malformed sensitive placeholder")
    records = _credentials(workspace)
    loot_records = _loot(workspace)
    if any(
        isinstance(record.get("secret"), str)
        and record["secret"]
        and record["secret"] in template
        for record in records.values()
    ):
        raise SensitiveReportError("template contains a stored credential value")
    if any(
        isinstance(record.get("value_text"), str)
        and record["value_text"]
        and record["value_text"] in template
        for record in loot_records.values()
    ):
        raise SensitiveReportError("template contains a stored loot value")
    try:
        report_contract.reject_secrets(workspace, remainder)
    except report_contract.ReportContractError as exc:
        raise SensitiveReportError(str(exc)) from exc
    credential_ids = list(dict.fromkeys(slot[0] for slot in credential_slots))
    loot_ids = list(dict.fromkeys(slot[0] for slot in loot_slots))
    return template, credential_slots, loot_slots, credential_ids, loot_ids


def _render_template(
    template: str,
    credential_slots: list[tuple[str, str, str]],
    loot_slots: list[tuple[str, str, str]],
    credentials: dict[str, dict[str, Any]],
    loot: dict[str, dict[str, Any]],
) -> str:
    for credential_id, field, _ in credential_slots:
        record = credentials.get(credential_id)
        if record is None:
            raise SensitiveReportError("template references an unknown credential ID")
        if record.get(field) is None:
            raise SensitiveReportError("template references unavailable credential metadata")

    def replacement(match: re.Match[str]) -> str:
        credential_id, field, renderer = match.groups()
        value = credentials[credential_id][field]
        if not isinstance(value, str):
            raise SensitiveReportError("credential field is not renderable text")
        return _render_value(value, renderer)

    for loot_id, field, _ in loot_slots:
        record = loot.get(loot_id)
        if record is None:
            raise SensitiveReportError("template references an unknown loot ID")
        if record.get(field) is None:
            raise SensitiveReportError("template references unavailable loot metadata")

    def loot_replacement(match: re.Match[str]) -> str:
        loot_id, field, renderer = match.groups()
        value = loot[loot_id][field]
        if not isinstance(value, str):
            raise SensitiveReportError("loot field is not renderable text")
        return _render_value(value, renderer)

    rendered = PLACEHOLDER_RE.sub(replacement, template)
    rendered = LOOT_PLACEHOLDER_RE.sub(loot_replacement, rendered)
    if "{{CRED:" in rendered or "{{LOOT:" in rendered:
        raise SensitiveReportError("rendered report contains an unresolved placeholder")
    if len(rendered.encode("utf-8")) > MAX_RENDERED_BYTES:
        raise SensitiveReportError("rendered report exceeds its size limit")
    return rendered


def _payload_plan(
    workspace: Path, supplied: list[str]
) -> list[tuple[str, bytes, str]]:
    planned: list[tuple[str, bytes, str]] = []
    names: set[str] = set()
    total = 0
    for value in supplied:
        path, raw = _real_input_file(workspace, value, maximum=MAX_PAYLOAD_BYTES)
        if path.name in names:
            raise SensitiveReportError("payload filenames must be unique")
        names.add(path.name)
        total += len(raw)
        if total > MAX_TOTAL_PAYLOAD_BYTES:
            raise SensitiveReportError("payload set exceeds its total size limit")
        planned.append((path.name, raw, hashlib.sha256(raw).hexdigest()))
    return planned


def _write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_temporary_bundle(path: Path) -> None:
    """Remove only the exact unpublished objects created by this exporter."""
    try:
        payload_dir = path / "payloads"
        if payload_dir.exists() and not payload_dir.is_symlink():
            for item in payload_dir.iterdir():
                metadata = item.lstat()
                if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                    item.unlink()
            payload_dir.rmdir()
        for name in (REPORT_NAME, MANIFEST_NAME, DISPOSAL_NAME):
            item = path / name
            try:
                metadata = item.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                item.unlink()
        path.rmdir()
    except OSError:
        pass


def _validate_export_record(record: dict[str, Any], source: str) -> None:
    if tuple(record) != EXPORT_FIELDS:
        raise SensitiveReportError(f"{source} has incorrect fields")
    if record["schema_version"] != "1.0":
        raise SensitiveReportError(f"{source} has unsupported schema version")
    created = _parse_timestamp(record["created_at_utc"])
    if record["export_event_id"] != _identifier("SRXE", created):
        raise SensitiveReportError(f"{source} has malformed event identity")
    if EXPORT_EVENT_RE.fullmatch(record["export_event_id"]) is None:
        raise SensitiveReportError(f"{source} has malformed event identity")
    if EXPORT_ID_RE.fullmatch(record["export_id"]) is None:
        raise SensitiveReportError(f"{source} has malformed export identity")
    if record["event"] not in {"planned", "verified", "failed"}:
        raise SensitiveReportError(f"{source} has unsupported lifecycle state")
    if engagement_policy.STANDING_ID_RE.fullmatch(record["standing_authorization_id"]) is None:
        raise SensitiveReportError(f"{source} has malformed standing authorization")
    destination = record["destination"]
    if (
        not isinstance(destination, str)
        or not Path(destination).is_absolute()
        or Path(destination).name != record["export_id"]
        or ".." in Path(destination).parts
    ):
        raise SensitiveReportError(f"{source} has malformed destination")
    template = record["template"]
    if (
        not isinstance(template, str)
        or Path(template).is_absolute()
        or ".." in Path(template).parts
    ):
        raise SensitiveReportError(f"{source} has malformed template reference")
    if (
        not isinstance(record["report_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["report_sha256"]) is None
    ):
        raise SensitiveReportError(f"{source} has malformed report hash")
    if not isinstance(record["credential_ids"], list) or not isinstance(
        record["loot_ids"], list
    ):
        raise SensitiveReportError(f"{source} has invalid sensitive references")
    if not record["credential_ids"] and not record["loot_ids"]:
        raise SensitiveReportError(f"{source} requires sensitive references")
    if any(
        not isinstance(value, str)
        or credential_intake.CREDENTIAL_ID_RE.fullmatch(value) is None
        for value in record["credential_ids"]
    ):
        raise SensitiveReportError(f"{source} has malformed credential references")
    if any(
        not isinstance(value, str) or LOOT_ID_RE.fullmatch(value) is None
        for value in record["loot_ids"]
    ):
        raise SensitiveReportError(f"{source} has malformed loot references")
    if len(record["credential_ids"]) != len(set(record["credential_ids"])) or len(
        record["loot_ids"]
    ) != len(set(record["loot_ids"])):
        raise SensitiveReportError(f"{source} duplicates sensitive references")
    if not isinstance(record["payloads"], list):
        raise SensitiveReportError(f"{source} has invalid payload metadata")
    payload_names: set[str] = set()
    for payload in record["payloads"]:
        if not isinstance(payload, dict) or tuple(payload) != (
            "name",
            "size_bytes",
            "sha256",
        ):
            raise SensitiveReportError(f"{source} has invalid payload metadata")
        name = payload["name"]
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name in payload_names
            or not isinstance(payload["size_bytes"], int)
            or payload["size_bytes"] < 0
            or not isinstance(payload["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["sha256"]) is None
        ):
            raise SensitiveReportError(f"{source} has invalid payload metadata")
        payload_names.add(name)
    if record["contains_plaintext_secrets"] is not True:
        raise SensitiveReportError(f"{source} has invalid sensitivity classification")
    _text(record["note"], "export note")


def load_export_events(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / EXPORT_LEDGER
    records = _read_jsonl(path)
    seen_events: set[str] = set()
    latest: dict[str, dict[str, Any]] = {}
    for number, record in enumerate(records, start=1):
        _validate_export_record(record, f"{path.name} line {number}")
        event_id = record["export_event_id"]
        export_id = record["export_id"]
        if event_id in seen_events:
            raise SensitiveReportError("plaintext export ledger duplicates an event ID")
        previous = latest.get(export_id)
        if previous is None and record["event"] != "planned":
            raise SensitiveReportError("plaintext export lifecycle must begin with planned")
        if previous is not None:
            if previous["event"] != "planned" or record["event"] == "planned":
                raise SensitiveReportError("plaintext export lifecycle is already terminal")
            stable = set(EXPORT_FIELDS) - {
                "export_event_id",
                "created_at_utc",
                "event",
                "note",
            }
            if any(previous[field] != record[field] for field in stable):
                raise SensitiveReportError("plaintext export lifecycle changed stable fields")
        seen_events.add(event_id)
        latest[export_id] = record
    return records


def render_bundle(
    *,
    workspace: str | Path,
    template_file: str,
    title: str,
    payload_files: list[str],
    apply: bool,
    now: datetime | None = None,
) -> tuple[str, Path | None, str, list[str], list[str]]:
    try:
        root = trace.validate_workspace(workspace)
    except trace.TraceError as exc:
        raise SensitiveReportError(str(exc)) from exc
    policy = active_policy(root, now)
    if policy is None:
        raise SensitiveReportError("plaintext-report policy is not active")
    if not engagement_policy.secret_display_enabled(root, now):
        raise SensitiveReportError("secret-display is not active")
    destination_root, _ = validate_destination_root(
        root, policy["destination_root"], allow_create=False
    )
    template_path, template_raw = _real_input_file(
        root, template_file, maximum=MAX_TEMPLATE_BYTES
    )
    template, credential_slots, loot_slots, credential_ids, loot_ids = _parse_template(
        root, template_raw
    )
    records = _credentials(root)
    loot_records = _loot(root)
    rendered = _render_template(
        template, credential_slots, loot_slots, records, loot_records
    )
    payloads = _payload_plan(root, payload_files)
    normalized_title = _text(title, "title", maximum=256)
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    export_id = _identifier("SRX", moment)
    final = destination_root / export_id
    report_bytes = rendered.encode("utf-8")
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    payload_metadata = [
        {"name": name, "size_bytes": len(raw), "sha256": digest}
        for name, raw, digest in payloads
    ]
    template_relative = str(template_path.relative_to(root))
    destination_text = str(final)
    base = {
        "schema_version": "1.0",
        "export_event_id": "",
        "created_at_utc": "",
        "export_id": export_id,
        "event": "",
        "standing_authorization_id": policy["standing_authorization_id"],
        "destination": destination_text,
        "template": template_relative,
        "credential_ids": credential_ids,
        "loot_ids": loot_ids,
        "report_sha256": report_sha256,
        "payloads": payload_metadata,
        "contains_plaintext_secrets": True,
        "note": "",
    }
    if not apply:
        return export_id, None, report_sha256, credential_ids, loot_ids
    if final.exists() or final.is_symlink():
        raise SensitiveReportError("export destination already exists")
    temporary = destination_root / f".{export_id}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise SensitiveReportError("temporary export destination already exists")
    temporary.mkdir(mode=0o700)
    planned_time = moment
    planned = dict(base)
    planned.update(
        export_event_id=_identifier("SRXE", planned_time),
        created_at_utc=_timestamp(planned_time),
        event="planned",
        note="Authorized private plaintext report export planned",
    )
    _validate_export_record(planned, "plaintext export planned event")
    planned_written = False
    try:
        _write_exclusive(temporary / REPORT_NAME, report_bytes)
        payload_dir = temporary / "payloads"
        if payloads:
            payload_dir.mkdir(mode=0o700)
            for name, raw, _ in payloads:
                _write_exclusive(payload_dir / name, raw)
        manifest = {
            "schema_version": "1.0",
            "export_id": export_id,
            "title": normalized_title,
            "standing_authorization_id": policy["standing_authorization_id"],
            "template": template_relative,
            "credential_ids": credential_ids,
            "loot_ids": loot_ids,
            "report": {
                "name": REPORT_NAME,
                "size_bytes": len(report_bytes),
                "sha256": report_sha256,
            },
            "payloads": payload_metadata,
            "contains_plaintext_secrets": True,
            "classification": "CYBER_PRIVATE_PLAINTEXT_CREDENTIAL_REPORT",
        }
        _write_exclusive(
            temporary / MANIFEST_NAME,
            (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        )
        disposal = (
            "# Sensitive export disposal\n\n"
            f"Export: `{export_id}`\n\n"
            "This bundle contains plaintext credentials. Retain only for the "
            "authorized Cyber-Operator reporting lifecycle. Disposal requires a direct "
            "operator decision and exact-path removal of this bundle.\n"
        ).encode()
        _write_exclusive(temporary / DISPOSAL_NAME, disposal)
        with engagement_policy._shared_policy_lock(root):
            current = active_policy(root, now)
            if (
                current is None
                or current["standing_authorization_id"]
                != policy["standing_authorization_id"]
                or current["destination_root"] != policy["destination_root"]
                or not engagement_policy.secret_display_enabled(root, now)
            ):
                raise SensitiveReportError(
                    "plaintext-report authorization changed before publication"
                )
            _append_record(root / EXPORT_LEDGER, planned)
            planned_written = True
            load_export_events(root)
            temporary.rename(final)
            verified_time = moment + timedelta(microseconds=1)
            verified = dict(base)
            verified.update(
                export_event_id=_identifier("SRXE", verified_time),
                created_at_utc=_timestamp(verified_time),
                event="verified",
                note="Bundle published with owner-only permissions and exact hashes",
            )
            _validate_export_record(verified, "plaintext export verified event")
            _append_record(root / EXPORT_LEDGER, verified)
            load_export_events(root)
        return export_id, final, report_sha256, credential_ids, loot_ids
    except (OSError, SensitiveReportError):
        if planned_written:
            failed_time = moment + timedelta(microseconds=1)
            failed = dict(base)
            failed.update(
                export_event_id=_identifier("SRXE", failed_time),
                created_at_utc=_timestamp(failed_time),
                event="failed",
                note="Bundle publication failed; inspect exact destination privately",
            )
            try:
                _append_record(root / EXPORT_LEDGER, failed)
            finally:
                if temporary.exists() and not temporary.is_symlink():
                    _cleanup_temporary_bundle(temporary)
        elif temporary.exists() and not temporary.is_symlink():
            _cleanup_temporary_bundle(temporary)
        raise


def verify_bundle(workspace: str | Path, export_id: str) -> tuple[Path, str]:
    try:
        root = trace.validate_workspace(workspace)
    except trace.TraceError as exc:
        raise SensitiveReportError(str(exc)) from exc
    if EXPORT_ID_RE.fullmatch(export_id) is None:
        raise SensitiveReportError("invalid export ID")
    events = [
        record for record in load_export_events(root) if record["export_id"] == export_id
    ]
    if not events or events[-1]["event"] != "verified":
        raise SensitiveReportError("export does not have a verified lifecycle")
    record = events[-1]
    destination = Path(record["destination"])
    policies = [
        item
        for item in load_policy_events(root)
        if item["standing_authorization_id"] == record["standing_authorization_id"]
    ]
    if not policies:
        raise SensitiveReportError("export has no matching plaintext-report policy")
    policy_root, _ = validate_destination_root(
        root, policies[0]["destination_root"], allow_create=False
    )
    if destination != policy_root / export_id:
        raise SensitiveReportError("export destination escapes its authorized root")
    metadata = destination.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SensitiveReportError("export destination is not a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
        raise SensitiveReportError("export directory permissions are not owner-only")
    report_path = destination / REPORT_NAME
    report_metadata = report_path.lstat()
    if (
        stat.S_ISLNK(report_metadata.st_mode)
        or not stat.S_ISREG(report_metadata.st_mode)
        or stat.S_IMODE(report_metadata.st_mode) != 0o600
        or report_metadata.st_uid != os.geteuid()
    ):
        raise SensitiveReportError("rendered report permissions are invalid")
    report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    if report_digest != record["report_sha256"]:
        raise SensitiveReportError("rendered report hash does not match the ledger")
    manifest_path = destination / MANIFEST_NAME
    manifest_metadata = manifest_path.lstat()
    if (
        stat.S_ISLNK(manifest_metadata.st_mode)
        or not stat.S_ISREG(manifest_metadata.st_mode)
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
        or manifest_metadata.st_uid != os.geteuid()
    ):
        raise SensitiveReportError("export manifest permissions are invalid")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SensitiveReportError("export manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("export_id") != export_id
        or manifest.get("credential_ids") != record["credential_ids"]
        or manifest.get("loot_ids") != record["loot_ids"]
        or manifest.get("report", {}).get("sha256") != report_digest
        or manifest.get("contains_plaintext_secrets") is not True
    ):
        raise SensitiveReportError("export manifest does not match the ledger")
    for payload in record["payloads"]:
        path = destination / "payloads" / payload["name"]
        payload_metadata = path.lstat()
        if (
            stat.S_ISLNK(payload_metadata.st_mode)
            or not stat.S_ISREG(payload_metadata.st_mode)
            or stat.S_IMODE(payload_metadata.st_mode) != 0o600
            or payload_metadata.st_size != payload["size_bytes"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != payload["sha256"]
        ):
            raise SensitiveReportError("payload verification failed")
    return destination, report_digest


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Manage explicitly authorized plaintext-secret report exports."
    )
    sub = root.add_subparsers(dest="command", required=True)
    policy = sub.add_parser("policy", help="manage the plaintext-report capability")
    policy_sub = policy.add_subparsers(dest="policy_action", required=True)
    status = policy_sub.add_parser("status")
    status.add_argument("--workspace", required=True)
    for action in ("enable", "disable"):
        item = policy_sub.add_parser(action)
        item.add_argument("--workspace", required=True)
        if action == "enable":
            item.add_argument("--destination-root", required=True)
            item.add_argument("--ack-plaintext-report", action="store_true")
            item.add_argument("--ack-credential-duplication", action="store_true")
            item.add_argument("--ack-local-retention", action="store_true")
        item.add_argument("--reason", required=True)
        mode = item.add_mutually_exclusive_group(required=True)
        mode.add_argument("--preview", action="store_true")
        mode.add_argument("--apply", action="store_true")
    render = sub.add_parser("render", help="render one sensitive report bundle")
    render.add_argument("--workspace", required=True)
    render.add_argument("--template", required=True)
    render.add_argument("--title", required=True)
    render.add_argument("--payload", action="append", default=[])
    render_mode = render.add_mutually_exclusive_group(required=True)
    render_mode.add_argument("--preview", action="store_true")
    render_mode.add_argument("--apply", action="store_true")
    verify = sub.add_parser("verify", help="verify a rendered bundle without outputting it")
    verify.add_argument("--workspace", required=True)
    verify.add_argument("--export-id", required=True)
    return root


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        if args.command == "policy" and args.policy_action == "status":
            root = trace.validate_workspace(args.workspace)
            policy = active_policy(root, now)
            print(f"status: {'enabled' if policy else 'disabled'}")
            print(f"path: {POLICY_LEDGER}")
            if policy:
                print(f"standing_authorization_id: {policy['standing_authorization_id']}")
                print(f"destination_root: {policy['destination_root']}")
            return 0
        if args.command == "policy":
            enabled = args.policy_action == "enable"
            _, record, created = set_policy(
                workspace=args.workspace,
                enabled=enabled,
                destination_root=getattr(args, "destination_root", None),
                reason=args.reason,
                acknowledged_plaintext=getattr(args, "ack_plaintext_report", False),
                acknowledged_duplication=getattr(args, "ack_credential_duplication", False),
                acknowledged_retention=getattr(args, "ack_local_retention", False),
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"status: {record['event']}")
            print(f"standing_authorization_id: {record['standing_authorization_id']}")
            print(f"destination_root: {record['destination_root']}")
            print(f"destination_created: {'yes' if created else 'no'}")
            print(f"path: {POLICY_LEDGER}")
            return 0
        if args.command == "render":
            export_id, destination, digest, credential_ids, loot_ids = render_bundle(
                workspace=args.workspace,
                template_file=args.template,
                title=args.title,
                payload_files=args.payload,
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"export_id: {export_id if args.apply else 'pending'}")
            print(f"credential_ids: {','.join(credential_ids)}")
            print(f"loot_ids: {','.join(loot_ids)}")
            print(f"report_sha256: {digest}")
            print(f"destination: {destination if destination else 'pending'}")
            print("contains_plaintext_secrets: yes")
            return 0
        if args.command == "verify":
            destination, digest = verify_bundle(args.workspace, args.export_id)
            print("status: verified")
            print(f"export_id: {args.export_id}")
            print(f"destination: {destination}")
            print(f"report_sha256: {digest}")
            print("secret_values_displayed: no")
            return 0
        raise SensitiveReportError("unsupported command")
    except (
        SensitiveReportError,
        engagement_policy.EngagementPolicyError,
        report_contract.ReportContractError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
