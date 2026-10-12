"""Operator-driven screenshot requests, evidence intake, and report coverage."""

from __future__ import annotations

import argparse
import binascii
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

if __package__:
    from . import (
        credential_intake,
        engagement_policy,
        host_identity,
        ledger_io,
        operational_profile,
        operational_trace,
        report_contract,
        runtime_config,
        workspace_transaction,
    )
    from .token_lifecycle import TokenLifecycleError, closure_readiness
else:
    import credential_intake  # type: ignore[no-redef]
    import engagement_policy  # type: ignore[no-redef]
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import operational_trace  # type: ignore[no-redef]
    import report_contract  # type: ignore[no-redef]
    import runtime_config
    import workspace_transaction  # type: ignore[no-redef]
    from token_lifecycle import (  # type: ignore[no-redef]
        TokenLifecycleError,
        closure_readiness,
    )

DEFAULT_COLLECTION = runtime_config.workspace_root()
LEDGER_NAME = "screenshot_requests.jsonl"
INDEX_NAME = "SCREENSHOT_INDEX.md"
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_PNG_BYTES = 25 * 1024 * 1024
MAX_PIXELS = 40_000_000
MAX_TEXT = 512
MAX_LIST_ITEMS = 32

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
OPERATOR_ID_RE = re.compile(r"^S(?=\d{3,}$)(0*[1-9]\d*)$")
CANONICAL_ID_RE = re.compile(r"^SCR-\d{8}T\d{12}Z$")
EVENT_ID_RE = re.compile(r"^SCRE-\d{8}T\d{12}Z$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
ATTEMPT_ID_RE = re.compile(r"^ATT-\d{8}T\d{12}Z$")
QUERY_ID_RE = re.compile(r"^QRY-\d{8}T\d{12}Z$")
PATH_ID_RE = re.compile(r"^PTH-\d{8}T\d{12}Z$")
CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE
)
JWT_RE = re.compile(
    r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"
)

STAGES = {
    "discovery",
    "access",
    "exploitation",
    "objective",
    "identity",
    "transition",
    "troubleshooting",
    "closure",
}
PRIORITIES = {"required", "recommended", "optional"}
INTERFACES = {"url", "terminal", "rdp", "ssh", "application", "api"}
EVENTS = {"requested", "captured", "invalid", "waived"}
SUSPICIOUS_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "password",
    "secret",
    "signature",
    "sig",
    "token",
}
MANAGED_START = "<!-- CYBER:SCREENSHOTS:START -->"
MANAGED_END = "<!-- CYBER:SCREENSHOTS:END -->"


class ScreenshotError(ValueError):
    """A bounded operator-safe workflow error."""


class _IdenticalInvalidCapture(RuntimeError):
    """Internal signal for an unchanged duplicate that needs no new ledger event."""

    def __init__(self, request: dict[str, Any]) -> None:
        self.request = request
        super().__init__("identical invalid screenshot")


def _fatal(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _text(value: str | None, name: str, maximum: int = MAX_TEXT) -> str:
    if value is None:
        raise ScreenshotError(f"{name} is required")
    if not isinstance(value, str):
        raise ScreenshotError(f"{name} must be text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ScreenshotError(f"{name} must not contain control characters")
    normalized = value.strip()
    if not normalized:
        raise ScreenshotError(f"{name} must not be empty")
    if len(normalized) > maximum:
        raise ScreenshotError(f"{name} is too long (maximum {maximum} characters)")
    return normalized


def _list(values: list[str] | None, name: str, *, required: bool = False) -> list[str]:
    supplied = values or []
    if required and not supplied:
        raise ScreenshotError(f"at least one {name} is required")
    if len(supplied) > MAX_LIST_ITEMS:
        raise ScreenshotError(f"too many {name} values (maximum {MAX_LIST_ITEMS})")
    result: list[str] = []
    for value in supplied:
        normalized = _text(value, name)
        if normalized not in result:
            result.append(normalized)
    return result


def _choice(value: str, name: str, allowed: set[str]) -> str:
    normalized = _text(value, name, 32).lower()
    if normalized not in allowed:
        raise ScreenshotError(
            f"invalid {name}; expected one of {', '.join(sorted(allowed))}"
        )
    return normalized


def _real_directory(path: Path, name: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ScreenshotError(f"{name} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ScreenshotError(f"{name} must be a real non-symlink directory")


def _real_file(path: Path, name: str, *, maximum: int | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ScreenshotError(f"{name} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ScreenshotError(f"{name} must be a real non-symlink regular file")
    if maximum is not None and metadata.st_size > maximum:
        raise ScreenshotError(f"{name} exceeds its size limit")
    return metadata


def _resolve_active(root: Path) -> Path:
    """Resolve a direct workspace or the selected module in a collection."""
    supplied = root.expanduser().absolute()
    if ".." in root.parts:
        raise ScreenshotError("workspace path must not contain parent traversal")
    _real_directory(supplied, "workspace")
    if (supplied / "global.md").exists():
        workspace = supplied
    else:
        marker = supplied / "ACTIVE_TASK"
        _real_file(marker, "ACTIVE_TASK", maximum=256)
        module = _text(marker.read_text(encoding="utf-8").strip(), "ACTIVE_TASK", 64)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", module):
            raise ScreenshotError("ACTIVE_TASK contains an invalid module name")
        workspace = supplied / module
        _real_directory(workspace, "active module workspace")
    for name in ("hosts", "evidence", "report", "inbox"):
        _real_directory(workspace / name, f"workspace {name}/")
    _real_file(workspace / "global.md", "workspace global.md")
    return workspace


def _host_identity(workspace: Path, host_id: str) -> tuple[str, str]:
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise ScreenshotError("invalid host ID; expected canonical Hxx form")
    try:
        canonical_id = host_identity.canonical_host_id(workspace, host_id)
        path = host_identity.host_paths(workspace, canonical_id).state
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    _real_file(path, "canonical host record", maximum=1024 * 1024)
    text = path.read_text(encoding="utf-8")
    ip_matches = re.findall(r"^- IP address: `([^`\r\n]+)`$", text, re.MULTILINE)
    name_matches = re.findall(r"^- Hostname: `([^`\r\n]+)`$", text, re.MULTILINE)
    id_matches = re.findall(r"^- Host ID: `([^`\r\n]+)`$", text, re.MULTILINE)
    if id_matches != [canonical_id] or len(ip_matches) != 1 or len(name_matches) != 1:
        raise ScreenshotError("canonical host record has malformed identity fields")
    return ip_matches[0], name_matches[0]


def _find_evidence_reference(
    workspace: Path, evidence_id: str
) -> tuple[Path, dict[str, Any]]:
    """Find one legacy or friendly metadata file without assuming its owner."""
    if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        raise ScreenshotError("evidence reference does not exist")
    candidates: list[Path] = []
    try:
        for _owner_host_id, directory in host_identity.evidence_roots(workspace):
            if not directory.is_dir() or directory.is_symlink():
                continue
            for path in directory.iterdir():
                if path.name == f"{evidence_id}.json" or path.name.endswith(
                    f"-{evidence_id}.json"
                ):
                    candidates.append(path)
    except (OSError, host_identity.HostIdentityError) as exc:
        raise ScreenshotError("evidence reference could not be inspected") from exc
    if len(candidates) != 1:
        raise ScreenshotError("evidence reference does not exist")
    path = candidates[0]
    _real_file(path, "evidence metadata", maximum=1024 * 1024)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScreenshotError("evidence reference metadata is invalid") from exc
    if not isinstance(record, dict) or record.get("evidence_id") != evidence_id:
        raise ScreenshotError("evidence reference metadata is invalid")
    return path, record


def _same_host(workspace: Path, left: str, right: str) -> bool:
    try:
        return host_identity.canonical_host_id(workspace, left) == host_identity.canonical_host_id(workspace, right)
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc


def _owned_evidence(workspace: Path, host_id: str, evidence_id: str) -> tuple[Path, dict[str, Any]]:
    path, record = _find_evidence_reference(workspace, evidence_id)
    if not _same_host(workspace, str(record.get("host_id")), host_id):
        raise ScreenshotError("evidence belongs to an unrelated host")
    try:
        host_identity.verify_evidence_artifact(path, record)
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    return path, record


def _ensure_layout(workspace: Path) -> dict[str, Path]:
    """Lazily create screenshot-only paths after all parent checks."""
    inbox = workspace / "inbox"
    report = workspace / "report"
    _real_directory(inbox, "workspace inbox/")
    _real_directory(report, "workspace report/")
    screenshots = inbox / "screenshots"
    paths = {
        "root": screenshots,
        "pending": screenshots / "pending",
        "processed": screenshots / "processed",
        "invalid": screenshots / "invalid",
    }
    for path in paths.values():
        if path.exists() or path.is_symlink():
            _real_directory(path, "screenshot directory")
        else:
            path.mkdir(mode=0o700)
    ledger = workspace / LEDGER_NAME
    if ledger.exists() or ledger.is_symlink():
        _real_file(ledger, "screenshot ledger", maximum=MAX_LEDGER_BYTES)
    else:
        descriptor = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    paths["ledger"] = ledger
    return paths


def _safe_url(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = _text(value, "URL", 2048)
    try:
        parsed = urlsplit(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ScreenshotError("URL is malformed") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ScreenshotError("URL must use http or https and contain a hostname")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise ScreenshotError("URL must not contain embedded credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ScreenshotError("URL port is outside 1..65535")
    if parsed.fragment:
        raise ScreenshotError("URL fragments are not persisted in screenshot requests")
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key.casefold() in SUSPICIOUS_QUERY_KEYS:
            raise ScreenshotError("URL contains a potentially secret-bearing query key")
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, "")
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    _real_file(path, path.name, maximum=MAX_LEDGER_BYTES)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScreenshotError(f"cannot read {path.name}") from exc
    if raw and not raw.endswith("\n"):
        raise ScreenshotError(f"{path.name} is missing its final newline")
    records: list[dict[str, Any]] = []
    lines = raw.splitlines()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            raise ScreenshotError(f"{path.name} line {number} is empty")
        try:
            record = ledger_io.loads_json(line)
        except ledger_io.LedgerIOError as exc:
            raise ScreenshotError(f"{path.name} line {number} is invalid JSON") from exc
        if not isinstance(record, dict):
            raise ScreenshotError(f"{path.name} line {number} must be an object")
        records.append(record)
    return records


def _validate_event(record: dict[str, Any], number: int) -> None:
    required = {
        "schema_version",
        "event_id",
        "created_at_utc",
        "event",
        "screenshot_id",
        "operator_id",
    }
    if not required.issubset(record):
        raise ScreenshotError(f"screenshot ledger line {number} has missing fields")
    if record["schema_version"] != "1.0" or record["event"] not in EVENTS:
        raise ScreenshotError(f"screenshot ledger line {number} has invalid metadata")
    if EVENT_ID_RE.fullmatch(str(record["event_id"])) is None:
        raise ScreenshotError(f"screenshot ledger line {number} has invalid event ID")
    if CANONICAL_ID_RE.fullmatch(str(record["screenshot_id"])) is None:
        raise ScreenshotError(
            f"screenshot ledger line {number} has invalid screenshot ID"
        )
    if OPERATOR_ID_RE.fullmatch(str(record["operator_id"])) is None:
        raise ScreenshotError(
            f"screenshot ledger line {number} has invalid operator ID"
        )
    if record["event"] == "requested":
        request_fields = {
            "host_id",
            "stage",
            "priority",
            "interface",
            "protocol",
            "endpoint",
            "steps",
            "must_include",
            "must_exclude",
            "filename",
            "pending_path",
            "evidence_ids",
            "query_ids",
        }
        if not request_fields.issubset(record):
            raise ScreenshotError(
                f"screenshot ledger line {number} has incomplete request fields"
            )
        if not isinstance(record.get("contains_secrets", False), bool):
            raise ScreenshotError(
                f"screenshot ledger line {number} has invalid secret classification"
            )
        host_id = str(record["host_id"])
        filename = str(record["filename"])
        list_fields = (
            "steps",
            "must_include",
            "must_exclude",
            "evidence_ids",
            "query_ids",
        )
        if (
            HOST_ID_RE.fullmatch(host_id) is None
            or record["stage"] not in STAGES
            or record["priority"] not in PRIORITIES
            or record["interface"] not in INTERFACES
            or not filename.startswith(f"{record['operator_id']}_{host_id}_")
            or not filename.endswith(".png")
            or "/" in filename
            or "\\" in filename
            or record["pending_path"] != f"inbox/screenshots/pending/{filename}"
            or not all(isinstance(record[field], list) for field in list_fields)
        ):
            raise ScreenshotError(
                f"screenshot ledger line {number} has invalid request metadata"
            )
        for field in ("reason", "protocol", "endpoint", "filename", "pending_path"):
            _text(record.get(field), field, 2048)
        for field in ("steps", "must_include", "must_exclude"):
            for value in record[field]:
                if not isinstance(value, str):
                    raise ScreenshotError(
                        f"screenshot ledger line {number} has invalid list metadata"
                    )
                _text(value, field)
        coverage_key = record.get("coverage_key")
        if coverage_key is not None:
            _text(coverage_key, "coverage_key", 256)
        report_step_id = record.get("report_step_id")
        if report_step_id is not None and (
            not isinstance(report_step_id, str)
            or report_contract.STEP_ID_RE.fullmatch(report_step_id) is None
        ):
            raise ScreenshotError(
                f"screenshot ledger line {number} has invalid report_step_id"
            )
    elif not isinstance(record.get("host_id"), str):
        raise ScreenshotError(
            f"screenshot ledger line {number} has invalid transition metadata"
        )
    elif record["event"] == "captured" and not {
        "screenshot_evidence_id",
        "sha256",
        "width",
        "height",
        "caption",
    }.issubset(record):
        raise ScreenshotError(
            f"screenshot ledger line {number} has incomplete captured metadata"
        )
    elif record["event"] == "invalid" and not {
        "reason",
        "sha256",
        "width",
        "height",
        "archived_path",
    }.issubset(record):
        raise ScreenshotError(
            f"screenshot ledger line {number} has incomplete invalid metadata"
        )
    elif record["event"] == "waived" and "reason" not in record:
        raise ScreenshotError(
            f"screenshot ledger line {number} has incomplete decision metadata"
        )
    if record["event"] == "captured":
        if (
            EVIDENCE_ID_RE.fullmatch(str(record["screenshot_evidence_id"])) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])) is None
            or not isinstance(record["width"], int)
            or not isinstance(record["height"], int)
            or record["width"] <= 0
            or record["height"] <= 0
            or not isinstance(record.get("contains_secrets", False), bool)
        ):
            raise ScreenshotError(
                f"screenshot ledger line {number} has invalid captured metadata"
            )
        _text(record["caption"], "caption")
    elif record["event"] in {"invalid", "waived"}:
        _text(record["reason"], "reason")
        if record["event"] == "invalid" and (
            re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])) is None
            or not isinstance(record["width"], int)
            or not isinstance(record["height"], int)
            or record["width"] <= 0
            or record["height"] <= 0
            or not str(record["archived_path"]).startswith("inbox/screenshots/invalid/")
        ):
            raise ScreenshotError(
                f"screenshot ledger line {number} has invalid rejection metadata"
            )
        if record["event"] == "waived" and (
            "authorization_id" in record or "alternative_evidence_ids" in record
        ):
            authorization_id = record.get("authorization_id")
            alternative = record.get("alternative_evidence_ids")
            if (
                not isinstance(authorization_id, str)
                or not re.fullmatch(r"AUTH-\d{8}T\d{12}Z", authorization_id)
                or not isinstance(alternative, list)
                or not alternative
                or any(
                    not isinstance(item, str)
                    or EVIDENCE_ID_RE.fullmatch(item) is None
                    for item in alternative
                )
            ):
                raise ScreenshotError(
                    f"screenshot ledger line {number} has invalid waiver provenance"
                )


def _load_events(ledger: Path) -> list[dict[str, Any]]:
    records = _read_jsonl(ledger)
    _validate_sequence(records)
    return records


def _validate_sequence(records: list[dict[str, Any]]) -> None:
    requests: dict[str, dict[str, Any]] = {}
    operator_ids: set[str] = set()
    event_ids: set[str] = set()
    terminal: set[str] = set()
    for number, record in enumerate(records, 1):
        _validate_event(record, number)
        screenshot_id = record["screenshot_id"]
        operator_id = record["operator_id"]
        if record["event_id"] in event_ids:
            raise ScreenshotError("screenshot ledger contains duplicate event IDs")
        event_ids.add(record["event_id"])
        if record["event"] == "requested":
            if screenshot_id in requests or operator_id in operator_ids:
                raise ScreenshotError(
                    "screenshot ledger contains duplicate request IDs"
                )
            requests[screenshot_id] = record
            operator_ids.add(operator_id)
        elif screenshot_id not in requests:
            raise ScreenshotError(
                "screenshot ledger contains a transition before request"
            )
        else:
            request = requests[screenshot_id]
            if operator_id != request["operator_id"] or record.get(
                "host_id"
            ) != request.get("host_id"):
                raise ScreenshotError(
                    "screenshot transition scope does not match request"
                )
            if record["event"] == "captured" and bool(
                record.get("contains_secrets", False)
            ) != bool(request.get("contains_secrets", False)):
                raise ScreenshotError(
                    "screenshot capture changed the request secret classification"
                )
            if screenshot_id in terminal:
                raise ScreenshotError(
                    "screenshot ledger contains a transition after closure"
                )
            if record["event"] in {"captured", "waived"}:
                terminal.add(screenshot_id)


def _effective(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    for record in events:
        screenshot_id = record["screenshot_id"]
        if record["event"] == "requested":
            states[screenshot_id] = {"request": record, "transition": None}
        else:
            states[screenshot_id]["transition"] = record
    return states


def _status(state: dict[str, Any]) -> str:
    transition = state["transition"]
    if transition is None:
        return "pending"
    if transition["event"] == "invalid":
        return "needs_recapture"
    return transition["event"]


def _append_built_event(
    ledger: Path,
    build: Callable[[list[dict[str, Any]]], dict[str, Any]],
    *,
    after_append: Callable[[list[dict[str, Any]]], None] | None = None,
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    with workspace_transaction.write_guard(ledger.parent):
        return _append_built_event_guarded(ledger, build, after_append=after_append)


def _append_built_event_guarded(
    ledger: Path,
    build: Callable[[list[dict[str, Any]]], dict[str, Any]],
    *,
    after_append: Callable[[list[dict[str, Any]]], None] | None = None,
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    """Build, validate, append, and derive state under one screenshot ledger lock."""
    lock_path = ledger.with_name(".screenshot_requests.lock")
    if lock_path.exists() or lock_path.is_symlink():
        _real_file(lock_path, "screenshot ledger lock", maximum=0)
    descriptor = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        events = _load_events(ledger)
        record = build(events)
        # A transaction builder may already have durably appended this event.
        events = _load_events(ledger)
        comparable = {
            key: value
            for key, value in record.items()
            if key not in {"event_id", "created_at_utc"}
        }
        for existing in events:
            previous = {
                key: value
                for key, value in existing.items()
                if key not in {"event_id", "created_at_utc"}
            }
            if previous == comparable:
                if after_append is not None:
                    after_append(events)
                return False, record, events
        _validate_sequence([*events, record])
        try:
            ledger_io.append_json_record(
                ledger,
                record,
                create=False,
                maximum_bytes=MAX_LEDGER_BYTES,
            )
        except ledger_io.LedgerIOError as exc:
            raise ScreenshotError(f"cannot append screenshot event: {exc}") from exc
        updated = [*events, record]
        if after_append is not None:
            after_append(updated)
    finally:
        os.close(descriptor)
    return True, record, updated


def _append_event(
    ledger: Path,
    record: dict[str, Any],
    *,
    after_append: Callable[[list[dict[str, Any]]], None] | None = None,
) -> bool:
    appended, _, _ = _append_built_event(
        ledger,
        lambda _events: record,
        after_append=after_append,
    )
    return appended


def _next_operator_id(events: list[dict[str, Any]]) -> str:
    numbers = [
        int(match.group(1))
        for record in events
        if (match := OPERATOR_ID_RE.fullmatch(record["operator_id"]))
    ]
    return f"S{max(numbers, default=0) + 1:03d}"


def _validate_references(workspace: Path, request: dict[str, Any]) -> None:
    def record_from_ledger(
        name: str, field: str, identifier_value: str
    ) -> dict[str, Any] | None:
        path = workspace / name
        if not path.exists():
            return None
        matches = [
            item
            for item in _read_jsonl(path)
            if item.get(field) == identifier_value
        ]
        if len(matches) > 1:
            raise ScreenshotError(f"{name} contains a duplicate {field}")
        return matches[0] if matches else None

    host_id = request["host_id"]
    attempt = request.get("attempt_id")
    if attempt is not None:
        attempt_record = record_from_ledger("attempts.jsonl", "attempt_id", attempt)
        if ATTEMPT_ID_RE.fullmatch(attempt) is None or attempt_record is None:
            raise ScreenshotError("attempt reference does not exist")
        if not _same_host(workspace, str(attempt_record.get("host_id")), host_id):
            raise ScreenshotError("attempt reference belongs to an unrelated host")
    path_event = request.get("path_event_id")
    if path_event is not None:
        path_record = record_from_ledger(
            "attack_paths.jsonl", "path_event_id", path_event
        )
        if PATH_ID_RE.fullmatch(path_event) is None or path_record is None:
            raise ScreenshotError("path-event reference does not exist")
        if not _same_host(workspace, str(path_record.get("destination_host_id")), host_id):
            raise ScreenshotError("path-event reference belongs to an unrelated host")
    for evidence_id in request.get("evidence_ids", []):
        metadata_path, metadata = _find_evidence_reference(workspace, evidence_id)
        _real_directory(metadata_path.parent, "referenced evidence host directory")
        _real_file(metadata_path, "referenced evidence metadata", maximum=1024 * 1024)
        if (
            not isinstance(metadata, dict)
            or metadata.get("evidence_id") != evidence_id
            or not _same_host(workspace, str(metadata.get("host_id")), host_id)
        ):
            raise ScreenshotError("evidence reference belongs to an unrelated host")
        try:
            host_identity.verify_evidence_artifact(metadata_path, metadata)
        except host_identity.HostIdentityError as exc:
            raise ScreenshotError(str(exc)) from exc
    query_ids = request.get("query_ids", [])
    queries: dict[str, dict[str, Any]] = {}
    if query_ids:
        try:
            queries = report_contract._query_index(workspace)
        except report_contract.ReportContractError as exc:
            raise ScreenshotError(str(exc)) from exc
    for query_id in query_ids:
        if QUERY_ID_RE.fullmatch(query_id) is None or query_id not in queries:
            raise ScreenshotError("query reference does not exist")
        if not report_contract._query_matches_host(queries[query_id], host_id, report_contract.ValidationContext(workspace)):
            raise ScreenshotError("query reference belongs to an unrelated host")
    report_step_id = request.get("report_step_id")
    if report_step_id is not None:
        try:
            _, states = report_contract.load_steps(workspace)
        except report_contract.ReportContractError as exc:
            raise ScreenshotError(str(exc)) from exc
        if report_step_id not in states:
            raise ScreenshotError("report-step reference does not exist")
        if not _same_host(workspace, states[report_step_id]["plan"]["host_id"], host_id):
            raise ScreenshotError("report-step reference belongs to an unrelated host")
    if _request_coverage_key(request) is not None:
        _validate_derived_coverage(workspace, request)


def _validate_waiver_references(
    workspace: Path,
    host_id: str,
    authorization_id: str,
    evidence_ids: list[str],
) -> None:
    try:
        authorizations = {
            item["authorization_id"]: item
            for item in operational_trace.load_authorizations(workspace)
        }
    except operational_trace.TraceError as exc:
        raise ScreenshotError(str(exc)) from exc
    authorization = authorizations.get(authorization_id)
    if authorization is None:
        raise ScreenshotError("waiver authorization reference does not exist")
    if host_id not in authorization["host_ids"]:
        raise ScreenshotError("waiver authorization does not cover the request host")
    for evidence_id in evidence_ids:
        try:
            metadata_path, metadata = _find_evidence_reference(workspace, evidence_id)
        except ScreenshotError as exc:
            raise ScreenshotError("waiver evidence reference does not exist") from exc
        _real_file(metadata_path, "waiver evidence metadata", maximum=1024 * 1024)
        if not _same_host(workspace, str(metadata.get("host_id")), host_id):
            raise ScreenshotError("waiver evidence belongs to an unrelated host")


def _credentials(workspace: Path) -> list[dict[str, Any]]:
    try:
        handles = credential_intake._open_workspace(str(workspace))
        try:
            hosts = credential_intake._discover_hosts(handles.workspace_fd)
            known_hosts = credential_intake._known_host_ids(hosts)
            snapshot = credential_intake._read_ledger(
                handles.credentials_fd, known_hosts
            )
            return [dict(record) for record in snapshot.records]
        finally:
            handles.close()
    except credential_intake.CredentialIntakeError as exc:
        raise ScreenshotError(str(exc)) from exc


def _resolve_credential(
    workspace: Path,
    host_id: str,
    service: str | None,
    credential_id: str | None,
) -> dict[str, Any]:
    records = _credentials(workspace)
    candidates = [
        item
        for item in records
        if item.get("host_id") == host_id
        and item.get("status") in {"unverified", "active"}
        and (
            service is None
            or str(item.get("service", "")).casefold() == service.casefold()
        )
        and (credential_id is None or item.get("credential_id") == credential_id)
    ]
    if not candidates:
        raise ScreenshotError("no canonical credential matches this host and service")
    if len(candidates) > 1:
        metadata = ", ".join(
            f"{item.get('credential_id')} ({item.get('service')}, {item.get('username')})"
            for item in candidates
        )
        raise ScreenshotError(f"multiple canonical credentials match: {metadata}")
    return candidates[0]


def _reject_secrets(workspace: Path, values: list[str]) -> None:
    secrets = [
        str(item.get("secret"))
        for item in _credentials(workspace)
        if item.get("secret")
    ]
    for value in values:
        if PRIVATE_KEY_RE.search(value):
            raise ScreenshotError("request metadata resembles private-key material")
        if re.search(
            r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+", value
        ) or JWT_RE.search(value):
            raise ScreenshotError("request metadata resembles a secret assignment")
        if any(secret and secret in value for secret in secrets):
            raise ScreenshotError("request metadata contains a stored credential value")


def _secret_display_enabled(workspace: Path, now: datetime | None = None) -> bool:
    try:
        return engagement_policy.secret_display_enabled(workspace, now)
    except engagement_policy.EngagementPolicyError as exc:
        raise ScreenshotError(str(exc)) from exc


def _automatic_command(
    interface: str, ip: str, port: int | None, username: str | None
) -> str | None:
    endpoint = ip if port is None else f"{ip}:{port}"
    if interface == "rdp" and username:
        return f"xfreerdp3 /v:{endpoint} /u:{username} /cert:ignore /dynamic-resolution"
    if interface == "ssh" and username:
        port_part = f" -p {port}" if port is not None and port != 22 else ""
        return f"ssh{port_part} {username}@{ip}"
    return None


def _render_instruction(
    workspace: Path, request: dict[str, Any], credential: dict[str, Any] | None
) -> str:
    ip, hostname = _host_identity(workspace, request["host_id"])
    priority = request["priority"].upper()
    lines = [
        f"SCREENSHOT NOW — {request['operator_id']} [{priority}]",
        "",
        f"Host: {request['host_id']} — {hostname}",
        f"IP: {ip}",
        f"Access: {request['interface'].upper()}",
        f"Endpoint: {request['safe_url'] or request['endpoint']}",
    ]
    if request.get("contains_secrets", False):
        lines.extend(
            [
                "",
                "SENSITIVE CAPTURE — necessary secret pixels are authorized",
                "Do not include unrelated credentials or private data. The caption and ledger metadata must remain secret-free.",
            ]
        )
    if credential is not None:
        lines.extend(
            [
                "",
                "SENSITIVE — operator-authorized credential reveal",
                f"Credential ID: {credential['credential_id']}",
                f"Host: {request['host_id']} — {hostname}",
                f"Service: {credential.get('service') or 'unspecified'}",
                f"Username or principal: {credential.get('username') or 'not applicable'}",
                f"Credential type: {credential['secret_type']}",
                f"Secret value: {credential['secret']}",
            ]
        )
    if request.get("command"):
        lines.extend(["", "Connect / open:", request["command"]])
        if credential is not None:
            lines.append("After connecting, enter the provided secret interactively.")
    lines.extend(["", "Steps:"])
    lines.extend(f"{number}. {step}" for number, step in enumerate(request["steps"], 1))
    lines.extend(["", "Must be visible:"])
    lines.extend(f"- {item}" for item in request["must_include"])
    lines.extend(["", "Must not be visible:"])
    lines.extend(f"- {item}" for item in request["must_exclude"])
    pending = workspace / request["pending_path"]
    lines.extend(
        [
            "",
            "Save to:",
            str(pending),
            "",
            "Capture:",
            f'import "{pending}"',
            "",
            "Reply:",
            f"{request['operator_id']} ready",
        ]
    )
    return "\n".join(lines)


def _workspace_writer(function):
    @wraps(function)
    def wrapped(args, *values, **keywords):
        workspace = _resolve_active(Path(args.workspace))
        try:
            with workspace_transaction.write_guard(workspace):
                return function(args, *values, **keywords)
        except (RuntimeError, OSError) as exc:
            raise ScreenshotError(str(exc)) from exc
    return wrapped


@_workspace_writer
def request_screenshot(
    args: argparse.Namespace, now: datetime | None = None
) -> dict[str, Any]:
    workspace = _resolve_active(Path(args.workspace))
    contains_secrets = bool(getattr(args, "contains_secrets", False))
    if contains_secrets and not _secret_display_enabled(workspace, now):
        raise ScreenshotError(
            "secret-bearing screenshots require the active controlled-engagement secret-display switch"
        )
    layout = _ensure_layout(workspace)
    ip, _ = _host_identity(workspace, args.host_id)
    stage = _choice(args.stage, "stage", STAGES)
    priority = _choice(args.priority, "priority", PRIORITIES)
    interface = _choice(args.interface, "interface", INTERFACES)
    reason = _text(args.reason, "reason")
    slug = _text(args.slug, "slug", 48)
    if SLUG_RE.fullmatch(slug) is None:
        raise ScreenshotError(
            "slug must use lowercase letters, digits, and single hyphens"
        )
    port = args.port
    if port is not None and not 1 <= port <= 65535:
        raise ScreenshotError("port must be from 1 through 65535")
    protocol = _text(args.protocol, "protocol", 32).lower()
    service = _text(args.service, "service", 128) if args.service else None
    safe_url = _safe_url(args.url)
    endpoint = _text(
        args.endpoint or (f"{ip}:{port}" if port else ip), "endpoint", 2048
    )
    steps = _list(args.steps, "step", required=True)
    must_include = _list(args.must_include, "must-include", required=True)
    must_exclude = _list(args.must_exclude, "must-exclude", required=True)
    credential: dict[str, Any] | None = None
    credential_id = args.credential_id
    if credential_id is not None and CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
        raise ScreenshotError("credential ID is malformed")
    if args.login_authorized:
        if service is None:
            raise ScreenshotError(
                "--service is required for a scope-matched authorized login"
            )
        credential = _resolve_credential(
            workspace, args.host_id, service, credential_id
        )
        credential_id = credential["credential_id"]
    elif credential_id is not None:
        raise ScreenshotError("credential selection requires --login-authorized")
    command = args.command
    if command is None:
        command = _automatic_command(
            interface, ip, port, credential.get("username") if credential else None
        )
    if command is not None:
        command = _text(command, "command", 2048)
    coverage_key = getattr(args, "coverage_key", None)
    derived_reconcile = bool(getattr(args, "derived_reconcile", False))
    if coverage_key is not None and not derived_reconcile:
        raise ScreenshotError("coverage keys are assigned only by reconcile")
    if coverage_key is not None:
        coverage_key = _text(coverage_key, "coverage-key", 256)
    report_step_id = getattr(args, "report_step_id", None)
    if report_step_id is not None and not derived_reconcile:
        raise ScreenshotError("report-step binding is assigned only by reconcile")
    if report_step_id is not None and (
        report_contract.STEP_ID_RE.fullmatch(report_step_id) is None
    ):
        raise ScreenshotError("report-step-id is malformed")
    values = [reason, endpoint, protocol, slug, *steps, *must_include, *must_exclude]
    if service:
        values.append(service)
    if safe_url:
        values.append(safe_url)
    if command:
        values.append(command)
    if coverage_key:
        values.append(coverage_key)
    _reject_secrets(workspace, values)

    requested_moment = now

    def build_request(events: list[dict[str, Any]]) -> dict[str, Any]:
        moment = requested_moment or datetime.now(UTC)
        screenshot_ids = {item["screenshot_id"] for item in events}
        event_ids = {item["event_id"] for item in events}
        while (
            _identifier("SCR", moment) in screenshot_ids
            or _identifier("SCRE", moment) in event_ids
        ):
            moment += timedelta(microseconds=1)
        operator_id = _next_operator_id(events)
        screenshot_id = _identifier("SCR", moment)
        filename = f"{operator_id}_{args.host_id}_{slug}.png"
        request: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": _identifier("SCRE", moment),
            "created_at_utc": _timestamp(moment),
            "event": "requested",
            "screenshot_id": screenshot_id,
            "operator_id": operator_id,
            "host_id": args.host_id,
            "stage": stage,
            "priority": priority,
            "reason": reason,
            "interface": interface,
            "protocol": protocol,
            "port": port,
            "endpoint": endpoint,
            "safe_url": safe_url,
            "service": service,
            "credential_id": credential_id,
            "command": command,
            "steps": steps,
            "must_include": must_include,
            "must_exclude": must_exclude,
            "contains_secrets": contains_secrets,
            "filename": filename,
            "pending_path": f"inbox/screenshots/pending/{filename}",
            "reproducibility": args.reproducibility,
            "attempt_id": args.attempt_id,
            "evidence_ids": _list(args.evidence_ids, "evidence ID"),
            "query_ids": _list(args.query_ids, "query ID"),
            "path_event_id": args.path_event_id,
            "coverage_key": coverage_key,
            "report_step_id": report_step_id,
        }
        _validate_references(workspace, request)
        return request

    _, request, _ = _append_built_event(
        layout["ledger"],
        build_request,
        after_append=lambda events: _rebuild_index(workspace, events),
    )
    print(_render_instruction(workspace, request, credential))
    return request


def _read_pending_png(path: Path) -> tuple[bytes, int, int]:
    before = _real_file(path, "pending screenshot", maximum=MAX_PNG_BYTES)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ScreenshotError("pending screenshot changed during validation")
        raw = b""
        while len(raw) <= MAX_PNG_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_PNG_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise ScreenshotError("pending screenshot changed during validation")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_PNG_BYTES:
        raise ScreenshotError("pending screenshot exceeds 25 MiB")
    width, height = _validate_png(raw)
    return raw, width, height


def _validate_png(raw: bytes) -> tuple[int, int]:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ScreenshotError("pending screenshot is not a PNG")
    offset = 8
    width = height = None
    saw_iend = False
    chunk_number = 0
    while offset + 12 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        kind = raw[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(raw):
            raise ScreenshotError("PNG contains a truncated chunk")
        data = raw[offset + 8 : offset + 8 + length]
        supplied_crc = struct.unpack(">I", raw[offset + 8 + length : end])[0]
        actual_crc = binascii.crc32(kind + data) & 0xFFFFFFFF
        if supplied_crc != actual_crc:
            raise ScreenshotError("PNG chunk checksum is invalid")
        if chunk_number == 0 and kind != b"IHDR":
            raise ScreenshotError("PNG first chunk is not IHDR")
        if kind == b"IHDR":
            if chunk_number != 0 or length != 13:
                raise ScreenshotError("PNG IHDR is invalid")
            width, height = struct.unpack(">II", data[:8])
            if width == 0 or height == 0:
                raise ScreenshotError("PNG dimensions must be non-zero")
        if kind == b"IEND":
            if length != 0 or end != len(raw):
                raise ScreenshotError("PNG IEND is invalid or trailing data exists")
            saw_iend = True
            break
        offset = end
        chunk_number += 1
    if width is None or height is None or not saw_iend:
        raise ScreenshotError("PNG structure is incomplete")
    if width * height > MAX_PIXELS:
        raise ScreenshotError("PNG exceeds the 40 megapixel limit")
    return width, height


def _capture_evidence_bytes(
    workspace: Path,
    host_id: str,
    raw: bytes,
    label: str,
    contains_secrets: bool,
    moment: datetime,
    transaction: workspace_transaction.Transaction,
) -> tuple[str, Path, str]:
    evidence_id = _identifier("EVD", moment)
    try:
        paths = host_identity.host_paths(workspace, host_id)
        basename = host_identity.evidence_basename(paths.record, evidence_id)
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    evidence_dir = paths.evidence
    _real_directory(evidence_dir, "host evidence directory")
    artifact = evidence_dir / f"{basename}.png"
    metadata = evidence_dir / f"{basename}.json"
    digest = hashlib.sha256(raw).hexdigest()
    relative = artifact.relative_to(workspace).as_posix()
    record = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "timestamp_utc": _timestamp(moment),
        "host_id": paths.record.host_id,
        "kind": "screenshot",
        "contains_secrets": contains_secrets,
        "sensitivity": "engagement-secret-bearing" if contains_secrets else "standard",
        "label": label,
        "artifact_path": relative,
        "size_bytes": len(raw),
        "sha256": digest,
    }
    transaction.add("create", artifact, raw)
    transaction.add("create", metadata, json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode())
    return evidence_id, artifact, digest


def _accepted_hashes(workspace: Path, events: list[dict[str, Any]]) -> set[str]:
    hashes: set[str] = set()
    for item in events:
        if item["event"] != "captured":
            continue
        evidence_id = item["screenshot_evidence_id"]
        try:
            metadata, _ = _owned_evidence(workspace, item["host_id"], evidence_id)
        except host_identity.HostIdentityError as exc:
            raise ScreenshotError(str(exc)) from exc
        _real_file(
            metadata, "accepted screenshot evidence metadata", maximum=1024 * 1024
        )
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
            if record.get("kind") != "screenshot":
                raise ScreenshotError(
                    "accepted screenshot evidence metadata has invalid kind"
                )
            hashes.add(str(record["sha256"]))
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as exc:
            raise ScreenshotError(
                "accepted screenshot evidence metadata is invalid"
            ) from exc
    return hashes


@_workspace_writer
def review_screenshot(
    args: argparse.Namespace, now: datetime | None = None
) -> dict[str, Any]:
    workspace = _resolve_active(Path(args.workspace))
    layout = _ensure_layout(workspace)
    if args.accept:
        if not args.visual_reviewed:
            raise ScreenshotError("--visual-reviewed is required before acceptance")
        caption = _text(args.caption, "caption")
        _reject_secrets(workspace, [caption])
        reason = None
    else:
        reason = _text(args.reason, "reason")
        _reject_secrets(workspace, [reason])

        caption = None

    requested_moment = now
    review_context: dict[str, str] = {}

    def build_review(events: list[dict[str, Any]]) -> dict[str, Any]:
        states = _effective(events)
        matches = [
            state
            for state in states.values()
            if state["request"]["operator_id"] == args.screenshot_id
        ]
        if len(matches) != 1:
            raise ScreenshotError("screenshot request does not exist")
        state = matches[0]
        request = state["request"]
        review_context["filename"] = request["filename"]
        if _status(state) in {"captured", "waived"}:
            raise ScreenshotError("screenshot request is already closed")

        pending = workspace / request["pending_path"]
        candidates = list(
            layout["pending"].glob(f"{request['operator_id']}_*.png")
        )
        if len(candidates) > 1:
            raise ScreenshotError(
                "multiple PNG files match this screenshot ID; intake is ambiguous"
            )
        if candidates and candidates[0].name != request["filename"]:
            raise ScreenshotError(
                f"filename does not match request; expected {request['filename']}"
            )
        raw, width, height = _read_pending_png(pending)
        digest = hashlib.sha256(raw).hexdigest()
        moment = requested_moment or datetime.now(UTC)
        existing_event_ids = {item["event_id"] for item in events}
        while _identifier("SCRE", moment) in existing_event_ids:
            moment += timedelta(microseconds=1)

        if args.accept:
            contains_secrets = bool(request.get("contains_secrets", False))
            if contains_secrets:
                if not args.secret_scope_reviewed:
                    raise ScreenshotError(
                        "--secret-scope-reviewed is required for a secret-bearing screenshot"
                    )
                if not _secret_display_enabled(workspace, moment):
                    raise ScreenshotError(
                        "secret-display switch is not active at screenshot acceptance"
                    )
            elif args.secret_scope_reviewed:
                raise ScreenshotError(
                    "--secret-scope-reviewed requires a secret-bearing screenshot request"
                )
            if digest in _accepted_hashes(workspace, events):
                raise ScreenshotError("an identical screenshot is already accepted")
            destination = layout["processed"] / request["filename"]
            if destination.exists() or destination.is_symlink():
                raise ScreenshotError(
                    "processed screenshot destination already exists"
                )
            evidence_id = _identifier("EVD", moment)
            event = {
                "schema_version": "1.0",
                "event_id": _identifier("SCRE", moment),
                "created_at_utc": _timestamp(moment),
                "event": "captured",
                "screenshot_id": request["screenshot_id"],
                "operator_id": request["operator_id"],
                "host_id": request["host_id"],
                "screenshot_evidence_id": evidence_id,
                "sha256": digest,
                "width": width,
                "height": height,
                "caption": caption,
                "contains_secrets": contains_secrets,
            }
            _validate_references(workspace, request)
            _validate_sequence([*events, event])
            transaction = workspace_transaction.Transaction(
                workspace, "screenshot", references={
                    "host_id": request["host_id"], "screenshot_id": request["screenshot_id"],
                    "reviewed_png_sha256": digest,
                    "visual_reviewed": True, "secret_scope_reviewed": bool(args.secret_scope_reviewed),
                },
            )
            captured_id, _, captured_digest = _capture_evidence_bytes(
                workspace,
                request["host_id"],
                raw,
                f"{request['operator_id']}: {caption}",
                contains_secrets,
                moment,
                transaction,
            )
            if captured_id != evidence_id or captured_digest != digest:
                raise ScreenshotError("captured screenshot identity changed")
            transaction.add("move", pending, raw, destination=destination)
            transaction.add("append", layout["ledger"], (json.dumps(event, separators=(",", ":")) + "\n").encode())
            transaction.commit()
            return event

        previous_invalid_hashes = {
            item.get("sha256")
            for item in events
            if item["event"] == "invalid"
            and item["screenshot_id"] == request["screenshot_id"]
        }
        suffix = moment.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = layout["invalid"] / f"{pending.stem}.invalid-{suffix}.png"
        event = {
            "schema_version": "1.0",
            "event_id": _identifier("SCRE", moment),
            "created_at_utc": _timestamp(moment),
            "event": "invalid",
            "screenshot_id": request["screenshot_id"],
            "operator_id": request["operator_id"],
            "host_id": request["host_id"],
            "sha256": digest,
            "width": width,
            "height": height,
            "reason": reason,
            "archived_path": destination.relative_to(workspace).as_posix(),
        }
        _validate_sequence([*events, event])
        if digest in previous_invalid_hashes:
            raise _IdenticalInvalidCapture(request)
        transaction = workspace_transaction.Transaction(
            workspace, "screenshot", references={"host_id": request["host_id"], "screenshot_id": request["screenshot_id"]},
        )
        transaction.add("move", pending, raw, destination=destination)
        transaction.add("append", layout["ledger"], (json.dumps(event, separators=(",", ":")) + "\n").encode())
        transaction.commit()
        return event

    def update_derived_state(updated: list[dict[str, Any]]) -> None:
        _rebuild_index(workspace, updated)
        if args.accept:
            _update_host_report(workspace, updated[-1]["host_id"], updated)

    try:
        _, event, _ = _append_built_event(
            layout["ledger"],
            build_review,
            after_append=update_derived_state,
        )
    except _IdenticalInvalidCapture as exc:
        print("status: identical-invalid-no-op")
        print(f"operator_id: {exc.request['operator_id']}")
        return {"event": "invalid", "duplicate": True}
    if args.accept:
        print(
            f"status: captured\noperator_id: {event['operator_id']}\nevidence_id: {event['screenshot_evidence_id']}\nsha256: {event['sha256']}"
        )
    else:
        print(
            f"status: needs_recapture\noperator_id: {event['operator_id']}\nreason: {event['reason']}\nexpected_filename: {review_context['filename']}"
        )
    return event


@_workspace_writer
def waive_screenshot(
    args: argparse.Namespace, now: datetime | None = None
) -> dict[str, Any]:
    workspace = _resolve_active(Path(args.workspace))
    layout = _ensure_layout(workspace)
    reason = _text(args.reason, "reason")
    _reject_secrets(workspace, [reason])
    authorization_id = getattr(args, "authorization_id", None)
    alternative_evidence_ids = _list(
        getattr(args, "alternative_evidence_ids", None),
        "alternative evidence ID",
    )
    if (authorization_id is not None or alternative_evidence_ids) and (
        authorization_id is None or not alternative_evidence_ids
    ):
        raise ScreenshotError(
            "waiver provenance must include authorization and alternative evidence"
        )

    requested_moment = now

    def build_waiver(events: list[dict[str, Any]]) -> dict[str, Any]:
        states = _effective(events)
        state = next(
            (
                item
                for item in states.values()
                if item["request"]["operator_id"] == args.screenshot_id
            ),
            None,
        )
        if state is None:
            raise ScreenshotError("screenshot request does not exist")
        if _status(state) in {"captured", "waived"}:
            raise ScreenshotError("screenshot request is already closed")
        request = state["request"]
        if request["priority"] == "required" and (
            authorization_id is None or not alternative_evidence_ids
        ):
            raise ScreenshotError(
                "required waiver needs --authorization-id and --alternative-evidence-id"
            )
        if authorization_id is not None:
            _validate_waiver_references(
                workspace,
                request["host_id"],
                authorization_id,
                alternative_evidence_ids,
            )
        moment = requested_moment or datetime.now(UTC)
        existing_event_ids = {item["event_id"] for item in events}
        while _identifier("SCRE", moment) in existing_event_ids:
            moment += timedelta(microseconds=1)
        event = {
            "schema_version": "1.0",
            "event_id": _identifier("SCRE", moment),
            "created_at_utc": _timestamp(moment),
            "event": "waived",
            "screenshot_id": request["screenshot_id"],
            "operator_id": request["operator_id"],
            "host_id": request["host_id"],
            "reason": reason,
        }
        if authorization_id is not None:
            event["authorization_id"] = authorization_id
            event["alternative_evidence_ids"] = alternative_evidence_ids
        return event

    _, event, _ = _append_built_event(
        layout["ledger"],
        build_waiver,
        after_append=lambda updated: _rebuild_index(workspace, updated),
    )
    print(f"status: waived\noperator_id: {event['operator_id']}")
    return event


def _atomic_text(path: Path, content: str) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    if path.exists() or path.is_symlink():
        _real_file(path, path.name, maximum=4 * 1024 * 1024)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _rebuild_index(workspace: Path, events: list[dict[str, Any]]) -> None:
    states = _effective(events)
    lines = [
        "# Screenshot Evidence Index",
        "",
        "Generated from the append-only screenshot request ledger.",
        "",
        "| ID | Host | Stage | Priority | Status | Evidence | Caption |",
        "|---|---|---|---|---|---|---|",
    ]
    for state in states.values():
        request = state["request"]
        transition = state["transition"]
        status = _status(state)
        evidence = "—"
        caption = "—"
        if transition and transition["event"] == "captured":
            evidence_id = transition["screenshot_evidence_id"]
            metadata, _ = _owned_evidence(workspace, request["host_id"], evidence_id)
            relative = metadata.relative_to(workspace).as_posix()
            evidence = f"[{evidence_id}](../{relative})"
            caption = transition["caption"].replace("|", "\\|")
            if transition.get("contains_secrets", False):
                caption = "SENSITIVE CAPTURE — " + caption
        lines.append(
            f"| {request['operator_id']} | {host_identity.canonical_host_id(workspace, request['host_id'])} | {request['stage']} | {request['priority']} | {status} | {evidence} | {caption} |"
        )
    _atomic_text(workspace / "report" / INDEX_NAME, "\n".join(lines) + "\n")


def _update_host_report(
    workspace: Path, host_id: str, events: list[dict[str, Any]]
) -> None:
    try:
        path = host_identity.host_paths(workspace, host_id).report
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    _real_file(path, "host report", maximum=4 * 1024 * 1024)
    original = path.read_text(encoding="utf-8")
    states = _effective(events)
    lines = [MANAGED_START, "### Managed screenshot evidence", ""]
    for state in states.values():
        request = state["request"]
        transition = state["transition"]
        if (
            not _same_host(workspace, request["host_id"], host_id)
            or not transition
            or transition["event"] != "captured"
        ):
            continue
        evidence_id = transition["screenshot_evidence_id"]
        caption = transition["caption"]
        secret_marker = (
            " — SENSITIVE CAPTURE"
            if transition.get("contains_secrets", False)
            else ""
        )
        metadata, record = _owned_evidence(workspace, host_id, evidence_id)
        artifact = host_identity.locate_evidence_artifact(metadata, record)
        metadata_link = f"../{metadata.relative_to(workspace).as_posix()}"
        artifact_link = f"../{artifact.relative_to(workspace).as_posix()}"
        lines.append(
            f"- **{request['operator_id']} — {caption}{secret_marker}**: "
            f"[{evidence_id}]({metadata_link})"
        )
        lines.extend(
            [
                "",
                (
                    f"  ![{request['operator_id']} — accepted screenshot]"
                    f"({artifact_link})"
                ),
                "",
            ]
        )
    lines.extend(["", MANAGED_END])
    block = "\n".join(lines)
    if MANAGED_START in original or MANAGED_END in original:
        if original.count(MANAGED_START) != 1 or original.count(MANAGED_END) != 1:
            raise ScreenshotError(
                "host report has malformed managed screenshot markers"
            )
        start = original.index(MANAGED_START)
        end = original.index(MANAGED_END, start) + len(MANAGED_END)
        updated = original[:start] + block + original[end:]
    else:
        separator = (
            ""
            if original.endswith("\n\n")
            else ("\n" if original.endswith("\n") else "\n\n")
        )
        updated = original + separator + block + "\n"
    _atomic_text(path, updated)


def status_screenshots(args: argparse.Namespace) -> int:
    workspace = _resolve_active(Path(args.workspace))
    ledger = workspace / LEDGER_NAME
    if not ledger.exists():
        print("requests: 0\npending: 0\nneeds_recapture: 0\ncaptured: 0\nwaived: 0")
        return 0
    states = _effective(_load_events(ledger))
    counts = {name: 0 for name in ("pending", "needs_recapture", "captured", "waived")}
    for state in states.values():
        status = _status(state)
        counts[status] += 1
        request = state["request"]
        print(
            f"{request['operator_id']} {host_identity.canonical_host_id(workspace, request['host_id'])} {request['priority']} {status} {request['filename']}"
        )
    print(f"requests: {len(states)}")
    for name, count in counts.items():
        print(f"{name}: {count}")
    return 0


def _verify_evidence(
    workspace: Path, request: dict[str, Any], transition: dict[str, Any]
) -> None:
    evidence_id = transition["screenshot_evidence_id"]
    if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        raise ScreenshotError("captured request has malformed evidence ID")
    try:
        metadata_path, _ = _owned_evidence(workspace, request["host_id"], evidence_id)
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    _real_directory(metadata_path.parent, "screenshot evidence host directory")
    _real_file(metadata_path, "screenshot evidence metadata", maximum=1024 * 1024)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (
        metadata.get("kind") != "screenshot"
        or not _same_host(workspace, str(metadata.get("host_id")), request["host_id"])
    ):
        raise ScreenshotError("screenshot evidence metadata has mismatched scope")
    try:
        artifact = host_identity.locate_evidence_artifact(metadata_path, metadata)
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    _real_file(artifact, "screenshot evidence artifact", maximum=MAX_PNG_BYTES)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != metadata.get("sha256") or digest != transition.get("sha256"):
        raise ScreenshotError("screenshot evidence SHA-256 verification failed")


def _request_coverage_key(request: dict[str, Any]) -> str | None:
    coverage_key = request.get("coverage_key")
    if isinstance(coverage_key, str) and coverage_key:
        return coverage_key
    path_event_id = request.get("path_event_id")
    if isinstance(path_event_id, str) and path_event_id:
        return f"path:{path_event_id}"
    report_step_id = request.get("report_step_id")
    if isinstance(report_step_id, str) and report_step_id:
        checkpoint = "other"
        return f"step:{report_step_id}:{checkpoint}"
    return None


def _validate_derived_coverage(workspace: Path, request: dict[str, Any]) -> None:
    key = _request_coverage_key(request)
    if key is None:
        return
    try:
        matches = [
            item
            for item in report_contract.derive_screenshot_requirements(workspace)
            if item.coverage_key == key
        ]
    except report_contract.ReportContractError as exc:
        raise ScreenshotError(str(exc)) from exc
    if len(matches) != 1:
        raise ScreenshotError("coverage key does not resolve to one derived requirement")
    requirement = matches[0]
    if not _same_host(workspace, request["host_id"], requirement.host_id):
        raise ScreenshotError("coverage request belongs to an unrelated host")
    if request.get("coverage_key") is None:
        if request.get("path_event_id") != requirement.path_event_id:
            raise ScreenshotError("legacy coverage request has mismatched path binding")
        if request.get("report_step_id") != requirement.report_step_id:
            raise ScreenshotError("legacy coverage request has mismatched step binding")
        return
    expected = {
        "priority": requirement.priority,
        "stage": requirement.stage,
        "reason": requirement.reason,
        "interface": requirement.interface,
        "protocol": requirement.protocol,
        "port": requirement.port,
        "endpoint": requirement.endpoint,
        "safe_url": requirement.safe_url,
        "service": requirement.service,
        "steps": list(requirement.steps),
        "must_include": list(requirement.must_include),
        "must_exclude": list(requirement.must_exclude),
        "reproducibility": requirement.reproducibility,
        "attempt_id": requirement.attempt_id,
        "evidence_ids": list(requirement.evidence_ids),
        "query_ids": list(requirement.query_ids),
        "path_event_id": requirement.path_event_id,
        "report_step_id": requirement.report_step_id,
    }
    if any(request.get(field) != value for field, value in expected.items()):
        raise ScreenshotError("coverage request does not match its derived requirement")


def _screenshot_source_embedded(
    workspace: Path, request: dict[str, Any], transition: dict[str, Any]
) -> bool:
    try:
        report = host_identity.host_paths(workspace, request["host_id"]).report
    except host_identity.HostIdentityError as exc:
        raise ScreenshotError(str(exc)) from exc
    _real_file(report, "host report", maximum=4 * 1024 * 1024)
    evidence_id = transition["screenshot_evidence_id"]
    metadata, record = _owned_evidence(workspace, request["host_id"], evidence_id)
    artifact = host_identity.locate_evidence_artifact(metadata, record)
    expected = f"../{artifact.relative_to(workspace).as_posix()}"
    image_reference = re.compile(
        rf"!\[[^\]\r\n]*\]\({re.escape(expected)}\)"
    )
    text = report.read_text(encoding="utf-8")
    if text.count(MANAGED_START) != 1 or text.count(MANAGED_END) != 1:
        raise ScreenshotError("host report has malformed managed screenshot markers")
    start = text.index(MANAGED_START) + len(MANAGED_START)
    end = text.index(MANAGED_END, start)
    in_fence = False
    fence_marker: str | None = None
    in_comment = False
    for raw_line in text[start:end].splitlines():
        line = raw_line.strip()
        if in_comment:
            if "-->" in line:
                in_comment = False
                line = line.split("-->", 1)[1].strip()
            else:
                continue
        if "<!--" in line:
            before, after = line.split("<!--", 1)
            line = before.strip()
            if "-->" not in after:
                in_comment = True
        if line.startswith(("```", "~~~")):
            marker = line[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = None
            continue
        if not in_fence and image_reference.fullmatch(line):
            return True
    return False


def _coverage_state(
    workspace: Path,
    requirements: list[report_contract.ScreenshotRequirement],
    states: dict[str, dict[str, Any]],
) -> tuple[list[report_contract.ScreenshotRequirement], list[str], list[str]]:
    by_key: dict[str, dict[str, Any]] = {}
    for state in states.values():
        key = _request_coverage_key(state["request"])
        if key is not None:
            if key in by_key:
                raise ScreenshotError("screenshot ledger has duplicate coverage keys")
            by_key[key] = state
    missing: list[report_contract.ScreenshotRequirement] = []
    blocking: list[str] = []
    waived: list[str] = []
    for requirement in requirements:
        state = by_key.get(requirement.coverage_key)
        if state is None:
            missing.append(requirement)
            if requirement.priority == "required":
                blocking.append(requirement.coverage_key)
            continue
        status = _status(state)
        if requirement.priority != "required":
            continue
        if status == "captured":
            transition = state["transition"]
            _verify_evidence(workspace, state["request"], transition)
            if not _screenshot_source_embedded(
                workspace, state["request"], transition
            ):
                blocking.append(f"{requirement.coverage_key}:not-embedded")
        elif status == "waived":
            waived.append(requirement.coverage_key)
            blocking.append(f"{requirement.coverage_key}:waived")
        else:
            blocking.append(requirement.coverage_key)
    return missing, blocking, waived


def reconcile_screenshots(
    args: argparse.Namespace, now: datetime | None = None
) -> int:
    workspace = _resolve_active(Path(args.workspace))
    try:
        requirements = report_contract.derive_screenshot_requirements(workspace)
    except report_contract.ReportContractError as exc:
        raise ScreenshotError(str(exc)) from exc
    ledger = workspace / LEDGER_NAME
    if ledger.exists() or ledger.is_symlink():
        states = _effective(_load_events(ledger))
    else:
        states = {}
    missing, _, _ = _coverage_state(workspace, requirements, states)
    generatable = [item for item in missing if not item.legacy_missing]
    legacy = [item for item in missing if item.legacy_missing]
    print(f"mode: {'apply' if args.apply else 'preview'}")
    print(f"derived_requirements: {len(requirements)}")
    print(f"new_requests: {len(generatable)}")
    print(f"legacy_missing: {len(legacy)}")
    for item in missing:
        status = "legacy_missing" if item.legacy_missing else "planned"
        print(
            f"coverage: {item.coverage_key} {item.host_id} "
            f"{item.priority} {status}"
        )
    if not args.apply:
        return 1 if any(item.priority == "required" for item in missing) else 0
    base = now or datetime.now(UTC)
    for index, item in enumerate(generatable):
        request_args = argparse.Namespace(
            workspace=str(workspace),
            host_id=item.host_id,
            stage=item.stage,
            priority=item.priority,
            reason=item.reason,
            interface=item.interface,
            protocol=item.protocol,
            port=item.port,
            endpoint=item.endpoint,
            url=item.safe_url,
            service=item.service,
            credential_id=None,
            login_authorized=False,
            command=None,
            steps=list(item.steps),
            must_include=list(item.must_include),
            must_exclude=list(item.must_exclude),
            slug=f"{item.stage}-{(item.report_step_id or item.host_id).lower()}",
            reproducibility=item.reproducibility,
            attempt_id=item.attempt_id,
            evidence_ids=list(item.evidence_ids),
            query_ids=list(item.query_ids),
            path_event_id=item.path_event_id,
            coverage_key=item.coverage_key,
            report_step_id=item.report_step_id,
            derived_reconcile=True,
        )
        request_screenshot(request_args, base + timedelta(microseconds=index))
    return 1 if any(item.priority == "required" for item in legacy) else 0


def report_check(args: argparse.Namespace) -> int:
    workspace = _resolve_active(Path(args.workspace))
    profile = operational_profile.workspace_profile(workspace)
    print(f"validation_barrier: {args.barrier}")
    requested_contract = getattr(args, "contract", "auto")
    contract = (
        "engagement"
        if requested_contract == "auto"
        and profile == operational_profile.CONTROLLED_ENGAGEMENT
        else (
            "operational" if requested_contract == "auto" else requested_contract
        )
    )
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    managed = engagement_config.load(workspace)
    if managed is not None:
        configured = managed["definition"]["report_contract"]
        if requested_contract not in {"auto", configured}:
            raise ValueError("report contract override conflicts with the reviewed engagement configuration")
        contract = configured
    ledger = workspace / LEDGER_NAME
    blockers: list[str] = []
    waived: list[str] = []
    required = 0
    states: dict[str, dict[str, Any]] = {}
    if ledger.exists() or ledger.is_symlink():
        events = _load_events(ledger)
        states = _effective(events)
        for state in states.values():
            request = state["request"]
            status = _status(state)
            _validate_references(workspace, request)
            if status == "captured":
                _verify_evidence(workspace, request, state["transition"])
            if request["priority"] == "required":
                required += 1
                if status in {"pending", "needs_recapture"}:
                    blockers.append(request["operator_id"])
                elif status == "waived":
                    waived.append(request["operator_id"])
    token_state = closure_readiness(workspace)
    token_warnings: tuple[str, ...] = ()
    token_blockers = () if token_warnings else token_state.blockers
    if contract == "operational":
        ready = not blockers and not token_blockers
        print(f"operational_profile: {profile}")
        print(f"report_contract: {contract}")
        print(f"report_ready: {'yes' if ready else 'no'}")
        print(f"required_requests: {required}")
        print(f"blocking_requests: {len(blockers)}")
        print(f"waived_requests: {len(waived)}")
        if blockers:
            print(f"blocking_ids: {','.join(blockers)}")
        if waived:
            print(f"waived_risk_ids: {','.join(waived)}")
        print(f"token_records: {token_state.total}")
        print(f"resolved_tokens: {token_state.resolved}")
        print(f"blocking_tokens: {len(token_blockers)}")
        if token_blockers:
            print(f"blocking_token_ids: {','.join(token_blockers)}")
        print(f"warning_tokens: {len(token_warnings)}")
        if token_warnings:
            print(f"warning_token_ids: {','.join(token_warnings)}")
        return 0 if ready else 1
    try:
        requirements = report_contract.derive_screenshot_requirements(workspace)
        contract_state = report_contract.evaluate_contract(workspace)
    except report_contract.ReportContractError as exc:
        raise ScreenshotError(str(exc)) from exc
    missing, coverage_blockers, coverage_waived = _coverage_state(
        workspace, requirements, states
    )
    for state in states.values():
        request = state["request"]
        if request["priority"] != "required":
            continue
        status = _status(state)
        key = _request_coverage_key(request) or request["operator_id"]
        if status == "captured":
            if not _screenshot_source_embedded(
                workspace, request, state["transition"]
            ):
                coverage_blockers.append(f"{key}:not-embedded")
        elif status == "waived":
            coverage_blockers.append(f"{key}:waived")
            coverage_waived.append(key)
        elif key not in coverage_blockers:
            coverage_blockers.append(key)
    screenshot_ready = not coverage_blockers
    documentation_ready = (
        contract_state.content_ready
        and screenshot_ready
        and contract_state.credential_ready
        and contract_state.query_appendix_ready
        and not token_blockers
    )
    print(f"operational_profile: {profile}")
    print(f"report_contract: {contract}")
    print(f"report_ready: {'yes' if documentation_ready else 'no'}")
    print(
        f"report_content_ready: "
        f"{'yes' if contract_state.content_ready else 'no'}"
    )
    print(f"screenshot_ready: {'yes' if screenshot_ready else 'no'}")
    print(
        f"credential_ready: "
        f"{'yes' if contract_state.credential_ready else 'no'}"
    )
    print(
        f"query_appendix_ready: "
        f"{'yes' if contract_state.query_appendix_ready else 'no'}"
    )
    print("render_ready: not_evaluated")
    print("submission_ready: not_evaluated")
    print(f"manifest_targets: {contract_state.manifest_targets}")
    print(f"active_report_steps: {contract_state.active_steps}")
    print(f"derived_requirements: {len(requirements)}")
    print(f"legacy_missing: {sum(item.legacy_missing for item in missing)}")
    print(f"required_requests: {required}")
    print(f"blocking_requests: {len(set(coverage_blockers))}")
    print(f"waived_requests: {len(set(coverage_waived))}")
    if coverage_blockers:
        print(f"blocking_ids: {','.join(sorted(set(coverage_blockers)))}")
    if coverage_waived:
        print(f"waived_risk_ids: {','.join(sorted(set(coverage_waived)))}")
    if contract_state.blockers:
        print(f"content_blockers: {','.join(contract_state.blockers)}")
    print(f"token_records: {token_state.total}")
    print(f"resolved_tokens: {token_state.resolved}")
    print(f"blocking_tokens: {len(token_blockers)}")
    if token_blockers:
        print(f"blocking_token_ids: {','.join(token_blockers)}")
    print(f"warning_tokens: {len(token_warnings)}")
    if token_warnings:
        print(f"warning_token_ids: {','.join(token_warnings)}")
    return 0 if documentation_ready else 1


def _common_workspace(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_COLLECTION),
        help="module workspace or active task collection",
    )


def screenshot_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage operator-driven screenshot evidence."
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)
    request = subparsers.add_parser("request", help="create a screenshot request")
    _common_workspace(request)
    request.add_argument("--host-id", required=True)
    request.add_argument("--stage", required=True, choices=sorted(STAGES))
    request.add_argument("--priority", default="required", choices=sorted(PRIORITIES))
    request.add_argument("--reason", required=True)
    request.add_argument("--interface", required=True, choices=sorted(INTERFACES))
    request.add_argument("--protocol", required=True)
    request.add_argument("--port", type=int)
    request.add_argument("--endpoint")
    request.add_argument("--url")
    request.add_argument("--service")
    request.add_argument("--credential-id")
    request.add_argument("--login-authorized", action="store_true")
    request.add_argument(
        "--contains-secrets",
        action="store_true",
        help="declare that necessary engagement secret values may appear in PNG pixels",
    )
    request.add_argument("--command")
    request.add_argument("--step", action="append", dest="steps")
    request.add_argument("--must-include", action="append")
    request.add_argument("--must-exclude", action="append")
    request.add_argument("--slug", required=True)
    request.add_argument(
        "--reproducibility",
        choices=("repeatable", "time-sensitive"),
        default="repeatable",
    )
    request.add_argument("--attempt-id")
    request.add_argument("--evidence-id", action="append", dest="evidence_ids")
    request.add_argument("--query-id", action="append", dest="query_ids")
    request.add_argument("--path-event-id")
    review = subparsers.add_parser(
        "review", help="accept or reject a visually reviewed PNG"
    )
    _common_workspace(review)
    review.add_argument(
        "--screenshot-id", required=True, help="operator-facing ID, e.g. S001"
    )
    decision = review.add_mutually_exclusive_group(required=True)
    decision.add_argument("--accept", action="store_true")
    decision.add_argument("--reject", action="store_true")
    review.add_argument("--visual-reviewed", action="store_true")
    review.add_argument(
        "--secret-scope-reviewed",
        action="store_true",
        help="confirm that only necessary in-scope engagement secrets are visible",
    )
    review.add_argument("--caption")
    review.add_argument("--reason")
    waive = subparsers.add_parser(
        "waive", help="waive a screenshot with an explicit reason"
    )
    _common_workspace(waive)
    waive.add_argument("--screenshot-id", required=True)
    waive.add_argument("--reason", required=True)
    waive.add_argument("--authorization-id")
    waive.add_argument(
        "--alternative-evidence-id",
        action="append",
        dest="alternative_evidence_ids",
    )
    reconcile = subparsers.add_parser(
        "reconcile", help="derive missing screenshot requests from canonical events"
    )
    _common_workspace(reconcile)
    reconcile_mode = reconcile.add_mutually_exclusive_group(required=True)
    reconcile_mode.add_argument("--preview", action="store_true")
    reconcile_mode.add_argument("--apply", action="store_true")
    status = subparsers.add_parser(
        "status", help="show metadata-only screenshot coverage"
    )
    _common_workspace(status)
    return parser


def screenshot_main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    args = screenshot_parser().parse_args(argv)
    try:
        if args.command_name == "request":
            request_screenshot(args, now)
        elif args.command_name == "review":
            review_screenshot(args, now)
        elif args.command_name == "waive":
            waive_screenshot(args, now)
        elif args.command_name == "reconcile":
            return reconcile_screenshots(args, now)
        else:
            return status_screenshots(args)
    except (
        ScreenshotError,
        operational_profile.OperationalProfileError,
        TokenLifecycleError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        report_contract.ReportContractError,
    ) as exc:
        _fatal(str(exc))
    return 0


def report_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage the canonical Cyber-Operator engagement report contract."
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)
    check = subparsers.add_parser(
        "check", help="check required screenshots and token closure"
    )
    _common_workspace(check)
    check.add_argument(
        "--contract",
        choices=("auto", "operational", "engagement"),
        default="auto",
    )
    check.add_argument(
        "--barrier",
        choices=report_contract.VALIDATION_BARRIERS,
        required=True,
        help="declare the milestone that justifies a full workspace report check",
    )
    manifest = subparsers.add_parser(
        "manifest", help="preview or apply one validated engagement manifest"
    )
    _common_workspace(manifest)
    manifest.add_argument("--input", required=True)
    manifest_mode = manifest.add_mutually_exclusive_group(required=True)
    manifest_mode.add_argument("--preview", action="store_true")
    manifest_mode.add_argument("--apply", action="store_true")
    manifest.add_argument("--replace", action="store_true")
    adjudication = subparsers.add_parser(
        "secret-adjudication",
        help="review exact retroactive credential-substring matches in report steps",
    )
    _common_workspace(adjudication)
    adjudication.add_argument("--credential-id", required=True)
    adjudication_mode = adjudication.add_mutually_exclusive_group(required=True)
    adjudication_mode.add_argument("--preview", action="store_true")
    adjudication_mode.add_argument("--apply", action="store_true")
    adjudication.add_argument(
        "--ack-reviewed-false-positives",
        action="store_true",
        help="confirm every listed match is ordinary metadata, not the credential",
    )
    step = subparsers.add_parser("step", help="append a report-step lifecycle event")
    step_actions = step.add_subparsers(dest="step_action", required=True)
    plan = step_actions.add_parser("plan", help="append a new planned report step")
    _common_workspace(plan)
    plan.add_argument("--host-id", required=True)
    plan.add_argument("--record", required=True)
    for event in ("complete", "failed", "partial", "legacy-missing"):
        outcome = step_actions.add_parser(event, help=f"append a {event} outcome")
        _common_workspace(outcome)
        outcome.add_argument("--step-id", required=True)
        outcome.add_argument("--record", required=True)
    supersede = step_actions.add_parser(
        "supersede", help="supersede one open step with a replacement"
    )
    _common_workspace(supersede)
    supersede.add_argument("--step-id", required=True)
    supersede.add_argument("--replacement-step-id", required=True)
    supersede.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command_name == "check":
            return report_check(args)
        workspace = _resolve_active(Path(args.workspace))
        if args.command_name == "manifest":
            action = report_contract.apply_manifest(
                workspace,
                Path(args.input),
                apply=args.apply,
                replace=args.replace,
            )
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"manifest_action: {action}")
            print(f"manifest_path: {workspace / report_contract.MANIFEST_NAME}")
            return 0
        if args.command_name == "secret-adjudication":
            result = report_contract.adjudicate_retroactive_step_secret_matches(
                workspace,
                args.credential_id,
                apply=args.apply,
                acknowledged=args.ack_reviewed_false_positives,
            )
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"credential_id: {result['credential_id']}")
            print(f"candidate_matches: {result['candidate_count']}")
            print(f"existing_matches: {result['existing_count']}")
            for match in result["matches"]:
                print(
                    "match: "
                    f"{match['step_event_id']} {match['field_path']} "
                    f"sha256:{match['field_sha256']}"
                )
            return 0
        if args.step_action == "plan":
            record = report_contract.plan_step(
                workspace, args.host_id, Path(args.record)
            )
        elif args.step_action == "supersede":
            record = report_contract.supersede_step(
                workspace,
                args.step_id,
                args.replacement_step_id,
                args.reason,
            )
        else:
            event = "completed" if args.step_action == "complete" else args.step_action.replace("-", "_")
            record = report_contract.transition_step(
                workspace, args.step_id, event, Path(args.record)
            )
        print(f"step_id: {record['step_id']}")
        print(f"event: {record['event']}")
        return 0
    except (
        ScreenshotError,
        operational_profile.OperationalProfileError,
        TokenLifecycleError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        report_contract.ReportContractError,
    ) as exc:
        _fatal(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(screenshot_main())
