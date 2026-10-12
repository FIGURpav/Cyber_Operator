"""Append-only findings, work items, and local-processing artifact metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import artifact_handling, host_identity, ledger_io, operational_trace
else:
    import artifact_handling
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]
    import operational_trace  # type: ignore[no-redef]

FINDING_LEDGER = "findings.jsonl"
WORK_ITEM_LEDGER = "work_items.jsonl"
LOCAL_ARTIFACT_LEDGER = "local_artifacts.jsonl"

HOST_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
FINDING_RE = re.compile(r"^FND-\d{8}T\d{12}Z$")
FINDING_EVENT_RE = re.compile(r"^FNE-\d{8}T\d{12}Z$")
WORK_ITEM_RE = re.compile(r"^WKI-\d{8}T\d{12}Z$")
WORK_ITEM_EVENT_RE = re.compile(r"^WIE-\d{8}T\d{12}Z$")
LOCAL_ARTIFACT_RE = re.compile(r"^LAR-\d{8}T\d{12}Z$")
LOCAL_ARTIFACT_EVENT_RE = re.compile(r"^LAE-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
REFERENCE_RE = re.compile(r"^(?:ATT|EVD|CLM)-\d{8}T\d{12}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

FINDING_STATES = ("hypothesis", "confirmed", "disproved", "unresolved")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
WORK_KINDS = ("assessment-task", "recon")
WORK_STATES = ("identified", "in_progress", "locally_complete", "blocked", "reviewed")
LOCAL_ARTIFACT_STATES = ("registered", "in_use", "retained", "disposed", "missing")
LOCAL_ARTIFACT_CLASSES = (
    "ssh-key", "certificate", "cracking-input", "database", "helper", "other"
)
MAX_LEDGER = 32 * 1024 * 1024
MAX_RECORD = 64 * 1024


class StructuredStateError(ValueError):
    """A bounded structured-state validation failure."""


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _text(value: str | None, name: str, maximum: int, *, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise StructuredStateError(f"{name} is required")
        return None
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise StructuredStateError(f"{name} must be bounded printable single-line text")
    if required and not value:
        raise StructuredStateError(f"{name} is required")
    if len(value) > maximum:
        raise StructuredStateError(f"{name} exceeds {maximum} characters")
    return value or None


def _choice(value: str, name: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise StructuredStateError(f"{name} must be one of: {', '.join(choices)}")
    return value


def _workspace(path: str | Path) -> Path:
    try:
        return operational_trace.validate_workspace(path)
    except operational_trace.TraceError as exc:
        raise StructuredStateError(str(exc)) from exc


def _host_ids(root: Path, values: list[str]) -> list[str]:
    if not values:
        raise StructuredStateError("at least one host-id is required")
    known = {item.host_id for item in host_identity.discover_hosts(root)}
    result: list[str] = []
    for value in values:
        if HOST_RE.fullmatch(value) is None:
            raise StructuredStateError("host-id must use canonical Hxx form")
        try:
            value = host_identity.canonical_host_id(root, value)
        except host_identity.HostIdentityError as exc:
            raise StructuredStateError(str(exc)) from exc
        if value not in known:
            raise StructuredStateError(f"unknown host-id: {value}")
        if value not in result:
            result.append(value)
    return sorted(result)


def _references(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        normalized = _text(value, "reference", 80)
        assert normalized is not None
        if REFERENCE_RE.fullmatch(normalized) is None:
            raise StructuredStateError("reference must be an ATT-, EVD-, or CLM-ID")
        if normalized not in result:
            result.append(normalized)
    return sorted(result)


def _validate_reference_existence(root: Path, values: set[str]) -> None:
    if not values:
        return
    available: set[str] = set()
    try:
        if any(value.startswith("ATT-") for value in values):
            available.update(operational_trace._attempt_index(root))
        if any(value.startswith("EVD-") for value in values):
            available.update(operational_trace._evidence_ids(root))
    except operational_trace.TraceError as exc:
        raise StructuredStateError(str(exc)) from exc
    if any(value.startswith("CLM-") for value in values):
        if __package__:
            from . import execution_provenance
        else:
            import execution_provenance
        try:
            available.update(execution_provenance.load_claims(root))
        except ValueError as exc:
            raise StructuredStateError(str(exc)) from exc
    missing = sorted(values - available)
    if missing:
        raise StructuredStateError(
            f"reference does not exist in canonical state: {missing[0]}"
        )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() and not path.is_symlink():
        return []
    try:
        info = path.lstat()
    except OSError as exc:
        raise StructuredStateError(f"cannot inspect {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StructuredStateError(f"{path.name} must be a dedicated regular file")
    if info.st_size > MAX_LEDGER:
        raise StructuredStateError(f"{path.name} exceeds its size limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StructuredStateError(f"cannot read {path.name}") from exc
    if raw and not raw.endswith(b"\n"):
        raise StructuredStateError(f"{path.name} has an unterminated final record")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line or len(line) > MAX_RECORD:
            raise StructuredStateError(f"{path.name} line {number} is invalid")
        try:
            record = ledger_io.loads_json(line)
        except ledger_io.LedgerIOError as exc:
            raise StructuredStateError(f"{path.name} line {number} is invalid") from exc
        if not isinstance(record, dict):
            raise StructuredStateError(f"{path.name} line {number} must be an object")
        records.append(record)
    return records


def _event_time(record: dict[str, Any], event_field: str, prefix: str) -> None:
    event_id = record.get(event_field)
    created = record.get("created_at_utc")
    pattern = {
        "FNE": FINDING_EVENT_RE,
        "WIE": WORK_ITEM_EVENT_RE,
        "LAE": LOCAL_ARTIFACT_EVENT_RE,
    }[prefix]
    if not isinstance(event_id, str) or pattern.fullmatch(event_id) is None:
        raise StructuredStateError(f"malformed {event_field}")
    if not isinstance(created, str) or TIMESTAMP_RE.fullmatch(created) is None:
        raise StructuredStateError("malformed created_at_utc")
    try:
        moment = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise StructuredStateError("malformed created_at_utc") from exc
    if event_id != _identifier(prefix, moment):
        raise StructuredStateError("event ID and timestamp do not match")


def _reject_secrets(root: Path, values: list[Any]) -> None:
    try:
        operational_trace._reject_secret_content(root, [json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value for value in values if value])
    except operational_trace.TraceError as exc:
        raise StructuredStateError(str(exc)) from exc


def load_findings(
    workspace: str | Path,
    *,
    known_host_ids: set[str] | None = None,
    known_reference_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    root = _workspace(workspace)
    records = _read_jsonl(root / FINDING_LEDGER)
    # Historical ledger rows remain immutable after an Hxx merge.  Accept both
    # active and archived source IDs here; projections canonicalize them through
    # historical_host_map without rewriting the retained event.
    known_hosts = (
        host_identity.known_host_ids(root)
        if known_host_ids is None
        else set(known_host_ids)
    )
    histories: dict[str, list[dict[str, Any]]] = {}
    event_ids: set[str] = set()
    referenced: set[str] = set()
    for number, record in enumerate(records, start=1):
        source = f"{FINDING_LEDGER} line {number}"
        expected = {
            "schema_version", "finding_event_id", "finding_id", "created_at_utc",
            "state", "host_ids", "severity", "title", "service", "endpoint",
            "impact", "remediation", "references", "note",
        }
        if set(record) != expected or record.get("schema_version") != "1.0":
            raise StructuredStateError(f"{source} has an invalid schema")
        _event_time(record, "finding_event_id", "FNE")
        if record["finding_event_id"] in event_ids:
            raise StructuredStateError(f"{source} duplicates an event ID")
        event_ids.add(record["finding_event_id"])
        if not isinstance(record["finding_id"], str) or FINDING_RE.fullmatch(record["finding_id"]) is None:
            raise StructuredStateError(f"{source} has a malformed finding ID")
        if record["state"] not in FINDING_STATES or record["severity"] not in SEVERITIES:
            raise StructuredStateError(f"{source} has an unsupported state or severity")
        if not isinstance(record["host_ids"], list) or not record["host_ids"] or any(
            not isinstance(value, str) or value not in known_hosts for value in record["host_ids"]
        ):
            raise StructuredStateError(f"{source} references an unknown host")
        if not isinstance(record["references"], list) or any(
            not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None
            for value in record["references"]
        ):
            raise StructuredStateError(f"{source} has malformed references")
        if record["state"] == "confirmed" and not record["references"]:
            raise StructuredStateError(
                f"{source} confirmed finding requires retained references"
            )
        referenced.update(record["references"])
        for field, maximum, required in (
            ("title", 240, True), ("service", 128, False), ("endpoint", 1024, False),
            ("impact", 2048, True), ("remediation", 2048, False), ("note", 1024, False),
        ):
            _text(record[field] or None, field, maximum, required=required)
        history = histories.setdefault(record["finding_id"], [])
        if not history:
            created = datetime.strptime(record["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            if record["finding_id"] != _identifier("FND", created):
                raise StructuredStateError(f"{source} finding ID and timestamp do not match")
        else:
            immutable = ("host_ids", "severity", "title", "service", "endpoint", "impact", "remediation")
            if any(record[field] != history[0][field] for field in immutable):
                raise StructuredStateError(f"{source} changes immutable finding metadata")
        history.append(record)
    if known_reference_ids is None:
        _validate_reference_existence(root, referenced)
    elif not referenced.issubset(known_reference_ids):
        missing = sorted(referenced - known_reference_ids)
        raise StructuredStateError(
            f"reference does not exist in canonical state: {missing[0]}"
        )
    return records


def finding_states(
    workspace: str | Path,
    *,
    known_host_ids: set[str] | None = None,
    known_reference_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    return {
        record["finding_id"]: record
        for record in load_findings(
            workspace,
            known_host_ids=known_host_ids,
            known_reference_ids=known_reference_ids,
        )
    }


def create_finding(
    workspace: str | Path, *, host_ids: list[str], state: str, severity: str,
    title: str, service: str | None = None, endpoint: str | None = None,
    impact: str | None = None, remediation: str | None = None,
    references: list[str] | None = None, note: str | None = None,
    apply: bool = False, now: datetime | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    moment = now or datetime.now(UTC)
    record = {
        "schema_version": "1.0", "finding_event_id": _identifier("FNE", moment),
        "finding_id": _identifier("FND", moment), "created_at_utc": _timestamp(moment),
        "state": _choice(state, "state", FINDING_STATES), "host_ids": _host_ids(root, host_ids),
        "severity": _choice(severity, "severity", SEVERITIES),
        "title": _text(title, "title", 240), "service": _text(service, "service", 128, required=False),
        "endpoint": _text(endpoint, "endpoint", 1024, required=False),
        "impact": _text(impact, "impact", 2048),
        "remediation": _text(remediation, "remediation", 2048, required=False),
        "references": _references(references or []), "note": _text(note, "note", 1024, required=False),
    }
    if record["state"] == "confirmed" and not record["references"]:
        raise StructuredStateError(
            "confirmed finding requires at least one ATT-, EVD-, or CLM-ID"
        )
    _validate_reference_existence(root, set(record["references"]))
    _reject_secrets(root, [record[field] for field in ("title", "service", "endpoint", "impact", "remediation", "note")])
    if apply:
        with ledger_io.exclusive_ledger_lock(root / FINDING_LEDGER):
            load_findings(root)
            ledger_io.append_json_record(root / FINDING_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def transition_finding(
    workspace: str | Path, *, finding_id: str, state: str,
    references: list[str] | None = None, note: str | None = None,
    apply: bool = False, now: datetime | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    states = finding_states(root)
    if finding_id not in states:
        raise StructuredStateError("finding-id does not exist")
    previous = states[finding_id]
    moment = now or datetime.now(UTC)
    record = dict(previous)
    record.update(
        finding_event_id=_identifier("FNE", moment), created_at_utc=_timestamp(moment),
        state=_choice(state, "state", FINDING_STATES),
        references=sorted(set(previous["references"]) | set(_references(references or []))),
        note=_text(note, "note", 1024, required=False),
    )
    if record["state"] == "confirmed" and not record["references"]:
        raise StructuredStateError(
            "confirmed finding requires at least one ATT-, EVD-, or CLM-ID"
        )
    _validate_reference_existence(root, set(record["references"]))
    _reject_secrets(root, [record["note"]])
    if apply:
        with ledger_io.exclusive_ledger_lock(root / FINDING_LEDGER):
            current = finding_states(root).get(finding_id)
            if current != previous:
                raise StructuredStateError("finding state changed after preview")
            ledger_io.append_json_record(root / FINDING_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def _review(state: str, reviewer: str | None, basis: str | None, now: datetime) -> dict[str, str] | None:
    if state != "reviewed":
        if reviewer is not None or basis is not None:
            raise StructuredStateError("review metadata requires state reviewed")
        return None
    if not reviewer or not basis:
        raise StructuredStateError("reviewed requires reviewer and review_basis")
    return {"reviewer_id": _text(reviewer, "reviewer", 128),
            "reviewed_at_utc": _timestamp(now), "basis": _text(basis, "review_basis", 1024)}


def _validate_review(record: dict[str, Any]) -> None:
    review = record["review"]
    if record["state"] != "reviewed":
        if review is not None:
            raise StructuredStateError("review metadata requires state reviewed")
        return
    if not isinstance(review, dict) or set(review) != {"reviewer_id", "reviewed_at_utc", "basis"}:
        raise StructuredStateError("reviewed state has incomplete review metadata")
    _text(review["reviewer_id"], "reviewer", 128)
    _text(review["basis"], "review_basis", 1024)
    if review["reviewed_at_utc"] != record["created_at_utc"]:
        raise StructuredStateError("review timestamp must match the review event")


def load_work_items(
    workspace: str | Path,
    *,
    known_host_ids: set[str] | None = None,
    known_reference_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    root = _workspace(workspace)
    records = _read_jsonl(root / WORK_ITEM_LEDGER)
    known_hosts = (
        host_identity.known_host_ids(root)
        if known_host_ids is None
        else set(known_host_ids)
    )
    histories: dict[str, list[dict[str, Any]]] = {}
    event_ids: set[str] = set()
    referenced: set[str] = set()
    for number, record in enumerate(records, start=1):
        source = f"{WORK_ITEM_LEDGER} line {number}"
        expected = {
            "schema_version", "work_item_event_id", "work_item_id", "created_at_utc",
            "kind", "external_ref", "host_ids", "state", "summary", "references", "note", "owner", "review",
        }
        if set(record) != expected or record.get("schema_version") != "2.0":
            raise StructuredStateError(f"{source} has an invalid schema")
        _event_time(record, "work_item_event_id", "WIE")
        if record["work_item_event_id"] in event_ids:
            raise StructuredStateError(f"{source} duplicates an event ID")
        event_ids.add(record["work_item_event_id"])
        if not isinstance(record["work_item_id"], str) or WORK_ITEM_RE.fullmatch(record["work_item_id"]) is None:
            raise StructuredStateError(f"{source} has a malformed work-item ID")
        if record["kind"] not in WORK_KINDS or record["state"] not in WORK_STATES:
            raise StructuredStateError(f"{source} has an unsupported kind or state")
        if not isinstance(record["host_ids"], list) or any(value not in known_hosts for value in record["host_ids"]):
            raise StructuredStateError(f"{source} references an unknown host")
        _text(record["owner"], "owner", 128)
        _validate_review(record)
        _text(record["external_ref"], "external_ref", 160)
        _text(record["summary"], "summary", 1024)
        _text(record["note"] or None, "note", 1024, required=False)
        if not isinstance(record["references"], list) or any(
            not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None for value in record["references"]
        ):
            raise StructuredStateError(f"{source} has malformed references")
        referenced.update(record["references"])
        history = histories.setdefault(record["work_item_id"], [])
        if not history:
            created = datetime.strptime(record["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            if record["work_item_id"] != _identifier("WKI", created):
                raise StructuredStateError(f"{source} work-item ID and timestamp do not match")
        elif any(record[field] != history[0][field] for field in ("kind", "external_ref", "host_ids", "summary", "owner")):
            raise StructuredStateError(f"{source} changes immutable work-item metadata")
        history.append(record)
    if known_reference_ids is None:
        _validate_reference_existence(root, referenced)
    elif not referenced.issubset(known_reference_ids):
        missing = sorted(referenced - known_reference_ids)
        raise StructuredStateError(
            f"reference does not exist in canonical state: {missing[0]}"
        )
    return records


def work_item_states(
    workspace: str | Path,
    *,
    known_host_ids: set[str] | None = None,
    known_reference_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    return {
        record["work_item_id"]: record
        for record in load_work_items(
            workspace,
            known_host_ids=known_host_ids,
            known_reference_ids=known_reference_ids,
        )
    }


def create_work_item(
    workspace: str | Path, *, kind: str, external_ref: str, host_ids: list[str],
    state: str, summary: str, references: list[str] | None = None,
    note: str | None = None, apply: bool = False, now: datetime | None = None,
    owner: str = "unassigned", reviewer: str | None = None, review_basis: str | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    moment = now or datetime.now(UTC)
    record = {
        "schema_version": "2.0", "work_item_event_id": _identifier("WIE", moment),
        "work_item_id": _identifier("WKI", moment), "created_at_utc": _timestamp(moment),
        "kind": _choice(kind, "kind", WORK_KINDS), "external_ref": _text(external_ref, "external_ref", 160),
        "host_ids": _host_ids(root, host_ids) if host_ids else [],
        "state": _choice(state, "state", WORK_STATES), "summary": _text(summary, "summary", 1024),
        "references": _references(references or []), "note": _text(note, "note", 1024, required=False),
    }
    record["owner"] = _text(owner, "owner", 128)
    record["review"] = _review(state, reviewer, review_basis, moment)
    _reject_secrets(root, [record["owner"], record["review"], record["external_ref"], record["summary"], record["note"]])
    _validate_reference_existence(root, set(record["references"]))
    if apply:
        with ledger_io.exclusive_ledger_lock(root / WORK_ITEM_LEDGER):
            load_work_items(root)
            ledger_io.append_json_record(root / WORK_ITEM_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def transition_work_item(
    workspace: str | Path, *, work_item_id: str, state: str,
    references: list[str] | None = None, note: str | None = None,
    apply: bool = False, now: datetime | None = None,
    reviewer: str | None = None, review_basis: str | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    states = work_item_states(root)
    if work_item_id not in states:
        raise StructuredStateError("work-item-id does not exist")
    previous = states[work_item_id]
    moment = now or datetime.now(UTC)
    record = dict(previous)
    record.update(
        work_item_event_id=_identifier("WIE", moment), created_at_utc=_timestamp(moment),
        state=_choice(state, "state", WORK_STATES),
        references=sorted(set(previous["references"]) | set(_references(references or []))),
        note=_text(note, "note", 1024, required=False),
    )
    record["review"] = _review(state, reviewer, review_basis, moment)
    _reject_secrets(root, [record["review"], record["note"]])
    _validate_reference_existence(root, set(record["references"]))
    if apply:
        with ledger_io.exclusive_ledger_lock(root / WORK_ITEM_LEDGER):
            current = work_item_states(root).get(work_item_id)
            if current != previous:
                raise StructuredStateError("work-item state changed after preview")
            ledger_io.append_json_record(root / WORK_ITEM_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def _local_processing_path(root: Path, value: str) -> tuple[Path, str]:
    supplied = Path(value)
    path = supplied if supplied.is_absolute() else root / supplied
    try:
        relative = path.resolve(strict=False).relative_to((root / "private/local_processing").resolve(strict=False))
    except ValueError as exc:
        raise StructuredStateError("artifact path must be inside private/local_processing") from exc
    if not relative.parts or ".." in relative.parts:
        raise StructuredStateError("artifact path must name one local-processing file")
    canonical = Path("private/local_processing") / relative
    return root / canonical, canonical.as_posix()


def _artifact_metadata(path: Path) -> tuple[int, str]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise StructuredStateError("local artifact is unavailable") from exc
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
            raise StructuredStateError("local artifact must be a private regular file")
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            if size > 1024 * 1024 * 1024:
                raise StructuredStateError("local artifact exceeds its size limit")
            digest.update(block)
    return size, digest.hexdigest()


def load_local_artifacts(
    workspace: str | Path, *, known_host_ids: set[str] | None = None
) -> list[dict[str, Any]]:
    root = _workspace(workspace)
    records = _read_jsonl(root / LOCAL_ARTIFACT_LEDGER)
    histories: dict[str, list[dict[str, Any]]] = {}
    event_ids: set[str] = set()
    known_hosts = (
        host_identity.known_host_ids(root)
        if known_host_ids is None
        else set(known_host_ids)
    )
    for number, record in enumerate(records, start=1):
        source = f"{LOCAL_ARTIFACT_LEDGER} line {number}"
        expected = {
            "schema_version", "local_artifact_event_id", "local_artifact_id", "created_at_utc",
            "state", "host_ids", "artifact_class", "purpose", "relative_path", "size_bytes",
            "sha256", "note",
        }
        if set(record) != expected or record.get("schema_version") != "1.0":
            raise StructuredStateError(f"{source} has an invalid schema")
        _event_time(record, "local_artifact_event_id", "LAE")
        if record["local_artifact_event_id"] in event_ids:
            raise StructuredStateError(f"{source} duplicates an event ID")
        event_ids.add(record["local_artifact_event_id"])
        if not isinstance(record["local_artifact_id"], str) or LOCAL_ARTIFACT_RE.fullmatch(record["local_artifact_id"]) is None:
            raise StructuredStateError(f"{source} has a malformed local-artifact ID")
        if record["state"] not in LOCAL_ARTIFACT_STATES or record["artifact_class"] not in LOCAL_ARTIFACT_CLASSES:
            raise StructuredStateError(f"{source} has an unsupported state or class")
        if not isinstance(record["host_ids"], list) or any(value not in known_hosts for value in record["host_ids"]):
            raise StructuredStateError(f"{source} references an unknown host")
        if type(record["size_bytes"]) is not int or record["size_bytes"] < 0:
            raise StructuredStateError(f"{source} has an invalid size")
        if not isinstance(record["sha256"], str) or SHA256_RE.fullmatch(record["sha256"]) is None:
            raise StructuredStateError(f"{source} has an invalid hash")
        path, relative = _local_processing_path(root, record["relative_path"])
        if relative != record["relative_path"]:
            raise StructuredStateError(f"{source} has a non-canonical path")
        _text(record["purpose"], "purpose", 512)
        _text(record["note"] or None, "note", 1024, required=False)
        history = histories.setdefault(record["local_artifact_id"], [])
        if not history:
            created = datetime.strptime(record["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            if record["local_artifact_id"] != _identifier("LAR", created) or record["state"] != "registered":
                raise StructuredStateError(f"{source} must begin with a matching registered event")
        elif any(record[field] != history[0][field] for field in (
            "host_ids", "artifact_class", "purpose", "relative_path", "size_bytes", "sha256"
        )):
            raise StructuredStateError(f"{source} changes immutable artifact metadata")
        history.append(record)
        _ = path
    return records


def local_artifact_states(
    workspace: str | Path, *, known_host_ids: set[str] | None = None
) -> dict[str, dict[str, Any]]:
    return {
        record["local_artifact_id"]: record
        for record in load_local_artifacts(
            workspace, known_host_ids=known_host_ids
        )
    }


def register_local_artifact(
    workspace: str | Path, *, path: str, artifact_class: str, purpose: str,
    host_ids: list[str] | None = None, note: str | None = None,
    apply: bool = False, now: datetime | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    try:
        artifact_handling.require_local_persistence(root, "target-file")
    except artifact_handling.ArtifactHandlingError as exc:
        raise StructuredStateError(str(exc)) from exc
    artifact, relative = _local_processing_path(root, path)
    size, digest = _artifact_metadata(artifact)
    moment = now or datetime.now(UTC)
    record = {
        "schema_version": "1.0", "local_artifact_event_id": _identifier("LAE", moment),
        "local_artifact_id": _identifier("LAR", moment), "created_at_utc": _timestamp(moment),
        "state": "registered", "host_ids": _host_ids(root, host_ids or []) if host_ids else [],
        "artifact_class": _choice(artifact_class, "artifact-class", LOCAL_ARTIFACT_CLASSES),
        "purpose": _text(purpose, "purpose", 512), "relative_path": relative,
        "size_bytes": size, "sha256": digest, "note": _text(note, "note", 1024, required=False),
    }
    _reject_secrets(root, [record["purpose"], record["note"]])
    if apply:
        with ledger_io.exclusive_ledger_lock(root / LOCAL_ARTIFACT_LEDGER):
            states = local_artifact_states(root)
            if any(item["relative_path"] == relative and item["state"] not in {"disposed", "missing"} for item in states.values()):
                raise StructuredStateError("local artifact path is already registered")
            ledger_io.append_json_record(root / LOCAL_ARTIFACT_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def transition_local_artifact(
    workspace: str | Path, *, local_artifact_id: str, state: str,
    note: str | None = None, apply: bool = False, now: datetime | None = None,
) -> dict[str, Any]:
    root = _workspace(workspace)
    states = local_artifact_states(root)
    if local_artifact_id not in states:
        raise StructuredStateError("local-artifact-id does not exist")
    previous = states[local_artifact_id]
    target_state = _choice(state, "state", LOCAL_ARTIFACT_STATES)
    allowed = {
        "registered": {"in_use", "retained", "disposed", "missing"},
        "in_use": {"retained", "disposed", "missing"},
        "retained": {"in_use", "disposed", "missing"},
        "disposed": set(),
        "missing": set(),
    }
    if target_state not in allowed[previous["state"]]:
        raise StructuredStateError(
            f"unsupported local artifact transition: {previous['state']} -> {target_state}"
        )
    path = root / previous["relative_path"]
    if target_state in {"in_use", "retained"}:
        size, digest = _artifact_metadata(path)
        if (size, digest) != (previous["size_bytes"], previous["sha256"]):
            raise StructuredStateError("local artifact bytes changed")
    if target_state in {"disposed", "missing"} and (path.exists() or path.is_symlink()):
        raise StructuredStateError(f"{target_state} can be recorded only after the file is absent")
    moment = now or datetime.now(UTC)
    record = dict(previous)
    record.update(
        local_artifact_event_id=_identifier("LAE", moment), created_at_utc=_timestamp(moment),
        state=target_state, note=_text(note, "note", 1024, required=False),
    )
    _reject_secrets(root, [record["note"]])
    if apply:
        with ledger_io.exclusive_ledger_lock(root / LOCAL_ARTIFACT_LEDGER):
            current = local_artifact_states(root).get(local_artifact_id)
            if current != previous:
                raise StructuredStateError("local artifact state changed after preview")
            ledger_io.append_json_record(root / LOCAL_ARTIFACT_LEDGER, record, create=True, maximum_bytes=MAX_RECORD)
    return record


def _print_record(record: dict[str, Any], id_field: str, apply: bool) -> None:
    print(f"mode: {'APPLY' if apply else 'PREVIEW'}")
    print(f"{id_field}: {record[id_field]}")
    print(f"state: {record['state']}")


def _refresh_after_apply(workspace: str, host_ids: list[str], apply: bool) -> None:
    if not apply or not host_ids:
        return
    try:
        if __package__:
            from . import host_state
        else:
            import host_state
        current = host_state.best_effort_refresh(workspace, host_ids)
        print(f"host_view: {'current' if current else 'stale'}")
        if not current:
            print("warning: host_view_stale", file=sys.stderr)
    except Exception:  # noqa: BLE001 - canonical ledger append already succeeded
        print("warning: host_view_stale", file=sys.stderr)
        print("host_view: stale")


def finding_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-finding")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--workspace", required=True); create.add_argument("--host-id", action="append", required=True)
    create.add_argument("--state", choices=FINDING_STATES, required=True); create.add_argument("--severity", choices=SEVERITIES, required=True)
    create.add_argument("--title", required=True); create.add_argument("--service"); create.add_argument("--endpoint")
    create.add_argument("--impact", required=True); create.add_argument("--remediation"); create.add_argument("--reference", action="append", default=[])
    create.add_argument("--note"); create.add_argument("--apply", action="store_true")
    transition = sub.add_parser("transition")
    transition.add_argument("--workspace", required=True); transition.add_argument("--finding-id", required=True)
    transition.add_argument("--state", choices=FINDING_STATES, required=True); transition.add_argument("--reference", action="append", default=[])
    transition.add_argument("--note"); transition.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        record = create_finding(args.workspace, host_ids=args.host_id, state=args.state, severity=args.severity,
            title=args.title, service=args.service, endpoint=args.endpoint, impact=args.impact,
            remediation=args.remediation, references=args.reference, note=args.note, apply=args.apply) if args.command == "create" else transition_finding(
            args.workspace, finding_id=args.finding_id, state=args.state, references=args.reference, note=args.note, apply=args.apply)
        _print_record(record, "finding_id", args.apply)
        _refresh_after_apply(args.workspace, record["host_ids"], args.apply)
        return 0
    except (StructuredStateError, ledger_io.LedgerIOError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 1


def work_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-work")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--workspace", required=True); create.add_argument("--kind", choices=WORK_KINDS, required=True)
    create.add_argument("--external-ref", required=True); create.add_argument("--host-id", action="append", default=[])
    create.add_argument("--state", choices=WORK_STATES, required=True); create.add_argument("--summary", required=True)
    create.add_argument("--reference", action="append", default=[]); create.add_argument("--note"); create.add_argument("--apply", action="store_true")
    transition = sub.add_parser("transition")
    transition.add_argument("--workspace", required=True); transition.add_argument("--work-item-id", required=True)
    transition.add_argument("--state", choices=WORK_STATES, required=True); transition.add_argument("--reference", action="append", default=[])
    transition.add_argument("--note"); transition.add_argument("--apply", action="store_true")
    create.add_argument("--owner", default="unassigned")
    for command in (create, transition):
        command.add_argument("--reviewer")
        command.add_argument("--review-basis")
    args = parser.parse_args(argv)
    try:
        record = create_work_item(args.workspace, kind=args.kind, external_ref=args.external_ref, host_ids=args.host_id,
            owner=args.owner, reviewer=args.reviewer, review_basis=args.review_basis, state=args.state, summary=args.summary, references=args.reference, note=args.note, apply=args.apply) if args.command == "create" else transition_work_item(
            args.workspace, reviewer=args.reviewer, review_basis=args.review_basis, work_item_id=args.work_item_id, state=args.state, references=args.reference, note=args.note, apply=args.apply)
        _print_record(record, "work_item_id", args.apply)
        _refresh_after_apply(args.workspace, record["host_ids"], args.apply)
        return 0
    except (StructuredStateError, ledger_io.LedgerIOError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 1


def local_artifact_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-local-artifact")
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register")
    register.add_argument("--workspace", required=True); register.add_argument("--path", required=True)
    register.add_argument("--artifact-class", choices=LOCAL_ARTIFACT_CLASSES, required=True)
    register.add_argument("--purpose", required=True); register.add_argument("--host-id", action="append", default=[])
    register.add_argument("--note"); register.add_argument("--apply", action="store_true")
    transition = sub.add_parser("transition")
    transition.add_argument("--workspace", required=True); transition.add_argument("--local-artifact-id", required=True)
    transition.add_argument("--state", choices=LOCAL_ARTIFACT_STATES, required=True)
    transition.add_argument("--note"); transition.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        record = register_local_artifact(args.workspace, path=args.path, artifact_class=args.artifact_class,
            purpose=args.purpose, host_ids=args.host_id, note=args.note, apply=args.apply) if args.command == "register" else transition_local_artifact(
            args.workspace, local_artifact_id=args.local_artifact_id, state=args.state, note=args.note, apply=args.apply)
        _print_record(record, "local_artifact_id", args.apply)
        print(f"artifact_class: {record['artifact_class']}")
        _refresh_after_apply(args.workspace, record["host_ids"], args.apply)
        return 0
    except (StructuredStateError, ledger_io.LedgerIOError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 1
