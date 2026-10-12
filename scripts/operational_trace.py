"""Append-only authorization, change, and attack-path operational records."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import host_identity, ledger_io
else:
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]

AUTHORIZATION_LEDGER = "authorizations.jsonl"
CHANGE_LEDGER = "changes.jsonl"
ATTACK_PATH_LEDGER = "attack_paths.jsonl"

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
AUTHORIZATION_ID_RE = re.compile(r"^AUTH-\d{8}T\d{12}Z$")
CHANGE_ID_RE = re.compile(r"^CHG-\d{8}T\d{12}Z$")
CHANGE_EVENT_ID_RE = re.compile(r"^CHGE-\d{8}T\d{12}Z$")
PATH_EVENT_ID_RE = re.compile(r"^PTH-\d{8}T\d{12}Z$")
ATTEMPT_ID_RE = re.compile(r"^ATT-\d{8}T\d{12}Z$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

IMPACT_LEVELS = ("low", "medium", "high", "critical", "moderate")
# Historical moderate records retain their bytes; both names have the same rank.
IMPACT_RANK = {"low": 0, "medium": 1, "moderate": 1, "high": 2, "critical": 3}
AUTHORIZATION_CATEGORIES = {
    "access-control",
    "bulk-data-access",
    "cloud",
    "configuration",
    "container",
    "data",
    "denial-of-service",
    "destructive",
    "external-callback",
    "filesystem",
    "identity-switch",
    "initial-access",
    "kubernetes",
    "lateral-movement",
    "model",
    "network",
    "other",
    "persistence",
    "pivot",
    "privilege-escalation",
    "service",
    "tunnel",
}
CHANGE_EVENTS = {
    "planned",
    "applied",
    "validated",
    "retained",
    "rolled_back",
    "failed",
}
REVERSIBILITY = {"reversible", "conditional", "irreversible", "unknown"}
PATH_TRANSITIONS = {
    "initial_access": "initial-access",
    "identity_switch": "identity-switch",
    "privilege_escalation": "privilege-escalation",
    "pivot": "pivot",
    "tunnel": "tunnel",
    "lateral_movement": "lateral-movement",
}
PATH_STATUSES = {"success", "failed", "partial", "blocked"}

AUTHORIZATION_FIELDS_V1 = (
    "schema_version",
    "authorization_id",
    "created_at_utc",
    "host_ids",
    "categories",
    "maximum_impact",
    "techniques",
    "exclusions",
    "source",
    "summary",
)
AUTHORIZATION_FIELDS_V2 = AUTHORIZATION_FIELDS_V1 + ("standing_authorization_id",)
AUTHORIZATION_FIELDS = AUTHORIZATION_FIELDS_V1
CHANGE_FIELDS = (
    "schema_version",
    "change_event_id",
    "created_at_utc",
    "change_id",
    "event",
    "authorization_id",
    "host_id",
    "category",
    "impact_level",
    "technique",
    "target",
    "description",
    "reversibility",
    "before_state",
    "rollback_steps",
    "validation_steps",
    "evidence_ids",
    "attempt_id",
    "note",
)
PATH_FIELDS = (
    "schema_version",
    "path_event_id",
    "created_at_utc",
    "authorization_id",
    "transition",
    "impact_level",
    "source_host_id",
    "source_identity",
    "destination_host_id",
    "destination_identity",
    "source_segment",
    "destination_segment",
    "service",
    "technique",
    "status",
    "credential_id",
    "attempt_id",
    "evidence_ids",
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"
)
JWT_RE = re.compile(
    r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"
)


class TraceError(ValueError):
    """Deterministic operational-trace validation failure."""


def _fatal(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _timestamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, now: datetime) -> str:
    return now.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _text(
    value: str | None,
    name: str,
    maximum: int,
    *,
    required: bool = True,
) -> str | None:
    if value is None:
        if required:
            raise TraceError(f"{name} is required")
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TraceError(f"{name} must not contain control characters")
    normalized = value.strip()
    if required and not normalized:
        raise TraceError(f"{name} must not be empty")
    if not normalized:
        return None
    if len(normalized) > maximum:
        raise TraceError(f"{name} is too long (maximum {maximum} characters)")
    return normalized


def _choice(value: str, name: str, allowed: set[str] | tuple[str, ...]) -> str:
    normalized = _text(value, name, 64)
    assert normalized is not None
    normalized = normalized.lower()
    if normalized not in allowed:
        raise TraceError(
            f"unsupported {name}: {value!r}; expected one of "
            + ", ".join(sorted(allowed))
        )
    return normalized


def _unique(values: Iterable[str], name: str, maximum: int = 240) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _text(value, name, maximum)
        assert item is not None
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return normalized


def _normalized_techniques(values: Iterable[str]) -> list[str]:
    techniques = [item.lower() for item in _unique(values, "technique")]
    if not techniques:
        raise TraceError("at least one technique is required")
    return techniques


def _real_regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise TraceError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TraceError(f"{label} must be a real non-symlink regular file: {path}")


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise TraceError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TraceError(f"{label} must be a real non-symlink directory: {path}")


def validate_workspace(workspace: str | Path) -> Path:
    supplied = Path(workspace)
    if ".." in supplied.parts:
        raise TraceError("workspace path must not contain '..'")
    resolved = supplied.expanduser().absolute()
    _real_directory(resolved, "workspace")
    for name in ("global.md", "attempts.jsonl"):
        _real_regular(resolved / name, f"workspace {name}")
    for name in ("hosts", "evidence", "report"):
        _real_directory(resolved / name, f"workspace {name}")
    for name in (AUTHORIZATION_LEDGER, CHANGE_LEDGER, ATTACK_PATH_LEDGER):
        path = resolved / name
        if path.exists() or path.is_symlink():
            _real_regular(path, f"workspace {name}")
    return resolved


def discover_active_host_ids(workspace: Path) -> set[str]:
    try:
        return {record.host_id for record in host_identity.discover_hosts(workspace)}
    except host_identity.HostIdentityError as exc:
        raise TraceError(str(exc)) from exc


def discover_host_ids(workspace: Path) -> set[str]:
    """Return active and historical host IDs for append-only ledger validation."""
    try:
        return host_identity.known_host_ids(workspace)
    except host_identity.HostIdentityError as exc:
        raise TraceError(str(exc)) from exc


def _validate_host_ids(workspace: Path, values: Iterable[str]) -> list[str]:
    known = discover_active_host_ids(workspace)
    host_ids = _unique(values, "host-id", 16)
    if not host_ids:
        raise TraceError("at least one host-id is required")
    for host_id in host_ids:
        if HOST_ID_RE.fullmatch(host_id) is None:
            raise TraceError(f"invalid host-id: {host_id!r}")
        if host_id not in known:
            raise TraceError(f"host-id is not registered in workspace: {host_id}")
    return sorted(host_ids, key=lambda value: int(value[1:]))


def _read_jsonl(path: Path, *, missing_ok: bool) -> list[dict[str, Any]]:
    if not path.exists():
        if missing_ok:
            return []
        raise TraceError(f"ledger does not exist: {path.name}")
    _real_regular(path, f"ledger {path.name}")
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n"):
                    raise TraceError(
                        f"{path.name} line {line_number} is not newline terminated"
                    )
                serialized = line[:-1]
                if not serialized:
                    raise TraceError(f"{path.name} line {line_number} is blank")
                try:
                    record = ledger_io.loads_json(serialized)
                except ledger_io.LedgerIOError as exc:
                    raise TraceError(
                        f"invalid JSON in {path.name} line {line_number}"
                    ) from exc
                if not isinstance(record, dict):
                    raise TraceError(
                        f"invalid record in {path.name} line {line_number}: expected object"
                    )
                records.append(record)
    except UnicodeDecodeError as exc:
        raise TraceError(f"invalid UTF-8 in {path.name}: {exc}") from exc
    return records


def _create_legacy_ledger(path: Path) -> None:
    if path.exists():
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except FileExistsError:
        _real_regular(path, f"ledger {path.name}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _append_record(path: Path, record: dict[str, Any]) -> None:
    """Append one record while the caller holds the matching ledger lock."""
    try:
        ledger_io.append_json_record(
            path,
            record,
            create=True,
            maximum_bytes=65536,
        )
    except ledger_io.LedgerIOError as exc:
        raise TraceError(f"failed to append {path.name}: {exc}") from exc


def _validate_timestamp_pair(identifier: str, prefix: str, created: str) -> None:
    try:
        identifier_time = datetime.strptime(
            identifier, f"{prefix}-%Y%m%dT%H%M%S%fZ"
        ).replace(tzinfo=UTC)
        created_time = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise TraceError(f"malformed {prefix} timestamp") from exc
    if identifier_time != created_time:
        raise TraceError(f"{prefix} identifier and timestamp do not match")


def _require_exact_fields(record: dict[str, Any], fields: tuple[str, ...], source: str) -> None:
    missing = [field for field in fields if field not in record]
    extra = [field for field in record if field not in fields]
    if missing:
        raise TraceError(f"{source} is missing fields: {', '.join(missing)}")
    if extra:
        raise TraceError(f"{source} has unexpected fields: {', '.join(extra)}")


def _validate_authorization_record(record: dict[str, Any], source: str) -> None:
    version = record.get("schema_version")
    if version == "1.0":
        fields = AUTHORIZATION_FIELDS_V1
    elif version == "2.0":
        fields = AUTHORIZATION_FIELDS_V2
    else:
        raise TraceError(f"{source} has unsupported schema_version")
    _require_exact_fields(record, fields, source)
    if not isinstance(record["authorization_id"], str) or AUTHORIZATION_ID_RE.fullmatch(
        record["authorization_id"]
    ) is None:
        raise TraceError(f"{source} has malformed authorization_id")
    if not isinstance(record["created_at_utc"], str) or TIMESTAMP_RE.fullmatch(
        record["created_at_utc"]
    ) is None:
        raise TraceError(f"{source} has malformed created_at_utc")
    _validate_timestamp_pair(
        record["authorization_id"], "AUTH", record["created_at_utc"]
    )
    if not isinstance(record["host_ids"], list) or not record["host_ids"]:
        raise TraceError(f"{source} host_ids must be a non-empty list")
    if len(set(record["host_ids"])) != len(record["host_ids"]):
        raise TraceError(f"{source} contains duplicate host_ids")
    if any(not isinstance(item, str) or HOST_ID_RE.fullmatch(item) is None for item in record["host_ids"]):
        raise TraceError(f"{source} contains invalid host_ids")
    if not isinstance(record["categories"], list) or not record["categories"]:
        raise TraceError(f"{source} categories must be a non-empty list")
    if len(set(record["categories"])) != len(record["categories"]):
        raise TraceError(f"{source} contains duplicate categories")
    if any(item not in AUTHORIZATION_CATEGORIES for item in record["categories"]):
        raise TraceError(f"{source} contains an unsupported category")
    if record["maximum_impact"] not in IMPACT_LEVELS:
        raise TraceError(f"{source} contains an unsupported maximum_impact")
    if not isinstance(record["techniques"], list) or not record["techniques"]:
        raise TraceError(f"{source} techniques must be a non-empty list")
    if len(set(record["techniques"])) != len(record["techniques"]):
        raise TraceError(f"{source} contains duplicate techniques")
    for field in ("exclusions",):
        if not isinstance(record[field], list) or any(
            not isinstance(item, str) for item in record[field]
        ):
            raise TraceError(f"{source} {field} must be a string list")
    for field in ("source", "summary"):
        if not isinstance(record[field], str) or not record[field]:
            raise TraceError(f"{source} {field} must be non-empty text")
    if version == "2.0":
        standing_id = record["standing_authorization_id"]
        if not isinstance(standing_id, str) or re.fullmatch(
            r"SAUTH-\d{8}T\d{12}Z", standing_id
        ) is None:
            raise TraceError(f"{source} has malformed standing_authorization_id")


def load_authorizations(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / AUTHORIZATION_LEDGER
    records = _read_jsonl(path, missing_ok=True)
    if (workspace / 'assessment_events.jsonl').exists():
        if __package__:
            from . import assessment_decisions
        else:
            import assessment_decisions
        records.extend(assessment_decisions.virtual_authorizations(workspace))
    identifiers: set[str] = set()
    known_hosts = discover_host_ids(workspace)
    for line_number, record in enumerate(records, start=1):
        source = f"{AUTHORIZATION_LEDGER} line {line_number}"
        _validate_authorization_record(record, source)
        if record["authorization_id"] in identifiers:
            raise TraceError(f"{source} duplicates authorization_id")
        if any(host_id not in known_hosts for host_id in record["host_ids"]):
            raise TraceError(f"{source} references an unknown host")
        identifiers.add(record["authorization_id"])
    return records


def _authorization_index(workspace: Path) -> dict[str, dict[str, Any]]:
    return {record["authorization_id"]: record for record in load_authorizations(workspace)}


def _assert_envelope(
    authorization: dict[str, Any],
    *,
    host_ids: Iterable[str],
    category: str,
    impact_level: str,
    technique: str,
) -> None:
    outside = sorted(set(host_ids) - set(authorization["host_ids"]))
    if outside:
        raise TraceError(
            "operation exceeds authorization hosts: " + ", ".join(outside)
        )
    if category not in authorization["categories"]:
        raise TraceError(f"operation category is outside authorization: {category}")
    if IMPACT_RANK[impact_level] > IMPACT_RANK[authorization["maximum_impact"]]:
        raise TraceError(
            f"operation impact {impact_level} exceeds authorization maximum "
            f"{authorization['maximum_impact']}"
        )
    if technique.lower() not in authorization["techniques"]:
        raise TraceError(f"operation technique is outside authorization: {technique}")


def _credential_records(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "private" / "credentials" / "credentials.jsonl"
    if not path.exists():
        return []
    _real_regular(path, "credential ledger")
    return _read_jsonl(path, missing_ok=False)


def _reject_secret_content(workspace: Path, values: Iterable[str | None]) -> None:
    text = "\n".join(value for value in values if value)
    if not text:
        return
    if "-----BEGIN PRIVATE KEY-----" in text:
        raise TraceError("operational trace text must not contain a private key")
    if SECRET_ASSIGNMENT_RE.search(text) or JWT_RE.search(text):
        raise TraceError("operational trace text appears to contain a secret")
    for record in _credential_records(workspace):
        secret = record.get("secret")
        if isinstance(secret, str) and secret and secret in text:
            raise TraceError("operational trace text contains a stored credential")


def _log_authorization_locked(
    *,
    workspace: str | Path,
    host_ids: list[str],
    categories: list[str],
    maximum_impact: str,
    techniques: list[str],
    exclusions: list[str],
    source: str,
    summary: str,
    standing_authorization_id: str | None = None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    root = validate_workspace(workspace)
    normalized_hosts = _validate_host_ids(root, host_ids)
    normalized_categories = sorted(
        {_choice(value, "category", AUTHORIZATION_CATEGORIES) for value in categories}
    )
    if not normalized_categories:
        raise TraceError("at least one category is required")
    impact = _choice(maximum_impact, "maximum-impact", IMPACT_LEVELS)
    normalized_techniques = sorted(set(_normalized_techniques(techniques)))
    normalized_exclusions = _unique(exclusions, "exclusion", 512)
    normalized_source = _text(source, "source", 128)
    normalized_summary = _text(summary, "summary", 1024)
    normalized_standing_id = None
    if standing_authorization_id is not None:
        normalized_standing_id = _text(
            standing_authorization_id, "standing-authorization-id", 48
        )
        if re.fullmatch(r"SAUTH-\d{8}T\d{12}Z", normalized_standing_id or "") is None:
            raise TraceError("invalid standing-authorization-id")
    assert normalized_source is not None and normalized_summary is not None
    _reject_secret_content(
        root,
        [normalized_source, normalized_summary, *normalized_exclusions, *normalized_techniques],
    )
    existing = load_authorizations(root)
    moment = now or datetime.now(UTC)
    authorization_id = _identifier("AUTH", moment)
    if any(item["authorization_id"] == authorization_id for item in existing):
        raise TraceError(f"duplicate authorization_id: {authorization_id}")
    record = {
        "schema_version": "2.0" if normalized_standing_id else "1.0",
        "authorization_id": authorization_id,
        "created_at_utc": _timestamp(moment),
        "host_ids": normalized_hosts,
        "categories": normalized_categories,
        "maximum_impact": impact,
        "techniques": normalized_techniques,
        "exclusions": normalized_exclusions,
        "source": normalized_source,
        "summary": normalized_summary,
    }
    fields = AUTHORIZATION_FIELDS_V1
    if normalized_standing_id:
        record["standing_authorization_id"] = normalized_standing_id
        fields = AUTHORIZATION_FIELDS_V2
    record = {field: record[field] for field in fields}
    if not validate_only:
        _append_record(root / AUTHORIZATION_LEDGER, record)
    return root, record


def log_authorization(
    *,
    workspace: str | Path,
    host_ids: list[str],
    categories: list[str],
    maximum_impact: str,
    techniques: list[str],
    exclusions: list[str],
    source: str,
    summary: str,
    standing_authorization_id: str | None = None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Validate and optionally append one authorization under its ledger lock."""
    root = validate_workspace(workspace)
    # Workspace closure is an independent lifecycle boundary.  Import lazily to
    # avoid the lifecycle module's validation dependency on this ledger module.
    if __package__:
        from . import engagement_config, workspace_lifecycle
    else:
        import engagement_config
        import workspace_lifecycle
    try:
        engagement_config.reject_legacy_mutation(root)
        workspace_lifecycle.assert_target_actions_open(root)
    except (workspace_lifecycle.WorkspaceLifecycleError, engagement_config.ConfigurationError) as exc:
        raise TraceError(str(exc)) from exc
    ledger = root / AUTHORIZATION_LEDGER
    try:
        with ledger_io.exclusive_ledger_lock(ledger):
            return _log_authorization_locked(
                workspace=root,
                host_ids=host_ids,
                categories=categories,
                maximum_impact=maximum_impact,
                techniques=techniques,
                exclusions=exclusions,
                source=source,
                summary=summary,
                standing_authorization_id=standing_authorization_id,
                now=now,
                validate_only=validate_only,
            )
    except ledger_io.LedgerIOError as exc:
        raise TraceError(f"failed to update {AUTHORIZATION_LEDGER}: {exc}") from exc


def _attempt_index(workspace: Path) -> dict[str, dict[str, Any]]:
    records = _read_jsonl(workspace / "attempts.jsonl", missing_ok=False)
    result: dict[str, dict[str, Any]] = {}
    for line_number, record in enumerate(records, start=1):
        attempt_id = record.get("attempt_id")
        host_id = record.get("host_id")
        if not isinstance(attempt_id, str) or ATTEMPT_ID_RE.fullmatch(attempt_id) is None:
            raise TraceError(f"attempts.jsonl line {line_number} has invalid attempt_id")
        if not isinstance(host_id, str) or HOST_ID_RE.fullmatch(host_id) is None:
            raise TraceError(f"attempts.jsonl line {line_number} has invalid host_id")
        if attempt_id in result:
            raise TraceError(f"attempts.jsonl line {line_number} duplicates attempt_id")
        result[attempt_id] = record
    return result


def _evidence_ids(workspace: Path) -> set[str]:
    result: set[str] = set()
    try:
        roots = host_identity.evidence_roots(workspace)
    except host_identity.HostIdentityError as exc:
        raise TraceError(str(exc)) from exc
    for owner_host_id, host_dir in roots:
        for metadata in host_dir.glob("*EVD-*.json"):
            _real_regular(metadata, "evidence metadata")
            try:
                record = json.loads(metadata.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TraceError(f"invalid evidence metadata: {metadata}") from exc
            if not isinstance(record, dict):
                raise TraceError(f"evidence metadata is not an object: {metadata}")
            evidence_id = record.get("evidence_id")
            if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
                raise TraceError(f"evidence metadata ID mismatch: {metadata}")
            if not metadata.stem.endswith(evidence_id):
                raise TraceError(f"evidence metadata filename mismatch: {metadata}")
            if record.get("host_id") != owner_host_id:
                raise TraceError(f"evidence metadata host mismatch: {metadata}")
            expected_size = record.get("size_bytes")
            expected_hash = record.get("sha256")
            try:
                artifact = host_identity.locate_evidence_artifact(metadata, record)
            except host_identity.HostIdentityError as exc:
                raise TraceError(str(exc)) from exc
            _real_regular(artifact, "evidence artifact")
            try:
                content = artifact.read_bytes()
            except OSError as exc:
                raise TraceError(f"cannot read evidence artifact: {artifact}") from exc
            if not isinstance(expected_size, int) or expected_size != len(content):
                raise TraceError(f"evidence artifact size mismatch: {artifact}")
            actual_hash = hashlib.sha256(content).hexdigest()
            if not isinstance(expected_hash, str) or expected_hash != actual_hash:
                raise TraceError(f"evidence artifact hash mismatch: {artifact}")
            if evidence_id in result:
                raise TraceError(f"duplicate evidence ID: {evidence_id}")
            result.add(evidence_id)
    return result


def _validate_evidence_ids(workspace: Path, supplied: Iterable[str]) -> list[str]:
    known = _evidence_ids(workspace)
    values = _unique(supplied, "evidence-id", 40)
    for value in values:
        if EVIDENCE_ID_RE.fullmatch(value) is None:
            raise TraceError(f"invalid evidence-id: {value!r}")
        if value not in known:
            raise TraceError(f"evidence-id does not exist in workspace: {value}")
    return values


def _validate_change_record(record: dict[str, Any], source: str) -> None:
    _require_exact_fields(record, CHANGE_FIELDS, source)
    if record["schema_version"] != "1.0":
        raise TraceError(f"{source} has unsupported schema_version")
    if not isinstance(record["change_event_id"], str) or CHANGE_EVENT_ID_RE.fullmatch(
        record["change_event_id"]
    ) is None:
        raise TraceError(f"{source} has malformed change_event_id")
    if not isinstance(record["created_at_utc"], str) or TIMESTAMP_RE.fullmatch(
        record["created_at_utc"]
    ) is None:
        raise TraceError(f"{source} has malformed created_at_utc")
    _validate_timestamp_pair(record["change_event_id"], "CHGE", record["created_at_utc"])
    if not isinstance(record["change_id"], str) or CHANGE_ID_RE.fullmatch(record["change_id"]) is None:
        raise TraceError(f"{source} has malformed change_id")
    if record["event"] not in CHANGE_EVENTS:
        raise TraceError(f"{source} has unsupported event")
    if not isinstance(record["authorization_id"], str) or AUTHORIZATION_ID_RE.fullmatch(record["authorization_id"]) is None:
        raise TraceError(f"{source} has malformed authorization_id")
    if not isinstance(record["host_id"], str) or HOST_ID_RE.fullmatch(record["host_id"]) is None:
        raise TraceError(f"{source} has malformed host_id")
    if record["category"] not in AUTHORIZATION_CATEGORIES:
        raise TraceError(f"{source} has unsupported category")
    if record["impact_level"] not in IMPACT_LEVELS:
        raise TraceError(f"{source} has unsupported impact_level")
    if record["reversibility"] not in REVERSIBILITY:
        raise TraceError(f"{source} has unsupported reversibility")
    for field in (
        "technique",
        "target",
        "description",
        "before_state",
        "note",
    ):
        if not isinstance(record[field], str):
            raise TraceError(f"{source} {field} must be text")
    for field in ("rollback_steps", "validation_steps", "evidence_ids"):
        if not isinstance(record[field], list) or any(not isinstance(value, str) for value in record[field]):
            raise TraceError(f"{source} {field} must be a string list")
    if record["event"] == "planned":
        if not record["rollback_steps"] or not record["validation_steps"]:
            raise TraceError(f"{source} planned event requires recovery steps")
        if record["attempt_id"] is not None:
            raise TraceError(f"{source} planned event must not reference an attempt")
    elif record["event"] in {"applied", "validated", "rolled_back", "failed"}:
        if not isinstance(record["attempt_id"], str) or ATTEMPT_ID_RE.fullmatch(record["attempt_id"]) is None:
            raise TraceError(f"{source} event requires a valid attempt_id")
    elif record["attempt_id"] is not None:
        if not isinstance(record["attempt_id"], str) or ATTEMPT_ID_RE.fullmatch(record["attempt_id"]) is None:
            raise TraceError(f"{source} has invalid attempt_id")


def change_is_active(history: list[dict[str, Any]]) -> bool:
    return any(item["event"] == "applied" for item in history) and not any(
        item["event"] == "rolled_back" for item in history
    )


def _validate_change_transition(history: list[dict[str, Any]], event: str) -> None:
    if not history:
        if event != "planned":
            raise TraceError("first change event must be planned")
        return
    if event == "planned":
        raise TraceError("planned event already exists for this change")
    if any(item["event"] == "rolled_back" for item in history):
        raise TraceError("rolled-back change is terminal")
    applied = any(item["event"] == "applied" for item in history)
    if event == "applied":
        if applied or history[0]["event"] != "planned" or any(
            item["event"] not in {"planned", "failed"} for item in history
        ):
            raise TraceError("applied requires one planned event and no prior apply")
        return
    if event == "failed":
        return
    if not applied:
        raise TraceError(f"{event} requires a prior applied event")
    if event == "validated" and any(item["event"] == "validated" for item in history):
        raise TraceError("change is already validated")
    if event == "retained" and history[-1]["event"] == "retained":
        raise TraceError("change is already retained")


def load_changes(workspace: Path) -> list[dict[str, Any]]:
    records = _read_jsonl(workspace / CHANGE_LEDGER, missing_ok=True)
    if not records:
        return []
    event_ids: set[str] = set()
    histories: dict[str, list[dict[str, Any]]] = defaultdict(list)
    known_hosts = discover_host_ids(workspace)
    authorizations = _authorization_index(workspace)
    attempts = _attempt_index(workspace)
    evidence = _evidence_ids(workspace)
    for line_number, record in enumerate(records, start=1):
        source = f"{CHANGE_LEDGER} line {line_number}"
        _validate_change_record(record, source)
        if record["change_event_id"] in event_ids:
            raise TraceError(f"{source} duplicates change_event_id")
        event_ids.add(record["change_event_id"])
        if record["host_id"] not in known_hosts:
            raise TraceError(f"{source} references an unknown host")
        authorization = authorizations.get(record["authorization_id"])
        if authorization is None:
            raise TraceError(f"{source} references an unknown authorization")
        _assert_envelope(
            authorization,
            host_ids=[record["host_id"]],
            category=record["category"],
            impact_level=record["impact_level"],
            technique=record["technique"],
        )
        if record["attempt_id"] is not None:
            attempt = attempts.get(record["attempt_id"])
            if attempt is None:
                raise TraceError(f"{source} references an unknown attempt")
            if attempt["host_id"] != record["host_id"]:
                raise TraceError(f"{source} attempt belongs to a different host")
        if any(item not in evidence for item in record["evidence_ids"]):
            raise TraceError(f"{source} references unknown evidence")
        history = histories[record["change_id"]]
        _validate_change_transition(history, record["event"])
        if history:
            planned = history[0]
            stable = (
                "authorization_id",
                "host_id",
                "category",
                "impact_level",
                "technique",
                "target",
                "description",
                "reversibility",
                "before_state",
                "rollback_steps",
                "validation_steps",
            )
            if any(record[field] != planned[field] for field in stable):
                raise TraceError(f"{source} changes immutable planned metadata")
        history.append(record)
    return records


def change_histories(records: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    histories: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        histories[record["change_id"]].append(record)
    return dict(histories)


def _log_change_locked(
    *,
    workspace: str | Path,
    event: str,
    change_id: str | None = None,
    authorization_id: str | None = None,
    host_id: str | None = None,
    category: str | None = None,
    impact_level: str | None = None,
    technique: str | None = None,
    target: str | None = None,
    description: str | None = None,
    reversibility: str | None = None,
    before_state: str | None = None,
    rollback_steps: list[str] | None = None,
    validation_steps: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    attempt_id: str | None = None,
    note: str | None = None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    root = validate_workspace(workspace)
    normalized_event = _choice(event, "event", CHANGE_EVENTS)
    existing = load_changes(root)
    histories = change_histories(existing)
    moment = now or datetime.now(UTC)
    change_event_id = _identifier("CHGE", moment)
    if any(item["change_event_id"] == change_event_id for item in existing):
        raise TraceError(f"duplicate change_event_id: {change_event_id}")
    normalized_evidence = _validate_evidence_ids(root, evidence_ids or [])
    normalized_note = _text(note, "note", 1024, required=False) or ""

    if normalized_event == "planned":
        if change_id is not None:
            raise TraceError("planned event assigns its own change-id")
        normalized_authorization = _text(authorization_id, "authorization-id", 40)
        normalized_host = _text(host_id, "host-id", 16)
        assert normalized_authorization is not None and normalized_host is not None
        if AUTHORIZATION_ID_RE.fullmatch(normalized_authorization) is None:
            raise TraceError("invalid authorization-id")
        if normalized_host not in discover_active_host_ids(root):
            raise TraceError(f"host-id is not registered in workspace: {normalized_host}")
        normalized_category = _choice(category or "", "category", AUTHORIZATION_CATEGORIES)
        normalized_impact = _choice(impact_level or "", "impact-level", IMPACT_LEVELS)
        normalized_technique = _text(technique, "technique", 240)
        normalized_target = _text(target, "target", 512)
        normalized_description = _text(description, "description", 1024)
        normalized_reversibility = _choice(
            reversibility or "", "reversibility", REVERSIBILITY
        )
        normalized_before = _text(before_state, "before-state", 1024)
        normalized_rollback = _unique(rollback_steps or [], "rollback-step", 1024)
        normalized_validation = _unique(validation_steps or [], "validation-step", 1024)
        if not normalized_rollback or not normalized_validation:
            raise TraceError("planned event requires rollback and validation steps")
        assert normalized_technique is not None
        assert normalized_target is not None
        assert normalized_description is not None
        assert normalized_before is not None
        authorization = _authorization_index(root).get(normalized_authorization)
        if authorization is None:
            raise TraceError("authorization-id does not exist in workspace")
        if __package__:
            from . import restore_checkpoint
        else:
            import restore_checkpoint
        try:
            restore_checkpoint.require_current_authorization(root, normalized_authorization)
        except restore_checkpoint.RestoreError as exc:
            raise TraceError(str(exc)) from exc
        _assert_envelope(
            authorization,
            host_ids=[normalized_host],
            category=normalized_category,
            impact_level=normalized_impact,
            technique=normalized_technique,
        )
        root_change_id = _identifier("CHG", moment)
        metadata = {
            "authorization_id": normalized_authorization,
            "host_id": normalized_host,
            "category": normalized_category,
            "impact_level": normalized_impact,
            "technique": normalized_technique.lower(),
            "target": normalized_target,
            "description": normalized_description,
            "reversibility": normalized_reversibility,
            "before_state": normalized_before,
            "rollback_steps": normalized_rollback,
            "validation_steps": normalized_validation,
        }
        if attempt_id is not None:
            raise TraceError("planned event must not reference an attempt")
    else:
        normalized_change_id = _text(change_id, "change-id", 40)
        assert normalized_change_id is not None
        if CHANGE_ID_RE.fullmatch(normalized_change_id) is None:
            raise TraceError("invalid change-id")
        history = histories.get(normalized_change_id)
        if history is None:
            raise TraceError("change-id does not exist in workspace")
        _validate_change_transition(history, normalized_event)
        root_change_id = normalized_change_id
        planned = history[0]
        metadata = {field: planned[field] for field in (
            "authorization_id",
            "host_id",
            "category",
            "impact_level",
            "technique",
            "target",
            "description",
            "reversibility",
            "before_state",
            "rollback_steps",
            "validation_steps",
        )}
        for supplied, name in (
            (authorization_id, "authorization-id"),
            (host_id, "host-id"),
            (category, "category"),
            (impact_level, "impact-level"),
            (technique, "technique"),
            (target, "target"),
            (description, "description"),
            (reversibility, "reversibility"),
            (before_state, "before-state"),
        ):
            if supplied is not None:
                raise TraceError(f"{name} is immutable after planned event")
        if rollback_steps or validation_steps:
            raise TraceError("recovery steps are immutable after planned event")
        if normalized_event in {"applied", "validated", "rolled_back", "failed"}:
            normalized_attempt = _text(attempt_id, "attempt-id", 40)
            assert normalized_attempt is not None
            attempt = _attempt_index(root).get(normalized_attempt)
            if attempt is None:
                raise TraceError("attempt-id does not exist in workspace")
            if attempt["host_id"] != metadata["host_id"]:
                raise TraceError("attempt-id belongs to a different host")
            attempt_id = normalized_attempt
        elif attempt_id is not None:
            normalized_attempt = _text(attempt_id, "attempt-id", 40)
            assert normalized_attempt is not None
            if normalized_attempt not in _attempt_index(root):
                raise TraceError("attempt-id does not exist in workspace")
            attempt_id = normalized_attempt

    _validate_change_transition(histories.get(root_change_id, []), normalized_event)
    secret_values = [
        metadata["technique"],
        metadata["target"],
        metadata["description"],
        metadata["before_state"],
        *metadata["rollback_steps"],
        *metadata["validation_steps"],
        normalized_note,
    ]
    _reject_secret_content(root, secret_values)
    record = {
        "schema_version": "1.0",
        "change_event_id": change_event_id,
        "created_at_utc": _timestamp(moment),
        "change_id": root_change_id,
        "event": normalized_event,
        **metadata,
        "evidence_ids": normalized_evidence,
        "attempt_id": attempt_id,
        "note": normalized_note,
    }
    record = {field: record[field] for field in CHANGE_FIELDS}
    if not validate_only:
        _append_record(root / CHANGE_LEDGER, record)
    return root, record


def log_change(
    *,
    workspace: str | Path,
    event: str,
    change_id: str | None = None,
    authorization_id: str | None = None,
    host_id: str | None = None,
    category: str | None = None,
    impact_level: str | None = None,
    technique: str | None = None,
    target: str | None = None,
    description: str | None = None,
    reversibility: str | None = None,
    before_state: str | None = None,
    rollback_steps: list[str] | None = None,
    validation_steps: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    attempt_id: str | None = None,
    note: str | None = None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Validate and optionally append one change event under its ledger lock."""
    root = validate_workspace(workspace)
    ledger = root / CHANGE_LEDGER
    try:
        with ledger_io.exclusive_ledger_lock(ledger):
            return _log_change_locked(
                workspace=root,
                event=event,
                change_id=change_id,
                authorization_id=authorization_id,
                host_id=host_id,
                category=category,
                impact_level=impact_level,
                technique=technique,
                target=target,
                description=description,
                reversibility=reversibility,
                before_state=before_state,
                rollback_steps=rollback_steps,
                validation_steps=validation_steps,
                evidence_ids=evidence_ids,
                attempt_id=attempt_id,
                note=note,
                now=now,
                validate_only=validate_only,
            )
    except ledger_io.LedgerIOError as exc:
        raise TraceError(f"failed to update {CHANGE_LEDGER}: {exc}") from exc


def _validate_path_record(record: dict[str, Any], source: str) -> None:
    _require_exact_fields(record, PATH_FIELDS, source)
    if record["schema_version"] != "1.0":
        raise TraceError(f"{source} has unsupported schema_version")
    if not isinstance(record["path_event_id"], str) or PATH_EVENT_ID_RE.fullmatch(record["path_event_id"]) is None:
        raise TraceError(f"{source} has malformed path_event_id")
    if not isinstance(record["created_at_utc"], str) or TIMESTAMP_RE.fullmatch(record["created_at_utc"]) is None:
        raise TraceError(f"{source} has malformed created_at_utc")
    _validate_timestamp_pair(record["path_event_id"], "PTH", record["created_at_utc"])
    if not isinstance(record["authorization_id"], str) or AUTHORIZATION_ID_RE.fullmatch(record["authorization_id"]) is None:
        raise TraceError(f"{source} has malformed authorization_id")
    if record["transition"] not in PATH_TRANSITIONS:
        raise TraceError(f"{source} has unsupported transition")
    if record["impact_level"] not in IMPACT_LEVELS:
        raise TraceError(f"{source} has unsupported impact_level")
    if record["source_host_id"] != "OPERATOR" and (
        not isinstance(record["source_host_id"], str)
        or HOST_ID_RE.fullmatch(record["source_host_id"]) is None
    ):
        raise TraceError(f"{source} has invalid source_host_id")
    if not isinstance(record["destination_host_id"], str) or HOST_ID_RE.fullmatch(record["destination_host_id"]) is None:
        raise TraceError(f"{source} has invalid destination_host_id")
    for field in (
        "source_identity",
        "destination_identity",
        "source_segment",
        "destination_segment",
        "service",
        "technique",
    ):
        if not isinstance(record[field], str) or not record[field]:
            raise TraceError(f"{source} {field} must be non-empty text")
    if record["status"] not in PATH_STATUSES:
        raise TraceError(f"{source} has unsupported status")
    if record["credential_id"] is not None and (
        not isinstance(record["credential_id"], str)
        or CREDENTIAL_ID_RE.fullmatch(record["credential_id"]) is None
    ):
        raise TraceError(f"{source} has malformed credential_id")
    if not isinstance(record["attempt_id"], str) or ATTEMPT_ID_RE.fullmatch(record["attempt_id"]) is None:
        raise TraceError(f"{source} has malformed attempt_id")
    if not isinstance(record["evidence_ids"], list) or any(
        not isinstance(item, str) for item in record["evidence_ids"]
    ):
        raise TraceError(f"{source} evidence_ids must be a string list")


def _credential_ids(workspace: Path) -> set[str]:
    result: set[str] = set()
    known_hosts = discover_host_ids(workspace)
    for line_number, record in enumerate(_credential_records(workspace), start=1):
        credential_id = record.get("credential_id")
        if not isinstance(credential_id, str) or CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
            raise TraceError(
                f"credential ledger line {line_number} has invalid credential_id"
            )
        if credential_id in result:
            raise TraceError(
                f"credential ledger line {line_number} duplicates credential_id"
            )
        if record.get("host_id") not in known_hosts:
            raise TraceError(
                f"credential ledger line {line_number} references an unknown host"
            )
        if not isinstance(record.get("secret"), str) or not record["secret"]:
            raise TraceError(
                f"credential ledger line {line_number} has an invalid secret field"
            )
        result.add(credential_id)
    return result


def load_attack_paths(workspace: Path, *, validate_credentials: bool = False) -> list[dict[str, Any]]:
    records = _read_jsonl(workspace / ATTACK_PATH_LEDGER, missing_ok=True)
    if not records:
        return []
    identifiers: set[str] = set()
    hosts = discover_host_ids(workspace)
    authorizations = _authorization_index(workspace)
    attempts = _attempt_index(workspace)
    evidence = _evidence_ids(workspace)
    credentials = _credential_ids(workspace) if validate_credentials else set()
    for line_number, record in enumerate(records, start=1):
        source = f"{ATTACK_PATH_LEDGER} line {line_number}"
        _validate_path_record(record, source)
        if record["path_event_id"] in identifiers:
            raise TraceError(f"{source} duplicates path_event_id")
        identifiers.add(record["path_event_id"])
        event_hosts = [record["destination_host_id"]]
        if record["source_host_id"] != "OPERATOR":
            event_hosts.append(record["source_host_id"])
        if any(host_id not in hosts for host_id in event_hosts):
            raise TraceError(f"{source} references an unknown host")
        authorization = authorizations.get(record["authorization_id"])
        if authorization is None:
            raise TraceError(f"{source} references an unknown authorization")
        _assert_envelope(
            authorization,
            host_ids=event_hosts,
            category=PATH_TRANSITIONS[record["transition"]],
            impact_level=record["impact_level"],
            technique=record["technique"],
        )
        attempt = attempts.get(record["attempt_id"])
        if attempt is None:
            raise TraceError(f"{source} references an unknown attempt")
        if attempt["host_id"] not in event_hosts:
            raise TraceError(f"{source} attempt belongs to an unrelated host")
        if any(item not in evidence for item in record["evidence_ids"]):
            raise TraceError(f"{source} references unknown evidence")
        if validate_credentials and record["credential_id"] is not None and record["credential_id"] not in credentials:
            raise TraceError(f"{source} references an unknown credential")
    return records


def _log_attack_path_locked(
    *,
    workspace: str | Path,
    authorization_id: str,
    transition: str,
    impact_level: str,
    source_host_id: str,
    source_identity: str,
    destination_host_id: str,
    destination_identity: str,
    source_segment: str,
    destination_segment: str,
    service: str,
    technique: str,
    status: str,
    credential_id: str | None,
    attempt_id: str,
    evidence_ids: list[str],
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    root = validate_workspace(workspace)
    auth_id = _text(authorization_id, "authorization-id", 40)
    assert auth_id is not None
    if AUTHORIZATION_ID_RE.fullmatch(auth_id) is None:
        raise TraceError("invalid authorization-id")
    normalized_transition = _choice(transition, "transition", set(PATH_TRANSITIONS))
    normalized_impact = _choice(impact_level, "impact-level", IMPACT_LEVELS)
    source_host = _text(source_host_id, "source-host-id", 16)
    destination_host = _text(destination_host_id, "destination-host-id", 16)
    assert source_host is not None and destination_host is not None
    known_hosts = discover_active_host_ids(root)
    event_hosts = [destination_host]
    if source_host != "OPERATOR":
        event_hosts.append(source_host)
    if destination_host not in known_hosts or any(
        value not in known_hosts for value in event_hosts if value != "OPERATOR"
    ):
        raise TraceError("attack path references an unregistered host")
    normalized_values = [
        _text(source_identity, "source-identity", 240),
        _text(destination_identity, "destination-identity", 240),
        _text(source_segment, "source-segment", 240),
        _text(destination_segment, "destination-segment", 240),
        _text(service, "service", 240),
        _text(technique, "technique", 240),
    ]
    assert all(value is not None for value in normalized_values)
    (
        normalized_source_identity,
        normalized_destination_identity,
        normalized_source_segment,
        normalized_destination_segment,
        normalized_service,
        normalized_technique,
    ) = normalized_values
    normalized_status = _choice(status, "status", PATH_STATUSES)
    normalized_attempt = _text(attempt_id, "attempt-id", 40)
    assert normalized_attempt is not None
    attempt = _attempt_index(root).get(normalized_attempt)
    if attempt is None:
        raise TraceError("attempt-id does not exist in workspace")
    if attempt["host_id"] not in event_hosts:
        raise TraceError("attempt-id belongs to an unrelated host")
    normalized_evidence = _validate_evidence_ids(root, evidence_ids)
    normalized_credential = _text(credential_id, "credential-id", 40, required=False)
    if normalized_credential is not None:
        if CREDENTIAL_ID_RE.fullmatch(normalized_credential) is None:
            raise TraceError("invalid credential-id")
        if normalized_credential not in _credential_ids(root):
            raise TraceError("credential-id does not exist in workspace")
    authorization = _authorization_index(root).get(auth_id)
    if authorization is None:
        raise TraceError("authorization-id does not exist in workspace")
    if __package__:
        from . import assessment_decisions
    else:
        import assessment_decisions
    try:
        assessment_decisions.require_current(root,auth_id,now=now)
    except ValueError as exc:
        raise TraceError(str(exc)) from exc
    assert normalized_technique is not None
    _assert_envelope(
        authorization,
        host_ids=event_hosts,
        category=PATH_TRANSITIONS[normalized_transition],
        impact_level=normalized_impact,
        technique=normalized_technique,
    )
    _reject_secret_content(root, [value for value in normalized_values if value])
    existing = load_attack_paths(root, validate_credentials=True)
    moment = now or datetime.now(UTC)
    path_event_id = _identifier("PTH", moment)
    if any(item["path_event_id"] == path_event_id for item in existing):
        raise TraceError(f"duplicate path_event_id: {path_event_id}")
    record = {
        "schema_version": "1.0",
        "path_event_id": path_event_id,
        "created_at_utc": _timestamp(moment),
        "authorization_id": auth_id,
        "transition": normalized_transition,
        "impact_level": normalized_impact,
        "source_host_id": source_host,
        "source_identity": normalized_source_identity,
        "destination_host_id": destination_host,
        "destination_identity": normalized_destination_identity,
        "source_segment": normalized_source_segment,
        "destination_segment": normalized_destination_segment,
        "service": normalized_service,
        "technique": normalized_technique.lower(),
        "status": normalized_status,
        "credential_id": normalized_credential,
        "attempt_id": normalized_attempt,
        "evidence_ids": normalized_evidence,
    }
    record = {field: record[field] for field in PATH_FIELDS}
    if not validate_only:
        _append_record(root / ATTACK_PATH_LEDGER, record)
    return root, record


def log_attack_path(
    *,
    workspace: str | Path,
    authorization_id: str,
    transition: str,
    impact_level: str,
    source_host_id: str,
    source_identity: str,
    destination_host_id: str,
    destination_identity: str,
    source_segment: str,
    destination_segment: str,
    service: str,
    technique: str,
    status: str,
    credential_id: str | None,
    attempt_id: str,
    evidence_ids: list[str],
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Validate and optionally append one attack-path event under its ledger lock."""
    root = validate_workspace(workspace)
    ledger = root / ATTACK_PATH_LEDGER
    try:
        with ledger_io.exclusive_ledger_lock(ledger):
            result = _log_attack_path_locked(
                workspace=root,
                authorization_id=authorization_id,
                transition=transition,
                impact_level=impact_level,
                source_host_id=source_host_id,
                source_identity=source_identity,
                destination_host_id=destination_host_id,
                destination_identity=destination_identity,
                source_segment=source_segment,
                destination_segment=destination_segment,
                service=service,
                technique=technique,
                status=status,
                credential_id=credential_id,
                attempt_id=attempt_id,
                evidence_ids=evidence_ids,
                now=now,
                validate_only=validate_only,
            )
    except ledger_io.LedgerIOError as exc:
        raise TraceError(f"failed to update {ATTACK_PATH_LEDGER}: {exc}") from exc
    if not validate_only:
        try:
            if __package__:
                from . import host_state
            else:
                import host_state
            host_state.best_effort_refresh(
                root,
                [result[1]["source_host_id"], result[1]["destination_host_id"]],
            )
        except Exception:  # noqa: BLE001 - the attack-path event is authoritative
            return result
    return result


def _md(value: Any) -> str:
    escaped = html.escape(str(value), quote=True).replace("\n", " ")
    return (
        escaped.replace("|", "\\|")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("{", "&#123;")
        .replace("}", "&#125;")
        .replace("`", "&#96;")
    )


def _mermaid(value: str) -> str:
    return (
        html.escape(value, quote=True)
        .replace("\n", " ")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("{", "&#123;")
        .replace("}", "&#125;")
        .replace("`", "&#96;")
    )


def _node_key(host_id: str, identity: str) -> tuple[str, str]:
    return host_id, identity


def build_attack_graph(records: list[dict[str, Any]], generated: datetime) -> str:
    node_segments: dict[tuple[str, str], str] = {}
    for record in records:
        source = _node_key(record["source_host_id"], record["source_identity"])
        destination = _node_key(
            record["destination_host_id"], record["destination_identity"]
        )
        node_segments.setdefault(source, record["source_segment"])
        node_segments.setdefault(destination, record["destination_segment"])
    ordered_nodes = sorted(node_segments, key=lambda item: (node_segments[item], item))
    node_ids = {node: f"N{index}" for index, node in enumerate(ordered_nodes, start=1)}
    segments: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for node in ordered_nodes:
        segments[node_segments[node]].append(node)

    lines = [
        "# Attack Graph",
        "",
        f"Generated UTC: `{_timestamp(generated)}`",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    for index, segment in enumerate(sorted(segments), start=1):
        lines.append(f'  subgraph S{index}["{_mermaid(segment)}"]')
        for node in segments[segment]:
            label = f"{node[0]}:{node[1]}"
            lines.append(f'    {node_ids[node]}["{_mermaid(label)}"]')
        lines.append("  end")
    for record in records:
        source = node_ids[_node_key(record["source_host_id"], record["source_identity"])]
        destination = node_ids[
            _node_key(record["destination_host_id"], record["destination_identity"])
        ]
        label = (
            f"{record['transition']} | {record['technique']} | {record['status']}"
        )
        lines.append(f'  {source} -->|"{_mermaid(label)}"| {destination}')
    lines.extend(["```", "", "## Chronology", ""])
    lines.append(
        "| Time | Event | From | To | Transition | Technique | Status | Authorization | Credential | Attempt | Evidence |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for record in records:
        source = f"{record['source_host_id']}:{record['source_identity']}"
        destination = (
            f"{record['destination_host_id']}:{record['destination_identity']}"
        )
        evidence = ", ".join(record["evidence_ids"]) or "none"
        lines.append(
            "| "
            + " | ".join(
                _md(value)
                for value in (
                    record["created_at_utc"],
                    record["path_event_id"],
                    source,
                    destination,
                    record["transition"],
                    record["technique"],
                    record["status"],
                    record["authorization_id"],
                    record["credential_id"] or "none",
                    record["attempt_id"],
                    evidence,
                )
            )
            + " |"
        )
    if not records:
        lines.extend(["", "No attack-path events recorded."])
    return "\n".join(lines) + "\n"


def _change_state(history: list[dict[str, Any]]) -> str:
    if any(item["event"] == "rolled_back" for item in history):
        return "rolled_back"
    if change_is_active(history):
        if history[-1]["event"] == "retained":
            return "retained"
        if history[-1]["event"] == "failed":
            return "active_after_failure"
        return "decision_pending"
    if history[-1]["event"] == "failed":
        return "apply_failed"
    return "planned"


def build_recovery_plan(records: list[dict[str, Any]], generated: datetime) -> str:
    histories = change_histories(records)
    active = [
        history for history in histories.values() if change_is_active(history)
    ]
    active.sort(
        key=lambda history: next(
            item["created_at_utc"] for item in history if item["event"] == "applied"
        ),
        reverse=True,
    )
    lines = [
        "# Recovery Plan",
        "",
        f"Generated UTC: `{_timestamp(generated)}`",
        "",
        "Rollback order is newest applied change first within each host.",
        "",
    ]
    if not active:
        lines.extend(["No active changes require rollback.", ""])
    else:
        by_host: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
        for history in active:
            by_host[history[0]["host_id"]].append(history)
        for host_id in sorted(by_host, key=lambda value: int(value[1:])):
            lines.extend([f"## Host {host_id}", ""])
            for history in by_host[host_id]:
                planned = history[0]
                lines.extend(
                    [
                        f"### {planned['change_id']} — {_md(planned['target'])}",
                        "",
                        f"- State: `{_change_state(history)}`",
                        f"- Authorization: `{planned['authorization_id']}`",
                        f"- Category / impact: `{planned['category']}` / `{planned['impact_level']}`",
                        f"- Technique: `{_md(planned['technique'])}`",
                        f"- Reversibility: `{planned['reversibility']}`",
                        f"- Before state: {_md(planned['before_state'])}",
                        "- Rollback steps:",
                    ]
                )
                lines.extend(f"  {index}. `{_md(step)}`" for index, step in enumerate(planned["rollback_steps"], start=1))
                lines.append("- Validation steps:")
                lines.extend(f"  {index}. `{_md(step)}`" for index, step in enumerate(planned["validation_steps"], start=1))
                lines.append("")
    lines.extend(["## Closed and inactive changes", ""])
    closed = len(histories) - len(active)
    lines.extend([f"Total: {closed}", ""])
    return "\n".join(lines)


def build_impact_summary(
    authorizations: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    generated: datetime,
) -> str:
    histories = change_histories(changes)
    states: dict[str, int] = defaultdict(int)
    for history in histories.values():
        states[_change_state(history)] += 1
    lines = [
        "# Impact Summary",
        "",
        f"Generated UTC: `{_timestamp(generated)}`",
        "",
        "## Authorization envelopes",
        "",
    ]
    if not authorizations:
        lines.extend(["No authorization envelopes recorded.", ""])
    for record in authorizations:
        lines.extend(
            [
                f"### {record['authorization_id']}",
                "",
                f"- Hosts: {', '.join(record['host_ids'])}",
                f"- Categories: {', '.join(record['categories'])}",
                f"- Maximum impact: `{record['maximum_impact']}`",
                f"- Techniques: {', '.join(_md(value) for value in record['techniques'])}",
                f"- Exclusions: {', '.join(_md(value) for value in record['exclusions']) or 'none'}",
                f"- Summary: {_md(record['summary'])}",
                "",
            ]
        )
    lines.extend(["## Execution state", ""])
    lines.append(f"- Change plans: {len(histories)}")
    for state in sorted(states):
        lines.append(f"- {state}: {states[state]}")
    lines.append(f"- Attack-path events: {len(paths)}")
    deviations = sum(record["status"] != "success" for record in paths) + sum(
        record["event"] == "failed" for record in changes
    )
    lines.extend([f"- Failed/partial/blocked deviations: {deviations}", ""])
    return "\n".join(lines)


def _write_report(path: Path, content: str, *, replace: bool) -> str:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    try:
        restore_checkpoint.require_path_instance(path)
    except restore_checkpoint.RestoreError as exc:
        raise TraceError(str(exc)) from exc
    existed = path.exists()
    if existed and not replace:
        raise TraceError(f"report already exists; use --replace: {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
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
    return "replaced" if existed else "created"


def build_operational_trace(
    *, workspace: str | Path, replace: bool, now: datetime | None = None
) -> tuple[Path, list[Path]]:
    root = validate_workspace(workspace)
    authorizations = load_authorizations(root)
    changes = load_changes(root)
    paths = load_attack_paths(root, validate_credentials=True)
    moment = now or datetime.now(UTC)
    outputs = {
        root / "report" / "ATTACK_GRAPH.md": build_attack_graph(paths, moment),
        root / "report" / "RECOVERY_PLAN.md": build_recovery_plan(changes, moment),
        root / "report" / "IMPACT_SUMMARY.md": build_impact_summary(
            authorizations, changes, paths, moment
        ),
    }
    for path in outputs:
        if path.exists() and not replace:
            raise TraceError(f"report already exists; use --replace: {path.name}")
    for path, content in outputs.items():
        _write_report(path, content, replace=replace)
    return root, list(outputs)


def authorization_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Append one impact authorization envelope.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--host-id", action="append", required=True)
    parser.add_argument(
        "--category",
        action="append",
        choices=sorted(AUTHORIZATION_CATEGORIES),
        required=True,
    )
    parser.add_argument("--maximum-impact", choices=IMPACT_LEVELS, required=True)
    parser.add_argument("--technique", action="append", required=True)
    parser.add_argument("--exclusion", action="append", default=[])
    parser.add_argument("--source", default="operator-chat")
    parser.add_argument("--summary", required=True)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate without changing authorizations.jsonl",
    )
    return parser


def authorization_main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = authorization_parser().parse_args(argv)
    try:
        workspace, record = log_authorization(
            workspace=args.workspace,
            host_ids=args.host_id,
            categories=args.category,
            maximum_impact=args.maximum_impact,
            techniques=args.technique,
            exclusions=args.exclusion,
            source=args.source,
            summary=args.summary,
            now=now,
            validate_only=args.validate_only,
        )
    except TraceError as exc:
        _fatal(str(exc))
    if args.validate_only:
        print("validation: valid")
        print(f"prospective_authorization_id: {record['authorization_id']}")
    else:
        print(f"authorization_id: {record['authorization_id']}")
    print(f"hosts: {','.join(record['host_ids'])}")
    print(f"maximum_impact: {record['maximum_impact']}")
    print(f"path: {(workspace / AUTHORIZATION_LEDGER).relative_to(workspace)}")
    return 0


def change_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Append one operational change lifecycle event.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--event", choices=sorted(CHANGE_EVENTS), required=True)
    parser.add_argument("--change-id")
    parser.add_argument("--authorization-id")
    parser.add_argument("--host-id")
    parser.add_argument("--category", choices=sorted(AUTHORIZATION_CATEGORIES))
    parser.add_argument("--impact-level", choices=IMPACT_LEVELS)
    parser.add_argument("--technique")
    parser.add_argument("--target")
    parser.add_argument("--description")
    parser.add_argument("--reversibility", choices=sorted(REVERSIBILITY))
    parser.add_argument("--before-state")
    parser.add_argument("--rollback-step", action="append", default=[])
    parser.add_argument("--validation-step", action="append", default=[])
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument("--attempt-id")
    parser.add_argument("--note")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate without changing changes.jsonl",
    )
    return parser


def change_main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = change_parser().parse_args(argv)
    try:
        workspace, record = log_change(
            workspace=args.workspace,
            event=args.event,
            change_id=args.change_id,
            authorization_id=args.authorization_id,
            host_id=args.host_id,
            category=args.category,
            impact_level=args.impact_level,
            technique=args.technique,
            target=args.target,
            description=args.description,
            reversibility=args.reversibility,
            before_state=args.before_state,
            rollback_steps=args.rollback_step,
            validation_steps=args.validation_step,
            evidence_ids=args.evidence,
            attempt_id=args.attempt_id,
            note=args.note,
            now=now,
            validate_only=args.validate_only,
        )
    except TraceError as exc:
        _fatal(str(exc))
    if args.validate_only:
        print("validation: valid")
        print(f"prospective_change_event_id: {record['change_event_id']}")
    else:
        print(f"change_event_id: {record['change_event_id']}")
    print(f"change_id: {record['change_id']}")
    print(f"event: {record['event']}")
    print(f"host_id: {record['host_id']}")
    print(f"path: {(workspace / CHANGE_LEDGER).relative_to(workspace)}")
    return 0


def attack_path_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Append one attack-path transition.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--transition", choices=sorted(PATH_TRANSITIONS), required=True)
    parser.add_argument("--impact-level", choices=IMPACT_LEVELS, required=True)
    parser.add_argument("--source-host-id", required=True)
    parser.add_argument("--source-identity", required=True)
    parser.add_argument("--destination-host-id", required=True)
    parser.add_argument("--destination-identity", required=True)
    parser.add_argument("--source-segment", default="unknown")
    parser.add_argument("--destination-segment", default="unknown")
    parser.add_argument("--service", required=True)
    parser.add_argument("--technique", required=True)
    parser.add_argument("--status", choices=sorted(PATH_STATUSES), required=True)
    parser.add_argument("--credential-id")
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate without changing attack_paths.jsonl",
    )
    return parser


def attack_path_main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = attack_path_parser().parse_args(argv)
    try:
        workspace, record = log_attack_path(
            workspace=args.workspace,
            authorization_id=args.authorization_id,
            transition=args.transition,
            impact_level=args.impact_level,
            source_host_id=args.source_host_id,
            source_identity=args.source_identity,
            destination_host_id=args.destination_host_id,
            destination_identity=args.destination_identity,
            source_segment=args.source_segment,
            destination_segment=args.destination_segment,
            service=args.service,
            technique=args.technique,
            status=args.status,
            credential_id=args.credential_id,
            attempt_id=args.attempt_id,
            evidence_ids=args.evidence,
            now=now,
            validate_only=args.validate_only,
        )
    except TraceError as exc:
        _fatal(str(exc))
    if args.validate_only:
        print("validation: valid")
        print(f"prospective_path_event_id: {record['path_event_id']}")
    else:
        print(f"path_event_id: {record['path_event_id']}")
    print(f"transition: {record['transition']}")
    print(f"destination: {record['destination_host_id']}:{record['destination_identity']}")
    print(f"path: {(workspace / ATTACK_PATH_LEDGER).relative_to(workspace)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build attack graph and recovery reports.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--replace", action="store_true")
    return parser


def build_main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        workspace, outputs = build_operational_trace(
            workspace=args.workspace, replace=args.replace, now=now
        )
    except TraceError as exc:
        _fatal(str(exc))
    for path in outputs:
        print(f"report: {path.relative_to(workspace)}")
    return 0
