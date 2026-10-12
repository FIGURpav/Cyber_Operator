"""Private, local coordination for many AI streams and one canonical writer."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

if __package__:
    from . import ledger_io
else:
    import ledger_io  # type: ignore[no-redef]


SCHEMA_VERSION = "1.0"
COORDINATION_RELATIVE = Path("private/coordination")
SESSION_FILE = "session.json"
LEASE_LEDGER = "stream_leases.jsonl"
LEASE_SNAPSHOT = Path("runtime/writer_lease.json")
STREAM_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{1,31}$")
SESSION_ID_RE = re.compile(r"^SES-[0-9a-f]{32}$")
LEASE_ID_RE = re.compile(r"^LEASE-[0-9a-f]{32}$")
LEASE_EVENT_ID_RE = re.compile(r"^LSE-[0-9a-f]{32}$")
COORDINATION_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CANONICAL_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9._:-]{1,96}$")
HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

ORCHESTRATION_MODES = {"managed", "manual-windows"}
STREAM_ROLES = {"controller", "worker", "writer", "reporter"}
STREAM_STATES = {"idle", "running", "waiting", "blocked", "complete", "retired"}
ACTION_STATES = {"proposed", "executed", "blocked", "complete"}
RECEIPT_STATUSES = {
    "applied",
    "rejected",
    "duplicate",
    "stale",
    "validation_failed",
}
WRITE_TYPES = {
    "attempt",
    "loot",
    "observation",
    "authorization",
    "change",
    "attack_path",
    "evidence",
    "execution_run",
    "claim",
    "report_step",
    "screenshot",
}

ASSIGNMENT_INPUT_FIELDS = {
    "schema_version",
    "objective",
    "success_condition",
    "stop_condition",
    "host_id",
    "target_generation",
    "authorization_refs",
    "input_refs",
    "exclusions",
}
INTENT_INPUT_FIELDS = {
    "schema_version",
    "coordination_key",
    "assignment_id",
    "host_id",
    "target_generation",
    "authorization_refs",
    "input_refs",
    "action_status",
    "result_summary",
    "requested_writes",
    "artifact_refs",
    "stop_or_recovery",
}
TYPED_WRITE_FIELDS = {"schema_version", "record_type", "arguments"}
REQUESTED_WRITE_FIELDS = {"record_type", "input_path", "input_sha256"}
ARTIFACT_REF_FIELDS = {"path", "size_bytes", "sha256"}

MAX_JSON_BYTES = 256 * 1024
MAX_TYPED_INPUT_BYTES = 128 * 1024
MAX_WRITES_PER_INTENT = 64
MAX_ARTIFACTS_PER_INTENT = 128
MIN_LEASE_TTL = 15
MAX_LEASE_TTL = 3600
DEFAULT_LEASE_TTL = 120
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"
)
JWT_RE = re.compile(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")


class CoordinationError(ValueError):
    """Deterministic coordination validation or state-transition failure."""


def _fatal(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise CoordinationError(f"{name} must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CoordinationError(f"{name} must be a UTC timestamp") from exc


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _text(
    value: Any,
    name: str,
    maximum: int,
    *,
    required: bool = True,
) -> str | None:
    if value is None:
        if required:
            raise CoordinationError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise CoordinationError(f"{name} must be text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CoordinationError(f"{name} must not contain control characters")
    normalized = value.strip()
    if required and not normalized:
        raise CoordinationError(f"{name} must not be empty")
    if not normalized:
        return None
    if len(normalized) > maximum:
        raise CoordinationError(f"{name} is too long (maximum {maximum} characters)")
    return normalized


def _stream_id(value: str, name: str = "stream-id") -> str:
    normalized = _text(value, name, 32)
    assert normalized is not None
    if STREAM_ID_RE.fullmatch(normalized) is None:
        raise CoordinationError(
            f"{name} must match {STREAM_ID_RE.pattern}, for example CTRL-01"
        )
    return normalized


def _string_list(value: Any, name: str, maximum_items: int = 128) -> list[str]:
    if not isinstance(value, list):
        raise CoordinationError(f"{name} must be a list")
    if len(value) > maximum_items:
        raise CoordinationError(f"{name} contains too many items")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = _text(item, name, 512)
        assert normalized is not None
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CoordinationError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CoordinationError(f"{label} must be a real non-symlink directory: {path}")


def _real_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CoordinationError(f"{label} does not exist: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise CoordinationError(
            f"{label} must be a dedicated real regular file: {path}"
        )
    return metadata


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _read_regular_bytes(path: Path, label: str, maximum: int) -> bytes:
    """Read bounded bytes from one stable, dedicated, non-symlink file."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or opened.st_nlink != 1
            or not _same_identity(opened, current)
        ):
            raise CoordinationError(
                f"{label} must be a stable dedicated real regular file"
            )
        if opened.st_size > maximum:
            raise CoordinationError(f"{label} is too large")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum:
            raise CoordinationError(f"{label} is too large")
        final_descriptor = os.fstat(descriptor)
        final_path = path.lstat()
        if (
            not _same_identity(opened, final_descriptor)
            or not _same_identity(opened, final_path)
            or opened.st_size != final_descriptor.st_size
            or opened.st_mtime_ns != final_descriptor.st_mtime_ns
        ):
            raise CoordinationError(f"{label} changed while it was read")
        return b"".join(chunks)
    except CoordinationError:
        raise
    except OSError as exc:
        raise CoordinationError(f"cannot read {label}: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_workspace(workspace: str | Path) -> Path:
    supplied = Path(workspace)
    if ".." in supplied.parts:
        raise CoordinationError("workspace path must not contain '..'")
    root = supplied.expanduser().absolute()
    _real_directory(root, "workspace")
    for name in ("global.md", "TASK_CONTEXT.md", "attempts.jsonl", "loot.jsonl"):
        _real_regular(root / name, f"workspace {name}")
    for name in ("hosts", "evidence", "report"):
        _real_directory(root / name, f"workspace {name}")
    return root


def _coordination_root(workspace: Path, *, initialized: bool) -> Path:
    root = workspace / COORDINATION_RELATIVE
    if initialized:
        _real_directory(root, "coordination directory")
        _real_regular(root / SESSION_FILE, "coordination session")
        _real_regular(root / LEASE_LEDGER, "write lease ledger")
    return root


def _ensure_private_directory(path: Path) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    try:
        restore_checkpoint.require_path_instance(path)
    except restore_checkpoint.RestoreError as exc:
        raise CoordinationError(str(exc)) from exc
    if path.exists() or path.is_symlink():
        _real_directory(path, "coordination directory")
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise CoordinationError(f"coordination directory is not private: {path}")
        return
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise CoordinationError(
            f"cannot create coordination directory: {path}"
        ) from exc
    os.chmod(path, 0o700)


def _encoded_json(value: dict[str, Any]) -> bytes:
    try:
        payload = (
            json.dumps(
                value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CoordinationError("record is not serializable as strict JSON") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise CoordinationError("coordination record is too large")
    return payload


def _write_all(descriptor: int, payload: bytes) -> None:
    written = 0
    while written < len(payload):
        count = os.write(descriptor, payload[written:])
        if count <= 0:
            raise OSError("short write")
        written += count


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    try:
        restore_checkpoint.require_path_instance(path)
    except restore_checkpoint.RestoreError as exc:
        raise CoordinationError(str(exc)) from exc
    payload = _encoded_json(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except FileExistsError as exc:
        raise CoordinationError(
            f"immutable coordination record already exists: {path}"
        ) from exc
    except OSError as exc:
        raise CoordinationError(f"cannot create coordination record: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _replace_json(path: Path, value: dict[str, Any]) -> None:
    payload = _encoded_json(value)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if path.exists() or path.is_symlink():
            _real_regular(path, "replaceable coordination snapshot")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise CoordinationError(
            f"cannot replace coordination snapshot: {path}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _read_json_payload(
    path: Path, label: str, maximum: int = MAX_JSON_BYTES
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = _read_regular_bytes(path, label, maximum)
        value = ledger_io.loads_json(raw)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"{label} is not valid strict JSON") from exc
    if not isinstance(value, dict):
        raise CoordinationError(f"{label} must be a JSON object")
    return value, raw


def _read_json(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    value, _raw = _read_json_payload(path, label, maximum)
    return value


def _coordination_lock(root: Path):
    return ledger_io.exclusive_ledger_lock(root / "coordination.jsonl")


def _append_lease_event(root: Path, record: dict[str, Any]) -> None:
    try:
        ledger_io.append_json_record(
            root / LEASE_LEDGER,
            record,
            create=False,
            maximum_bytes=16 * 1024,
        )
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot append {LEASE_LEDGER}: {exc}") from exc


def _session(root: Path) -> dict[str, Any]:
    record = _read_json(root / SESSION_FILE, "coordination session")
    required = {
        "schema_version",
        "session_id",
        "created_at_utc",
        "controller_stream_id",
        "orchestration_mode",
        "runtime_provider",
        "capability_source",
        "state",
    }
    if set(record) != required or record.get("schema_version") != SCHEMA_VERSION:
        raise CoordinationError("coordination session has an unsupported schema")
    if SESSION_ID_RE.fullmatch(str(record.get("session_id"))) is None:
        raise CoordinationError("coordination session has an invalid session_id")
    _stream_id(str(record.get("controller_stream_id")), "controller stream ID")
    if record.get("orchestration_mode") not in ORCHESTRATION_MODES:
        raise CoordinationError(
            "coordination session has an invalid orchestration mode"
        )
    if record.get("state") != "active":
        raise CoordinationError("coordination session is not active")
    _parse_timestamp(record.get("created_at_utc"), "session created_at_utc")
    return record


def _stream_path(root: Path, stream_id: str) -> Path:
    return root / "streams" / f"{stream_id}.json"


def _stream(root: Path, stream_id: str) -> dict[str, Any]:
    normalized = _stream_id(stream_id)
    record = _read_json(_stream_path(root, normalized), f"stream {normalized}")
    required = {
        "schema_version",
        "session_id",
        "stream_id",
        "role",
        "scope",
        "runtime_agent_id",
        "registered_at_utc",
        "state",
        "current_assignment_id",
        "status_summary",
        "updated_at_utc",
    }
    if set(record) != required or record.get("schema_version") != SCHEMA_VERSION:
        raise CoordinationError(
            f"stream record has an unsupported schema: {normalized}"
        )
    if record.get("session_id") != _session(root)["session_id"]:
        raise CoordinationError(f"stream belongs to another session: {normalized}")
    if (
        record.get("role") not in STREAM_ROLES
        or record.get("state") not in STREAM_STATES
    ):
        raise CoordinationError(f"stream record has invalid state: {normalized}")
    if record.get("stream_id") != normalized or record.get("state") == "retired":
        raise CoordinationError(f"stream is not active: {normalized}")
    _text(record.get("scope"), "stored stream scope", 512)
    _text(
        record.get("runtime_agent_id"),
        "stored runtime agent ID",
        128,
        required=False,
    )
    _text(record.get("status_summary"), "stored stream status", 512)
    _parse_timestamp(record.get("registered_at_utc"), "stream registered_at_utc")
    _parse_timestamp(record.get("updated_at_utc"), "stream updated_at_utc")
    return record


def initialize(
    workspace: str | Path,
    controller_id: str,
    orchestration_mode: str,
    runtime_provider: str,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    root = validate_workspace(workspace)
    controller = _stream_id(controller_id, "controller-id")
    if orchestration_mode not in ORCHESTRATION_MODES:
        raise CoordinationError("invalid orchestration mode")
    provider = _text(runtime_provider, "runtime-provider", 128)
    assert provider is not None
    moment = now or datetime.now(UTC)
    record = {
        "schema_version": SCHEMA_VERSION,
        "session_id": _new_id("SES"),
        "created_at_utc": _timestamp(moment),
        "controller_stream_id": controller,
        "orchestration_mode": orchestration_mode,
        "runtime_provider": provider,
        "capability_source": "operator-declared",
        "state": "active",
    }
    coordination = _coordination_root(root, initialized=False)
    if not apply:
        return root, record, "preview"
    private = root / "private"
    if not private.exists():
        _ensure_private_directory(private)
    else:
        _real_directory(private, "workspace private directory")
    _ensure_private_directory(coordination)
    for relative in (
        "streams",
        "runtime",
        "assignments",
        "intents",
        "intent-keys",
        "receipts",
        "typed-inputs",
    ):
        _ensure_private_directory(coordination / relative)
    try:
        with _coordination_lock(coordination):
            session_path = coordination / SESSION_FILE
            if session_path.exists() or session_path.is_symlink():
                existing = _session(coordination)
                comparable = {
                    "controller_stream_id": controller,
                    "orchestration_mode": orchestration_mode,
                    "runtime_provider": provider,
                }
                if any(existing[key] != value for key, value in comparable.items()):
                    raise CoordinationError(
                        "an incompatible coordination session already exists"
                    )
                _ensure_lease_ledger(coordination)
                _register_locked(
                    coordination,
                    existing,
                    controller,
                    "controller",
                    "Coordinate the active task and route canonical writes",
                    None,
                    moment,
                )
                return root, existing, "existing"
            _write_new_json(session_path, record)
            _ensure_lease_ledger(coordination)
            _register_locked(
                coordination,
                record,
                controller,
                "controller",
                "Coordinate the active task and route canonical writes",
                None,
                moment,
            )
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return root, record, "initialized"


def _ensure_lease_ledger(root: Path) -> None:
    path = root / LEASE_LEDGER
    if path.exists() or path.is_symlink():
        metadata = _real_regular(path, "write lease ledger")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CoordinationError("write lease ledger is not private")
        return
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except OSError as exc:
        raise CoordinationError("cannot create the write lease ledger") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _register_locked(
    root: Path,
    session: dict[str, Any],
    stream_id: str,
    role: str,
    scope: str,
    runtime_agent_id: str | None,
    moment: datetime,
) -> dict[str, Any]:
    path = _stream_path(root, stream_id)
    if path.exists() or path.is_symlink():
        existing = _read_json(path, f"stream {stream_id}")
        if (
            existing.get("session_id") == session["session_id"]
            and existing.get("role") == role
            and existing.get("scope") == scope
            and existing.get("runtime_agent_id") == runtime_agent_id
        ):
            return existing
        raise CoordinationError(f"stream ID is already registered: {stream_id}")
    if runtime_agent_id is not None:
        for existing_path in sorted((root / "streams").glob("*.json")):
            existing = _read_json(existing_path, "registered stream")
            if existing.get("runtime_agent_id") == runtime_agent_id:
                raise CoordinationError(
                    "runtime-agent-id is already bound to another stream"
                )
    record = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session["session_id"],
        "stream_id": stream_id,
        "role": role,
        "scope": scope,
        "runtime_agent_id": runtime_agent_id,
        "registered_at_utc": _timestamp(moment),
        "state": "idle",
        "current_assignment_id": None,
        "status_summary": "registered",
        "updated_at_utc": _timestamp(moment),
    }
    _write_new_json(path, record)
    typed = root / "typed-inputs" / stream_id
    _ensure_private_directory(typed)
    for record_type in sorted(WRITE_TYPES):
        _ensure_private_directory(typed / record_type)
    _ensure_private_directory(root / "assignments" / stream_id)
    _ensure_private_directory(root / "intents" / stream_id)
    _ensure_private_directory(root / "receipts" / stream_id)
    return record


def register_stream(
    workspace: str | Path,
    stream_id: str,
    role: str,
    scope: str,
    runtime_agent_id: str | None,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    session = _session(root)
    normalized_id = _stream_id(stream_id)
    if role not in STREAM_ROLES:
        raise CoordinationError("invalid stream role")
    normalized_scope = _text(scope, "scope", 512)
    normalized_runtime = _text(
        runtime_agent_id, "runtime-agent-id", 128, required=False
    )
    assert normalized_scope is not None
    if not apply:
        preview = {
            "stream_id": normalized_id,
            "role": role,
            "scope": normalized_scope,
            "runtime_agent_id": normalized_runtime,
        }
        return workspace_root, preview, "preview"
    try:
        with _coordination_lock(root):
            record = _register_locked(
                root,
                session,
                normalized_id,
                role,
                normalized_scope,
                normalized_runtime,
                now or datetime.now(UTC),
            )
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, record, "registered"


def update_stream_status(
    workspace: str | Path,
    stream_id: str,
    state: str,
    summary: str,
    assignment_id: str | None,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    normalized_id = _stream_id(stream_id)
    if state not in STREAM_STATES:
        raise CoordinationError("invalid stream state")
    normalized_summary = _text(summary, "status-summary", 512)
    normalized_assignment = _text(assignment_id, "assignment-id", 96, required=False)
    assert normalized_summary is not None
    try:
        with _coordination_lock(root):
            record = _stream(root, normalized_id)
            updated = {
                **record,
                "state": state,
                "current_assignment_id": normalized_assignment,
                "status_summary": normalized_summary,
                "updated_at_utc": _timestamp(now or datetime.now(UTC)),
            }
            if apply:
                _replace_json(_stream_path(root, normalized_id), updated)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, updated, "updated" if apply else "validated"


def _load_input(path_text: str, label: str) -> tuple[dict[str, Any], str]:
    path = Path(path_text)
    if ".." in path.parts:
        raise CoordinationError(f"{label} path must not contain '..'")
    record, raw = _read_json_payload(path.absolute(), label)
    digest = hashlib.sha256(raw).hexdigest()
    return record, digest


def _validate_host_generation(
    host_id: Any, generation: Any
) -> tuple[str | None, str | None]:
    host = _text(host_id, "host_id", 16, required=False)
    target_generation = _text(generation, "target_generation", 128, required=False)
    if host is not None and HOST_ID_RE.fullmatch(host) is None:
        raise CoordinationError("host_id must be null or a canonical Hxx ID")
    if (
        target_generation is not None
        and GENERATION_RE.fullmatch(target_generation) is None
    ):
        raise CoordinationError("target_generation contains unsupported characters")
    if (host is None) != (target_generation is None):
        raise CoordinationError(
            "host_id and target_generation must be supplied together"
        )
    return host, target_generation


def validate_assignment_input(value: dict[str, Any]) -> dict[str, Any]:
    if (
        set(value) != ASSIGNMENT_INPUT_FIELDS
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise CoordinationError(
            "assignment input must contain exactly the documented fields"
        )
    objective = _text(value["objective"], "objective", 2048)
    success = _text(value["success_condition"], "success_condition", 1024)
    stop = _text(value["stop_condition"], "stop_condition", 1024)
    host, generation = _validate_host_generation(
        value["host_id"], value["target_generation"]
    )
    assert objective is not None and success is not None and stop is not None
    return {
        "schema_version": SCHEMA_VERSION,
        "objective": objective,
        "success_condition": success,
        "stop_condition": stop,
        "host_id": host,
        "target_generation": generation,
        "authorization_refs": _string_list(
            value["authorization_refs"], "authorization_refs"
        ),
        "input_refs": _string_list(value["input_refs"], "input_refs"),
        "exclusions": _string_list(value["exclusions"], "exclusions"),
    }


def submit_assignment(
    workspace: str | Path,
    controller_id: str,
    stream_id: str,
    input_path: str,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    session = _session(root)
    controller = _stream_id(controller_id, "controller-id")
    worker = _stream_id(stream_id)
    if controller != session["controller_stream_id"]:
        raise CoordinationError("only the declared controller may submit assignments")
    _stream(root, controller)
    _stream(root, worker)
    supplied, input_sha256 = _load_input(input_path, "assignment input")
    normalized = validate_assignment_input(supplied)
    _reject_secret_summary(
        workspace_root,
        [
            normalized["objective"],
            normalized["success_condition"],
            normalized["stop_condition"],
            *normalized["exclusions"],
        ],
    )
    moment = now or datetime.now(UTC)
    record = {
        **normalized,
        "assignment_id": _new_id("ASN"),
        "created_at_utc": _timestamp(moment),
        "controller_stream_id": controller,
        "worker_stream_id": worker,
        "input_sha256": input_sha256,
    }
    if not apply:
        return workspace_root, record, "validated"
    try:
        with _coordination_lock(root):
            _stream(root, controller)
            _stream(root, worker)
            _write_new_json(
                root / "assignments" / worker / f"{record['assignment_id']}.json",
                record,
            )
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, record, "submitted"


def _workspace_relative(
    workspace: Path, path_text: Any, label: str
) -> tuple[Path, str]:
    normalized = _text(path_text, label, 1024)
    assert normalized is not None
    supplied = Path(normalized)
    if supplied.is_absolute() or ".." in supplied.parts or "." in supplied.parts:
        raise CoordinationError(f"{label} must be a normalized workspace-relative path")
    absolute = workspace / supplied
    try:
        absolute.relative_to(workspace)
    except ValueError as exc:
        raise CoordinationError(f"{label} escapes the workspace") from exc
    return absolute, supplied.as_posix()


def _validate_typed_write(
    workspace: Path,
    root: Path,
    stream_id: str,
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUESTED_WRITE_FIELDS:
        raise CoordinationError(
            "requested write must contain exactly the documented fields"
        )
    record_type = value.get("record_type")
    if record_type not in WRITE_TYPES:
        raise CoordinationError("requested write has an unsupported record_type")
    expected_hash = value.get("input_sha256")
    if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
        raise CoordinationError(
            "requested write input_sha256 must be lowercase SHA-256"
        )
    path, relative = _workspace_relative(
        workspace, value.get("input_path"), "input_path"
    )
    required_parent = root / "typed-inputs" / stream_id / str(record_type)
    try:
        path.relative_to(required_parent)
    except ValueError as exc:
        raise CoordinationError(
            "typed input must be inside the submitting stream's record-type directory"
        ) from exc
    typed, raw = _read_json_payload(
        path, "typed write input", maximum=MAX_TYPED_INPUT_BYTES
    )
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_hash:
        raise CoordinationError("typed write input hash does not match")
    if not isinstance(typed, dict) or set(typed) != TYPED_WRITE_FIELDS:
        raise CoordinationError(
            "typed write input must contain exactly the documented fields"
        )
    if typed.get("schema_version") != SCHEMA_VERSION:
        raise CoordinationError("typed write input has an unsupported schema_version")
    if typed.get("record_type") != record_type:
        raise CoordinationError("typed write record_type does not match its intent")
    if not isinstance(typed.get("arguments"), dict):
        raise CoordinationError("typed write arguments must be a JSON object")
    return {
        "record_type": record_type,
        "input_path": relative,
        "input_sha256": actual_hash,
    }


def _known_secrets(workspace: Path) -> list[str]:
    if __package__:
        from . import secret_provider
    else:
        import secret_provider
    vault_values = [item['secret'] for item in secret_provider.extend_credentials(workspace, [])]
    ledger = workspace / "private" / "credentials" / "credentials.jsonl"
    if not ledger.exists():
        return vault_values
    _real_regular(ledger, "credential ledger")
    result: list[str] = vault_values
    try:
        with ledger.open("rb") as handle:
            for line in handle:
                if not line.endswith(b"\n"):
                    raise CoordinationError(
                        "credential ledger has an incomplete record"
                    )
                record = ledger_io.loads_json(line)
                if isinstance(record, dict):
                    secret = record.get("secret")
                    if isinstance(secret, str) and secret:
                        result.append(secret)
    except (OSError, ledger_io.LedgerIOError) as exc:
        raise CoordinationError("cannot validate credential-safe summary text") from exc
    return result


def _reject_secret_summary(workspace: Path, values: list[str | None]) -> None:
    text = "\n".join(value for value in values if value)
    if not text:
        return
    if "-----BEGIN PRIVATE KEY-----" in text:
        raise CoordinationError("coordination summary must not contain a private key")
    if SECRET_ASSIGNMENT_RE.search(text) or JWT_RE.search(text):
        raise CoordinationError("coordination summary appears to contain a secret")
    if any(secret in text for secret in _known_secrets(workspace)):
        raise CoordinationError("coordination summary contains a stored credential")


def validate_intent_input(
    workspace: Path,
    root: Path,
    stream_id: str,
    value: dict[str, Any],
) -> dict[str, Any]:
    if (
        set(value) != INTENT_INPUT_FIELDS
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise CoordinationError(
            "intent input must contain exactly the documented fields"
        )
    key = _text(value["coordination_key"], "coordination_key", 128)
    assert key is not None
    if COORDINATION_KEY_RE.fullmatch(key) is None:
        raise CoordinationError("coordination_key contains unsupported characters")
    assignment_id = _text(value["assignment_id"], "assignment_id", 96, required=False)
    host, generation = _validate_host_generation(
        value["host_id"], value["target_generation"]
    )
    action_status = value["action_status"]
    if action_status not in ACTION_STATES:
        raise CoordinationError("intent action_status is unsupported")
    summary = _text(value["result_summary"], "result_summary", 2048, required=False)
    stop = _text(value["stop_or_recovery"], "stop_or_recovery", 1024, required=False)
    _reject_secret_summary(workspace, [summary, stop])
    writes = value["requested_writes"]
    if not isinstance(writes, list) or len(writes) > MAX_WRITES_PER_INTENT:
        raise CoordinationError("requested_writes must be a bounded list")
    normalized_writes = [
        _validate_typed_write(workspace, root, stream_id, item) for item in writes
    ]
    artifacts = value["artifact_refs"]
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS_PER_INTENT:
        raise CoordinationError("artifact_refs must be a bounded list")
    normalized_artifacts: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != ARTIFACT_REF_FIELDS:
            raise CoordinationError(
                "artifact ref must contain exactly the documented fields"
            )
        _path, relative = _workspace_relative(workspace, item["path"], "artifact path")
        size = item["size_bytes"]
        digest = item["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise CoordinationError(
                "artifact size_bytes must be a non-negative integer"
            )
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise CoordinationError("artifact sha256 must be lowercase SHA-256")
        normalized_artifacts.append(
            {"path": relative, "size_bytes": size, "sha256": digest}
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "coordination_key": key,
        "assignment_id": assignment_id,
        "host_id": host,
        "target_generation": generation,
        "authorization_refs": _string_list(
            value["authorization_refs"], "authorization_refs"
        ),
        "input_refs": _string_list(value["input_refs"], "input_refs"),
        "action_status": action_status,
        "result_summary": summary,
        "requested_writes": normalized_writes,
        "artifact_refs": normalized_artifacts,
        "stop_or_recovery": stop,
    }


def _intent_key_path(root: Path, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return root / "intent-keys" / f"{digest}.json"


def _intent_key_record(root: Path, intent: dict[str, Any]) -> dict[str, Any]:
    stream_id = str(intent["stream_id"])
    intent_id = str(intent["intent_id"])
    intent_path = root / "intents" / stream_id / f"{intent_id}.json"
    return {
        "schema_version": SCHEMA_VERSION,
        "coordination_key": intent["coordination_key"],
        "stream_id": stream_id,
        "intent_id": intent_id,
        "intent_sha256": hashlib.sha256(
            _read_regular_bytes(intent_path, "intent record", MAX_JSON_BYTES)
        ).hexdigest(),
    }


def _find_coordination_key(root: Path, key: str) -> tuple[dict[str, Any] | None, bool]:
    index_path = _intent_key_path(root, key)
    if index_path.exists() or index_path.is_symlink():
        index = _read_json(index_path, "intent-key index")
        required = {
            "schema_version",
            "coordination_key",
            "stream_id",
            "intent_id",
            "intent_sha256",
        }
        if set(index) != required or index.get("coordination_key") != key:
            raise CoordinationError("intent-key index is malformed")
        stream_id = _stream_id(str(index.get("stream_id")))
        intent_id = str(index.get("intent_id"))
        intent_path = root / "intents" / stream_id / f"{intent_id}.json"
        record = _read_json(intent_path, "indexed intent record")
        digest = hashlib.sha256(
            _read_regular_bytes(intent_path, "indexed intent record", MAX_JSON_BYTES)
        ).hexdigest()
        if (
            digest != index.get("intent_sha256")
            or record.get("coordination_key") != key
        ):
            raise CoordinationError("intent-key index does not match its intent")
        return record, True
    for stream_dir in sorted((root / "intents").iterdir()):
        _real_directory(stream_dir, "stream intent directory")
        for path in sorted(stream_dir.glob("INT-*.json")):
            record = _read_json(path, "intent record")
            if record.get("coordination_key") == key:
                return record, False
    return None, False


def submit_intent(
    workspace: str | Path,
    stream_id: str,
    input_path: str,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    worker = _stream_id(stream_id)
    _stream(root, worker)
    supplied, input_sha256 = _load_input(input_path, "intent input")
    normalized = validate_intent_input(workspace_root, root, worker, supplied)
    moment = now or datetime.now(UTC)
    record = {
        **normalized,
        "intent_id": _new_id("INT"),
        "created_at_utc": _timestamp(moment),
        "stream_id": worker,
        "input_sha256": input_sha256,
    }
    try:
        with _coordination_lock(root):
            _stream(root, worker)
            existing, indexed = _find_coordination_key(
                root, normalized["coordination_key"]
            )
            if existing is not None:
                comparable = {key: record[key] for key in normalized}
                if existing.get("stream_id") == worker and all(
                    existing.get(key) == value for key, value in comparable.items()
                ):
                    if apply and not indexed:
                        _write_new_json(
                            _intent_key_path(root, normalized["coordination_key"]),
                            _intent_key_record(root, existing),
                        )
                    return workspace_root, existing, "duplicate"
                raise CoordinationError(
                    "coordination_key already identifies a different intent"
                )
            if not apply:
                return workspace_root, record, "validated"
            _write_new_json(
                root / "intents" / worker / f"{record['intent_id']}.json",
                record,
            )
            _write_new_json(
                _intent_key_path(root, normalized["coordination_key"]),
                _intent_key_record(root, record),
            )
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, record, "submitted"


def _lease_snapshot(root: Path, *, missing_ok: bool = False) -> dict[str, Any] | None:
    path = root / LEASE_SNAPSHOT
    if not path.exists() and not path.is_symlink():
        if missing_ok:
            return None
        raise CoordinationError("writer lease does not exist")
    record = _read_json(path, "writer lease snapshot")
    required = {
        "schema_version",
        "session_id",
        "lease_id",
        "writer_stream_id",
        "fencing_token",
        "state",
        "acquired_at_utc",
        "last_heartbeat_at_utc",
        "expires_at_utc",
        "ttl_seconds",
    }
    if set(record) != required or record.get("schema_version") != SCHEMA_VERSION:
        raise CoordinationError("writer lease snapshot has an unsupported schema")
    if record.get("session_id") != _session(root)["session_id"]:
        raise CoordinationError("writer lease snapshot belongs to another session")
    if LEASE_ID_RE.fullmatch(str(record.get("lease_id"))) is None:
        raise CoordinationError("writer lease snapshot has an invalid lease_id")
    _stream_id(str(record.get("writer_stream_id")), "lease writer stream ID")
    token = record.get("fencing_token")
    ttl = record.get("ttl_seconds")
    if not isinstance(token, int) or isinstance(token, bool) or token < 1:
        raise CoordinationError("writer lease snapshot has an invalid fencing token")
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        raise CoordinationError("writer lease snapshot has an invalid TTL")
    _ttl(ttl)
    if record.get("state") not in {"active", "released"}:
        raise CoordinationError("writer lease snapshot has an invalid state")
    acquired = _parse_timestamp(record.get("acquired_at_utc"), "lease acquired_at_utc")
    heartbeat = _parse_timestamp(
        record.get("last_heartbeat_at_utc"), "lease last_heartbeat_at_utc"
    )
    expires = _parse_timestamp(record.get("expires_at_utc"), "lease expires_at_utc")
    if heartbeat < acquired or expires < heartbeat:
        raise CoordinationError("writer lease snapshot timestamps are inconsistent")
    return record


def _lease_is_live(record: dict[str, Any], moment: datetime) -> bool:
    return record.get("state") == "active" and _parse_timestamp(
        record.get("expires_at_utc"), "lease expires_at_utc"
    ) > moment.astimezone(UTC)


def _max_fencing_token(root: Path) -> int:
    maximum = 0
    event_ids: set[str] = set()
    active_leases: dict[str, int] = {}
    required = {
        "schema_version",
        "session_id",
        "lease_id",
        "writer_stream_id",
        "fencing_token",
        "state",
        "acquired_at_utc",
        "last_heartbeat_at_utc",
        "expires_at_utc",
        "ttl_seconds",
        "lease_event_id",
        "event",
        "previous_lease_id",
    }
    session_id = _session(root)["session_id"]
    try:
        with (root / LEASE_LEDGER).open("rb") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.endswith(b"\n"):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} is not newline terminated"
                    )
                try:
                    record = ledger_io.loads_json(line)
                except ledger_io.LedgerIOError as exc:
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} is invalid strict JSON"
                    ) from exc
                if not isinstance(record, dict):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} is not an object"
                    )
                if (
                    set(record) != required
                    or record.get("schema_version") != SCHEMA_VERSION
                ):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has an unsupported schema"
                    )
                if record.get("session_id") != session_id:
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} belongs to another session"
                    )
                lease_id = record.get("lease_id")
                event_id = record.get("lease_event_id")
                event = record.get("event")
                if (
                    not isinstance(lease_id, str)
                    or LEASE_ID_RE.fullmatch(lease_id) is None
                ):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has invalid lease_id"
                    )
                if (
                    not isinstance(event_id, str)
                    or LEASE_EVENT_ID_RE.fullmatch(event_id) is None
                    or event_id in event_ids
                ):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has invalid lease_event_id"
                    )
                event_ids.add(event_id)
                token = record.get("fencing_token")
                if not isinstance(token, int) or isinstance(token, bool) or token < 1:
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has invalid token"
                    )
                _stream_id(
                    str(record.get("writer_stream_id")), "lease writer stream ID"
                )
                _ttl_value = record.get("ttl_seconds")
                if not isinstance(_ttl_value, int) or isinstance(_ttl_value, bool):
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has invalid TTL"
                    )
                _ttl(_ttl_value)
                acquired = _parse_timestamp(
                    record.get("acquired_at_utc"), "lease acquired_at_utc"
                )
                heartbeat = _parse_timestamp(
                    record.get("last_heartbeat_at_utc"),
                    "lease last_heartbeat_at_utc",
                )
                expires = _parse_timestamp(
                    record.get("expires_at_utc"), "lease expires_at_utc"
                )
                if heartbeat < acquired or expires < heartbeat:
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has inconsistent timestamps"
                    )
                if event in {"acquired", "expired_takeover", "forced_takeover"}:
                    if record.get("state") != "active" or token <= maximum:
                        raise CoordinationError(
                            f"{LEASE_LEDGER} line {number} has invalid acquisition state"
                        )
                    active_leases[lease_id] = token
                    maximum = token
                elif event == "released":
                    if (
                        record.get("state") != "released"
                        or active_leases.get(lease_id) != token
                        or record.get("previous_lease_id") != lease_id
                    ):
                        raise CoordinationError(
                            f"{LEASE_LEDGER} line {number} has invalid release state"
                        )
                    del active_leases[lease_id]
                else:
                    raise CoordinationError(
                        f"{LEASE_LEDGER} line {number} has invalid event"
                    )
    except OSError as exc:
        raise CoordinationError(f"cannot read {LEASE_LEDGER}") from exc
    return maximum


def _ttl(value: int) -> int:
    if not MIN_LEASE_TTL <= value <= MAX_LEASE_TTL:
        raise CoordinationError(
            f"ttl-seconds must be from {MIN_LEASE_TTL} through {MAX_LEASE_TTL}"
        )
    return value


def acquire_lease(
    workspace: str | Path,
    writer_id: str,
    ttl_seconds: int,
    *,
    apply: bool,
    allow_active_takeover: bool = False,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    session = _session(root)
    writer = _stream_id(writer_id, "writer-id")
    stream = _stream(root, writer)
    if stream.get("role") not in {"writer", "controller"}:
        raise CoordinationError("writer lease requires a writer or controller stream")
    ttl = _ttl(ttl_seconds)
    moment = now or datetime.now(UTC)
    try:
        with _coordination_lock(root):
            current = _lease_snapshot(root, missing_ok=True)
            if current is not None and _lease_is_live(current, moment):
                if current.get("writer_stream_id") == writer:
                    return workspace_root, current, "existing"
                if not allow_active_takeover:
                    raise CoordinationError(
                        "another writer holds a live lease; wait, release it, or use "
                        "an explicitly acknowledged active takeover"
                    )
                event = "forced_takeover"
            elif current is not None and current.get("state") == "active":
                event = "expired_takeover"
            else:
                event = "acquired"
            acquired = _timestamp(moment)
            record = {
                "schema_version": SCHEMA_VERSION,
                "session_id": session["session_id"],
                "lease_id": _new_id("LEASE"),
                "writer_stream_id": writer,
                "fencing_token": _max_fencing_token(root) + 1,
                "state": "active",
                "acquired_at_utc": acquired,
                "last_heartbeat_at_utc": acquired,
                "expires_at_utc": _timestamp(moment + timedelta(seconds=ttl)),
                "ttl_seconds": ttl,
            }
            if apply:
                _append_lease_event(
                    root,
                    {
                        **record,
                        "lease_event_id": _new_id("LSE"),
                        "event": event,
                        "previous_lease_id": (
                            current.get("lease_id") if current is not None else None
                        ),
                    },
                )
                _replace_json(root / LEASE_SNAPSHOT, record)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, record, event if apply else "validated"


def _require_lease_identity(
    root: Path,
    writer_id: str,
    lease_id: str,
    fencing_token: int,
    moment: datetime,
    *,
    require_live: bool,
) -> dict[str, Any]:
    current = _lease_snapshot(root)
    assert current is not None
    if (
        current.get("writer_stream_id") != writer_id
        or current.get("lease_id") != lease_id
        or current.get("fencing_token") != fencing_token
    ):
        raise CoordinationError("writer lease identity or fencing token is stale")
    if current.get("state") != "active":
        raise CoordinationError("writer lease is not active")
    if require_live and not _lease_is_live(current, moment):
        raise CoordinationError("writer lease has expired")
    return current


@contextlib.contextmanager
def writer_guard_from_environment(
    workspace: str | Path,
    *,
    now: datetime | None = None,
) -> Iterator[None]:
    """Fence one canonical append using the process-local writer identity."""
    try:
        workspace_root = validate_workspace(workspace)
        root = _coordination_root(workspace_root, initialized=True)
    except CoordinationError as exc:
        raise ledger_io.LedgerIOError(
            f"coordinated workspace validation failed: {exc}"
        ) from exc
    writer_value = os.environ.get("CYBER_STREAM_ID")
    lease_value = os.environ.get("CYBER_WRITER_LEASE_ID")
    token_value = os.environ.get("CYBER_WRITER_FENCING_TOKEN")
    if writer_value is None or lease_value is None or token_value is None:
        raise ledger_io.LedgerIOError(
            "active coordination requires CYBER_STREAM_ID, "
            "CYBER_WRITER_LEASE_ID, and CYBER_WRITER_FENCING_TOKEN"
        )
    try:
        writer = _stream_id(writer_value, "CYBER_STREAM_ID")
        token = int(token_value, 10)
    except (CoordinationError, ValueError) as exc:
        raise ledger_io.LedgerIOError("invalid writer lease environment") from exc
    if str(token) != token_value or token < 1:
        raise ledger_io.LedgerIOError("invalid writer fencing token environment")
    try:
        with _coordination_lock(root):
            _stream(root, writer)
            _require_lease_identity(
                root,
                writer,
                lease_value,
                token,
                now or datetime.now(UTC),
                require_live=True,
            )
            yield
    except CoordinationError as exc:
        raise ledger_io.LedgerIOError(f"writer lease rejected: {exc}") from exc
    except ledger_io.LedgerIOError:
        raise


def renew_lease(
    workspace: str | Path,
    writer_id: str,
    lease_id: str,
    fencing_token: int,
    ttl_seconds: int | None,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    writer = _stream_id(writer_id, "writer-id")
    moment = now or datetime.now(UTC)
    try:
        with _coordination_lock(root):
            current = _require_lease_identity(
                root, writer, lease_id, fencing_token, moment, require_live=True
            )
            ttl = _ttl(ttl_seconds or int(current["ttl_seconds"]))
            updated = {
                **current,
                "last_heartbeat_at_utc": _timestamp(moment),
                "expires_at_utc": _timestamp(moment + timedelta(seconds=ttl)),
                "ttl_seconds": ttl,
            }
            if apply:
                _replace_json(root / LEASE_SNAPSHOT, updated)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, updated, "renewed" if apply else "validated"


def release_lease(
    workspace: str | Path,
    writer_id: str,
    lease_id: str,
    fencing_token: int,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    writer = _stream_id(writer_id, "writer-id")
    moment = now or datetime.now(UTC)
    try:
        with _coordination_lock(root):
            current = _require_lease_identity(
                root, writer, lease_id, fencing_token, moment, require_live=False
            )
            updated = {
                **current,
                "state": "released",
                "last_heartbeat_at_utc": _timestamp(moment),
                "expires_at_utc": _timestamp(moment),
            }
            if apply:
                _append_lease_event(
                    root,
                    {
                        **updated,
                        "lease_event_id": _new_id("LSE"),
                        "event": "released",
                        "previous_lease_id": current["lease_id"],
                    },
                )
                _replace_json(root / LEASE_SNAPSHOT, updated)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, updated, "released" if apply else "validated"


def issue_receipt(
    workspace: str | Path,
    writer_id: str,
    lease_id: str,
    fencing_token: int,
    source_stream_id: str,
    intent_id: str,
    status: str,
    canonical_ids: list[str],
    message: str,
    *,
    apply: bool,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any], str]:
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    writer = _stream_id(writer_id, "writer-id")
    source = _stream_id(source_stream_id, "source-stream-id")
    if status not in RECEIPT_STATUSES:
        raise CoordinationError("unsupported receipt status")
    normalized_message = _text(message, "message", 1024)
    assert normalized_message is not None
    _reject_secret_summary(workspace_root, [normalized_message])
    normalized_ids: list[str] = []
    for value in canonical_ids:
        normalized = _text(value, "canonical-id", 128)
        assert normalized is not None
        if CANONICAL_ID_RE.fullmatch(normalized) is None:
            raise CoordinationError(f"invalid canonical ID: {normalized}")
        if normalized not in normalized_ids:
            normalized_ids.append(normalized)
    intent_path = root / "intents" / source / f"{intent_id}.json"
    intent = _read_json(intent_path, "intent record")
    if intent.get("intent_id") != intent_id or intent.get("stream_id") != source:
        raise CoordinationError("intent identity mismatch")
    requested_writes = intent.get("requested_writes")
    if not isinstance(requested_writes, list):
        raise CoordinationError("intent requested_writes is malformed")
    if status in {"applied", "duplicate"} and requested_writes and not normalized_ids:
        raise CoordinationError(
            "an applied or duplicate write receipt requires canonical IDs"
        )
    if status in {"rejected", "stale", "validation_failed"} and normalized_ids:
        raise CoordinationError("a non-writing receipt must not claim canonical IDs")
    moment = now or datetime.now(UTC)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": _new_id("RCP"),
        "created_at_utc": _timestamp(moment),
        "intent_id": intent_id,
        "intent_sha256": hashlib.sha256(
            _read_regular_bytes(intent_path, "intent record", MAX_JSON_BYTES)
        ).hexdigest(),
        "coordination_key": intent["coordination_key"],
        "source_stream_id": source,
        "writer_stream_id": writer,
        "writer_lease_id": lease_id,
        "fencing_token": fencing_token,
        "status": status,
        "canonical_ids": normalized_ids,
        "message": normalized_message,
    }
    receipt_path = root / "receipts" / source / f"{intent_id}.json"
    try:
        with _coordination_lock(root):
            _require_lease_identity(
                root, writer, lease_id, fencing_token, moment, require_live=True
            )
            if receipt_path.exists() or receipt_path.is_symlink():
                existing = _read_json(receipt_path, "write receipt")
                comparable = set(receipt) - {"receipt_id", "created_at_utc"}
                if all(existing.get(key) == receipt[key] for key in comparable):
                    return workspace_root, existing, "duplicate"
                raise CoordinationError("a different immutable receipt already exists")
            if apply:
                _write_new_json(receipt_path, receipt)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return workspace_root, receipt, "issued" if apply else "validated"


def status_snapshot(
    workspace: str | Path,
    *,
    detail_limit: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not 1 <= detail_limit <= 500:
        raise CoordinationError("status detail limit must be from 1 through 500")
    workspace_root = validate_workspace(workspace)
    root = _coordination_root(workspace_root, initialized=True)
    moment = now or datetime.now(UTC)
    try:
        with _coordination_lock(root):
            streams = [
                _read_json(path, "stream record")
                for path in sorted((root / "streams").glob("*.json"))
            ]
            lease = _lease_snapshot(root, missing_ok=True)
            if lease is not None:
                lease = {**lease, "live": _lease_is_live(lease, moment)}
            assignment_paths = set((root / "assignments").glob("*/*.json"))
            intent_paths = {
                (path.parent.name, path.stem): path
                for path in (root / "intents").glob("*/*.json")
            }
            receipt_paths = {
                (path.parent.name, path.stem): path
                for path in (root / "receipts").glob("*/*.json")
            }
            intents = set(intent_paths)
            receipts = set(receipt_paths)
            dangling = receipts - intents
            if dangling:
                raise CoordinationError("receipt exists without its source intent")
            pending = intents - receipts

            def recent_records(paths: list[Path], label: str) -> list[dict[str, Any]]:
                records = [_read_json(path, label) for path in paths]
                records.sort(key=lambda item: str(item.get("created_at_utc", "")))
                return records[-detail_limit:]

            recent_assignments = recent_records(
                list(assignment_paths), "assignment record"
            )
            pending_intents = recent_records(
                [intent_paths[key] for key in pending], "pending intent record"
            )
            recent_receipts = recent_records(
                list(receipt_paths.values()), "write receipt"
            )
            session = _session(root)
    except ledger_io.LedgerIOError as exc:
        raise CoordinationError(f"cannot lock coordination state: {exc}") from exc
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": _timestamp(moment),
        "session": session,
        "streams": streams,
        "stream_count": len(streams),
        "assignment_count": len(assignment_paths),
        "intent_count": len(intents),
        "receipt_count": len(receipts),
        "pending_intent_count": len(pending),
        "recent_assignments": recent_assignments,
        "pending_intents": pending_intents,
        "recent_receipts": recent_receipts,
        "detail_limit": detail_limit,
        "details_truncated": any(
            value > detail_limit
            for value in (len(assignment_paths), len(pending), len(receipts))
        ),
        "writer_lease": lease,
        "agent_limit": None,
        "agent_limit_note": "not imposed by Cyber-Operator; runtime limits are external",
    }


def schemas() -> dict[str, Any]:
    """Return machine-readable schemas for agent-generated coordination input."""
    text = {"type": "string", "minLength": 1}
    nullable_text = {"type": ["string", "null"]}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": SCHEMA_VERSION,
        "assignment_input": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(ASSIGNMENT_INPUT_FIELDS),
            "properties": {
                "schema_version": {"const": SCHEMA_VERSION},
                "objective": {**text, "maxLength": 2048},
                "success_condition": {**text, "maxLength": 1024},
                "stop_condition": {**text, "maxLength": 1024},
                "host_id": nullable_text,
                "target_generation": nullable_text,
                "authorization_refs": {"type": "array", "items": text},
                "input_refs": {"type": "array", "items": text},
                "exclusions": {"type": "array", "items": text},
            },
        },
        "typed_write_input": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(TYPED_WRITE_FIELDS),
            "properties": {
                "schema_version": {"const": SCHEMA_VERSION},
                "record_type": {"enum": sorted(WRITE_TYPES)},
                "arguments": {"type": "object"},
            },
        },
        "intent_input": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(INTENT_INPUT_FIELDS),
            "properties": {
                "schema_version": {"const": SCHEMA_VERSION},
                "coordination_key": {
                    "type": "string",
                    "pattern": COORDINATION_KEY_RE.pattern,
                },
                "assignment_id": nullable_text,
                "host_id": nullable_text,
                "target_generation": nullable_text,
                "authorization_refs": {"type": "array", "items": text},
                "input_refs": {"type": "array", "items": text},
                "action_status": {"enum": sorted(ACTION_STATES)},
                "result_summary": nullable_text,
                "requested_writes": {
                    "type": "array",
                    "maxItems": MAX_WRITES_PER_INTENT,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(REQUESTED_WRITE_FIELDS),
                        "properties": {
                            "record_type": {"enum": sorted(WRITE_TYPES)},
                            "input_path": text,
                            "input_sha256": {
                                "type": "string",
                                "pattern": SHA256_RE.pattern,
                            },
                        },
                    },
                },
                "artifact_refs": {
                    "type": "array",
                    "maxItems": MAX_ARTIFACTS_PER_INTENT,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(ARTIFACT_REF_FIELDS),
                        "properties": {
                            "path": text,
                            "size_bytes": {"type": "integer", "minimum": 0},
                            "sha256": {
                                "type": "string",
                                "pattern": SHA256_RE.pattern,
                            },
                        },
                    },
                },
                "stop_or_recovery": nullable_text,
            },
        },
    }


def _add_apply(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--apply", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Coordinate many AI streams through one leased canonical writer."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    schema = commands.add_parser("schema", help="print coordination JSON schemas")
    schema.add_argument("--json", action="store_true", required=True)

    initialize_parser = commands.add_parser(
        "init", help="initialize private coordination"
    )
    initialize_parser.add_argument("--workspace", required=True)
    initialize_parser.add_argument("--controller-id", required=True)
    initialize_parser.add_argument(
        "--orchestration-mode", choices=sorted(ORCHESTRATION_MODES), required=True
    )
    initialize_parser.add_argument("--runtime-provider", default="codex")
    _add_apply(initialize_parser)

    register = commands.add_parser(
        "register", help="register one stream; no fixed count"
    )
    register.add_argument("--workspace", required=True)
    register.add_argument("--stream-id", required=True)
    register.add_argument("--role", choices=sorted(STREAM_ROLES), required=True)
    register.add_argument("--scope", required=True)
    register.add_argument("--runtime-agent-id")
    _add_apply(register)

    heartbeat = commands.add_parser(
        "heartbeat", help="update one stream status snapshot"
    )
    heartbeat.add_argument("--workspace", required=True)
    heartbeat.add_argument("--stream-id", required=True)
    heartbeat.add_argument("--state", choices=sorted(STREAM_STATES), required=True)
    heartbeat.add_argument("--summary", required=True)
    heartbeat.add_argument("--assignment-id")
    _add_apply(heartbeat)

    assignment = commands.add_parser(
        "assignment", help="validate or submit an assignment"
    )
    assignment.add_argument("--workspace", required=True)
    assignment.add_argument("--controller-id", required=True)
    assignment.add_argument("--stream-id", required=True)
    assignment.add_argument("--input", required=True)
    assignment_mode = assignment.add_mutually_exclusive_group()
    assignment_mode.add_argument("--validate-only", action="store_true")
    assignment_mode.add_argument("--apply", action="store_true")

    intent = commands.add_parser(
        "intent", help="validate or submit a typed write intent"
    )
    intent.add_argument("--workspace", required=True)
    intent.add_argument("--stream-id", required=True)
    intent.add_argument("--input", required=True)
    intent_mode = intent.add_mutually_exclusive_group()
    intent_mode.add_argument("--validate-only", action="store_true")
    intent_mode.add_argument("--apply", action="store_true")

    writer = commands.add_parser("writer", help="manage the single writer lease")
    writer_commands = writer.add_subparsers(dest="writer_command", required=True)
    acquire = writer_commands.add_parser("acquire")
    acquire.add_argument("--workspace", required=True)
    acquire.add_argument("--writer-id", required=True)
    acquire.add_argument("--ttl-seconds", type=int, default=DEFAULT_LEASE_TTL)
    acquire.add_argument("--ack-fence-active-writer", action="store_true")
    _add_apply(acquire)
    renew = writer_commands.add_parser("renew")
    renew.add_argument("--workspace", required=True)
    renew.add_argument("--writer-id", required=True)
    renew.add_argument("--lease-id", required=True)
    renew.add_argument("--fencing-token", type=int, required=True)
    renew.add_argument("--ttl-seconds", type=int)
    _add_apply(renew)
    release = writer_commands.add_parser("release")
    release.add_argument("--workspace", required=True)
    release.add_argument("--writer-id", required=True)
    release.add_argument("--lease-id", required=True)
    release.add_argument("--fencing-token", type=int, required=True)
    _add_apply(release)

    receipt = commands.add_parser("receipt", help="issue one immutable write receipt")
    receipt.add_argument("--workspace", required=True)
    receipt.add_argument("--writer-id", required=True)
    receipt.add_argument("--lease-id", required=True)
    receipt.add_argument("--fencing-token", type=int, required=True)
    receipt.add_argument("--source-stream-id", required=True)
    receipt.add_argument("--intent-id", required=True)
    receipt.add_argument("--status", choices=sorted(RECEIPT_STATUSES), required=True)
    receipt.add_argument("--canonical-id", action="append", default=[])
    receipt.add_argument("--message", required=True)
    receipt_mode = receipt.add_mutually_exclusive_group()
    receipt_mode.add_argument("--validate-only", action="store_true")
    receipt_mode.add_argument("--apply", action="store_true")

    status = commands.add_parser(
        "status", help="show the complete coordination snapshot"
    )
    status.add_argument("--workspace", required=True)
    status.add_argument("--json", action="store_true")
    status.add_argument(
        "--limit",
        type=int,
        default=50,
        help="maximum recent assignment/intent/receipt details (default: 50)",
    )
    return parser


def _print_record(record: dict[str, Any], status: str, *keys: str) -> None:
    print(f"status: {status}")
    for key in keys:
        if key in record:
            print(f"{key}: {record[key]}")


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "schema":
            print(json.dumps(schemas(), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.command == "init":
            _root, record, state = initialize(
                args.workspace,
                args.controller_id,
                args.orchestration_mode,
                args.runtime_provider,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "session_id", "controller_stream_id")
            return 0
        if args.command == "register":
            _root, record, state = register_stream(
                args.workspace,
                args.stream_id,
                args.role,
                args.scope,
                args.runtime_agent_id,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "stream_id", "role")
            return 0
        if args.command == "heartbeat":
            _root, record, state = update_stream_status(
                args.workspace,
                args.stream_id,
                args.state,
                args.summary,
                args.assignment_id,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "stream_id", "state")
            return 0
        if args.command == "assignment":
            _root, record, state = submit_assignment(
                args.workspace,
                args.controller_id,
                args.stream_id,
                args.input,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "assignment_id", "worker_stream_id")
            return 0
        if args.command == "intent":
            _root, record, state = submit_intent(
                args.workspace,
                args.stream_id,
                args.input,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "intent_id", "coordination_key")
            return 0
        if args.command == "writer":
            if args.writer_command == "acquire":
                _root, record, state = acquire_lease(
                    args.workspace,
                    args.writer_id,
                    args.ttl_seconds,
                    apply=args.apply,
                    allow_active_takeover=args.ack_fence_active_writer,
                    now=now,
                )
            elif args.writer_command == "renew":
                _root, record, state = renew_lease(
                    args.workspace,
                    args.writer_id,
                    args.lease_id,
                    args.fencing_token,
                    args.ttl_seconds,
                    apply=args.apply,
                    now=now,
                )
            else:
                _root, record, state = release_lease(
                    args.workspace,
                    args.writer_id,
                    args.lease_id,
                    args.fencing_token,
                    apply=args.apply,
                    now=now,
                )
            _print_record(
                record,
                state,
                "lease_id",
                "writer_stream_id",
                "fencing_token",
                "expires_at_utc",
            )
            return 0
        if args.command == "receipt":
            _root, record, state = issue_receipt(
                args.workspace,
                args.writer_id,
                args.lease_id,
                args.fencing_token,
                args.source_stream_id,
                args.intent_id,
                args.status,
                args.canonical_id,
                args.message,
                apply=args.apply,
                now=now,
            )
            _print_record(record, state, "receipt_id", "intent_id", "writer_stream_id")
            return 0
        snapshot = status_snapshot(args.workspace, detail_limit=args.limit, now=now)
        if args.json:
            print(json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(f"session_id: {snapshot['session']['session_id']}")
            print(f"orchestration_mode: {snapshot['session']['orchestration_mode']}")
            print(f"streams: {snapshot['stream_count']}")
            print(f"assignments: {snapshot['assignment_count']}")
            print(f"intents: {snapshot['intent_count']}")
            print(f"pending_intents: {snapshot['pending_intent_count']}")
            lease = snapshot["writer_lease"]
            print(f"writer: {lease['writer_stream_id'] if lease else 'none'}")
            print(f"writer_live: {bool(lease and lease['live'])}")
            print("agent_limit: external-runtime")
        return 0
    except CoordinationError as exc:
        _fatal(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
