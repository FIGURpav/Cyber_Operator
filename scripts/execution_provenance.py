#!/usr/bin/env python3
"""Capture exact helper runs and evidence-bound atomic report claims."""

from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import html
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

if __package__:
    from . import host_identity, ledger_io, report_contract, runtime_config
else:
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]
    import report_contract  # type: ignore[no-redef]
    import runtime_config

DEFAULT_COLLECTION = runtime_config.workspace_root()
RUN_LEDGER = "execution_runs.jsonl"
CLAIM_LEDGER = "claims.jsonl"
SECRET_ADJUDICATION_LEDGER = Path(
    "private/provenance_secret_false_positives.jsonl"
)
CLAIM_SECRET_ADJUDICATION_LEDGER = Path(
    "private/claim_secret_false_positives.jsonl"
)
RUN_DIRECTORY = "execution_runs"
INDEX_PATH = Path("report/PROVENANCE_INDEX.md")
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_TEXT = 2048
MAX_EXCHANGES = 256
MAX_ASSERTIONS = 256

RUN_ID_RE = re.compile(r"^RUN-\d{8}T\d{12}Z$")
CLAIM_ID_RE = re.compile(r"^CLM-\d{8}T\d{12}Z$")
SECRET_ADJUDICATION_ID_RE = re.compile(r"^PSF-\d{8}T\d{12}Z$")
CLAIM_SECRET_ADJUDICATION_ID_RE = re.compile(r"^CSF-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HTTP_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
ASSERTION_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")

RUN_STATUSES = {"success", "failed", "partial"}
CLAIM_CLASSIFICATIONS = {
    "observed",
    "configuration",
    "reconstructed",
    "inferred",
    "unsupported",
}
SUPPORT_STATUSES = {"supported", "disproved", "unknown", "not_supported"}
CLAIM_TYPES = {
    "http_exchange",
    "helper_assertion",
    "credential_provenance",
    "artifact_fact",
    "text",
}
ASSERTION_STATUSES = {"pass", "fail", "error"}
SOURCE_KINDS = {
    "endpoint",
    "file",
    "snapshot",
    "command-output",
    "operator-supplied",
    "other",
}

HTTP_EXCHANGE_FIELDS = {
    "sequence",
    "method",
    "scheme",
    "host",
    "port",
    "path",
    "query_sha256",
    "status_code",
    "evidence_id",
}
ASSERTION_FIELDS = {"name", "status", "value_sha256", "evidence_id"}
SECRET_ADJUDICATION_FIELDS = {
    "schema_version",
    "adjudication_id",
    "created_at_utc",
    "credential_id",
    "run_id",
    "field_path",
    "field_sha256",
    "reason",
}
CLAIM_SECRET_ADJUDICATION_FIELDS = (
    SECRET_ADJUDICATION_FIELDS - {"run_id"}
) | {"claim_id"}
SECRET_ADJUDICATION_REASON = "operator-reviewed retroactive substring collision"
RUN_INPUT_FIELDS = {
    "status",
    "started_at_utc",
    "finished_at_utc",
    "exit_code",
    "source_generation",
    "attempt_id",
    "evidence_ids",
    "stdout_evidence_id",
    "stderr_evidence_id",
    "http_exchanges",
    "assertions",
}
RUN_FIELDS = {
    "schema_version",
    "run_id",
    "captured_at_utc",
    "host_id",
    "report_step_id",
    "plan_event_id",
    "operation_kind",
    "operation_origin",
    "input_sha256",
    *RUN_INPUT_FIELDS,
    "tool",
    "dependencies",
}
CLAIM_INPUT_FIELDS = {
    "classification",
    "support_status",
    "claim_type",
    "statement",
    "run_id",
    "evidence_ids",
    "credential_ids",
    "verification",
}
CLAIM_FIELDS = {
    "schema_version",
    "claim_id",
    "created_at_utc",
    "host_id",
    "report_step_id",
    *CLAIM_INPUT_FIELDS,
}
SNAPSHOT_FIELDS = {
    "original_name",
    "source_path",
    "artifact_path",
    "size_bytes",
    "sha256",
    "capabilities",
}
DEPENDENCY_FIELDS = SNAPSHOT_FIELDS - {"capabilities"}


class ProvenanceError(ValueError):
    """A deterministic, secret-safe provenance validation failure."""


@dataclass(frozen=True)
class ProvenanceReadiness:
    """Machine-verifiable report provenance readiness."""

    enabled: bool
    ready: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    run_count: int
    claim_count: int


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _real_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ProvenanceError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ProvenanceError(f"{label} must be a real non-symlink directory")
    return metadata


def _real_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ProvenanceError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProvenanceError(f"{label} must be a real non-symlink regular file")
    if metadata.st_size > maximum:
        raise ProvenanceError(f"{label} exceeds its size limit")
    return metadata


def _text(
    value: Any,
    label: str,
    maximum: int = MAX_TEXT,
    *,
    nullable: bool = False,
    single_line: bool = True,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ProvenanceError(f"{label} must be text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ProvenanceError(f"{label} contains control characters")
    normalized = value.strip()
    if not normalized:
        raise ProvenanceError(f"{label} must not be empty")
    if single_line and ("\n" in normalized or "\r" in normalized):
        raise ProvenanceError(f"{label} must be single-line text")
    if len(normalized) > maximum:
        raise ProvenanceError(f"{label} is too long")
    return normalized


def _string_list(
    value: Any,
    label: str,
    pattern: re.Pattern[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProvenanceError(f"{label} must be a string list")
    result: list[str] = []
    for item in value:
        normalized = _text(item, label, 256)
        assert normalized is not None
        if pattern is not None and pattern.fullmatch(normalized) is None:
            raise ProvenanceError(f"{label} contains a malformed identifier")
        if normalized not in result:
            result.append(normalized)
    return result


def _sha256(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ProvenanceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise ProvenanceError(f"{label} has a malformed timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ProvenanceError(f"{label} has an invalid timestamp") from exc


def resolve_workspace(root: Path) -> Path:
    """Resolve a direct module workspace or the selected active module."""
    if ".." in root.parts:
        raise ProvenanceError("workspace path must not contain parent traversal")
    supplied = root.expanduser().absolute()
    _real_directory(supplied, "workspace")
    if _lexists(supplied / "global.md"):
        workspace = supplied
    else:
        marker = supplied / "ACTIVE_TASK"
        _real_file(marker, "ACTIVE_TASK", 256)
        module = _text(
            marker.read_text(encoding="utf-8").strip(), "ACTIVE_TASK", 64
        )
        assert module is not None
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", module) is None:
            raise ProvenanceError("ACTIVE_TASK contains an invalid module name")
        workspace = supplied / module
        _real_directory(workspace, "active module workspace")
    for name in ("hosts", "evidence", "report"):
        _real_directory(workspace / name, f"workspace {name}/")
    _real_file(workspace / "global.md", "workspace global.md", 4 * 1024 * 1024)
    return workspace


def _json_file(path: Path, label: str) -> dict[str, Any]:
    _real_file(path, label, MAX_RECORD_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProvenanceError(f"{label} must contain one JSON object")
    return value


def _jsonl(path: Path, label: str, *, missing_ok: bool = False) -> list[dict[str, Any]]:
    if not _lexists(path):
        if missing_ok:
            return []
        raise ProvenanceError(f"{label} does not exist")
    _real_file(path, label, MAX_LEDGER_BYTES)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProvenanceError(f"{label} is not valid UTF-8") from exc
    if raw and not raw.endswith("\n"):
        raise ProvenanceError(f"{label} is missing its final newline")
    lines = raw.splitlines()
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise ProvenanceError(f"{label} line {line_number} is empty")
        try:
            value = ledger_io.loads_json(line)
        except ledger_io.LedgerIOError as exc:
            raise ProvenanceError(
                f"{label} line {line_number} is invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise ProvenanceError(f"{label} line {line_number} must be an object")
        result.append(value)
    return result


def _atomic_write(path: Path, raw: bytes, *, replace: bool) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if not replace and _lexists(path):
            raise ProvenanceError(f"destination already exists: {path.name}")
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _append_record(path: Path, record: dict[str, Any]) -> None:
    encoded = (
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()
    if len(encoded) > MAX_RECORD_BYTES:
        raise ProvenanceError("provenance record exceeds its size limit")
    if _real_file(path, "provenance ledger", MAX_LEDGER_BYTES).st_size + len(
        encoded
    ) > MAX_LEDGER_BYTES:
        raise ProvenanceError("provenance ledger exceeds its size limit")
    try:
        ledger_io.append_json_record(
            path,
            record,
            create=False,
            maximum_bytes=MAX_RECORD_BYTES,
        )
    except ledger_io.LedgerIOError as exc:
        raise ProvenanceError(str(exc)) from exc


def _step_input_sha256(plan: dict[str, Any]) -> str:
    payload = {
        "operation_kind": plan["operation_kind"],
        "input_text": plan["input_text"],
        "query_ids": plan["query_ids"],
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _read_snapshot(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    supplied = path.expanduser().absolute()
    if ".." in path.parts:
        raise ProvenanceError(f"{label} path must not contain parent traversal")
    current = Path(supplied.anchor)
    for component in supplied.parts[1:-1]:
        current /= component
        _real_directory(current, f"{label} parent")
    before = _real_file(supplied, label, MAX_SNAPSHOT_BYTES)
    descriptor = os.open(supplied, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise ProvenanceError(f"{label} changed during open")
        chunks: list[bytes] = []
        remaining = MAX_SNAPSHOT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > MAX_SNAPSHOT_BYTES or (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ProvenanceError(f"{label} changed during read")
        return raw, after
    finally:
        os.close(descriptor)


def _call_name(node: ast.expr) -> str:
    parts: list[str] = []
    current: ast.expr | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _constant_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _path_literals(node: ast.AST) -> set[str]:
    paths: set[str] = set()
    for child in ast.walk(node):
        value = _constant_text(child)
        if value is None:
            continue
        for candidate in re.findall(r"/[A-Za-z0-9_./%?=&+~-]*", value):
            path = candidate.split("?", 1)[0]
            if path.startswith("/") and len(path) <= 2048:
                paths.add(path)
    return paths


def python_capabilities(raw: bytes, original_name: str) -> dict[str, Any] | None:
    """Return conservative, reproducible Python HTTP capabilities."""
    if not original_name.lower().endswith(".py"):
        return None
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError):
        return {
            "analyzer": "python-ast-v1",
            "parse_status": "failed",
            "recognized_http_calls": 0,
            "http_methods": [],
            "http_paths": [],
            "dynamic_method": True,
            "dynamic_path": True,
        }
    methods: set[str] = set()
    paths = _path_literals(tree)
    recognized = 0
    dynamic_method = False
    dynamic_path = False
    method_attributes = {"get", "post", "put", "patch", "delete", "head", "options"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        leaf = name.rsplit(".", 1)[-1].lower()
        url_node: ast.AST | None = None
        if leaf in method_attributes:
            recognized += 1
            methods.add(leaf.upper())
            url_node = node.args[0] if node.args else None
        elif name.endswith("urllib.request.Request"):
            recognized += 1
            explicit = next(
                (
                    _constant_text(keyword.value)
                    for keyword in node.keywords
                    if keyword.arg == "method"
                ),
                None,
            )
            has_data = any(keyword.arg == "data" for keyword in node.keywords)
            methods.add((explicit or ("POST" if has_data else "GET")).upper())
            url_node = node.args[0] if node.args else None
        elif leaf == "request":
            recognized += 1
            method_node = node.args[0] if node.args else None
            method = _constant_text(method_node)
            if method is None:
                method = next(
                    (
                        _constant_text(keyword.value)
                        for keyword in node.keywords
                        if keyword.arg == "method"
                    ),
                    None,
                )
            if method is None:
                dynamic_method = True
            else:
                methods.add(method.upper())
            url_node = node.args[1] if len(node.args) > 1 else None
            if url_node is None:
                url_node = next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "url"),
                    None,
                )
        if url_node is not None:
            discovered = _path_literals(url_node)
            if discovered:
                paths.update(discovered)
            elif not isinstance(url_node, ast.Constant):
                dynamic_path = True
    return {
        "analyzer": "python-ast-v1",
        "parse_status": "ok",
        "recognized_http_calls": recognized,
        "http_methods": sorted(methods),
        "http_paths": sorted(paths),
        "dynamic_method": dynamic_method,
        "dynamic_path": dynamic_path,
    }


def _source_path(workspace: Path, source: Path) -> str | None:
    try:
        return source.expanduser().absolute().relative_to(workspace).as_posix()
    except ValueError:
        return None


def _snapshot_record(
    workspace: Path,
    source: Path,
    artifact: Path,
    raw: bytes,
    *,
    capabilities: dict[str, Any] | None | object = ...,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "original_name": source.name,
        "source_path": _source_path(workspace, source),
        "artifact_path": artifact.relative_to(workspace).as_posix(),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if capabilities is not ...:
        record["capabilities"] = capabilities
    return record


def _validate_http_exchange(value: Any, host_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != HTTP_EXCHANGE_FIELDS:
        raise ProvenanceError("HTTP exchange has unexpected fields")
    sequence = value["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ProvenanceError("HTTP exchange sequence must be a positive integer")
    method = value["method"]
    if not isinstance(method, str) or HTTP_METHOD_RE.fullmatch(method) is None:
        raise ProvenanceError("HTTP exchange method is malformed")
    if value["scheme"] not in {"http", "https"}:
        raise ProvenanceError("HTTP exchange scheme is invalid")
    host = value["host"]
    if not isinstance(host, str) or HOST_RE.fullmatch(host) is None:
        raise ProvenanceError("HTTP exchange host is malformed")
    port = value["port"]
    if port is not None and (
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
    ):
        raise ProvenanceError("HTTP exchange port is invalid")
    path = value["path"]
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "?" in path
        or "#" in path
        or any(character.isspace() for character in path)
        or len(path) > 2048
    ):
        raise ProvenanceError("HTTP exchange path must exclude query and fragment")
    _sha256(value["query_sha256"], "HTTP query hash", nullable=True)
    status_code = value["status_code"]
    if status_code is not None and (
        not isinstance(status_code, int)
        or isinstance(status_code, bool)
        or not 100 <= status_code <= 599
    ):
        raise ProvenanceError("HTTP exchange status code is invalid")
    evidence_id = value["evidence_id"]
    if (
        not isinstance(evidence_id, str)
        or report_contract.EVIDENCE_ID_RE.fullmatch(evidence_id) is None
    ):
        raise ProvenanceError("HTTP exchange evidence ID is malformed")
    del host_id
    return value


def _validate_assertion(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ASSERTION_FIELDS:
        raise ProvenanceError("helper assertion has unexpected fields")
    if (
        not isinstance(value["name"], str)
        or ASSERTION_NAME_RE.fullmatch(value["name"]) is None
    ):
        raise ProvenanceError("helper assertion name is malformed")
    if value["status"] not in ASSERTION_STATUSES:
        raise ProvenanceError("helper assertion status is invalid")
    _sha256(value["value_sha256"], "assertion value hash", nullable=True)
    evidence_id = value["evidence_id"]
    if (
        not isinstance(evidence_id, str)
        or report_contract.EVIDENCE_ID_RE.fullmatch(evidence_id) is None
    ):
        raise ProvenanceError("helper assertion evidence ID is malformed")
    return value


def _run_secret_adjudication_exemptions(
    workspace: Path,
    run_records: list[dict[str, Any]],
    *,
    extra_records: list[dict[str, Any]] | None = None,
    context: report_contract.ValidationContext | None = None,
) -> dict[str, dict[str, set[str]]]:
    records = _jsonl(
        workspace / SECRET_ADJUDICATION_LEDGER,
        "provenance secret false-positive ledger",
        missing_ok=True,
    )
    if extra_records:
        records.extend(extra_records)
    active_context = report_contract._validation_context(workspace, context)
    credentials = active_context.credentials
    runs = {
        record.get("run_id"): record
        for record in run_records
        if isinstance(record.get("run_id"), str)
    }
    result: dict[str, dict[str, set[str]]] = {}
    adjudication_ids: set[str] = set()
    keys: set[tuple[str, str, str]] = set()
    for line_number, record in enumerate(records, 1):
        if (
            set(record) != SECRET_ADJUDICATION_FIELDS
            or record.get("schema_version") != "1.0"
        ):
            raise ProvenanceError(
                f"provenance secret false-positive line {line_number} has invalid metadata"
            )
        adjudication_id = record.get("adjudication_id")
        credential_id = record.get("credential_id")
        run_id = record.get("run_id")
        field_path = record.get("field_path")
        field_sha256 = record.get("field_sha256")
        if (
            not isinstance(adjudication_id, str)
            or SECRET_ADJUDICATION_ID_RE.fullmatch(adjudication_id) is None
            or adjudication_id in adjudication_ids
            or not isinstance(credential_id, str)
            or report_contract.CREDENTIAL_ID_RE.fullmatch(credential_id) is None
            or credential_id not in credentials
            or not isinstance(run_id, str)
            or RUN_ID_RE.fullmatch(run_id) is None
            or run_id not in runs
            or not isinstance(field_path, str)
            or not field_path.startswith("/")
            or not isinstance(field_sha256, str)
            or SHA256_RE.fullmatch(field_sha256) is None
            or record.get("reason") != SECRET_ADJUDICATION_REASON
        ):
            raise ProvenanceError(
                f"provenance secret false-positive line {line_number} is malformed"
            )
        adjudication_ids.add(adjudication_id)
        key = (credential_id, run_id, field_path)
        if key in keys:
            raise ProvenanceError(
                "provenance secret false-positive ledger contains a duplicate target"
            )
        keys.add(key)
        text_fields = dict(report_contract._text_fields(runs[run_id]))
        text = text_fields.get(field_path)
        secret = credentials[credential_id].get("secret")
        if (
            text is None
            or not isinstance(secret, str)
            or not secret
            or secret not in text
            or hashlib.sha256(text.encode()).hexdigest() != field_sha256
        ):
            raise ProvenanceError(
                "provenance secret false-positive adjudication no longer matches its target"
            )
        run_time = _parse_timestamp(
            runs[run_id].get("captured_at_utc"), "run adjudication timestamp"
        )
        credential_time = _parse_timestamp(
            credentials[credential_id].get("created_at_utc"),
            "credential adjudication timestamp",
        )
        adjudication_time = _parse_timestamp(
            record.get("created_at_utc"),
            "provenance secret false-positive timestamp",
        )
        if run_time >= credential_time or adjudication_time < credential_time:
            raise ProvenanceError(
                "provenance secret false-positive is not a retroactive match"
            )
        result.setdefault(run_id, {}).setdefault(field_path, set()).add(
            credential_id
        )
    return result


def _ensure_run_secret_adjudication_ledger(workspace: Path) -> Path:
    private = workspace / "private"
    _real_directory(private, "workspace private directory")
    path = workspace / SECRET_ADJUDICATION_LEDGER
    if _lexists(path):
        _real_file(path, "provenance secret false-positive ledger", MAX_LEDGER_BYTES)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    return path


def adjudicate_retroactive_run_secret_matches(
    workspace: Path,
    credential_id: str,
    *,
    apply: bool,
    acknowledged: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind reviewed late-credential collisions to exact immutable run fields."""
    if report_contract.CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
        raise ProvenanceError("credential_id is malformed")
    step_descriptor = report_contract._acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_SH
    )
    descriptor: int | None = None
    try:
        descriptor = report_contract._acquire_ledger_lock(
            workspace, ".execution_runs.lock", fcntl.LOCK_EX
        )
        context = report_contract.ValidationContext(workspace)
        run_records = _jsonl(workspace / RUN_LEDGER, "execution run ledger")
        credentials = context.credentials
        credential = credentials.get(credential_id)
        if credential is None:
            raise ProvenanceError("credential_id does not exist")
        secret = credential.get("secret")
        if not isinstance(secret, str) or not secret:
            raise ProvenanceError("credential record has no usable secret value")
        credential_time = _parse_timestamp(
            credential.get("created_at_utc"), "credential adjudication timestamp"
        )
        existing = _run_secret_adjudication_exemptions(
            workspace, run_records, context=context
        )
        existing_keys = {
            (run_id, field_path, known_credential_id)
            for run_id, fields in existing.items()
            for field_path, credential_ids in fields.items()
            for known_credential_id in credential_ids
        }
        matches: list[tuple[str, str, str]] = []
        existing_match_count = 0
        for run in run_records:
            run_id = run.get("run_id")
            if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
                raise ProvenanceError("execution run has malformed adjudication identity")
            if _parse_timestamp(
                run.get("captured_at_utc"), "run adjudication timestamp"
            ) >= credential_time:
                continue
            for field_path, text_value in report_contract._text_fields(run):
                if secret not in text_value:
                    continue
                digest = hashlib.sha256(text_value.encode()).hexdigest()
                key = (run_id, field_path, credential_id)
                if key in existing_keys:
                    existing_match_count += 1
                else:
                    matches.append((run_id, field_path, digest))
        if apply and matches and not acknowledged:
            raise ProvenanceError("apply requires --ack-reviewed-false-positives")
        moment = now or datetime.now(UTC)
        new_records = [
            {
                "schema_version": "1.0",
                "adjudication_id": _identifier(
                    "PSF", moment + timedelta(microseconds=index)
                ),
                "created_at_utc": _timestamp(
                    moment + timedelta(microseconds=index)
                ),
                "credential_id": credential_id,
                "run_id": run_id,
                "field_path": field_path,
                "field_sha256": digest,
                "reason": SECRET_ADJUDICATION_REASON,
            }
            for index, (run_id, field_path, digest) in enumerate(matches)
        ]
        exemptions = _run_secret_adjudication_exemptions(
            workspace,
            run_records,
            extra_records=new_records,
            context=context,
        )
        _, states = report_contract.load_steps(workspace, context=context)
        for run in run_records:
            _validate_run_record(
                workspace,
                run,
                states,
                verify_artifacts=True,
                secret_exemptions=exemptions.get(run["run_id"]),
                context=context,
            )
        if apply and new_records:
            ledger = _ensure_run_secret_adjudication_ledger(workspace)
            encoded = b"".join(
                (
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                ).encode()
                for record in new_records
            )
            if ledger.stat().st_size + len(encoded) > MAX_LEDGER_BYTES:
                raise ProvenanceError(
                    "provenance secret false-positive ledger exceeds its size limit"
                )
            with ledger.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        return {
            "credential_id": credential_id,
            "candidate_count": len(new_records),
            "existing_count": existing_match_count,
            "matches": [
                {
                    "run_id": record["run_id"],
                    "field_path": record["field_path"],
                    "field_sha256": record["field_sha256"],
                }
                for record in new_records
            ],
        }
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(step_descriptor)


def _claim_secret_adjudication_exemptions(
    workspace: Path,
    claim_records: list[dict[str, Any]],
    *,
    extra_records: list[dict[str, Any]] | None = None,
    context: report_contract.ValidationContext | None = None,
) -> dict[str, dict[str, set[str]]]:
    records = _jsonl(
        workspace / CLAIM_SECRET_ADJUDICATION_LEDGER,
        "claim secret false-positive ledger",
        missing_ok=True,
    )
    if extra_records:
        records.extend(extra_records)
    active_context = report_contract._validation_context(workspace, context)
    credentials = active_context.credentials
    claims = {
        record.get("claim_id"): record
        for record in claim_records
        if isinstance(record.get("claim_id"), str)
    }
    result: dict[str, dict[str, set[str]]] = {}
    adjudication_ids: set[str] = set()
    keys: set[tuple[str, str, str]] = set()
    for line_number, record in enumerate(records, 1):
        if (
            set(record) != CLAIM_SECRET_ADJUDICATION_FIELDS
            or record.get("schema_version") != "1.0"
        ):
            raise ProvenanceError(
                f"claim secret false-positive line {line_number} has invalid metadata"
            )
        adjudication_id = record.get("adjudication_id")
        credential_id = record.get("credential_id")
        claim_id = record.get("claim_id")
        field_path = record.get("field_path")
        field_sha256 = record.get("field_sha256")
        if (
            not isinstance(adjudication_id, str)
            or CLAIM_SECRET_ADJUDICATION_ID_RE.fullmatch(adjudication_id) is None
            or adjudication_id in adjudication_ids
            or not isinstance(credential_id, str)
            or report_contract.CREDENTIAL_ID_RE.fullmatch(credential_id) is None
            or credential_id not in credentials
            or not isinstance(claim_id, str)
            or CLAIM_ID_RE.fullmatch(claim_id) is None
            or claim_id not in claims
            or not isinstance(field_path, str)
            or not field_path.startswith("/")
            or not isinstance(field_sha256, str)
            or SHA256_RE.fullmatch(field_sha256) is None
            or record.get("reason") != SECRET_ADJUDICATION_REASON
        ):
            raise ProvenanceError(
                f"claim secret false-positive line {line_number} is malformed"
            )
        adjudication_ids.add(adjudication_id)
        key = (credential_id, claim_id, field_path)
        if key in keys:
            raise ProvenanceError(
                "claim secret false-positive ledger contains a duplicate target"
            )
        keys.add(key)
        text = dict(report_contract._text_fields(claims[claim_id])).get(field_path)
        secret = credentials[credential_id].get("secret")
        if (
            text is None
            or not isinstance(secret, str)
            or not secret
            or secret not in text
            or hashlib.sha256(text.encode()).hexdigest() != field_sha256
        ):
            raise ProvenanceError(
                "claim secret false-positive adjudication no longer matches its target"
            )
        claim_time = _parse_timestamp(
            claims[claim_id].get("created_at_utc"), "claim adjudication timestamp"
        )
        credential_time = _parse_timestamp(
            credentials[credential_id].get("created_at_utc"),
            "credential adjudication timestamp",
        )
        adjudication_time = _parse_timestamp(
            record.get("created_at_utc"), "claim secret false-positive timestamp"
        )
        if claim_time >= credential_time or adjudication_time < credential_time:
            raise ProvenanceError(
                "claim secret false-positive is not a retroactive match"
            )
        result.setdefault(claim_id, {}).setdefault(field_path, set()).add(
            credential_id
        )
    return result


def _ensure_claim_secret_adjudication_ledger(workspace: Path) -> Path:
    private = workspace / "private"
    _real_directory(private, "workspace private directory")
    path = workspace / CLAIM_SECRET_ADJUDICATION_LEDGER
    if _lexists(path):
        _real_file(path, "claim secret false-positive ledger", MAX_LEDGER_BYTES)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    return path


def adjudicate_retroactive_claim_secret_matches(
    workspace: Path,
    credential_id: str,
    *,
    apply: bool,
    acknowledged: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind reviewed late-credential collisions to exact immutable claim fields."""
    if report_contract.CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
        raise ProvenanceError("credential_id is malformed")
    step_descriptor = report_contract._acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_SH
    )
    run_descriptor: int | None = None
    descriptor: int | None = None
    try:
        run_descriptor = report_contract._acquire_ledger_lock(
            workspace, ".execution_runs.lock", fcntl.LOCK_SH
        )
        descriptor = report_contract._acquire_ledger_lock(
            workspace, ".claims.lock", fcntl.LOCK_EX
        )
        context = report_contract.ValidationContext(workspace)
        claim_records = _jsonl(workspace / CLAIM_LEDGER, "claim ledger")
        credentials = context.credentials
        credential = credentials.get(credential_id)
        if credential is None:
            raise ProvenanceError("credential_id does not exist")
        secret = credential.get("secret")
        if not isinstance(secret, str) or not secret:
            raise ProvenanceError("credential record has no usable secret value")
        credential_time = _parse_timestamp(
            credential.get("created_at_utc"), "credential adjudication timestamp"
        )
        existing = _claim_secret_adjudication_exemptions(
            workspace, claim_records, context=context
        )
        existing_keys = {
            (claim_id, field_path, known_credential_id)
            for claim_id, fields in existing.items()
            for field_path, credential_ids in fields.items()
            for known_credential_id in credential_ids
        }
        matches: list[tuple[str, str, str]] = []
        existing_match_count = 0
        for claim in claim_records:
            claim_id = claim.get("claim_id")
            if (
                not isinstance(claim_id, str)
                or CLAIM_ID_RE.fullmatch(claim_id) is None
            ):
                raise ProvenanceError("claim has malformed adjudication identity")
            if _parse_timestamp(
                claim.get("created_at_utc"), "claim adjudication timestamp"
            ) >= credential_time:
                continue
            for field_path, text_value in report_contract._text_fields(claim):
                if secret not in text_value:
                    continue
                digest = hashlib.sha256(text_value.encode()).hexdigest()
                key = (claim_id, field_path, credential_id)
                if key in existing_keys:
                    existing_match_count += 1
                else:
                    matches.append((claim_id, field_path, digest))
        if apply and matches and not acknowledged:
            raise ProvenanceError("apply requires --ack-reviewed-false-positives")
        moment = now or datetime.now(UTC)
        new_records = [
            {
                "schema_version": "1.0",
                "adjudication_id": _identifier(
                    "CSF", moment + timedelta(microseconds=index)
                ),
                "created_at_utc": _timestamp(
                    moment + timedelta(microseconds=index)
                ),
                "credential_id": credential_id,
                "claim_id": claim_id,
                "field_path": field_path,
                "field_sha256": digest,
                "reason": SECRET_ADJUDICATION_REASON,
            }
            for index, (claim_id, field_path, digest) in enumerate(matches)
        ]
        exemptions = _claim_secret_adjudication_exemptions(
            workspace,
            claim_records,
            extra_records=new_records,
            context=context,
        )
        _, states = report_contract.load_steps(workspace, context=context)
        runs = _load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
        for claim in claim_records:
            _validate_claim_record(
                workspace,
                claim,
                states,
                runs,
                secret_exemptions=exemptions.get(claim["claim_id"]),
                context=context,
            )
        if apply and new_records:
            ledger = _ensure_claim_secret_adjudication_ledger(workspace)
            encoded = b"".join(
                (
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                ).encode()
                for record in new_records
            )
            if ledger.stat().st_size + len(encoded) > MAX_LEDGER_BYTES:
                raise ProvenanceError(
                    "claim secret false-positive ledger exceeds its size limit"
                )
            with ledger.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        return {
            "credential_id": credential_id,
            "candidate_count": len(new_records),
            "existing_count": existing_match_count,
            "matches": [
                {
                    "claim_id": record["claim_id"],
                    "field_path": record["field_path"],
                    "field_sha256": record["field_sha256"],
                }
                for record in new_records
            ],
        }
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if run_descriptor is not None:
            os.close(run_descriptor)
        os.close(step_descriptor)


def _validate_run_input(
    workspace: Path,
    host_id: str,
    value: dict[str, Any],
    *,
    secret_exemptions: dict[str, set[str]] | None = None,
    context: report_contract.ValidationContext | None = None,
) -> dict[str, Any]:
    active_context = report_contract._validation_context(workspace, context)
    if set(value) != RUN_INPUT_FIELDS:
        raise ProvenanceError("run input has unexpected fields")
    if value["status"] not in RUN_STATUSES:
        raise ProvenanceError("run status is invalid")
    started = _parse_timestamp(value["started_at_utc"], "run start")
    finished = _parse_timestamp(value["finished_at_utc"], "run finish")
    if finished < started:
        raise ProvenanceError("run finish precedes its start")
    exit_code = value["exit_code"]
    if exit_code is not None and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        raise ProvenanceError("run exit_code must be an integer or null")
    if value["status"] == "success" and exit_code not in {0, None}:
        raise ProvenanceError("successful run cannot have a non-zero exit_code")
    _text(value["source_generation"], "source_generation", 256, nullable=True)
    attempt_id = value["attempt_id"]
    attempts = active_context.attempts
    if attempt_id is not None and (
        not isinstance(attempt_id, str)
        or report_contract.ATTEMPT_ID_RE.fullmatch(attempt_id) is None
        or attempt_id not in attempts
        or not active_context.same_host(attempts[attempt_id].get("host_id"), host_id)
    ):
        raise ProvenanceError("run attempt does not exist on the selected host")
    evidence_ids = _string_list(
        value["evidence_ids"], "run evidence_ids", report_contract.EVIDENCE_ID_RE
    )
    evidence = active_context.evidence
    if any(
        item not in evidence or not active_context.same_host(evidence[item].get("host_id"), host_id)
        for item in evidence_ids
    ):
        raise ProvenanceError("run evidence does not exist on the selected host")
    for field in ("stdout_evidence_id", "stderr_evidence_id"):
        supplied = value[field]
        if supplied is not None and supplied not in evidence_ids:
            raise ProvenanceError(f"{field} must also appear in evidence_ids")
    exchanges = value["http_exchanges"]
    assertions = value["assertions"]
    if not isinstance(exchanges, list) or len(exchanges) > MAX_EXCHANGES:
        raise ProvenanceError("run http_exchanges must be a bounded list")
    if not isinstance(assertions, list) or len(assertions) > MAX_ASSERTIONS:
        raise ProvenanceError("run assertions must be a bounded list")
    sequences: set[int] = set()
    for exchange in exchanges:
        _validate_http_exchange(exchange, host_id)
        if exchange["sequence"] in sequences:
            raise ProvenanceError("HTTP exchange sequence is duplicated")
        sequences.add(exchange["sequence"])
        if exchange["evidence_id"] not in evidence_ids:
            raise ProvenanceError("HTTP exchange evidence must appear in evidence_ids")
    assertion_names: set[str] = set()
    for assertion in assertions:
        _validate_assertion(assertion)
        if assertion["name"] in assertion_names:
            raise ProvenanceError("helper assertion name is duplicated")
        assertion_names.add(assertion["name"])
        if assertion["evidence_id"] not in evidence_ids:
            raise ProvenanceError("assertion evidence must appear in evidence_ids")
    if attempt_id is None and not evidence_ids:
        raise ProvenanceError("run requires attempt or evidence provenance")
    report_contract.reject_secrets(
        workspace,
        value,
        allowed_credential_ids_by_path=secret_exemptions,
        context=active_context,
    )
    return value


def _validate_snapshot(
    workspace: Path,
    value: Any,
    *,
    tool: bool,
    verify_artifact: bool,
) -> dict[str, Any]:
    expected = SNAPSHOT_FIELDS if tool else DEPENDENCY_FIELDS
    if not isinstance(value, dict) or set(value) != expected:
        raise ProvenanceError("snapshot metadata has unexpected fields")
    _text(value["original_name"], "snapshot original name", 255)
    source_path = value["source_path"]
    if source_path is not None:
        _text(source_path, "snapshot source path", 2048)
        source = Path(source_path)
        if source.is_absolute() or ".." in source.parts:
            raise ProvenanceError("snapshot source path must stay within workspace")
    artifact_path = _text(value["artifact_path"], "snapshot artifact path", 2048)
    assert artifact_path is not None
    relative = Path(artifact_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProvenanceError("snapshot artifact path must stay within workspace")
    size = value["size_bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_SNAPSHOT_BYTES:
        raise ProvenanceError("snapshot size is invalid")
    digest = _sha256(value["sha256"], "snapshot SHA-256")
    if tool:
        capabilities = value["capabilities"]
        if capabilities is not None and not isinstance(capabilities, dict):
            raise ProvenanceError("tool capabilities must be an object or null")
    if verify_artifact:
        artifact = workspace / relative
        metadata = _real_file(artifact, "snapshot artifact", MAX_SNAPSHOT_BYTES)
        raw = artifact.read_bytes()
        if metadata.st_size != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ProvenanceError("snapshot artifact hash validation failed")
        if tool and python_capabilities(raw, value["original_name"]) != value["capabilities"]:
            raise ProvenanceError("snapshot capability attestation is stale")
    return value


def _validate_run_record(
    workspace: Path,
    record: dict[str, Any],
    states: dict[str, dict[str, Any]],
    *,
    verify_artifacts: bool,
    secret_exemptions: dict[str, set[str]] | None = None,
    context: report_contract.ValidationContext | None = None,
) -> dict[str, Any]:
    active_context = report_contract._validation_context(workspace, context)
    if set(record) != RUN_FIELDS or record.get("schema_version") != "1.0":
        raise ProvenanceError("execution run has unsupported schema")
    run_id = record["run_id"]
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ProvenanceError("execution run has malformed identity")
    _parse_timestamp(record["captured_at_utc"], "run capture")
    step_id = record["report_step_id"]
    state = states.get(step_id)
    if state is None:
        raise ProvenanceError("execution run references an unknown report step")
    plan = state["plan"]
    transition = state["transition"]
    if plan["operation_origin"] == "missing" or (
        transition is not None
        and transition["event"] in {"legacy_missing", "superseded"}
    ):
        raise ProvenanceError("execution run cannot bind unavailable report history")
    if record["host_id"] != plan["host_id"]:
        raise ProvenanceError("execution run belongs to an unrelated host")
    if record["plan_event_id"] != plan["step_event_id"]:
        raise ProvenanceError("execution run references a different step plan version")
    if record["operation_kind"] != plan["operation_kind"]:
        raise ProvenanceError("execution run operation kind differs from its step")
    if record["operation_origin"] != plan["operation_origin"]:
        raise ProvenanceError("execution run operation origin differs from its step")
    if record["input_sha256"] != _step_input_sha256(plan):
        raise ProvenanceError("execution run input hash differs from its step")
    run_input = {field: record[field] for field in RUN_INPUT_FIELDS}
    _validate_run_input(
        workspace,
        plan["host_id"],
        run_input,
        secret_exemptions=secret_exemptions,
        context=active_context,
    )
    tool = record["tool"]
    if tool is not None:
        _validate_snapshot(
            workspace, tool, tool=True, verify_artifact=verify_artifacts
        )
        if Path(tool["artifact_path"]).parent != Path(
            RUN_DIRECTORY, record["host_id"], run_id
        ):
            raise ProvenanceError("tool snapshot is outside its RUN-ID directory")
    dependencies = record["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) > 32:
        raise ProvenanceError("execution run dependencies must be a bounded list")
    artifact_paths: set[str] = set()
    for dependency in dependencies:
        _validate_snapshot(
            workspace, dependency, tool=False, verify_artifact=verify_artifacts
        )
        if Path(dependency["artifact_path"]).parent != Path(
            RUN_DIRECTORY, record["host_id"], run_id
        ):
            raise ProvenanceError(
                "dependency snapshot is outside its RUN-ID directory"
            )
        if dependency["artifact_path"] in artifact_paths:
            raise ProvenanceError("execution run dependency artifact is duplicated")
        artifact_paths.add(dependency["artifact_path"])
    if tool is not None and tool["artifact_path"] in artifact_paths:
        raise ProvenanceError("execution run snapshot artifact is duplicated")
    report_contract.reject_secrets(
        workspace,
        record,
        allowed_credential_ids_by_path=secret_exemptions,
        context=active_context,
    )
    return record


def _load_runs_with_context(
    workspace: Path,
    states: dict[str, dict[str, Any]],
    context: report_contract.ValidationContext,
    *,
    verify_artifacts: bool,
) -> dict[str, dict[str, Any]]:
    records = _jsonl(workspace / RUN_LEDGER, "execution run ledger")
    exemptions = _run_secret_adjudication_exemptions(
        workspace, records, context=context
    )
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        _validate_run_record(
            workspace,
            record,
            states,
            verify_artifacts=verify_artifacts,
            secret_exemptions=exemptions.get(record.get("run_id", "")),
            context=context,
        )
        run_id = record["run_id"]
        if run_id in result:
            raise ProvenanceError("execution run ledger contains duplicate IDs")
        result[run_id] = record
    return result


def load_runs(
    workspace: Path, *, verify_artifacts: bool = True
) -> dict[str, dict[str, Any]]:
    context = report_contract.ValidationContext(workspace)
    _, states = report_contract.load_steps(workspace, context=context)
    return _load_runs_with_context(
        workspace,
        states,
        context,
        verify_artifacts=verify_artifacts,
    )


def _http_capability_matches(run: dict[str, Any], method: str, path: str) -> bool:
    tool = run["tool"]
    if tool is None or tool["capabilities"] is None:
        return True
    capabilities = tool["capabilities"]
    if capabilities.get("parse_status") != "ok":
        return True
    if capabilities.get("recognized_http_calls", 0) < 1:
        return True
    methods = capabilities.get("http_methods", [])
    if not capabilities.get("dynamic_method", False) and method not in methods:
        return False
    paths = capabilities.get("http_paths", [])
    return not (
        paths
        and not capabilities.get("dynamic_path", False)
        and path not in paths
    )


def _validate_verification(
    workspace: Path,
    record: dict[str, Any],
    run: dict[str, Any] | None,
    *,
    context: report_contract.ValidationContext | None = None,
) -> None:
    active_context = report_contract._validation_context(workspace, context)
    claim_type = record["claim_type"]
    verification = record["verification"]
    if not isinstance(verification, dict):
        raise ProvenanceError("claim verification must be an object")
    if claim_type == "http_exchange":
        if set(verification) != {"method", "path", "status_code"}:
            raise ProvenanceError("HTTP claim verification is malformed")
        method = verification["method"]
        path = verification["path"]
        status_code = verification["status_code"]
        if not isinstance(method, str) or HTTP_METHOD_RE.fullmatch(method) is None:
            raise ProvenanceError("HTTP claim method is malformed")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or "#" in path
        ):
            raise ProvenanceError("HTTP claim path is malformed")
        if not isinstance(status_code, int) or not 100 <= status_code <= 599:
            raise ProvenanceError("HTTP claim status code is malformed")
        if record["support_status"] == "supported":
            if run is None:
                raise ProvenanceError("supported HTTP claim requires one RUN-ID")
            matches = [
                item
                for item in run["http_exchanges"]
                if item["method"] == method
                and item["path"] == path
                and item["status_code"] == status_code
            ]
            if len(matches) != 1:
                raise ProvenanceError("HTTP claim is absent from the structured run trace")
            if matches[0]["evidence_id"] not in record["evidence_ids"]:
                raise ProvenanceError("HTTP claim omits its exact exchange evidence")
            if not _http_capability_matches(run, method, path):
                raise ProvenanceError("HTTP claim contradicts the snapshotted helper")
    elif claim_type == "helper_assertion":
        if set(verification) != {"name", "value_sha256"}:
            raise ProvenanceError("helper claim verification is malformed")
        name = verification["name"]
        if not isinstance(name, str) or ASSERTION_NAME_RE.fullmatch(name) is None:
            raise ProvenanceError("helper claim assertion name is malformed")
        value_sha256 = _sha256(
            verification["value_sha256"], "helper claim value hash", nullable=True
        )
        if record["support_status"] == "supported":
            if run is None:
                raise ProvenanceError("supported helper claim requires one RUN-ID")
            matches = [item for item in run["assertions"] if item["name"] == name]
            if len(matches) != 1 or matches[0]["status"] != "pass":
                raise ProvenanceError("helper claim lacks one passing run assertion")
            if value_sha256 is not None and matches[0]["value_sha256"] != value_sha256:
                raise ProvenanceError("helper claim value hash differs from the run")
            if matches[0]["evidence_id"] not in record["evidence_ids"]:
                raise ProvenanceError("helper claim omits its exact assertion evidence")
    elif claim_type == "credential_provenance":
        if set(verification) != {"source_kind", "source_locator", "source_sha256"}:
            raise ProvenanceError("credential provenance verification is malformed")
        if verification["source_kind"] not in SOURCE_KINDS:
            raise ProvenanceError("credential provenance source kind is invalid")
        locator = _text(
            verification["source_locator"], "credential source locator", 2048
        )
        assert locator is not None
        if "?" in locator or "#" in locator or "@" in locator:
            raise ProvenanceError("credential source locator may expose URL secrets")
        source_sha256 = _sha256(
            verification["source_sha256"],
            "credential source SHA-256",
            nullable=True,
        )
        if len(record["credential_ids"]) != 1:
            raise ProvenanceError("credential provenance requires exactly one CRED-ID")
        if record["support_status"] == "supported" and not record["evidence_ids"]:
            raise ProvenanceError("credential provenance requires retained evidence")
        if source_sha256 is not None:
            evidence = active_context.evidence
            if not any(
                evidence[item].get("sha256") == source_sha256
                for item in record["evidence_ids"]
            ):
                raise ProvenanceError(
                    "credential source hash is absent from retained evidence"
                )
    elif claim_type == "artifact_fact":
        if set(verification) != {"artifact_sha256"}:
            raise ProvenanceError("artifact claim verification is malformed")
        digest = _sha256(verification["artifact_sha256"], "artifact claim SHA-256")
        evidence = active_context.evidence
        if record["support_status"] == "supported" and not any(
            evidence[item].get("sha256") == digest for item in record["evidence_ids"]
        ):
            raise ProvenanceError("artifact claim hash is absent from retained evidence")
    else:
        if set(verification) != {"basis"} or verification["basis"] != "manual-review":
            raise ProvenanceError("text claim verification must declare manual-review")
        if record["support_status"] == "supported" and run is None and not record["evidence_ids"]:
            raise ProvenanceError("supported text claim requires run or evidence support")


def _validate_claim_record(
    workspace: Path,
    record: dict[str, Any],
    states: dict[str, dict[str, Any]],
    runs: dict[str, dict[str, Any]],
    *,
    secret_exemptions: dict[str, set[str]] | None = None,
    context: report_contract.ValidationContext | None = None,
) -> dict[str, Any]:
    active_context = report_contract._validation_context(workspace, context)
    if set(record) != CLAIM_FIELDS or record.get("schema_version") != "1.0":
        raise ProvenanceError("claim has unsupported schema")
    claim_id = record["claim_id"]
    if not isinstance(claim_id, str) or CLAIM_ID_RE.fullmatch(claim_id) is None:
        raise ProvenanceError("claim has malformed identity")
    _parse_timestamp(record["created_at_utc"], "claim creation")
    step_id = record["report_step_id"]
    state = states.get(step_id)
    if state is None or state["plan"]["host_id"] != record["host_id"]:
        raise ProvenanceError("claim references an unknown or unrelated report step")
    transition = state["transition"]
    if transition is not None and transition["event"] in {
        "legacy_missing",
        "superseded",
    }:
        raise ProvenanceError("claim cannot bind unavailable report history")
    if record["classification"] not in CLAIM_CLASSIFICATIONS:
        raise ProvenanceError("claim classification is invalid")
    if record["support_status"] not in SUPPORT_STATUSES:
        raise ProvenanceError("claim support status is invalid")
    if record["claim_type"] not in CLAIM_TYPES:
        raise ProvenanceError("claim type is invalid")
    _text(record["statement"], "claim statement", 1024)
    if record["classification"] == "unsupported" and record["support_status"] != "not_supported":
        raise ProvenanceError("unsupported claim must use not_supported status")
    if record["support_status"] == "not_supported" and record["classification"] != "unsupported":
        raise ProvenanceError("not_supported status requires unsupported classification")
    if record["support_status"] == "supported" and record["classification"] == "unsupported":
        raise ProvenanceError("unsupported claim cannot be marked supported")
    run_id = record["run_id"]
    run: dict[str, Any] | None = None
    if run_id is not None:
        if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
            raise ProvenanceError("claim RUN-ID is malformed")
        run = runs.get(run_id)
        if run is None:
            raise ProvenanceError("claim references an unknown RUN-ID")
        if run["host_id"] != record["host_id"] or run["report_step_id"] != step_id:
            raise ProvenanceError("claim RUN-ID belongs to another operation")
    evidence_ids = _string_list(
        record["evidence_ids"], "claim evidence_ids", report_contract.EVIDENCE_ID_RE
    )
    evidence = active_context.evidence
    if any(
        item not in evidence or not active_context.same_host(evidence[item].get("host_id"), record["host_id"])
        for item in evidence_ids
    ):
        raise ProvenanceError("claim evidence belongs to an unrelated host")
    if run is not None and any(item not in run["evidence_ids"] for item in evidence_ids):
        raise ProvenanceError("claim evidence was not captured by its RUN-ID")
    credential_ids = _string_list(
        record["credential_ids"],
        "claim credential_ids",
        report_contract.CREDENTIAL_ID_RE,
    )
    credentials = active_context.credentials
    if any(
        item not in credentials
        or not active_context.same_host(credentials[item].get("host_id"), record["host_id"])
        for item in credential_ids
    ):
        raise ProvenanceError("claim credential belongs to an unrelated host")
    if record["claim_type"] != "credential_provenance" and credential_ids:
        raise ProvenanceError("only credential provenance claims may bind CRED-IDs")
    _validate_verification(
        workspace, record, run, context=active_context
    )
    report_contract.reject_secrets(
        workspace,
        record,
        allowed_credential_ids_by_path=secret_exemptions,
        context=active_context,
    )
    return record


def _load_claims_with_context(
    workspace: Path,
    states: dict[str, dict[str, Any]],
    runs: dict[str, dict[str, Any]],
    context: report_contract.ValidationContext,
) -> dict[str, dict[str, Any]]:
    records = _jsonl(workspace / CLAIM_LEDGER, "claim ledger")
    exemptions = _claim_secret_adjudication_exemptions(
        workspace, records, context=context
    )
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        _validate_claim_record(
            workspace,
            record,
            states,
            runs,
            secret_exemptions=exemptions.get(record.get("claim_id", "")),
            context=context,
        )
        claim_id = record["claim_id"]
        if claim_id in result:
            raise ProvenanceError("claim ledger contains duplicate IDs")
        result[claim_id] = record
    return result


def load_claims(
    workspace: Path,
    runs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    context = report_contract.ValidationContext(workspace)
    _, states = report_contract.load_steps(workspace, context=context)
    active_runs = runs
    if active_runs is None:
        active_runs = _load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
    return _load_claims_with_context(
        workspace, states, active_runs, context
    )


def initialize(
    workspace: Path,
    *,
    apply: bool,
) -> tuple[str, ...]:
    """Preview or initialize provenance state without replacing existing data."""
    desired = [workspace / RUN_DIRECTORY, workspace / RUN_LEDGER, workspace / CLAIM_LEDGER]
    desired.extend(
        workspace / RUN_DIRECTORY / host_id
        for host_id in sorted(host_identity.known_host_ids(workspace))
    )
    actions = tuple(
        f"create:{path.relative_to(workspace).as_posix()}"
        for path in desired
        if not _lexists(path)
    )
    for path in desired:
        if not _lexists(path):
            continue
        if path.suffix == ".jsonl":
            _real_file(path, f"workspace {path.name}", MAX_LEDGER_BYTES)
        else:
            _real_directory(path, f"workspace {path.name}")
    if not apply:
        return actions
    lock_path = workspace / ".provenance.init.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        root = workspace / RUN_DIRECTORY
        root.mkdir(mode=0o700, exist_ok=True)
        _real_directory(root, "execution run directory")
        for host_id in sorted(host_identity.known_host_ids(workspace)):
            host_root = root / host_id
            host_root.mkdir(mode=0o700, exist_ok=True)
            _real_directory(host_root, "host execution run directory")
        for name in (RUN_LEDGER, CLAIM_LEDGER):
            path = workspace / name
            if not _lexists(path):
                file_descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                os.close(file_descriptor)
            _real_file(path, f"workspace {name}", MAX_LEDGER_BYTES)
    finally:
        os.close(descriptor)
    return actions


def capture_run(
    workspace: Path,
    step_id: str,
    input_path: Path,
    *,
    tool_path: Path | None,
    dependency_paths: list[Path],
    apply: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Capture one exact, non-executing receipt for one report operation."""
    _real_directory(workspace / RUN_DIRECTORY, "execution run directory")
    _real_file(workspace / RUN_LEDGER, "execution run ledger", MAX_LEDGER_BYTES)
    value = _json_file(input_path, "run input")
    moment = now or datetime.now(UTC)
    run_id = _identifier("RUN", moment)

    def prepare(
        context: report_contract.ValidationContext,
    ) -> tuple[
        dict[str, Any],
        dict[str, dict[str, Any]],
        Path,
        Path,
        bytes | None,
        list[tuple[bytes, dict[str, Any]]],
    ]:
        _, states = report_contract.load_steps(workspace, context=context)
        state = states.get(step_id)
        if state is None:
            raise ProvenanceError("execution run references an unknown report step")
        plan = state["plan"]
        host_id = plan["host_id"]
        _validate_run_input(workspace, host_id, value, context=context)
        existing = _load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
        if any(
            record["report_step_id"] == step_id for record in existing.values()
        ):
            raise ProvenanceError("report step already has an execution RUN-ID")
        if run_id in existing:
            raise ProvenanceError("generated RUN-ID already exists; retry")
        host_root = workspace / RUN_DIRECTORY / host_id
        _real_directory(host_root, "host execution run directory")
        final = host_root / run_id
        if _lexists(final):
            raise ProvenanceError("execution run artifact directory already exists")
        tool_raw: bytes | None = None
        tool_record: dict[str, Any] | None = None
        if tool_path is not None:
            tool_raw, _ = _read_snapshot(tool_path, "tool source")
            suffix = tool_path.suffix.lower() if len(tool_path.suffix) <= 16 else ""
            artifact = final / f"tool{suffix}"
            tool_record = _snapshot_record(
                workspace,
                tool_path,
                artifact,
                tool_raw,
                capabilities=python_capabilities(tool_raw, tool_path.name),
            )
        dependency_data: list[tuple[bytes, dict[str, Any]]] = []
        for index, dependency in enumerate(dependency_paths, 1):
            raw, _ = _read_snapshot(dependency, "dependency source")
            suffix = (
                dependency.suffix.lower()
                if len(dependency.suffix) <= 16
                else ""
            )
            artifact = final / f"dependency-{index:02d}{suffix}"
            dependency_data.append(
                (raw, _snapshot_record(workspace, dependency, artifact, raw))
            )
        record = {
            "schema_version": "1.0",
            "run_id": run_id,
            "captured_at_utc": _timestamp(moment),
            "host_id": host_id,
            "report_step_id": step_id,
            "plan_event_id": plan["step_event_id"],
            "operation_kind": plan["operation_kind"],
            "operation_origin": plan["operation_origin"],
            "input_sha256": _step_input_sha256(plan),
            **value,
            "tool": tool_record,
            "dependencies": [item[1] for item in dependency_data],
        }
        _validate_run_record(
            workspace,
            record,
            states,
            verify_artifacts=False,
            context=context,
        )
        return (
            record,
            states,
            host_root,
            final,
            tool_raw,
            dependency_data,
        )

    if not apply:
        record, _, _, _, _, _ = prepare(
            report_contract.ValidationContext(workspace)
        )
        return record
    step_descriptor = report_contract._acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_SH
    )
    descriptor: int | None = None
    published = False
    final: Path | None = None
    try:
        descriptor = report_contract._acquire_ledger_lock(
            workspace, ".execution_runs.lock", fcntl.LOCK_EX
        )
        context = report_contract.ValidationContext(workspace)
        (
            record,
            states,
            host_root,
            final,
            tool_raw,
            dependency_data,
        ) = prepare(context)
        tool_record = record["tool"]
        temporary: Path | None = None
        try:
            temporary = Path(
                tempfile.mkdtemp(prefix=f".{run_id}.", dir=host_root)
            )
            os.chmod(temporary, 0o700)
            if tool_record is not None and tool_raw is not None:
                _atomic_write(
                    temporary / Path(tool_record["artifact_path"]).name,
                    tool_raw,
                    replace=False,
                )
            for raw, snapshot in dependency_data:
                _atomic_write(
                    temporary / Path(snapshot["artifact_path"]).name,
                    raw,
                    replace=False,
                )
            os.rename(temporary, final)
            published = True
        finally:
            if temporary is not None and _lexists(temporary):
                shutil.rmtree(temporary)
        _validate_run_record(
            workspace,
            record,
            states,
            verify_artifacts=True,
            context=context,
        )
        _append_record(workspace / RUN_LEDGER, record)
    except BaseException as exc:
        if published and final is not None and _lexists(final):
            # The run lock is still held here. A failed append can be
            # pre-commit, or it can be durability-ambiguous after the complete
            # JSON line became visible but fsync failed. Never remove an
            # artifact that a canonical RUN-ID may already reference.
            try:
                current = _load_runs_with_context(
                    workspace,
                    states,
                    report_contract.ValidationContext(workspace),
                    verify_artifacts=True,
                )
            except (OSError, ProvenanceError, report_contract.ReportContractError):
                raise ProvenanceError(
                    "execution run commit outcome is ambiguous; ledger recovery "
                    "is required and the snapshot was preserved"
                ) from exc
            if run_id in current:
                raise ProvenanceError(
                    "execution run commit outcome is ambiguous; canonical RUN-ID "
                    "is present and the snapshot was preserved for recovery"
                ) from exc
            try:
                shutil.rmtree(final)
            except OSError as recovery_exc:
                raise ProvenanceError(
                    "execution run was not committed, but snapshot cleanup failed "
                    "and recovery is required"
                ) from recovery_exc
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(step_descriptor)
    return record


def append_claim(
    workspace: Path,
    host_id: str,
    step_id: str,
    input_path: Path,
    *,
    apply: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Preview or append one atomic, typed report claim."""
    value = _json_file(input_path, "claim input")
    if set(value) != CLAIM_INPUT_FIELDS:
        raise ProvenanceError("claim input has unexpected fields")
    moment = now or datetime.now(UTC)
    claim_id = _identifier("CLM", moment)
    record = {
        "schema_version": "1.0",
        "claim_id": claim_id,
        "created_at_utc": _timestamp(moment),
        "host_id": host_id,
        "report_step_id": step_id,
        **value,
    }

    def validate_current(context: report_contract.ValidationContext) -> None:
        _, states = report_contract.load_steps(workspace, context=context)
        runs = _load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
        claims = _load_claims_with_context(
            workspace, states, runs, context
        )
        if claim_id in claims:
            raise ProvenanceError("generated CLM-ID already exists; retry")
        _validate_claim_record(
            workspace,
            record,
            states,
            runs,
            context=context,
        )

    if not apply:
        validate_current(report_contract.ValidationContext(workspace))
        return record
    step_descriptor = report_contract._acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_SH
    )
    run_descriptor: int | None = None
    descriptor: int | None = None
    try:
        run_descriptor = report_contract._acquire_ledger_lock(
            workspace, ".execution_runs.lock", fcntl.LOCK_SH
        )
        descriptor = report_contract._acquire_ledger_lock(
            workspace, ".claims.lock", fcntl.LOCK_EX
        )
        validate_current(report_contract.ValidationContext(workspace))
        _append_record(workspace / CLAIM_LEDGER, record)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if run_descriptor is not None:
            os.close(run_descriptor)
        os.close(step_descriptor)
    return record


def _render_index_text(
    workspace: Path,
    runs: dict[str, dict[str, Any]],
    claims: dict[str, dict[str, Any]],
    states: dict[str, dict[str, Any]],
) -> str:
    lines = [
        "# Execution Provenance and Atomic Claims",
        "",
        "Generated only from `execution_runs.jsonl` and `claims.jsonl`.",
        "Response bodies and credential values are intentionally excluded.",
        "",
    ]
    for step_id in states:
        step_runs = [item for item in runs.values() if item["report_step_id"] == step_id]
        step_claims = [
            item for item in claims.values() if item["report_step_id"] == step_id
        ]
        if not step_runs and not step_claims:
            continue
        lines.extend([f"## {step_id}", ""])
        for run in sorted(step_runs, key=lambda item: item["run_id"]):
            tool = run["tool"]
            tool_text = "none"
            if tool is not None:
                tool_text = (
                    f"`{tool['artifact_path']}` "
                    f"(`sha256:{tool['sha256']}`)"
                )
            lines.extend(
                [
                    f"- **Run**: `{run['run_id']}`",
                    f"- **Status**: `{run['status']}`",
                    f"- **Plan input SHA-256**: `{run['input_sha256']}`",
                    f"- **Exact tool snapshot**: {tool_text}",
                ]
            )
            for exchange in run["http_exchanges"]:
                lines.append(
                    "- **HTTP exchange**: "
                    f"`{exchange['method']} {exchange['path']}` -> "
                    f"`{exchange['status_code']}` "
                    f"(`{exchange['evidence_id']}`)"
                )
            for assertion in run["assertions"]:
                lines.append(
                    "- **Helper assertion**: "
                    f"`{assertion['name']}` = `{assertion['status']}` "
                    f"(`{assertion['evidence_id']}`)"
                )
        for claim in sorted(step_claims, key=lambda item: item["claim_id"]):
            statement = html.escape(claim["statement"])
            if claim["support_status"] == "not_supported":
                statement = "NOT SUPPORTED BY RETAINED EVIDENCE — " + statement
            lines.append(
                f"- **Claim `{claim['claim_id']}`** "
                f"(`{claim['classification']}`, `{claim['support_status']}`): "
                f"{statement}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_index(workspace: Path, *, apply: bool) -> str:
    def render_current() -> tuple[Path, str, str]:
        context = report_contract.ValidationContext(workspace)
        _, states = report_contract.load_steps(workspace, context=context)
        runs = _load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
        claims = _load_claims_with_context(
            workspace, states, runs, context
        )
        text = _render_index_text(workspace, runs, claims, states)
        # Exact credential values were checked on every source record above. The
        # deterministic renderer may reproduce an explicitly adjudicated historical
        # substring collision, so only intrinsic secret shapes are checked again.
        report_contract.reject_secret_shapes(text)
        path = workspace / INDEX_PATH
        action = (
            "noop"
            if _lexists(path) and path.read_text(encoding="utf-8") == text
            else "replace"
        )
        return path, text, action

    if not apply:
        return render_current()[2]

    # Applying the derived index is one cross-ledger snapshot transaction. Keep
    # the shared locks through the atomic replacement so every cooperating writer
    # is ordered either before or after the committed index.
    step_descriptor = report_contract._acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_SH
    )
    run_descriptor: int | None = None
    claim_descriptor: int | None = None
    try:
        run_descriptor = report_contract._acquire_ledger_lock(
            workspace, ".execution_runs.lock", fcntl.LOCK_SH
        )
        claim_descriptor = report_contract._acquire_ledger_lock(
            workspace, ".claims.lock", fcntl.LOCK_SH
        )
        path, text, action = render_current()
        if action != "noop":
            _atomic_write(path, text.encode(), replace=True)
        return action
    finally:
        if claim_descriptor is not None:
            os.close(claim_descriptor)
        if run_descriptor is not None:
            os.close(run_descriptor)
        os.close(step_descriptor)


def _evaluate_provenance_with_context(
    workspace: Path,
    *,
    strict: bool,
    context: report_contract.ValidationContext,
    states: dict[str, dict[str, Any]] | None = None,
) -> ProvenanceReadiness:
    blockers: list[str] = []
    warnings: list[str] = []
    required = (workspace / RUN_LEDGER, workspace / CLAIM_LEDGER, workspace / RUN_DIRECTORY)
    enabled = all(_lexists(path) for path in required)
    if not enabled:
        if strict:
            blockers.append("provenance:not-initialized")
        return ProvenanceReadiness(
            enabled=False,
            ready=not blockers,
            blockers=tuple(blockers),
            warnings=(),
            run_count=0,
            claim_count=0,
        )
    active_context = report_contract._validation_context(workspace, context)
    active_states = states
    if active_states is None:
        _, active_states = report_contract.load_steps(
            workspace, context=active_context
        )
    runs = _load_runs_with_context(
        workspace,
        active_states,
        active_context,
        verify_artifacts=True,
    )
    claims = _load_claims_with_context(
        workspace, active_states, runs, active_context
    )
    if strict and not active_states:
        blockers.append("provenance:report-steps-empty")
    runs_by_step: dict[str, list[dict[str, Any]]] = {}
    claims_by_step: dict[str, list[dict[str, Any]]] = {}
    for run in runs.values():
        runs_by_step.setdefault(run["report_step_id"], []).append(run)
        tool = run["tool"]
        if tool is not None and tool["source_path"] is not None:
            source = workspace / tool["source_path"]
            if not _lexists(source):
                warnings.append(f"run:{run['run_id']}:current-source-missing")
            else:
                try:
                    raw, _ = _read_snapshot(source, "current tool source")
                except ProvenanceError:
                    warnings.append(f"run:{run['run_id']}:current-source-unreadable")
                else:
                    if hashlib.sha256(raw).hexdigest() != tool["sha256"]:
                        warnings.append(f"run:{run['run_id']}:current-source-drift")
    for claim in claims.values():
        claims_by_step.setdefault(claim["report_step_id"], []).append(claim)
    expected_status = {
        "completed": "success",
        "failed": "failed",
        "partial": "partial",
    }
    for step_id, state in active_states.items():
        transition = state["transition"]
        if transition is None or transition["event"] in {"superseded", "legacy_missing"}:
            continue
        step_runs = runs_by_step.get(step_id, [])
        if len(step_runs) != 1:
            blockers.append(f"step:{step_id}:execution-run-count:{len(step_runs)}")
            continue
        expected = expected_status.get(transition["event"])
        if expected is not None and step_runs[0]["status"] != expected:
            blockers.append(f"step:{step_id}:run-outcome-mismatch")
        step_claims = claims_by_step.get(step_id, [])
        if not step_claims:
            blockers.append(f"step:{step_id}:claim-missing")
        if transition["event"] == "completed":
            for claim in step_claims:
                if claim["support_status"] != "supported":
                    blockers.append(f"claim:{claim['claim_id']}:not-supported")
                if claim["classification"] in {"inferred", "unsupported"}:
                    blockers.append(f"claim:{claim['claim_id']}:non-factual")
    credentials_with_provenance = {
        credential_id
        for claim in claims.values()
        if claim["claim_type"] == "credential_provenance"
        and claim["support_status"] == "supported"
        for credential_id in claim["credential_ids"]
    }
    for state in active_states.values():
        credential_ids = list(state["plan"]["credential_ids"])
        transition = state["transition"]
        if transition is not None and transition["event"] != "superseded":
            credential_ids.extend(transition.get("credential_ids", []))
        for credential_id in credential_ids:
            if credential_id not in credentials_with_provenance:
                blockers.append(f"credential:{credential_id}:source-provenance-missing")
    if runs or claims:
        expected_index = _render_index_text(
            workspace, runs, claims, active_states
        )
        index = workspace / INDEX_PATH
        if not _lexists(index):
            blockers.append("provenance:index-missing")
        else:
            _real_file(index, "provenance index", 16 * 1024 * 1024)
            try:
                current = index.read_text(encoding="utf-8")
            except UnicodeError as exc:
                raise ProvenanceError("provenance index is not valid UTF-8") from exc
            if current != expected_index:
                blockers.append("provenance:index-stale")
    return ProvenanceReadiness(
        enabled=True,
        ready=not blockers,
        blockers=tuple(dict.fromkeys(blockers)),
        warnings=tuple(dict.fromkeys(warnings)),
        run_count=len(runs),
        claim_count=len(claims),
    )


def evaluate_provenance(
    workspace: Path,
    *,
    strict: bool,
) -> ProvenanceReadiness:
    return _evaluate_provenance_with_context(
        workspace,
        strict=strict,
        context=report_contract.ValidationContext(workspace),
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Capture exact execution receipts and atomic report claims."
    )
    commands = root.add_subparsers(dest="command", required=True)
    initialize_parser = commands.add_parser("init", help="initialize provenance state")
    initialize_parser.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    mode = initialize_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    adjudication = commands.add_parser(
        "secret-adjudication",
        help="review exact retroactive credential-substring matches in run records",
    )
    adjudication.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    adjudication.add_argument("--credential-id", required=True)
    adjudication.add_argument(
        "--record-type", choices=("run", "claim"), default="run"
    )
    mode = adjudication.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    adjudication.add_argument(
        "--ack-reviewed-false-positives", action="store_true"
    )
    run = commands.add_parser("record", aliases=["run"], help="record a supplied execution receipt; does not execute commands")
    run.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    run.add_argument("--step-id", required=True)
    run.add_argument("--record", required=True)
    run.add_argument("--tool")
    run.add_argument("--dependency", action="append", default=[])
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    claim = commands.add_parser("claim", help="append one typed atomic claim")
    claim.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    claim.add_argument("--host-id", required=True)
    claim.add_argument("--step-id", required=True)
    claim.add_argument("--record", required=True)
    mode = claim.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    render = commands.add_parser("render", help="render the canonical provenance index")
    render.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    mode = render.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    check = commands.add_parser("check", help="check provenance readiness")
    check.add_argument("--workspace", default=str(DEFAULT_COLLECTION))
    check.add_argument("--strict", action="store_true")
    check.add_argument(
        "--barrier",
        choices=report_contract.VALIDATION_BARRIERS,
        required=True,
        help="declare the milestone that justifies a full provenance check",
    )
    return root


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        workspace = resolve_workspace(Path(args.workspace))
        if args.command == "init":
            actions = initialize(workspace, apply=args.apply)
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"actions: {len(actions)}")
            for action in actions:
                print(action)
            return 0
        if args.command == "secret-adjudication":
            adjudicator = (
                adjudicate_retroactive_run_secret_matches
                if args.record_type == "run"
                else adjudicate_retroactive_claim_secret_matches
            )
            result = adjudicator(
                workspace,
                args.credential_id,
                apply=args.apply,
                acknowledged=args.ack_reviewed_false_positives,
                now=now,
            )
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"credential_id: {result['credential_id']}")
            print(f"candidate_matches: {result['candidate_count']}")
            print(f"existing_matches: {result['existing_count']}")
            for match in result["matches"]:
                record_id = match.get("run_id") or match.get("claim_id")
                print(
                    "match: "
                    f"{record_id} {match['field_path']} "
                    f"sha256:{match['field_sha256']}"
                )
            return 0
        if args.command in {"run", "record"}:
            record = capture_run(
                workspace,
                args.step_id,
                Path(args.record),
                tool_path=Path(args.tool) if args.tool else None,
                dependency_paths=[Path(item) for item in args.dependency],
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"run_id: {record['run_id']}")
            print(f"step_id: {record['report_step_id']}")
            print(f"tool_sha256: {record['tool']['sha256'] if record['tool'] else 'none'}")
            return 0
        if args.command == "claim":
            record = append_claim(
                workspace,
                args.host_id,
                args.step_id,
                Path(args.record),
                apply=args.apply,
                now=now,
            )
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"claim_id: {record['claim_id']}")
            print(f"support_status: {record['support_status']}")
            return 0
        if args.command == "render":
            action = render_index(workspace, apply=args.apply)
            print(f"mode: {'apply' if args.apply else 'preview'}")
            print(f"render_action: {action}")
            print(f"index_path: {workspace / INDEX_PATH}")
            return 0
        state = evaluate_provenance(workspace, strict=args.strict)
        print(f"validation_barrier: {args.barrier}")
        print(f"provenance_enabled: {'yes' if state.enabled else 'no'}")
        print(f"provenance_ready: {'yes' if state.ready else 'no'}")
        print(f"execution_runs: {state.run_count}")
        print(f"atomic_claims: {state.claim_count}")
        print(f"blocking_items: {len(state.blockers)}")
        if state.blockers:
            print(f"blockers: {','.join(state.blockers)}")
        print(f"warning_items: {len(state.warnings)}")
        if state.warnings:
            print(f"warnings: {','.join(state.warnings)}")
        return 0 if state.ready else 1
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        host_identity.HostIdentityError,
        report_contract.ReportContractError,
        ProvenanceError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
