"""Secure lifecycle management for ephemeral session tokens."""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

if __package__:
    from . import credential_intake, host_identity, operational_profile, runtime_config
else:
    import credential_intake  # type: ignore[no-redef]
    import host_identity  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import runtime_config

DEFAULT_COLLECTION = runtime_config.workspace_root()
TOKEN_ROOT = Path("private/session_tokens")
ACTIVE_DIRECTORY = "active"
LEDGER_NAME = "events.jsonl"
LOCK_NAME = ".token.lock"
FINGERPRINT_KEY_NAME = ".fingerprint-key"
INDEX_NAME = "TOKEN_INDEX.md"
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_SECRET_BYTES = 4096
MAX_TEXT = 512
HMAC_KEY_BYTES = 32
RENAME_NOREPLACE = 1

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
TOKEN_ID_RE = re.compile(r"^TOK-\d{8}T\d{12}Z$")
EVENT_ID_RE = re.compile(r"^TKE-\d{8}T\d{12}Z$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
ATTEMPT_ID_RE = re.compile(r"^ATT-\d{8}T\d{12}Z$")
CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
FINGERPRINT_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
SECRET_PATH_RE = re.compile(
    r"^private/session_tokens/active/(TOK-\d{8}T\d{12}Z)\.secret$"
)
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"
)

TOKEN_KINDS = {"session", "bearer", "api"}
EVENTS = {
    "captured",
    "validated",
    "promoted",
    "expired",
    "revoked",
    "discarded",
    "cleaned",
    "not_retained",
}
VALIDATION_STATES = {"unverified", "valid", "invalid"}
TERMINAL_EVENTS = {"cleaned", "not_retained"}
BASE_FIELDS = (
    "host_id",
    "service",
    "principal",
    "token_kind",
    "source_evidence_id",
    "source_attempt_id",
    "expires_at_utc",
    "scope",
    "audience",
    "fingerprint",
    "secret_path",
)
EVENT_FIELDS = (
    "schema_version",
    "event_id",
    "token_id",
    "created_at_utc",
    "event",
    *BASE_FIELDS,
    "validation_status",
    "validation_evidence_id",
    "validation_attempt_id",
    "credential_id",
    "reason",
)


class TokenLifecycleError(ValueError):
    """A bounded error that never includes a token value."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo attacker-supplied values."""

    def error(self, message: str) -> None:
        del message
        raise TokenLifecycleError("invalid command-line arguments")


@dataclass(frozen=True)
class TokenReadiness:
    """Metadata-only token closure summary."""

    total: int
    resolved: int
    blockers: tuple[str, ...]
    active_secret_files: int


@dataclass
class TokenLayout:
    """Verified filesystem layout used by one mutating transaction."""

    workspace: Path
    root: Path
    active: Path
    root_fd: int
    active_fd: int
    lock_fd: int

    def close(self) -> None:
        for name in ("lock_fd", "active_fd", "root_fd"):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                if name == "lock_fd":
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(descriptor)
                setattr(self, name, -1)


def _fault_point(event: str, **details: object) -> None:
    """No-op test seam for deterministic substitution and failure tests."""
    del event, details


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: str, name: str) -> datetime:
    if TIMESTAMP_RE.fullmatch(value) is None:
        raise TokenLifecycleError(f"{name} must use UTC microsecond format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TokenLifecycleError(f"{name} is not a valid timestamp") from exc


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _text(
    value: str | None,
    name: str,
    maximum: int = MAX_TEXT,
    *,
    required: bool = True,
) -> str | None:
    if value is None:
        if required:
            raise TokenLifecycleError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise TokenLifecycleError(f"{name} must be text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TokenLifecycleError(f"{name} must not contain control characters")
    normalized = value.strip()
    if not normalized:
        if required:
            raise TokenLifecycleError(f"{name} must not be empty")
        return None
    if len(normalized) > maximum:
        raise TokenLifecycleError(f"{name} exceeds its size limit")
    if (
        SECRET_ASSIGNMENT_RE.search(normalized)
        or JWT_RE.search(normalized)
        or "-----BEGIN " in normalized
    ):
        raise TokenLifecycleError(f"{name} appears to contain secret material")
    return normalized


def _real_directory(path: Path, label: str, *, private: bool = False) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise TokenLifecycleError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TokenLifecycleError(f"{label} must be a real non-symlink directory")
    if private and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise TokenLifecycleError(f"{label} must be user-owned with mode 0700")
    return metadata


def _real_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    private: bool = False,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise TokenLifecycleError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TokenLifecycleError(f"{label} must be a real non-symlink regular file")
    if metadata.st_size > maximum:
        raise TokenLifecycleError(f"{label} exceeds its size limit")
    if private and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise TokenLifecycleError(f"{label} must be user-owned with mode 0600")
    return metadata


def resolve_workspace(root: Path) -> Path:
    """Resolve a direct module workspace or the selected active module."""
    if ".." in root.parts:
        raise TokenLifecycleError("workspace path must not contain parent traversal")
    supplied = root.expanduser().absolute()
    _real_directory(supplied, "workspace")
    if (supplied / "global.md").exists():
        workspace = supplied
    else:
        marker = supplied / "ACTIVE_TASK"
        _real_file(marker, "ACTIVE_TASK", maximum=256, private=True)
        module = _text(
            marker.read_text(encoding="utf-8").strip(), "ACTIVE_TASK", 64
        )
        assert module is not None
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", module) is None:
            raise TokenLifecycleError("ACTIVE_TASK contains an invalid module name")
        workspace = supplied / module
        _real_directory(workspace, "active module workspace")
    for name in ("hosts", "report"):
        _real_directory(workspace / name, f"workspace {name}/")
    _real_file(workspace / "global.md", "workspace global.md", maximum=4 * 1024 * 1024)
    return workspace


def _ensure_private_directory(parent: Path, name: str) -> Path:
    path = parent / name
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _real_directory(path, name, private=True)
    return path


def _open_private_directory(path: Path, label: str) -> int:
    _real_directory(path, label, private=True)
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    opened = os.fstat(descriptor)
    current = path.lstat()
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        os.close(descriptor)
        raise TokenLifecycleError(f"{label} changed during open")
    return descriptor


def _open_lock(root_fd: int) -> int:
    created = False
    try:
        descriptor = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
    except FileNotFoundError:
        descriptor = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        created = True
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TokenLifecycleError("token lock must be user-owned with mode 0600")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except BaseException:
        os.close(descriptor)
        if created:
            try:
                os.unlink(LOCK_NAME, dir_fd=root_fd)
            except OSError:
                pass
        raise


def _ensure_layout(workspace: Path) -> TokenLayout:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(workspace)
    private = _ensure_private_directory(workspace, "private")
    root = _ensure_private_directory(private, "session_tokens")
    active = _ensure_private_directory(root, ACTIVE_DIRECTORY)
    root_fd = _open_private_directory(root, "session token directory")
    active_fd = -1
    lock_fd = -1
    try:
        active_fd = _open_private_directory(active, "active token directory")
        lock_fd = _open_lock(root_fd)
        return TokenLayout(workspace, root, active, root_fd, active_fd, lock_fd)
    except BaseException:
        if lock_fd >= 0:
            os.close(lock_fd)
        if active_fd >= 0:
            os.close(active_fd)
        os.close(root_fd)
        raise


def _read_fd(descriptor: int, maximum: int, label: str) -> bytes:
    opened = os.fstat(descriptor)
    if opened.st_size > maximum:
        raise TokenLifecycleError(f"{label} exceeds its size limit")
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    if len(raw) > maximum or len(raw) != after.st_size or (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise TokenLifecycleError(f"{label} changed during read")
    return raw


def _read_regular_at(
    directory_fd: int, name: str, maximum: int, label: str
) -> tuple[bytes, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise TokenLifecycleError(f"{label} does not exist") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise TokenLifecycleError(f"{label} must be user-owned with mode 0600")
    _fault_point("before_secret_open", directory_fd=directory_fd, name=name)
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
        )
    except OSError as exc:
        raise TokenLifecycleError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise TokenLifecycleError(f"{label} changed during open")
        raw = _read_fd(descriptor, maximum, label)
        return raw, opened
    finally:
        os.close(descriptor)


def _read_secret_stdin() -> bytes:
    raw = sys.stdin.buffer.readline(MAX_SECRET_BYTES + 2)
    remainder = sys.stdin.buffer.read(1)
    if remainder or len(raw) > MAX_SECRET_BYTES + 1:
        raise TokenLifecycleError("secret input exceeds its size limit")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    return _validate_secret(raw)


def _read_secret_interactive() -> bytes:
    try:
        value = getpass.getpass("Token value: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise TokenLifecycleError("secret input was not provided") from exc
    return _validate_secret(value.encode("utf-8"))


def _validate_secret(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_SECRET_BYTES:
        raise TokenLifecycleError("token value is empty or exceeds its size limit")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TokenLifecycleError("token value must be valid UTF-8") from exc
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TokenLifecycleError("token value must not contain control characters")
    return raw


def _fingerprint_key(layout: TokenLayout) -> bytes:
    try:
        raw, _ = _read_regular_at(
            layout.root_fd,
            FINGERPRINT_KEY_NAME,
            HMAC_KEY_BYTES,
            "fingerprint key",
        )
    except TokenLifecycleError as exc:
        try:
            os.stat(
                FINGERPRINT_KEY_NAME,
                dir_fd=layout.root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raw = secrets.token_bytes(HMAC_KEY_BYTES)
            descriptor = os.open(
                FINGERPRINT_KEY_NAME,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
                dir_fd=layout.root_fd,
            )
            try:
                os.write(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        else:
            raise exc
    if len(raw) != HMAC_KEY_BYTES:
        raise TokenLifecycleError("fingerprint key has an invalid size")
    return raw


def _fingerprint(key: bytes, secret: bytes) -> str:
    return "hmac-sha256:" + hmac.new(key, secret, hashlib.sha256).hexdigest()


def _reject_secret_text(secret: bytes, values: tuple[str | None, ...]) -> None:
    decoded = secret.decode("utf-8")
    for value in values:
        if value is not None and (
            value == decoded or (len(decoded) >= 8 and decoded in value)
        ):
            raise TokenLifecycleError("persistent metadata contains the token value")


def _write_secret(layout: TokenLayout, token_id: str, raw: bytes) -> os.stat_result:
    name = f"{token_id}.secret"
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=layout.active_fd,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_size != len(raw)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TokenLifecycleError("ephemeral token file failed verification")
        return metadata
    finally:
        os.close(descriptor)


def _renameat2(directory_fd: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        raise TokenLifecycleError("secure atomic cleanup is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _secure_remove(
    layout: TokenLayout,
    token_id: str,
    expected: os.stat_result,
    expected_secret: bytes,
) -> None:
    name = f"{token_id}.secret"
    quarantine = f".token-quarantine-{secrets.token_hex(16)}"
    _fault_point(
        "before_quarantine",
        directory_fd=layout.active_fd,
        name=name,
        quarantine=quarantine,
    )
    try:
        _renameat2(layout.active_fd, name, quarantine)
    except FileNotFoundError as exc:
        raise TokenLifecycleError("ephemeral token disappeared before cleanup") from exc
    except FileExistsError as exc:
        raise TokenLifecycleError("token quarantine collision") from exc
    _fault_point(
        "after_quarantine",
        directory_fd=layout.active_fd,
        name=name,
        quarantine=quarantine,
    )
    moved = os.stat(quarantine, dir_fd=layout.active_fd, follow_symlinks=False)
    if (
        moved.st_dev,
        moved.st_ino,
        stat.S_IFMT(moved.st_mode),
    ) != (
        expected.st_dev,
        expected.st_ino,
        stat.S_IFREG,
    ):
        raise TokenLifecycleError(
            "unexpected token object preserved for private adjudication"
        )
    descriptor = os.open(
        quarantine,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=layout.active_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise TokenLifecycleError(
                "unexpected token object preserved for private adjudication"
            )
        # Filesystems may immediately reuse an unlinked inode. Identity alone
        # does not prove that the quarantined bytes are the validated secret.
        actual = _read_fd(descriptor, MAX_SECRET_BYTES, "quarantined token")
        if not hmac.compare_digest(actual, expected_secret):
            raise TokenLifecycleError(
                "unexpected token object preserved for private adjudication"
            )
    finally:
        os.close(descriptor)
    os.unlink(quarantine, dir_fd=layout.active_fd)
    try:
        os.stat(quarantine, dir_fd=layout.active_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise TokenLifecycleError("token cleanup could not be verified")


def _reference_exists(
    workspace: Path,
    host_id: str,
    evidence_id: str | None,
    attempt_id: str | None,
) -> None:
    if evidence_id is not None:
        if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
            raise TokenLifecycleError("invalid evidence ID")
        try:
            metadata = host_identity.locate_evidence_metadata(
                workspace, host_id, evidence_id
            )
        except host_identity.HostIdentityError as exc:
            raise TokenLifecycleError(str(exc)) from exc
        _real_file(metadata, "evidence metadata", maximum=1024 * 1024)
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise TokenLifecycleError("evidence metadata is invalid") from exc
        if record.get("evidence_id") != evidence_id or record.get("host_id") != host_id:
            raise TokenLifecycleError("evidence reference has mismatched scope")
        digest = record.get("sha256")
        if not isinstance(digest, str):
            raise TokenLifecycleError("evidence metadata is incomplete")
        try:
            artifact = host_identity.locate_evidence_artifact(metadata, record)
        except host_identity.HostIdentityError as exc:
            raise TokenLifecycleError(str(exc)) from exc
        _real_file(artifact, "evidence artifact", maximum=64 * 1024 * 1024)
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
            raise TokenLifecycleError("evidence artifact hash verification failed")
    if attempt_id is not None:
        if ATTEMPT_ID_RE.fullmatch(attempt_id) is None:
            raise TokenLifecycleError("invalid attempt ID")
        ledger = workspace / "attempts.jsonl"
        _real_file(ledger, "attempt ledger", maximum=16 * 1024 * 1024)
        found = 0
        try:
            for line in ledger.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                if record.get("attempt_id") == attempt_id:
                    if record.get("host_id") != host_id:
                        raise TokenLifecycleError(
                            "attempt reference has mismatched scope"
                        )
                    found += 1
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise TokenLifecycleError("attempt ledger is invalid") from exc
        if found == 0:
            raise TokenLifecycleError("attempt reference does not exist")
        if found != 1:
            raise TokenLifecycleError("attempt ledger contains a duplicate attempt ID")


def _host_exists(workspace: Path, host_id: str) -> None:
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise TokenLifecycleError("invalid host ID; expected canonical Hxx form")
    try:
        record = host_identity.host_paths(workspace, host_id).state
    except host_identity.HostIdentityError as exc:
        raise TokenLifecycleError(str(exc)) from exc
    _real_file(record, "canonical host record", maximum=1024 * 1024)
    text = record.read_text(encoding="utf-8")
    matches = re.findall(r"^- Host ID: `([^`\r\n]+)`$", text, re.MULTILINE)
    if matches != [host_id]:
        raise TokenLifecycleError("canonical host record has mismatched identity")


def _credential_reference_exists(
    workspace: Path, state: dict[str, Any]
) -> None:
    credential_id = state["credential_id"]
    if credential_id is None:
        return
    path = workspace / "private/credentials/credentials.jsonl"
    _real_file(path, "credential ledger", maximum=16 * 1024 * 1024, private=True)
    matches = 0
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record.get("credential_id") != credential_id:
                continue
            if (
                record.get("host_id") != state["host_id"]
                or record.get("secret_type") != "token"
                or record.get("service") != state["service"]
                or record.get("username") != state["principal"]
            ):
                raise TokenLifecycleError(
                    "promoted credential reference has mismatched scope"
                )
            matches += 1
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise TokenLifecycleError("credential ledger is invalid") from exc
    if matches != 1:
        raise TokenLifecycleError(
            "promoted credential reference is missing or ambiguous"
        )


def _event_record(
    *,
    event_id: str,
    token_id: str,
    moment: datetime,
    event: str,
    base: dict[str, Any],
    validation_status: str,
    validation_evidence_id: str | None = None,
    validation_attempt_id: str | None = None,
    credential_id: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    record = {
        "schema_version": "1.0",
        "event_id": event_id,
        "token_id": token_id,
        "created_at_utc": _timestamp(moment),
        "event": event,
        **{field: base[field] for field in BASE_FIELDS},
        "validation_status": validation_status,
        "validation_evidence_id": validation_evidence_id,
        "validation_attempt_id": validation_attempt_id,
        "credential_id": credential_id,
        "reason": reason,
    }
    return {field: record[field] for field in EVENT_FIELDS}


def _validate_event(record: dict[str, Any], line_number: int) -> None:
    if list(record) != list(EVENT_FIELDS):
        raise TokenLifecycleError(
            f"token ledger line {line_number} has incorrect fields"
        )
    if record["schema_version"] != "1.0":
        raise TokenLifecycleError(
            f"token ledger line {line_number} has an invalid schema version"
        )
    if not isinstance(record["event_id"], str) or EVENT_ID_RE.fullmatch(record["event_id"]) is None:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid event ID")
    if not isinstance(record["token_id"], str) or TOKEN_ID_RE.fullmatch(record["token_id"]) is None:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid token ID")
    if not isinstance(record["created_at_utc"], str):
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid timestamp")
    _parse_timestamp(record["created_at_utc"], "event timestamp")
    if record["event"] not in EVENTS:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid event")
    if not isinstance(record["host_id"], str) or HOST_ID_RE.fullmatch(record["host_id"]) is None:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid host")
    for field in ("service", "token_kind", "validation_status"):
        if not isinstance(record[field], str):
            raise TokenLifecycleError(f"token ledger line {line_number} has an invalid {field}")
    if record["token_kind"] not in TOKEN_KINDS:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid token kind")
    if record["validation_status"] not in VALIDATION_STATES:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid validation status")
    nullable_text = (
        "principal",
        "source_evidence_id",
        "source_attempt_id",
        "expires_at_utc",
        "scope",
        "audience",
        "fingerprint",
        "secret_path",
        "validation_evidence_id",
        "validation_attempt_id",
        "credential_id",
        "reason",
    )
    for field in nullable_text:
        if record[field] is not None and not isinstance(record[field], str):
            raise TokenLifecycleError(f"token ledger line {line_number} has an invalid {field}")
    normalized_service = _text(record["service"], "service", 128)
    normalized_principal = _text(
        record["principal"], "principal", 256, required=False
    )
    normalized_scope = _text(record["scope"], "scope", required=False)
    normalized_audience = _text(record["audience"], "audience", required=False)
    normalized_reason = _text(record["reason"], "reason", required=False)
    if (
        normalized_service != record["service"]
        or normalized_principal != record["principal"]
        or normalized_scope != record["scope"]
        or normalized_audience != record["audience"]
        or normalized_reason != record["reason"]
    ):
        raise TokenLifecycleError(
            f"token ledger line {line_number} contains non-canonical text"
        )
    if record["expires_at_utc"] is not None:
        _parse_timestamp(record["expires_at_utc"], "token expiry")
    if record["fingerprint"] is not None and FINGERPRINT_RE.fullmatch(record["fingerprint"]) is None:
        raise TokenLifecycleError(f"token ledger line {line_number} has an invalid fingerprint")
    if record["secret_path"] is not None:
        match = SECRET_PATH_RE.fullmatch(record["secret_path"])
        if match is None or match.group(1) != record["token_id"]:
            raise TokenLifecycleError(f"token ledger line {line_number} has an invalid secret path")
    id_fields = (
        ("source_evidence_id", EVIDENCE_ID_RE),
        ("validation_evidence_id", EVIDENCE_ID_RE),
        ("source_attempt_id", ATTEMPT_ID_RE),
        ("validation_attempt_id", ATTEMPT_ID_RE),
        ("credential_id", CREDENTIAL_ID_RE),
    )
    for field, pattern in id_fields:
        if record[field] is not None and pattern.fullmatch(record[field]) is None:
            raise TokenLifecycleError(f"token ledger line {line_number} has an invalid {field}")
    if record["source_evidence_id"] is None and record["source_attempt_id"] is None:
        raise TokenLifecycleError("token metadata lacks acquisition provenance")
    if record["event"] == "not_retained":
        if record["fingerprint"] is not None or record["secret_path"] is not None:
            raise TokenLifecycleError("not-retained token metadata must not claim a secret")
    elif record["fingerprint"] is None or record["secret_path"] is None:
        raise TokenLifecycleError("tracked token metadata is incomplete")


def _load_events(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / TOKEN_ROOT / LEDGER_NAME
    if not path.exists() and not path.is_symlink():
        return []
    before = _real_file(path, "token ledger", maximum=MAX_LEDGER_BYTES, private=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise TokenLifecycleError("token ledger changed during open")
        raw = _read_fd(descriptor, MAX_LEDGER_BYTES, "token ledger")
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise TokenLifecycleError("token ledger must be UTF-8") from exc
    if raw and not raw.endswith(b"\n"):
        raise TokenLifecycleError("token ledger is not line terminated")
    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    base_by_token: dict[str, dict[str, Any]] = {}
    latest: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise TokenLifecycleError(f"token ledger line {line_number} is empty")
        pairs: list[tuple[str, Any]] = []

        def collect(items: list[tuple[str, Any]]) -> dict[str, Any]:
            nonlocal pairs
            pairs = items
            return dict(items)

        try:
            record = json.loads(line, object_pairs_hook=collect)
        except json.JSONDecodeError as exc:
            raise TokenLifecycleError(
                f"token ledger line {line_number} is invalid JSON"
            ) from exc
        if not isinstance(record, dict):
            raise TokenLifecycleError(
                f"token ledger line {line_number} must be an object"
            )
        if [name for name, _ in pairs] != list(EVENT_FIELDS):
            raise TokenLifecycleError(
                f"token ledger line {line_number} has duplicate or reordered fields"
            )
        _validate_event(record, line_number)
        if record["event_id"] in event_ids:
            raise TokenLifecycleError("token ledger contains a duplicate event ID")
        event_ids.add(record["event_id"])
        token_id = record["token_id"]
        if token_id not in base_by_token:
            if record["event"] not in {"captured", "not_retained"}:
                raise TokenLifecycleError("token lifecycle does not start with capture")
            base_by_token[token_id] = {field: record[field] for field in BASE_FIELDS}
        elif any(record[field] != base_by_token[token_id][field] for field in BASE_FIELDS):
            raise TokenLifecycleError("token lifecycle metadata changed between events")
        previous_record = latest.get(token_id)
        previous = None if previous_record is None else previous_record["event"]
        if previous in TERMINAL_EVENTS:
            raise TokenLifecycleError("token lifecycle continues after terminal state")
        if record["event"] == "validated" and previous not in {"captured", "validated"}:
            raise TokenLifecycleError("token validation transition is invalid")
        if record["event"] in {"promoted", "expired", "revoked", "discarded"} and previous not in {"captured", "validated"}:
            raise TokenLifecycleError("token resolution transition is invalid")
        if record["event"] == "cleaned" and previous not in {"promoted", "expired", "revoked", "discarded"}:
            raise TokenLifecycleError("token cleanup transition is invalid")
        if record["event"] in {"captured", "not_retained"}:
            if record["validation_status"] != "unverified":
                raise TokenLifecycleError("initial token validation state is invalid")
        elif record["event"] == "validated":
            if record["validation_status"] not in {"valid", "invalid"} or (
                record["validation_evidence_id"] is None
                and record["validation_attempt_id"] is None
            ):
                raise TokenLifecycleError("token validation metadata is incomplete")
        else:
            assert previous_record is not None
            for field in (
                "validation_status",
                "validation_evidence_id",
                "validation_attempt_id",
            ):
                if record[field] != previous_record[field]:
                    raise TokenLifecycleError(
                        "token validation metadata changed outside validation"
                    )
        if record["event"] == "promoted":
            if (
                record["validation_status"] != "valid"
                or record["credential_id"] is None
            ):
                raise TokenLifecycleError("promoted token metadata is incomplete")
        elif (
            previous_record is not None
            and record["event"] != "promoted"
            and record["credential_id"] != previous_record["credential_id"]
        ):
            raise TokenLifecycleError(
                "token credential reference changed outside promotion"
            )
        latest[token_id] = record
        events.append(record)
    return events


def _effective(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for event in events:
        result[event["token_id"]] = event
    return result


def _next_identifier(
    prefix: str,
    moment: datetime,
    existing: set[str],
) -> str:
    for offset in range(1_000_000):
        candidate = _identifier(prefix, moment + timedelta(microseconds=offset))
        if candidate not in existing:
            return candidate
    raise TokenLifecycleError("could not allocate a unique lifecycle identifier")


def _append_event(layout: TokenLayout, record: dict[str, Any]) -> None:
    _validate_event(record, 0)
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = layout.root / LEDGER_NAME
    current_size = path.stat().st_size if path.exists() else 0
    if current_size + len(encoded) > MAX_LEDGER_BYTES:
        raise TokenLifecycleError("token ledger exceeds its size limit")
    descriptor = os.open(
        LEDGER_NAME,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=layout.root_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TokenLifecycleError("token ledger must be user-owned with mode 0600")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_text(path: Path, content: str) -> None:
    _real_directory(path.parent, "report directory")
    if path.exists() or path.is_symlink():
        _real_file(path, "token report index", maximum=4 * 1024 * 1024)
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
        "# Session Token Index",
        "",
        "Generated from the append-only token lifecycle ledger. Raw token values are excluded.",
        "",
        "| Token | Host | Service | Principal | Kind | State | Validation | Expiry | Fingerprint | Credential | Provenance |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for token_id, state in states.items():
        fingerprint = state["fingerprint"]
        displayed_fingerprint = (
            "—" if fingerprint is None else f"hmac-sha256:{fingerprint.split(':', 1)[1][:12]}"
        )
        provenance = ", ".join(
            value
            for value in (
                state["source_evidence_id"],
                state["source_attempt_id"],
                state["validation_evidence_id"],
                state["validation_attempt_id"],
            )
            if value is not None
        ) or "—"
        values = [
            token_id,
            state["host_id"],
            state["service"],
            state["principal"] or "—",
            state["token_kind"],
            state["event"],
            state["validation_status"],
            state["expires_at_utc"] or "unknown",
            displayed_fingerprint,
            state["credential_id"] or "—",
            provenance,
        ]
        lines.append("| " + " | ".join(value.replace("|", "\\|") for value in values) + " |")
    if not states:
        lines.extend(["", "No session tokens recorded."])
    _atomic_text(workspace / "report" / INDEX_NAME, "\n".join(lines) + "\n")


def _secret_for_state(
    layout: TokenLayout, state: dict[str, Any]
) -> tuple[bytes, os.stat_result]:
    raw, metadata = _read_regular_at(
        layout.active_fd,
        f"{state['token_id']}.secret",
        MAX_SECRET_BYTES,
        "ephemeral token",
    )
    key = _fingerprint_key(layout)
    if not hmac.compare_digest(_fingerprint(key, raw), state["fingerprint"]):
        raise TokenLifecycleError("ephemeral token fingerprint verification failed")
    return raw, metadata


def _base_from_state(state: dict[str, Any]) -> dict[str, Any]:
    return {field: state[field] for field in BASE_FIELDS}


def _event_ids(events: list[dict[str, Any]]) -> set[str]:
    return {event["event_id"] for event in events}


def _token_ids(events: list[dict[str, Any]]) -> set[str]:
    return {event["token_id"] for event in events}


def capture_token(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    _host_exists(workspace, args.host_id)
    service = _text(args.service, "service", 128)
    principal = _text(args.principal, "principal", 256, required=False)
    scope = _text(args.scope, "scope", required=False)
    audience = _text(args.audience, "audience", required=False)
    if args.token_kind not in TOKEN_KINDS:
        raise TokenLifecycleError("invalid token kind")
    evidence_id = args.source_evidence_id
    attempt_id = args.source_attempt_id
    if evidence_id is None and attempt_id is None:
        raise TokenLifecycleError("at least one source evidence or attempt ID is required")
    _reference_exists(workspace, args.host_id, evidence_id, attempt_id)
    expires = None
    if args.expires_at is not None:
        expires = _timestamp(_parse_timestamp(args.expires_at, "token expiry"))
    raw = _read_secret_stdin() if args.secret_stdin else _read_secret_interactive()
    _reject_secret_text(raw, (service, principal, scope, audience))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    secret_metadata: os.stat_result | None = None
    token_id = ""
    try:
        events = _load_events(workspace)
        token_id = _next_identifier("TOK", moment, _token_ids(events))
        event_id = _next_identifier("TKE", moment, _event_ids(events))
        fingerprint = _fingerprint(_fingerprint_key(layout), raw)
        secret_metadata = _write_secret(layout, token_id, raw)
        base = {
            "host_id": args.host_id,
            "service": service,
            "principal": principal,
            "token_kind": args.token_kind,
            "source_evidence_id": evidence_id,
            "source_attempt_id": attempt_id,
            "expires_at_utc": expires,
            "scope": scope,
            "audience": audience,
            "fingerprint": fingerprint,
            "secret_path": f"private/session_tokens/active/{token_id}.secret",
        }
        record = _event_record(
            event_id=event_id,
            token_id=token_id,
            moment=moment,
            event="captured",
            base=base,
            validation_status="unverified",
        )
        _append_event(layout, record)
        _rebuild_index(workspace, events + [record])
    except BaseException:
        if secret_metadata is not None and token_id:
            try:
                _secure_remove(layout, token_id, secret_metadata, raw)
            except (OSError, TokenLifecycleError):
                pass
        raise
    finally:
        raw = b""
        layout.close()
    print(f"status: captured\ntoken_id: {token_id}\nsecret_persisted: ephemeral")
    return 0


def record_validation(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    try:
        restore_checkpoint.require_new_validation_refs(workspace, args.evidence_id, args.attempt_id)
    except restore_checkpoint.RestoreError as exc:
        raise TokenLifecycleError(str(exc)) from exc
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    try:
        events = _load_events(workspace)
        states = _effective(events)
        state = states.get(args.token_id)
        if state is None:
            raise TokenLifecycleError("token ID does not exist")
        if state["event"] not in {"captured", "validated"}:
            raise TokenLifecycleError("token is not active for validation")
        secret, _ = _secret_for_state(layout, state)
        _reference_exists(
            workspace,
            state["host_id"],
            args.evidence_id,
            args.attempt_id,
        )
        if args.evidence_id is None and args.attempt_id is None:
            raise TokenLifecycleError("validation requires evidence or attempt provenance")
        event_id = _next_identifier("TKE", moment, _event_ids(events))
        reason = _text(args.reason, "reason", required=False)
        _reject_secret_text(secret, (reason,))
        record = _event_record(
            event_id=event_id,
            token_id=state["token_id"],
            moment=moment,
            event="validated",
            base=_base_from_state(state),
            validation_status="valid" if args.result == "valid" else "invalid",
            validation_evidence_id=args.evidence_id,
            validation_attempt_id=args.attempt_id,
            reason=reason,
        )
        _append_event(layout, record)
        _rebuild_index(workspace, events + [record])
    finally:
        layout.close()
    print(f"status: validated\ntoken_id: {args.token_id}\nresult: {args.result}")
    return 0


def _credential_input(state: dict[str, Any], secret: bytes) -> bytes:
    value = secret.decode("utf-8")
    lines = [f"host: {state['host_id']}", f"token: {value}"]
    if state["principal"] is not None:
        lines.append(f"username: {state['principal']}")
    lines.append(f"service: {state['service']}")
    lines.append(f"note: Promoted from {state['token_id']}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def promote_token(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    secret = b""
    try:
        events = _load_events(workspace)
        state = _effective(events).get(args.token_id)
        if state is None:
            raise TokenLifecycleError("token ID does not exist")
        if state["event"] not in {"captured", "validated"}:
            raise TokenLifecycleError("token is not active for promotion")
        if __package__:
            from . import restore_checkpoint
        else:
            import restore_checkpoint
        try:
            restore_checkpoint.require_current_token_validation(workspace, state)
        except restore_checkpoint.RestoreError as exc:
            raise TokenLifecycleError(str(exc)) from exc
        if state["validation_status"] != "valid":
            raise TokenLifecycleError("only a successfully validated token may be promoted")
        secret, metadata = _secret_for_state(layout, state)
        reason = _text(args.reason, "reason", required=False)
        _reject_secret_text(secret, (reason,))
        result = credential_intake.store_credential_bytes(
            workspace,
            _credential_input(state, secret),
            now=moment,
        )
        if len(result.credential_ids) != 1:
            raise TokenLifecycleError("credential promotion returned an ambiguous result")
        credential_id = result.credential_ids[0]
        event_id = _next_identifier("TKE", moment, _event_ids(events))
        promoted = _event_record(
            event_id=event_id,
            token_id=state["token_id"],
            moment=moment,
            event="promoted",
            base=_base_from_state(state),
            validation_status=state["validation_status"],
            validation_evidence_id=state["validation_evidence_id"],
            validation_attempt_id=state["validation_attempt_id"],
            credential_id=credential_id,
            reason=reason or "retained as a canonical credential",
        )
        _append_event(layout, promoted)
        _secure_remove(layout, state["token_id"], metadata, secret)
        cleaned = _event_record(
            event_id=_next_identifier(
                "TKE", moment + timedelta(microseconds=1), _event_ids(events) | {event_id}
            ),
            token_id=state["token_id"],
            moment=moment + timedelta(microseconds=1),
            event="cleaned",
            base=_base_from_state(state),
            validation_status=state["validation_status"],
            validation_evidence_id=state["validation_evidence_id"],
            validation_attempt_id=state["validation_attempt_id"],
            credential_id=credential_id,
            reason="ephemeral copy removed after canonical promotion",
        )
        _append_event(layout, cleaned)
        _rebuild_index(workspace, events + [promoted, cleaned])
    except credential_intake.CredentialIntakeError as exc:
        raise TokenLifecycleError(str(exc)) from None
    finally:
        secret = b""
        layout.close()
    print(
        f"status: promoted\ntoken_id: {args.token_id}\ncredential_id: {credential_id}\nephemeral_copy: removed"
    )
    try:
        if __package__:
            from . import host_state
        else:
            import host_state
        host_state.best_effort_refresh(workspace, [state["host_id"]])
    except Exception:  # noqa: BLE001 - promotion and cleanup already succeeded
        return 0
    return 0


def _resolve_and_cleanup(
    workspace: Path,
    layout: TokenLayout,
    events: list[dict[str, Any]],
    state: dict[str, Any],
    *,
    resolution: str,
    reason: str,
    moment: datetime,
) -> list[dict[str, Any]]:
    secret, metadata = _secret_for_state(layout, state)
    _reject_secret_text(secret, (reason,))
    event_id = _next_identifier("TKE", moment, _event_ids(events))
    resolved = _event_record(
        event_id=event_id,
        token_id=state["token_id"],
        moment=moment,
        event=resolution,
        base=_base_from_state(state),
        validation_status=state["validation_status"],
        validation_evidence_id=state["validation_evidence_id"],
        validation_attempt_id=state["validation_attempt_id"],
        credential_id=state["credential_id"],
        reason=reason,
    )
    _append_event(layout, resolved)
    _secure_remove(layout, state["token_id"], metadata, secret)
    cleaned = _event_record(
        event_id=_next_identifier(
            "TKE", moment + timedelta(microseconds=1), _event_ids(events) | {event_id}
        ),
        token_id=state["token_id"],
        moment=moment + timedelta(microseconds=1),
        event="cleaned",
        base=_base_from_state(state),
        validation_status=state["validation_status"],
        validation_evidence_id=state["validation_evidence_id"],
        validation_attempt_id=state["validation_attempt_id"],
        credential_id=state["credential_id"],
        reason=f"ephemeral copy removed after {resolution}",
    )
    _append_event(layout, cleaned)
    updated = events + [resolved, cleaned]
    _rebuild_index(workspace, updated)
    return updated


def resolve_token(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    try:
        events = _load_events(workspace)
        state = _effective(events).get(args.token_id)
        if state is None:
            raise TokenLifecycleError("token ID does not exist")
        if state["event"] not in {
            "captured",
            "validated",
            "promoted",
            "expired",
            "revoked",
            "discarded",
        }:
            raise TokenLifecycleError("token is already resolved")
        if args.command_name == "cleanup":
            resolution = "discarded"
        else:
            if state["event"] not in {"captured", "validated"}:
                raise TokenLifecycleError("token resolution is already pending cleanup")
            resolution = {"expire": "expired", "revoke": "revoked"}[
                args.command_name
            ]
        reason = _text(args.reason, "reason")
        assert reason is not None
        if state["event"] in {"promoted", "expired", "revoked", "discarded"}:
            name = f"{state['token_id']}.secret"
            try:
                secret, metadata = _secret_for_state(layout, state)
                _reject_secret_text(secret, (reason,))
            except TokenLifecycleError:
                try:
                    os.stat(name, dir_fd=layout.active_fd, follow_symlinks=False)
                except FileNotFoundError:
                    metadata = None
                else:
                    raise
            if metadata is not None:
                _secure_remove(layout, state["token_id"], metadata, secret)
            record = _event_record(
                event_id=_next_identifier("TKE", moment, _event_ids(events)),
                token_id=state["token_id"],
                moment=moment,
                event="cleaned",
                base=_base_from_state(state),
                validation_status=state["validation_status"],
                validation_evidence_id=state["validation_evidence_id"],
                validation_attempt_id=state["validation_attempt_id"],
                credential_id=state["credential_id"],
                reason=reason,
            )
            _append_event(layout, record)
            _rebuild_index(workspace, events + [record])
        else:
            _resolve_and_cleanup(
                workspace,
                layout,
                events,
                state,
                resolution=resolution,
                reason=reason,
                moment=moment,
            )
    finally:
        layout.close()
    print(
        f"status: {resolution}\ntoken_id: {args.token_id}\nephemeral_copy: removed"
    )
    return 0


def auto_cleanup(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    cleaned_ids: list[str] = []
    try:
        events = _load_events(workspace)
        states = _effective(events)
        for state in tuple(states.values()):
            expiry = state["expires_at_utc"]
            if (
                state["event"] in {"captured", "validated"}
                and expiry is not None
                and _parse_timestamp(expiry, "token expiry") <= moment
            ):
                events = _resolve_and_cleanup(
                    workspace,
                    layout,
                    events,
                    state,
                    resolution="expired",
                    reason="automatic cleanup after recorded expiry",
                    moment=moment,
                )
                cleaned_ids.append(state["token_id"])
                moment += timedelta(microseconds=2)
    finally:
        layout.close()
    print(f"status: auto_cleanup\ncleaned_tokens: {len(cleaned_ids)}")
    if cleaned_ids:
        print(f"token_ids: {','.join(cleaned_ids)}")
    return 0


def record_not_retained(args: argparse.Namespace, now: datetime | None = None) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    _host_exists(workspace, args.host_id)
    service = _text(args.service, "service", 128)
    principal = _text(args.principal, "principal", 256, required=False)
    reason = _text(args.reason, "reason")
    _reference_exists(
        workspace,
        args.host_id,
        args.source_evidence_id,
        args.source_attempt_id,
    )
    if args.source_evidence_id is None and args.source_attempt_id is None:
        raise TokenLifecycleError("historical record requires evidence or attempt provenance")
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    layout = _ensure_layout(workspace)
    try:
        events = _load_events(workspace)
        token_id = _next_identifier("TOK", moment, _token_ids(events))
        base = {
            "host_id": args.host_id,
            "service": service,
            "principal": principal,
            "token_kind": args.token_kind,
            "source_evidence_id": args.source_evidence_id,
            "source_attempt_id": args.source_attempt_id,
            "expires_at_utc": None,
            "scope": None,
            "audience": None,
            "fingerprint": None,
            "secret_path": None,
        }
        record = _event_record(
            event_id=_next_identifier("TKE", moment, _event_ids(events)),
            token_id=token_id,
            moment=moment,
            event="not_retained",
            base=base,
            validation_status="unverified",
            reason=reason,
        )
        _append_event(layout, record)
        _rebuild_index(workspace, events + [record])
    finally:
        layout.close()
    print(f"status: not_retained\ntoken_id: {token_id}\nsecret_present: no")
    return 0


def closure_readiness(workspace: Path) -> TokenReadiness:
    """Return token blockers without creating legacy token state."""
    root = workspace / TOKEN_ROOT
    if not root.exists() and not root.is_symlink():
        return TokenReadiness(0, 0, (), 0)
    _real_directory(root, "session token directory", private=True)
    events = _load_events(workspace)
    states = _effective(events)
    active = root / ACTIVE_DIRECTORY
    _real_directory(active, "active token directory", private=True)
    known_files = {
        f"{token_id}.secret"
        for token_id, state in states.items()
        if state["secret_path"] is not None
    }
    blockers: list[str] = []
    present_files: set[str] = set()
    active_secret_files = 0
    for entry in active.iterdir():
        present_files.add(entry.name)
        try:
            metadata = entry.lstat()
        except OSError:
            blockers.append(f"ORPHAN:{entry.name}")
            continue
        if stat.S_ISREG(metadata.st_mode):
            active_secret_files += 1
        if (
            entry.name not in known_files
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            blockers.append(f"ORPHAN:{entry.name}")
    resolved = 0
    for token_id, state in states.items():
        _host_exists(workspace, state["host_id"])
        _reference_exists(
            workspace,
            state["host_id"],
            state["source_evidence_id"],
            state["source_attempt_id"],
        )
        _reference_exists(
            workspace,
            state["host_id"],
            state["validation_evidence_id"],
            state["validation_attempt_id"],
        )
        _credential_reference_exists(workspace, state)
        filename = f"{token_id}.secret"
        if state["event"] in TERMINAL_EVENTS and filename not in present_files:
            resolved += 1
        else:
            blockers.append(token_id)
    return TokenReadiness(
        total=len(states),
        resolved=resolved,
        blockers=tuple(sorted(set(blockers))),
        active_secret_files=active_secret_files,
    )


def show_status(args: argparse.Namespace) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    events = _load_events(workspace)
    states = _effective(events)
    for token_id, state in states.items():
        fingerprint = state["fingerprint"]
        displayed = "none" if fingerprint is None else fingerprint[:27]
        print(
            f"{token_id} {state['host_id']} {state['service']} {state['token_kind']} "
            f"{state['event']} {state['validation_status']} fingerprint={displayed} "
            f"credential={state['credential_id'] or 'none'}"
        )
    readiness = closure_readiness(workspace)
    print(f"tokens: {readiness.total}")
    print(f"resolved_tokens: {readiness.resolved}")
    print(f"blocking_tokens: {len(readiness.blockers)}")
    if readiness.blockers:
        print(f"blocking_token_ids: {','.join(readiness.blockers)}")
    return 0


def closure_check(args: argparse.Namespace) -> int:
    workspace = resolve_workspace(Path(args.workspace))
    readiness = closure_readiness(workspace)
    profile = operational_profile.workspace_profile(workspace)
    warning_only = False
    effective_blockers = () if warning_only else readiness.blockers
    warnings = readiness.blockers if warning_only else ()
    print(f"operational_profile: {profile}")
    print(f"closure_ready: {'no' if effective_blockers else 'yes'}")
    print(f"tokens: {readiness.total}")
    print(f"resolved_tokens: {readiness.resolved}")
    print(f"blocking_tokens: {len(effective_blockers)}")
    if effective_blockers:
        print(f"blocking_token_ids: {','.join(effective_blockers)}")
    print(f"warning_tokens: {len(warnings)}")
    if warnings:
        print(f"warning_token_ids: {','.join(warnings)}")
    return 1 if effective_blockers else 0


def _workspace_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_COLLECTION),
        help="module workspace or active task collection",
    )


def parser() -> argparse.ArgumentParser:
    root = SafeArgumentParser(
        description="Manage ephemeral session-token lifecycle."
    )
    sub = root.add_subparsers(dest="command_name", required=True)
    capture = sub.add_parser("capture", help="capture one token into the ephemeral vault")
    _workspace_argument(capture)
    capture.add_argument("--host-id", required=True)
    capture.add_argument("--service", required=True)
    capture.add_argument("--principal")
    capture.add_argument("--token-kind", choices=sorted(TOKEN_KINDS), default="session")
    capture.add_argument("--source-evidence-id")
    capture.add_argument("--source-attempt-id")
    capture.add_argument("--expires-at")
    capture.add_argument("--scope")
    capture.add_argument("--audience")
    capture.add_argument("--secret-stdin", action="store_true")

    validate = sub.add_parser("validate", help="record a bounded token validation result")
    _workspace_argument(validate)
    validate.add_argument("--token-id", required=True)
    validate.add_argument("--result", choices=("valid", "invalid"), required=True)
    validate.add_argument("--evidence-id")
    validate.add_argument("--attempt-id")
    validate.add_argument("--reason")

    promote = sub.add_parser("promote", help="promote a validated token to canonical credentials")
    _workspace_argument(promote)
    promote.add_argument("--token-id", required=True)
    promote.add_argument("--reason")

    for name in ("expire", "revoke"):
        action = sub.add_parser(name, help=f"record {name} and remove the ephemeral copy")
        _workspace_argument(action)
        action.add_argument("--token-id", required=True)
        action.add_argument("--reason", required=True)

    cleanup = sub.add_parser("cleanup", help="remove an explicitly discarded ephemeral token")
    _workspace_argument(cleanup)
    cleanup_mode = cleanup.add_mutually_exclusive_group(required=True)
    cleanup_mode.add_argument("--token-id")
    cleanup_mode.add_argument("--auto", action="store_true")
    cleanup.add_argument("--reason")

    historical = sub.add_parser(
        "record-not-retained", help="record a historical token whose value is unavailable"
    )
    _workspace_argument(historical)
    historical.add_argument("--host-id", required=True)
    historical.add_argument("--service", required=True)
    historical.add_argument("--principal")
    historical.add_argument("--token-kind", choices=sorted(TOKEN_KINDS), default="session")
    historical.add_argument("--source-evidence-id")
    historical.add_argument("--source-attempt-id")
    historical.add_argument("--reason", required=True)

    status = sub.add_parser("status", help="show token lifecycle metadata only")
    _workspace_argument(status)
    check = sub.add_parser("closure-check", help="check whether token closure is resolved")
    _workspace_argument(check)
    return root


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    supplied = list(sys.argv[1:] if argv is None else argv)
    if any(
        item in {"--secret", "--token-value", "--value"}
        or item.startswith(("--secret=", "--token-value=", "--value="))
        for item in supplied
    ):
        print(
            "error: token values are accepted only through interactive input or stdin",
            file=sys.stderr,
        )
        return 1
    try:
        args = parser().parse_args(supplied)
        if args.command_name == "capture":
            return capture_token(args, now)
        if args.command_name == "validate":
            return record_validation(args, now)
        if args.command_name == "promote":
            return promote_token(args, now)
        if args.command_name in {"expire", "revoke"}:
            return resolve_token(args, now)
        if args.command_name == "cleanup":
            if args.auto:
                return auto_cleanup(args, now)
            if args.reason is None:
                raise TokenLifecycleError("manual cleanup requires a reason")
            return resolve_token(args, now)
        if args.command_name == "record-not-retained":
            return record_not_retained(args, now)
        if args.command_name == "status":
            return show_status(args)
        return closure_check(args)
    except (
        TokenLifecycleError,
        operational_profile.OperationalProfileError,
        credential_intake.CredentialIntakeError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - keep token-bearing tracebacks private
        print("error: token lifecycle processing failed safely", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
