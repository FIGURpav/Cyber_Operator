"""Preview and apply bounded private credential intake."""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

if __package__:
    from . import host_identity
    from .new_host import (
        HOST_ID_PATTERN,
        HOSTNAME_PATTERN,
    )
    from .operator_intake import ExistingHost, Mapping
else:
    import host_identity  # type: ignore[no-redef]
    from new_host import (  # type: ignore[no-redef]
        HOST_ID_PATTERN,
        HOSTNAME_PATTERN,
    )
    from operator_intake import (  # type: ignore[no-redef]
        ExistingHost,
        Mapping,
    )

MAX_INPUT_BYTES = 64 * 1024
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_SECRET_LENGTH = 4096
MAX_USERNAME_LENGTH = 256
MAX_SERVICE_LENGTH = 128
MAX_URL_LENGTH = 2048
MAX_REALM_LENGTH = 256
MAX_NOTE_LENGTH = 2048
MAX_HOST_RECORD_BYTES = 1024 * 1024
MAX_MERGE_LEDGER_BYTES = 4 * 1024 * 1024
LOCK_NAME = ".credentials.lock"
LEDGER_NAME = "credentials.jsonl"
RENAME_EXCHANGE = 2
RENAME_NOREPLACE = 1
QUARANTINE_PREFIX = ".credentials.txn-"

HOST_FIELD_PATTERNS = {
    "host_id": re.compile(r"^- Host ID: `([^`\r\n]+)`$", re.MULTILINE),
    "ip": re.compile(r"^- IP address: `([^`\r\n]+)`$", re.MULTILINE),
    "label": re.compile(r"^- Hostname: `([^`\r\n]+)`$", re.MULTILINE),
}

CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
CREATED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
KEY_RE = re.compile(r"^[0-9a-f]{64}$")
SECRET_TYPES = ("password", "token", "api_key")
SELECTOR_FIELDS = ("host", "ip", "hostname")
OPTIONAL_FIELDS = ("username", "service", "url", "realm", "note")
INPUT_FIELDS = frozenset((*SELECTOR_FIELDS, *SECRET_TYPES, *OPTIONAL_FIELDS))
CREDENTIAL_FIELDS = (
    "credential_id",
    "created_at_utc",
    "host_id",
    "secret_type",
    "username",
    "service",
    "url",
    "realm",
    "note",
    "secret",
    "status",
    "source",
    "credential_key",
)


class CredentialIntakeError(Exception):
    """An operator-safe error that contains no credential material."""


@dataclass(frozen=True)
class CredentialCandidate:
    """One validated credential without its apply-time identity fields."""

    host_id: str
    secret_type: str
    username: str | None
    service: str | None
    url: str | None
    realm: str | None
    note: str | None
    secret: str
    credential_key: str

    @property
    def identity(self) -> tuple[str, str, str | None, str | None, str | None]:
        """Return the bounded identity used for changed-secret warnings."""
        return (
            self.host_id,
            self.secret_type,
            self.username,
            self.service.casefold() if self.service is not None else None,
            self.url,
        )


@dataclass(frozen=True)
class PlannedCredential:
    """One redacted plan result in input order."""

    status: str
    candidate: CredentialCandidate
    warning: bool


@dataclass(frozen=True)
class LedgerSnapshot:
    """Validated ledger bytes and stable filesystem identity."""

    exists: bool
    raw: bytes
    records: tuple[dict[str, Any], ...]
    metadata: os.stat_result | None


@dataclass(frozen=True)
class CredentialPlan:
    """A completely validated, read-only credential intake plan."""

    workspace: Path
    input_bytes: bytes
    input_sha256: str
    planned: tuple[PlannedCredential, ...]
    ledger: LedgerSnapshot

    @property
    def existing_count(self) -> int:
        """Return the number of supplied exact duplicates."""
        return sum(item.status == "existing" for item in self.planned)

    @property
    def new_items(self) -> tuple[PlannedCredential, ...]:
        """Return new unique credentials in their original order."""
        return tuple(item for item in self.planned if item.status == "create")

    @property
    def warning_count(self) -> int:
        """Return the number of changed-secret identity warnings."""
        return sum(item.warning for item in self.planned)


@dataclass(frozen=True)
class CredentialStoreResult:
    """Redacted result returned by in-process credential promotion."""

    credential_ids: tuple[str, ...]
    created_count: int
    existing_count: int
    preserved_input: str | None


def _error(message: str) -> CredentialIntakeError:
    """Build a deliberately redacted validation error."""
    return CredentialIntakeError(message)


def _fault_point(event: str, **details: object) -> None:
    """Provide a no-op seam for deterministic filesystem race/fault tests."""
    del event, details


def _open_directory_path(path_text: str, label: str) -> tuple[Path, int]:
    """Open an absolute directory through a verified no-symlink descriptor chain."""
    supplied = Path(path_text)
    if ".." in supplied.parts:
        raise _error(f"{label} path must not contain parent traversal")
    absolute = supplied if supplied.is_absolute() else Path.cwd() / supplied
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        for component in absolute.parts[1:]:
            opened = _open_dir_at(descriptor, component, label)
            os.close(descriptor)
            descriptor = opened
        return absolute, descriptor
    except FileNotFoundError as exc:
        os.close(descriptor)
        raise _error(f"{label} is unavailable") from exc
    except OSError:
        os.close(descriptor)
        raise
    except BaseException:
        os.close(descriptor)
        raise


def _open_dir_at(parent_fd: int, name: str, label: str) -> int:
    """Open and verify one direct child directory without following links."""
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise _error(f"{label} path must be a real non-symlink directory")
    _fault_point("directory_after_stat", parent_fd=parent_fd, name=name, label=label)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        _fault_point(
            "directory_after_open",
            parent_fd=parent_fd,
            name=name,
            label=label,
            descriptor=descriptor,
        )
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise _error(f"{label} path changed during validation")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    """Return identity and content-change fields required for verified reads."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IFMT(metadata.st_mode),
    )


def _verified_read_at(
    parent_fd: int,
    name: str,
    *,
    limit: int,
    label: str,
    expected: os.stat_result | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read a bounded regular file through one verified descriptor."""
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(f"{label} is unavailable") from exc
    if not stat.S_ISREG(before.st_mode):
        raise _error(f"{label} must be a real non-symlink regular file")
    if expected is not None and (
        before.st_dev,
        before.st_ino,
        stat.S_IFMT(before.st_mode),
    ) != (
        expected.st_dev,
        expected.st_ino,
        stat.S_IFMT(expected.st_mode),
    ):
        raise _error(f"{label} changed during operation")
    if before.st_size > limit:
        raise _error(f"{label} exceeds its size limit")
    _fault_point("verified_read_after_stat", label=label, parent_fd=parent_fd, name=name)
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        _fault_point(
            "verified_read_after_open",
            label=label,
            parent_fd=parent_fd,
            name=name,
            descriptor=descriptor,
        )
        opened = os.fstat(descriptor)
        if _stable_file_metadata(before) != _stable_file_metadata(opened):
            raise _error(f"{label} changed during read")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > limit
            or len(raw) != after.st_size
            or _stable_file_metadata(opened) != _stable_file_metadata(after)
        ):
            raise _error(f"{label} changed during read")
        return raw, after
    except OSError as exc:
        raise _error(f"{label} could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded_file(path_text: str) -> bytes:
    """Read operator input with a verified parent and file descriptor."""
    supplied = Path(path_text)
    if ".." in supplied.parts or supplied.name in {"", ".", ".."}:
        raise _error("input path must not contain parent traversal")
    absolute = supplied if supplied.is_absolute() else Path.cwd() / supplied
    _, parent_fd = _open_directory_path(str(absolute.parent), "input parent")
    try:
        raw, _ = _verified_read_at(
            parent_fd, absolute.name, limit=MAX_INPUT_BYTES, label="input file"
        )
        return raw
    finally:
        os.close(parent_fd)


def _decode_input(raw: bytes) -> str:
    """Decode UTF-8 while keeping credential text out of errors."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error("input must be valid UTF-8") from exc
    if not text.strip():
        raise _error("input contains no credential blocks")
    return text


def _blocks(text: str) -> tuple[tuple[str, ...], ...]:
    """Split the bounded grammar on completely blank lines."""
    lines = text.replace("\r\n", "\n").split("\n")
    result: list[tuple[str, ...]] = []
    current: list[str] = []
    for line in lines:
        if line == "":
            if current:
                result.append(tuple(current))
                current = []
            continue
        current.append(line)
    if current:
        result.append(tuple(current))
    if not result:
        raise _error("input contains no credential blocks")
    return tuple(result)


def _after_delimiter(raw: str) -> str:
    """Remove at most one conventional separator space after a colon."""
    return raw.removeprefix(" ")


def _validate_text(
    value: str,
    *,
    record_number: int,
    field: str,
    limit: int,
) -> str:
    """Validate one non-secret bounded single-line text field."""
    if not value:
        raise _error(f"record {record_number} has an empty {field} field")
    if value != value.strip():
        raise _error(f"record {record_number} has {field} boundary whitespace")
    if len(value) > limit:
        raise _error(f"record {record_number} {field} exceeds its length limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise _error(f"record {record_number} {field} contains a prohibited control")
    return value


def _validate_secret(value: str, record_number: int) -> str:
    """Validate a secret without altering or reproducing it."""
    if not value:
        raise _error(f"record {record_number} has an empty secret")
    if len(value) > MAX_SECRET_LENGTH:
        raise _error(f"record {record_number} secret exceeds its length limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise _error(f"record {record_number} secret contains a prohibited control")
    return value


def _canonical_url(value: str, record_number: int) -> str:
    """Validate and normalize one HTTP(S) URL without network access."""
    if len(value) > MAX_URL_LENGTH:
        raise _error(f"record {record_number} url exceeds its length limit")
    if value != value.strip() or any(character.isspace() for character in value):
        raise _error(f"record {record_number} has an invalid url")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise _error(f"record {record_number} has an invalid url")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise _error(f"record {record_number} has an invalid url") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise _error(f"record {record_number} url must use HTTP or HTTPS")
    if not parsed.hostname:
        raise _error(f"record {record_number} url requires a hostname")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise _error(f"record {record_number} url must not contain credentials")
    if parsed.fragment:
        raise _error(f"record {record_number} url must not contain a fragment")
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    canonical = urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))
    if len(canonical) > MAX_URL_LENGTH:
        raise _error(f"record {record_number} url exceeds its length limit")
    return canonical


def _credential_key(candidate: dict[str, str | None]) -> str:
    """Return the private deterministic exact-duplicate key."""
    payload = {
        "host_id": candidate["host_id"],
        "secret_type": candidate["secret_type"],
        "username": candidate["username"],
        "service": (
            candidate["service"].casefold()
            if candidate["service"] is not None
            else None
        ),
        "url": candidate["url"],
        "realm": candidate["realm"],
        "secret": candidate["secret"],
    }
    compact = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(compact).hexdigest()


def _resolve_selector(
    kind: str,
    value: str,
    hosts: tuple[ExistingHost, ...],
    record_number: int,
) -> str:
    """Resolve one selector to exactly one canonical known host."""
    matches: list[ExistingHost]
    if kind == "host":
        if HOST_ID_PATTERN.fullmatch(value) is None:
            raise _error(f"record {record_number} has an invalid host selector")
        matches = [
            host
            for host in hosts
            if host.host_id == value or value in host.merged_ids
        ]
    elif kind == "ip":
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise _error(f"record {record_number} has an invalid IP selector") from exc
        matches = [
            host
            for host in hosts
            if host.mapping is not None
            and (host.mapping.ip == canonical or canonical in host.additional_ips)
        ]
    else:
        if HOSTNAME_PATTERN.fullmatch(value) is None:
            raise _error(f"record {record_number} has an invalid hostname selector")
        key = value.casefold()
        matches = [
            host
            for host in hosts
            if host.mapping is not None and host.mapping.label_key == key
        ]
    if not matches:
        raise _error(
            f"record {record_number} does not resolve to an existing host; use host intake first"
        )
    if len(matches) != 1 or matches[0].mapping is None:
        raise _error(f"record {record_number} has an ambiguous or unknown host identity")
    return matches[0].host_id


def _standalone_selector(value: str, hosts: tuple[ExistingHost, ...]) -> str:
    """Classify a standalone selector without exposing its text."""
    if HOST_ID_PATTERN.fullmatch(value) is not None:
        return "host"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "hostname"
    return "ip"


def _parse_block(
    lines: tuple[str, ...],
    hosts: tuple[ExistingHost, ...],
    record_number: int,
) -> CredentialCandidate:
    """Parse and resolve one key-value credential block."""
    fields: dict[str, str] = {}
    standalone: str | None = None
    for line_number, line in enumerate(lines, start=1):
        if ":" not in line:
            if line_number != 1 or standalone is not None:
                raise _error(f"record {record_number} has an unsupported input line")
            standalone = _validate_text(
                line,
                record_number=record_number,
                field="host selector",
                limit=MAX_URL_LENGTH,
            )
            continue
        name, raw_value = line.split(":", 1)
        if name not in INPUT_FIELDS:
            raise _error(f"record {record_number} contains an unsupported field")
        if name in fields:
            raise _error(f"record {record_number} repeats a field")
        fields[name] = _after_delimiter(raw_value)

    secret_names = [name for name in SECRET_TYPES if name in fields]
    if len(secret_names) != 1:
        raise _error(f"record {record_number} must contain exactly one secret field")
    secret_type = secret_names[0]
    secret = _validate_secret(fields[secret_type], record_number)

    metadata_limits = {
        "username": MAX_USERNAME_LENGTH,
        "service": MAX_SERVICE_LENGTH,
        "realm": MAX_REALM_LENGTH,
        "note": MAX_NOTE_LENGTH,
    }
    metadata: dict[str, str | None] = {}
    for name, limit in metadata_limits.items():
        metadata[name] = (
            _validate_text(
                fields[name], record_number=record_number, field=name, limit=limit
            )
            if name in fields
            else None
        )
    if secret_type == "password" and metadata["username"] is None:
        raise _error(f"record {record_number} password requires username")
    url = (
        _canonical_url(
            _validate_text(
                fields["url"],
                record_number=record_number,
                field="url",
                limit=MAX_URL_LENGTH,
            ),
            record_number,
        )
        if "url" in fields
        else None
    )

    selectors: list[tuple[str, str]] = []
    if standalone is not None:
        selectors.append((_standalone_selector(standalone, hosts), standalone))
    for name in SELECTOR_FIELDS:
        if name in fields:
            limit = MAX_URL_LENGTH if name == "hostname" else MAX_USERNAME_LENGTH
            selectors.append(
                (
                    name,
                    _validate_text(
                        fields[name],
                        record_number=record_number,
                        field=f"{name} selector",
                        limit=limit,
                    ),
                )
            )
    if not selectors:
        raise _error(f"record {record_number} is missing a host selector")
    if len({kind for kind, _ in selectors}) != len(selectors):
        raise _error(f"record {record_number} repeats a host selector")
    resolved = {
        _resolve_selector(kind, value, hosts, record_number)
        for kind, value in selectors
    }
    if len(resolved) != 1:
        raise _error(f"record {record_number} host selectors conflict")
    host_id = resolved.pop()
    key_data = {
        "host_id": host_id,
        "secret_type": secret_type,
        "username": metadata["username"],
        "service": metadata["service"],
        "url": url,
        "realm": metadata["realm"],
        "secret": secret,
    }
    return CredentialCandidate(
        host_id=host_id,
        secret_type=secret_type,
        username=metadata["username"],
        service=metadata["service"],
        url=url,
        realm=metadata["realm"],
        note=metadata["note"],
        secret=secret,
        credential_key=_credential_key(key_data),
    )


@dataclass
class WorkspaceHandles:
    """Verified directory descriptors retained for one complete operation."""

    workspace: Path
    workspace_fd: int
    private_fd: int | None = None
    credentials_fd: int | None = None
    intake_fd: int | None = None

    def close(self) -> None:
        """Close every retained descriptor exactly once."""
        for name in ("intake_fd", "credentials_fd", "private_fd", "workspace_fd"):
            descriptor = getattr(self, name)
            if descriptor is not None and descriptor >= 0:
                os.close(descriptor)
                setattr(self, name, None)


def _optional_stat_at(parent_fd: int, name: str) -> os.stat_result | None:
    """Return one non-following child stat, or None only for absence."""
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _validate_private_file_at(
    parent_fd: int, name: str, label: str
) -> os.stat_result | None:
    """Validate an optional canonical private regular file."""
    metadata = _optional_stat_at(parent_fd, name)
    if metadata is None:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise _error(f"{label} must be a real non-symlink regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise _error(f"{label} must use mode 0600")
    if metadata.st_uid != os.geteuid():
        raise _error(f"{label} must be owned by the effective user")
    return metadata


def _inspect_private_layout(handles: WorkspaceHandles) -> None:
    """Open every existing private directory through the retained fd chain."""
    private = _optional_stat_at(handles.workspace_fd, "private")
    if private is None:
        return
    handles.private_fd = _open_dir_at(handles.workspace_fd, "private", "private")
    if stat.S_IMODE(os.fstat(handles.private_fd).st_mode) != 0o700:
        raise _error("private path must use mode 0700")
    credentials = _optional_stat_at(handles.private_fd, "credentials")
    if credentials is None:
        return
    handles.credentials_fd = _open_dir_at(
        handles.private_fd, "credentials", "credentials"
    )
    if stat.S_IMODE(os.fstat(handles.credentials_fd).st_mode) != 0o700:
        raise _error("credentials path must use mode 0700")
    intake = _optional_stat_at(handles.credentials_fd, "intake")
    if intake is not None:
        handles.intake_fd = _open_dir_at(handles.credentials_fd, "intake", "intake")
        if stat.S_IMODE(os.fstat(handles.intake_fd).st_mode) != 0o700:
            raise _error("intake path must use mode 0700")
    _validate_private_file_at(handles.credentials_fd, LEDGER_NAME, "credential ledger")
    _validate_private_file_at(handles.credentials_fd, LOCK_NAME, "credential lock")


def _open_workspace(path_text: str) -> WorkspaceHandles:
    """Open and retain a verified workspace directory chain."""
    workspace, workspace_fd = _open_directory_path(path_text, "workspace")
    handles = WorkspaceHandles(workspace, workspace_fd)
    try:
        _inspect_private_layout(handles)
        return handles
    except BaseException:
        handles.close()
        raise


def _discover_hosts(workspace_fd: int) -> tuple[ExistingHost, ...]:
    """Read canonical hosts only through verified descriptors."""
    try:
        hosts_fd = _open_dir_at(workspace_fd, "hosts", "workspace hosts")
    except FileNotFoundError as exc:
        raise _error("workspace contains no canonical hosts; use host intake first") from exc
    try:
        names = sorted(
            name
            for name in os.listdir(hosts_fd)
            if name.endswith(".md")
            and host_identity.host_id_from_stem(name[:-3]) is not None
        )
        records: list[ExistingHost] = []
        for name in names:
            raw, _ = _verified_read_at(
                hosts_fd,
                name,
                limit=MAX_HOST_RECORD_BYTES,
                label="canonical host record",
            )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _error("a canonical host record must be valid UTF-8") from exc
            values: dict[str, str] = {}
            for field, pattern in HOST_FIELD_PATTERNS.items():
                matches = pattern.findall(text)
                if len(matches) != 1:
                    raise _error(
                        "an existing canonical host record has malformed identity fields"
                    )
                values[field] = matches[0]
            host_id = host_identity.host_id_from_stem(name[:-3])
            if (
                host_id is None
                or HOST_ID_PATTERN.fullmatch(host_id) is None
                or values["host_id"] != host_id
            ):
                raise _error(
                    "an existing canonical host record has an invalid or mismatched host ID"
                )
            number = int(host_id[1:])
            ip_value, label_value = values["ip"], values["label"]
            if ip_value == "unknown" and label_value == "unknown":
                records.append(ExistingHost(host_id, number, None))
                continue
            if ip_value == "unknown" or label_value == "unknown":
                raise _error(
                    "an existing canonical host record has incomplete identity fields"
                )
            try:
                canonical_ip = str(ipaddress.ip_address(ip_value))
            except ValueError as exc:
                raise _error(
                    "an existing canonical host record has an invalid IP address"
                ) from exc
            if (
                len(label_value) > 253
                or HOSTNAME_PATTERN.fullmatch(label_value) is None
            ):
                raise _error(
                    "an existing canonical host record has an invalid hostname"
                )
            records.append(
                ExistingHost(host_id, number, Mapping(canonical_ip, label_value))
            )
        if not records:
            raise _error("workspace contains no canonical hosts; use host intake first")
        by_id = {record.host_id: record for record in records}
        merge_metadata = _optional_stat_at(
            workspace_fd, host_identity.MERGE_LEDGER_NAME
        )
        if merge_metadata is not None:
            raw_merges, _ = _verified_read_at(
                workspace_fd,
                host_identity.MERGE_LEDGER_NAME,
                limit=MAX_MERGE_LEDGER_BYTES,
                label="host merge ledger",
            )
            try:
                merge_lines = raw_merges.decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                raise _error("host merge ledger must be valid UTF-8") from exc
            seen_merged: set[str] = set()
            for line in merge_lines:
                if not line:
                    raise _error("host merge ledger contains a blank line")
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise _error("host merge ledger contains invalid JSON") from exc
                if not isinstance(event, dict) or event.get("status") != "applied":
                    continue
                source = event.get("source_host_id")
                destination = event.get("destination_host_id")
                source_ip = event.get("source_ip")
                if (
                    not isinstance(source, str)
                    or HOST_ID_PATTERN.fullmatch(source) is None
                    or not isinstance(destination, str)
                    or HOST_ID_PATTERN.fullmatch(destination) is None
                    or not isinstance(source_ip, str)
                    or source in seen_merged
                    or destination not in by_id
                ):
                    raise _error("host merge ledger contains invalid applied data")
                try:
                    canonical_source_ip = str(ipaddress.ip_address(source_ip))
                except ValueError as exc:
                    raise _error("host merge ledger contains an invalid endpoint") from exc
                target = by_id[destination]
                by_id[destination] = ExistingHost(
                    target.host_id,
                    target.number,
                    target.mapping,
                    target.additional_ips + (canonical_source_ip,),
                    target.merged_ids + (source,),
                )
                seen_merged.add(source)
            records = [by_id[record.host_id] for record in records]
        seen_numbers: set[int] = set()
        seen_ips: set[str] = set()
        seen_labels: set[str] = set()
        for record in records:
            if record.number in seen_numbers:
                raise _error("duplicate existing canonical host ID detected")
            seen_numbers.add(record.number)
            if record.mapping is None:
                continue
            all_ips = (record.mapping.ip, *record.additional_ips)
            if any(endpoint in seen_ips for endpoint in all_ips):
                raise _error("duplicate existing canonical host IP detected")
            if record.mapping.label_key in seen_labels:
                raise _error("duplicate existing canonical host label detected")
            seen_ips.update(all_ips)
            seen_labels.add(record.mapping.label_key)
        return tuple(records)
    finally:
        os.close(hosts_fd)


def _json_object(text: str, line_number: int) -> dict[str, Any]:
    """Load one JSON object while rejecting duplicate or reordered fields."""
    pairs: list[tuple[str, Any]] = []

    def collect(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal pairs
        pairs = items
        return dict(items)

    try:
        value = json.loads(text, object_pairs_hook=collect)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise _error(f"credential ledger line {line_number} contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise _error(f"credential ledger line {line_number} must be an object")
    names = [name for name, _ in pairs]
    if names != list(CREDENTIAL_FIELDS) or len(set(names)) != len(names):
        raise _error(f"credential ledger line {line_number} has incorrect fields")
    return value


def _nullable_text(
    record: dict[str, Any], field: str, line_number: int, limit: int
) -> str | None:
    """Validate one nullable canonical ledger field."""
    value = record[field]
    if value is None:
        return None
    if not isinstance(value, str):
        raise _error(f"credential ledger line {line_number} has an invalid {field} type")
    return _validate_text(value, record_number=line_number, field=field, limit=limit)


def _validate_ledger_record(
    record: dict[str, Any], line_number: int, known_hosts: set[str]
) -> None:
    """Validate one canonical private ledger record without exposing values."""
    required_strings = (
        "credential_id",
        "created_at_utc",
        "host_id",
        "secret_type",
        "secret",
        "status",
        "source",
        "credential_key",
    )
    if any(not isinstance(record[field], str) for field in required_strings):
        raise _error(f"credential ledger line {line_number} has an invalid field type")
    if CREDENTIAL_ID_RE.fullmatch(record["credential_id"]) is None:
        raise _error(f"credential ledger line {line_number} has an invalid credential ID")
    if CREATED_AT_RE.fullmatch(record["created_at_utc"]) is None:
        raise _error(f"credential ledger line {line_number} has an invalid timestamp")
    try:
        id_time = datetime.strptime(
            record["credential_id"], "CRED-%Y%m%dT%H%M%S%fZ"
        ).replace(tzinfo=UTC)
        created_time = datetime.strptime(
            record["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise _error(f"credential ledger line {line_number} has invalid time fields") from exc
    if id_time != created_time:
        raise _error(f"credential ledger line {line_number} has mismatched time fields")
    if record["host_id"] not in known_hosts:
        raise _error(f"credential ledger line {line_number} references an unknown host")
    if record["secret_type"] not in SECRET_TYPES:
        raise _error(f"credential ledger line {line_number} has an invalid secret type")
    username = _nullable_text(record, "username", line_number, MAX_USERNAME_LENGTH)
    service = _nullable_text(record, "service", line_number, MAX_SERVICE_LENGTH)
    realm = _nullable_text(record, "realm", line_number, MAX_REALM_LENGTH)
    _nullable_text(record, "note", line_number, MAX_NOTE_LENGTH)
    url = _nullable_text(record, "url", line_number, MAX_URL_LENGTH)
    if url is not None and _canonical_url(url, line_number) != url:
        raise _error(f"credential ledger line {line_number} has a noncanonical url")
    if record["secret_type"] == "password" and username is None:
        raise _error(f"credential ledger line {line_number} password lacks username")
    _validate_secret(record["secret"], line_number)
    if record["status"] != "unverified" or record["source"] != "operator":
        raise _error(f"credential ledger line {line_number} has invalid canonical values")
    if KEY_RE.fullmatch(record["credential_key"]) is None:
        raise _error(f"credential ledger line {line_number} has an invalid credential key")
    key_data = {
        "host_id": record["host_id"],
        "secret_type": record["secret_type"],
        "username": username,
        "service": service,
        "url": url,
        "realm": realm,
        "secret": record["secret"],
    }
    if _credential_key(key_data) != record["credential_key"]:
        raise _error(f"credential ledger line {line_number} has an incorrect credential key")


def _read_ledger(credentials_fd: int | None, known_hosts: set[str]) -> LedgerSnapshot:
    """Read and completely validate the canonical private ledger by descriptor."""
    if credentials_fd is None:
        return LedgerSnapshot(False, b"", (), None)
    metadata = _validate_private_file_at(
        credentials_fd, LEDGER_NAME, "credential ledger"
    )
    if metadata is None:
        return LedgerSnapshot(False, b"", (), None)
    raw, metadata = _verified_read_at(
        credentials_fd,
        LEDGER_NAME,
        limit=MAX_LEDGER_BYTES,
        label="credential ledger",
        expected=metadata,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error("credential ledger must be valid UTF-8") from exc
    if raw and not raw.endswith(b"\n"):
        raise _error("credential ledger is not canonically line-terminated")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    keys: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise _error(f"credential ledger line {line_number} is empty")
        record = _json_object(line, line_number)
        _validate_ledger_record(record, line_number, known_hosts)
        if record["credential_id"] in identifiers:
            raise _error("credential ledger contains a duplicate credential ID")
        if record["credential_key"] in keys:
            raise _error("credential ledger contains a duplicate credential key")
        identifiers.add(record["credential_id"])
        keys.add(record["credential_key"])
        records.append(record)
    return LedgerSnapshot(True, raw, tuple(records), metadata)


def _parse_candidates(
    input_bytes: bytes, hosts: tuple[ExistingHost, ...]
) -> tuple[CredentialCandidate, ...]:
    """Parse all candidates without consulting mutable credential state."""
    if any(host.mapping is None for host in hosts):
        raise _error("canonical host state contains an unknown host identity")
    return tuple(
        _parse_block(lines, hosts, record_number)
        for record_number, lines in enumerate(_blocks(_decode_input(input_bytes)), start=1)
    )


def _plan_from(
    workspace: Path,
    input_bytes: bytes,
    candidates: tuple[CredentialCandidate, ...],
    ledger: LedgerSnapshot,
) -> CredentialPlan:
    """Plan against one descriptor-verified ledger snapshot."""
    known_keys = {record["credential_key"] for record in ledger.records}
    identities: dict[tuple[str, str, str | None, str | None, str | None], set[str]] = {}
    for record in ledger.records:
        identity = (
            record["host_id"],
            record["secret_type"],
            record["username"],
            record["service"].casefold() if record["service"] is not None else None,
            record["url"],
        )
        identities.setdefault(identity, set()).add(record["credential_key"])

    planned: list[PlannedCredential] = []
    for candidate in candidates:
        existing = candidate.credential_key in known_keys
        warning = not existing and bool(identities.get(candidate.identity))
        planned.append(
            PlannedCredential("existing" if existing else "create", candidate, warning)
        )
        if not existing:
            known_keys.add(candidate.credential_key)
            identities.setdefault(candidate.identity, set()).add(candidate.credential_key)
    return CredentialPlan(
        workspace=workspace,
        input_bytes=input_bytes,
        input_sha256=hashlib.sha256(input_bytes).hexdigest(),
        planned=tuple(planned),
        ledger=ledger,
    )


def _known_host_ids(hosts: tuple[ExistingHost, ...]) -> set[str]:
    return {
        host_id
        for host in hosts
        for host_id in (host.host_id, *host.merged_ids)
    }


def build_plan(workspace: Path, input_bytes: bytes) -> CredentialPlan:
    """Build a safe read-only plan; apply re-plans separately under its lock."""
    handles = _open_workspace(str(workspace))
    try:
        hosts = _discover_hosts(handles.workspace_fd)
        candidates = _parse_candidates(input_bytes, hosts)
        ledger = _read_ledger(handles.credentials_fd, _known_host_ids(hosts))
        return _plan_from(handles.workspace, input_bytes, candidates, ledger)
    finally:
        handles.close()


def store_credential_bytes(
    workspace: Path,
    input_bytes: bytes,
    *,
    now: datetime | None = None,
) -> CredentialStoreResult:
    """Store validated credential bytes without writing the secret to a temp input."""
    handles = _open_workspace(str(workspace))
    lock_fd = -1
    try:
        hosts = _discover_hosts(handles.workspace_fd)
        candidates = _parse_candidates(input_bytes, hosts)
        known_hosts = _known_host_ids(hosts)
        _ensure_apply_layout(handles)
        if handles.credentials_fd is None:
            raise _error("credential directory is unavailable")
        lock_fd = _acquire_lock(handles.credentials_fd)
        ledger = _read_ledger(handles.credentials_fd, known_hosts)
        plan = _plan_from(handles.workspace, input_bytes, candidates, ledger)
        if not plan.new_items:
            by_key = {
                record["credential_key"]: record["credential_id"]
                for record in ledger.records
            }
            identifiers = tuple(
                by_key[item.candidate.credential_key] for item in plan.planned
            )
            return CredentialStoreResult(
                credential_ids=identifiers,
                created_count=0,
                existing_count=plan.existing_count,
                preserved_input=None,
            )

        current = (now or datetime.now(UTC)).astimezone(UTC)
        replacement = _replacement_bytes(plan, current)
        records = tuple(
            json.loads(line) for line in replacement.decode("utf-8").splitlines()
        )
        by_key = {
            record["credential_key"]: record["credential_id"] for record in records
        }
        identifiers = tuple(
            by_key[item.candidate.credential_key] for item in plan.planned
        )
        timestamp = current.strftime("%Y%m%dT%H%M%S%fZ")
        intake_name = f"INTAKE-{timestamp}.txt"
        tracker = CreationTrackerAt()
        try:
            _ensure_intake(handles, tracker)
            if handles.intake_fd is None:
                raise _error("credential intake directory is unavailable")
            if not _has_write_search(
                handles.credentials_fd
            ) or not _has_write_search(handles.intake_fd):
                raise _error(
                    "a required private path is not writable and searchable"
                )
            _write_exclusive_at(
                handles.intake_fd, intake_name, plan.input_bytes, tracker
            )
            _publish_ledger(
                handles.credentials_fd, replacement, plan.ledger, tracker
            )
        except BaseException:
            _rollback_created(tracker)
            raise
        return CredentialStoreResult(
            credential_ids=identifiers,
            created_count=len(plan.new_items),
            existing_count=plan.existing_count,
            preserved_input=f"private/credentials/intake/{intake_name}",
        )
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        handles.close()


def _has_write_search(descriptor: int) -> bool:
    """Return effective write/search access for an already verified directory."""
    try:
        return os.access(
            ".",
            os.W_OK | os.X_OK,
            dir_fd=descriptor,
            effective_ids=True,
        )
    except TypeError:
        return os.access(".", os.W_OK | os.X_OK, dir_fd=descriptor)


@dataclass(frozen=True)
class CreatedAt:
    """Identity of one object created relative to a retained parent fd."""

    parent_fd: int
    name: str
    device: int
    inode: int
    is_directory: bool


class CreationTrackerAt:
    """Track exact transaction-created entries without pathname re-resolution."""

    def __init__(self) -> None:
        self.created: list[CreatedAt] = []

    def record(
        self, parent_fd: int, name: str, metadata: os.stat_result, *, directory: bool
    ) -> None:
        """Record an already verified object."""
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_type(metadata.st_mode):
            raise OSError("created private object has an unexpected type")
        self.created.append(
            CreatedAt(parent_fd, name, metadata.st_dev, metadata.st_ino, directory)
        )


def _rollback_created(tracker: CreationTrackerAt) -> None:
    """Remove only still-identical objects created by this transaction."""
    for created in reversed(tracker.created):
        try:
            expected = os.stat_result(
                (
                    stat.S_IFDIR if created.is_directory else stat.S_IFREG,
                    created.inode,
                    created.device,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            )
            _atomic_remove_at(
                created.parent_fd,
                created.name,
                expected,
                directory=created.is_directory,
                missing_ok=True,
                label="apply-created object",
            )
        except (CredentialIntakeError, OSError):
            continue


def _ensure_directory_at(
    parent_fd: int,
    name: str,
    label: str,
    tracker: CreationTrackerAt | None = None,
) -> int:
    """Create if absent, then open and validate an exact 0700 directory."""
    if not _has_write_search(parent_fd):
        raise _error("a required private path is not writable and searchable")
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    descriptor = _open_dir_at(parent_fd, name, label)
    try:
        _fault_point(
            "ensure_directory_before_fstat",
            parent_fd=parent_fd,
            name=name,
            descriptor=descriptor,
            label=label,
        )
        metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise _error(f"{label} path must use mode 0700")
        if metadata.st_uid != os.geteuid():
            raise _error(f"{label} path must be owned by the effective user")
        if created and tracker is not None:
            tracker.record(parent_fd, name, metadata, directory=True)
        return descriptor
    except BaseException:
        if created:
            try:
                created_metadata = os.fstat(descriptor)
                _atomic_remove_at(
                    parent_fd,
                    name,
                    created_metadata,
                    directory=True,
                    missing_ok=True,
                    label="apply-created directory",
                )
            except (CredentialIntakeError, OSError):
                pass
        os.close(descriptor)
        raise


def _ensure_apply_layout(handles: WorkspaceHandles) -> None:
    """Securely create/open canonical private and credential directories."""
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(handles.workspace)
    if handles.private_fd is None:
        handles.private_fd = _ensure_directory_at(
            handles.workspace_fd, "private", "private"
        )
    if handles.credentials_fd is None:
        handles.credentials_fd = _ensure_directory_at(
            handles.private_fd, "credentials", "credentials"
        )


def _ensure_intake(
    handles: WorkspaceHandles, tracker: CreationTrackerAt | None = None
) -> None:
    """Securely create/open the canonical raw-intake directory."""
    if handles.credentials_fd is None:
        raise _error("credential directory is unavailable")
    if handles.intake_fd is None:
        handles.intake_fd = _ensure_directory_at(
            handles.credentials_fd, "intake", "intake", tracker
        )


def _write_all(descriptor: int, raw: bytes) -> None:
    """Write all bytes to an already opened file descriptor."""
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short filesystem write")
        offset += written


def _write_exclusive_at(
    parent_fd: int,
    name: str,
    raw: bytes,
    tracker: CreationTrackerAt | None = None,
) -> os.stat_result:
    """Create a no-follow 0600 file relative to a verified directory."""
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=parent_fd,
    )
    metadata: os.stat_result | None = None
    try:
        _fault_point(
            "write_after_open",
            parent_fd=parent_fd,
            name=name,
            descriptor=descriptor,
        )
        metadata = os.fstat(descriptor)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if tracker is not None:
            tracker.record(parent_fd, name, metadata, directory=False)
        return metadata
    except BaseException:
        try:
            metadata = metadata or os.fstat(descriptor)
            _atomic_remove_at(
                parent_fd,
                name,
                metadata,
                missing_ok=True,
                label="apply-created file",
            )
        except (CredentialIntakeError, OSError):
            pass
        raise
    finally:
        os.close(descriptor)


def _acquire_lock(credentials_fd: int) -> int:
    """Open/create the retained canonical lock and take its advisory lock."""
    descriptor = -1
    created = False
    try:
        descriptor = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=credentials_fd,
        )
        created = True
    except FileExistsError:
        descriptor = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=credentials_fd,
        )
    try:
        if created:
            _fault_point(
                "lock_after_create",
                credentials_fd=credentials_fd,
                descriptor=descriptor,
            )
            os.fchmod(descriptor, 0o600)
        _fault_point(
            "lock_before_fstat",
            credentials_fd=credentials_fd,
            descriptor=descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise _error(
                "credential lock must be a user-owned regular file with mode 0600"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.stat(LOCK_NAME, dir_fd=credentials_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise _error("credential lock changed during acquisition")
        _fault_point("lock_acquired", credentials_fd=credentials_fd)
        return descriptor
    except BaseException:
        if created:
            try:
                created_metadata = os.fstat(descriptor)
                _atomic_remove_at(
                    credentials_fd,
                    LOCK_NAME,
                    created_metadata,
                    missing_ok=True,
                    label="apply-created credential lock",
                )
            except (CredentialIntakeError, OSError):
                pass
        os.close(descriptor)
        raise


def _record_for(candidate: CredentialCandidate, timestamp: datetime) -> dict[str, Any]:
    """Build one canonical record in exact schema order."""
    utc = timestamp.astimezone(UTC)
    record = {
        "credential_id": f"CRED-{utc.strftime('%Y%m%dT%H%M%S%fZ')}",
        "created_at_utc": utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": candidate.host_id,
        "secret_type": candidate.secret_type,
        "username": candidate.username,
        "service": candidate.service,
        "url": candidate.url,
        "realm": candidate.realm,
        "note": candidate.note,
        "secret": candidate.secret,
        "status": "unverified",
        "source": "operator",
        "credential_key": candidate.credential_key,
    }
    return {field: record[field] for field in CREDENTIAL_FIELDS}


def _replacement_bytes(plan: CredentialPlan, now: datetime) -> bytes:
    """Construct the complete append-only replacement bytes in memory."""
    used_ids = {record["credential_id"] for record in plan.ledger.records}
    new_records: list[dict[str, Any]] = []
    offset = 0
    for item in plan.new_items:
        while True:
            timestamp = now.astimezone(UTC) + timedelta(microseconds=offset)
            offset += 1
            record = _record_for(item.candidate, timestamp)
            if record["credential_id"] not in used_ids:
                break
        used_ids.add(record["credential_id"])
        new_records.append(record)
    suffix = b"".join(
        (
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for record in new_records
    )
    replacement = plan.ledger.raw + suffix
    if len(replacement) > MAX_LEDGER_BYTES:
        raise _error("planned credential ledger exceeds its size limit")
    return replacement


def _renameat2(directory_fd: int, left: str, right: str, flags: int) -> None:
    """Invoke Linux renameat2 on two names in one verified directory."""
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise _error("secure atomic filesystem operation is unavailable")
    result = renameat2(
        ctypes.c_int(directory_fd),
        ctypes.c_char_p(os.fsencode(left)),
        ctypes.c_int(directory_fd),
        ctypes.c_char_p(os.fsencode(right)),
        ctypes.c_uint(flags),
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV}:
        raise _error("secure atomic filesystem operation is unavailable")
    raise OSError(error_number, os.strerror(error_number))


def _rename_exchange(directory_fd: int, left: str, right: str) -> None:
    """Atomically exchange two names with Linux renameat2 or fail closed."""
    try:
        _renameat2(directory_fd, left, right, RENAME_EXCHANGE)
    except CredentialIntakeError as exc:
        raise _error("secure atomic ledger exchange is unavailable") from exc


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    """Atomically rename without overwriting an existing destination."""
    try:
        _renameat2(directory_fd, source, destination, RENAME_NOREPLACE)
    except CredentialIntakeError as exc:
        raise _error("secure atomic cleanup is unavailable") from exc


def _temporary_file_at(directory_fd: int, replacement: bytes) -> tuple[str, os.stat_result]:
    """Create one unpredictable verified replacement file in the ledger directory."""
    for _ in range(64):
        name = f".{LEDGER_NAME}.{secrets.token_hex(16)}.tmp"
        try:
            metadata = _write_exclusive_at(directory_fd, name, replacement)
            return name, metadata
        except FileExistsError:
            continue
    raise _error("could not allocate a secure ledger replacement")


def _snapshot_link_at(
    directory_fd: int, snapshot: LedgerSnapshot
) -> tuple[str, os.stat_result]:
    """Retain a verified hard-link handle to the validated original ledger."""
    if snapshot.metadata is None:
        raise _error("credential ledger snapshot is incomplete")
    for _ in range(64):
        name = f".{LEDGER_NAME}.{secrets.token_hex(16)}.original"
        try:
            os.link(
                LEDGER_NAME,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            continue
        try:
            metadata = _verified_exact_at(
                directory_fd,
                name,
                snapshot.metadata,
                snapshot.raw,
                "retained credential ledger",
            )
            return name, metadata
        except BaseException:
            try:
                _atomic_remove_at(
                    directory_fd,
                    name,
                    snapshot.metadata,
                    missing_ok=True,
                    label="retained credential ledger",
                )
            except (CredentialIntakeError, OSError):
                pass
            raise
    raise _error("could not retain the verified credential ledger")


def _quarantine_name() -> str:
    """Return one bounded unpredictable private transaction name."""
    return f"{QUARANTINE_PREFIX}{secrets.token_hex(16)}"


def _atomic_remove_at(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    *,
    directory: bool = False,
    missing_ok: bool = False,
    label: str = "transaction object",
) -> bool:
    """Atomically quarantine, verify, and remove only the expected object."""
    quarantine = _quarantine_name()
    _fault_point(
        "before_quarantine",
        directory_fd=directory_fd,
        name=name,
        quarantine=quarantine,
        label=label,
    )
    try:
        _rename_noreplace(directory_fd, name, quarantine)
    except FileNotFoundError as exc:
        if missing_ok:
            return False
        raise _error(f"{label} disappeared before secure cleanup") from exc
    except FileExistsError as exc:
        raise _error("private cleanup quarantine collision") from exc

    _fault_point(
        "quarantine_after_move",
        directory_fd=directory_fd,
        name=name,
        quarantine=quarantine,
        label=label,
    )
    try:
        moved = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(f"{label} requires private operator adjudication") from exc
    expected_type = stat.S_IFDIR if directory else stat.S_IFREG
    if (
        moved.st_dev,
        moved.st_ino,
        stat.S_IFMT(moved.st_mode),
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected_type,
    ):
        raise _error(f"{label} preserved for private operator adjudication")

    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if directory:
            flags |= os.O_DIRECTORY
        descriptor = os.open(quarantine, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ) != (
            expected.st_dev,
            expected.st_ino,
            expected_type,
        ):
            raise _error(f"{label} preserved for private operator adjudication")
    except OSError as exc:
        raise _error(f"{label} preserved for private operator adjudication") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        if directory:
            os.rmdir(quarantine, dir_fd=directory_fd)
        else:
            os.unlink(quarantine, dir_fd=directory_fd)
    except OSError as exc:
        raise _error(f"{label} cleanup requires private operator adjudication") from exc
    try:
        os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    raise _error(f"{label} cleanup could not be verified")


def _verified_exact_at(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    expected_raw: bytes,
    label: str,
) -> os.stat_result:
    """Verify both descriptor identity and exact bytes for a transaction object."""
    raw, metadata = _verified_read_at(
        directory_fd,
        name,
        limit=MAX_LEDGER_BYTES,
        label=label,
        expected=expected,
    )
    if raw != expected_raw:
        raise _error(f"{label} changed during operation")
    if (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_uid,
        stat.S_IMODE(expected.st_mode),
    ):
        raise _error(f"{label} metadata changed during operation")
    return metadata


def _entry_matches_exact(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    expected_raw: bytes,
) -> bool:
    """Return whether a transaction name still identifies exact expected bytes."""
    try:
        _verified_exact_at(
            directory_fd, name, expected, expected_raw, "transaction object"
        )
    except (CredentialIntakeError, OSError):
        return False
    return True


def _cleanup_transaction_entry(
    directory_fd: int,
    name: str,
    expected_objects: tuple[tuple[os.stat_result, bytes], ...],
) -> None:
    """Remove a known transaction entry or quarantine an unexpected substitute."""
    if not name:
        return
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    selected = expected_objects[0][0]
    for metadata, _raw in expected_objects:
        if (current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)) == (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFREG,
        ):
            selected = metadata
            break
    _atomic_remove_at(
        directory_fd,
        name,
        selected,
        missing_ok=True,
        label="credential transaction object",
    )


def _restore_exchanged_ledger(
    credentials_fd: int,
    temporary: str,
    retained: str,
    replacement_metadata: os.stat_result,
    replacement: bytes,
    snapshot: LedgerSnapshot,
) -> None:
    """Restore the verified original and privately preserve unexpected objects."""
    if snapshot.metadata is None:
        raise _error("credential ledger snapshot is incomplete")
    source = ""
    if temporary and _entry_matches_exact(
        credentials_fd, temporary, snapshot.metadata, snapshot.raw
    ):
        source = temporary
    elif retained and _entry_matches_exact(
        credentials_fd, retained, snapshot.metadata, snapshot.raw
    ):
        source = retained
    if not source:
        raise _error("verified original ledger is unavailable for restoration")
    _rename_exchange(credentials_fd, source, LEDGER_NAME)
    _verified_exact_at(
        credentials_fd,
        LEDGER_NAME,
        snapshot.metadata,
        snapshot.raw,
        "restored credential ledger",
    )
    expected_objects = (
        (replacement_metadata, replacement),
        (snapshot.metadata, snapshot.raw),
    )
    for name in (temporary, retained):
        if not name:
            continue
        try:
            _cleanup_transaction_entry(credentials_fd, name, expected_objects)
        except (CredentialIntakeError, OSError):
            continue


def _publish_ledger(
    credentials_fd: int,
    replacement: bytes,
    snapshot: LedgerSnapshot,
    tracker: CreationTrackerAt,
) -> None:
    """Publish a new ledger no-overwrite or exchange an existing ledger safely."""
    temporary, replacement_metadata = _temporary_file_at(credentials_fd, replacement)
    exchanged = False
    retained = ""
    try:
        if snapshot.exists:
            if snapshot.metadata is None:
                raise _error("credential ledger snapshot is incomplete")
            retained, _ = _snapshot_link_at(credentials_fd, snapshot)
            _fault_point("before_ledger_exchange", credentials_fd=credentials_fd)
            _rename_exchange(credentials_fd, temporary, LEDGER_NAME)
            exchanged = True
            _fault_point("after_ledger_exchange", credentials_fd=credentials_fd)
            _verified_exact_at(
                credentials_fd,
                LEDGER_NAME,
                replacement_metadata,
                replacement,
                "published credential ledger",
            )
            _verified_exact_at(
                credentials_fd,
                temporary,
                snapshot.metadata,
                snapshot.raw,
                "displaced credential ledger",
            )
            _fault_point("before_ledger_commit", credentials_fd=credentials_fd)
            _atomic_remove_at(
                credentials_fd,
                temporary,
                snapshot.metadata,
                label="displaced credential ledger",
            )
            temporary = ""
            _atomic_remove_at(
                credentials_fd,
                retained,
                snapshot.metadata,
                label="retained credential ledger",
            )
            retained = ""
            exchanged = False
        else:
            _fault_point("before_new_ledger_publish", credentials_fd=credentials_fd)
            try:
                os.link(
                    temporary,
                    LEDGER_NAME,
                    src_dir_fd=credentials_fd,
                    dst_dir_fd=credentials_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise _error("credential ledger appeared during apply") from exc
            metadata = os.stat(
                LEDGER_NAME, dir_fd=credentials_fd, follow_symlinks=False
            )
            try:
                if (metadata.st_dev, metadata.st_ino) != (
                    replacement_metadata.st_dev,
                    replacement_metadata.st_ino,
                ):
                    raise _error("new credential ledger changed during publication")
                tracker.record(
                    credentials_fd, LEDGER_NAME, metadata, directory=False
                )
            except BaseException:
                _atomic_remove_at(
                    credentials_fd,
                    LEDGER_NAME,
                    replacement_metadata,
                    missing_ok=True,
                    label="new credential ledger",
                )
                raise
            _atomic_remove_at(
                credentials_fd,
                temporary,
                replacement_metadata,
                label="ledger replacement",
            )
            temporary = ""
    except BaseException:
        if exchanged and snapshot.metadata is not None:
            try:
                _restore_exchanged_ledger(
                    credentials_fd,
                    temporary,
                    retained,
                    replacement_metadata,
                    replacement,
                    snapshot,
                )
                temporary = ""
                retained = ""
            except (CredentialIntakeError, OSError):
                _fault_point("ledger_restore_failed", credentials_fd=credentials_fd)
        raise
    finally:
        if temporary:
            try:
                expected_objects = ((replacement_metadata, replacement),)
                if snapshot.metadata is not None:
                    expected_objects += ((snapshot.metadata, snapshot.raw),)
                _cleanup_transaction_entry(
                    credentials_fd, temporary, expected_objects
                )
            except (CredentialIntakeError, OSError):
                pass
        if retained and snapshot.metadata is not None:
            try:
                _cleanup_transaction_entry(
                    credentials_fd,
                    retained,
                    (
                        (snapshot.metadata, snapshot.raw),
                        (replacement_metadata, replacement),
                    ),
                )
            except (CredentialIntakeError, OSError):
                pass


def _print_plan(mode: str, plan: CredentialPlan, intake_path: str | None = None) -> None:
    """Print only explicitly permitted redacted plan metadata."""
    print(f"mode: {mode}")
    print(f"input_sha256: {plan.input_sha256}")
    print(f"parsed_credentials: {len(plan.planned)}")
    print(f"existing_credentials: {plan.existing_count}")
    print(f"new_credentials: {len(plan.new_items)}")
    print(f"warning_count: {plan.warning_count}")
    for item in plan.planned:
        candidate = item.candidate
        if candidate.service is not None:
            identity = f"service:{candidate.service}"
        elif candidate.url is not None:
            identity = f"url:{candidate.url}"
        else:
            identity = "unspecified"
        print(
            f"credential: status={item.status} host_id={candidate.host_id} "
            f"type={candidate.secret_type} "
            f"username_present={'yes' if candidate.username is not None else 'no'} "
            f"identity={identity} warning={'yes' if item.warning else 'no'}"
        )
    if mode == "apply":
        print(f"preserved_input: {intake_path or '(none)'}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the bounded credential-intake CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Preview or apply bounded private credential intake."
    )
    parser.add_argument("--workspace", required=True, help="private workspace directory")
    parser.add_argument("--input-file", required=True, help="regular UTF-8 credential file")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preview", action="store_true", help="validate a read-only plan")
    modes.add_argument("--apply", action="store_true", help="preserve and store new records")
    return parser.parse_args(argv)


def _filesystem_error(exc: OSError) -> str:
    """Return bounded filesystem meaning without paths or attacker-controlled text."""
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "filesystem operation failed: permission denied"
    if exc.errno == errno.ENOSPC:
        return "filesystem operation failed: no space left on device"
    return "filesystem operation failed"


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    """CLI entry point."""
    handles: WorkspaceHandles | None = None
    lock_fd = -1
    try:
        args = parse_args(argv)
        input_bytes = _read_bounded_file(args.input_file)
        handles = _open_workspace(args.workspace)
        hosts = _discover_hosts(handles.workspace_fd)
        candidates = _parse_candidates(input_bytes, hosts)
        known_hosts = _known_host_ids(hosts)
        if args.preview:
            ledger = _read_ledger(handles.credentials_fd, known_hosts)
            plan = _plan_from(handles.workspace, input_bytes, candidates, ledger)
            _print_plan("preview", plan)
            return 0

        _ensure_apply_layout(handles)
        if handles.credentials_fd is None:
            raise _error("credential directory is unavailable")
        lock_fd = _acquire_lock(handles.credentials_fd)
        ledger = _read_ledger(handles.credentials_fd, known_hosts)
        plan = _plan_from(handles.workspace, input_bytes, candidates, ledger)
        if not plan.new_items:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            lock_fd = -1
            _print_plan("apply", plan)
            return 0
        current = (now or datetime.now(UTC)).astimezone(UTC)
        replacement = _replacement_bytes(plan, current)
        timestamp = current.strftime("%Y%m%dT%H%M%S%fZ")
        intake_name = f"INTAKE-{timestamp}.txt"
        tracker = CreationTrackerAt()
        try:
            _ensure_intake(handles, tracker)
            if handles.intake_fd is None:
                raise _error("credential intake directory is unavailable")
            if not _has_write_search(
                handles.credentials_fd
            ) or not _has_write_search(handles.intake_fd):
                raise _error("a required private path is not writable and searchable")
            _write_exclusive_at(
                handles.intake_fd, intake_name, plan.input_bytes, tracker
            )
            _publish_ledger(
                handles.credentials_fd, replacement, plan.ledger, tracker
            )
        except BaseException:
            _rollback_created(tracker)
            raise
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        lock_fd = -1
        relative = f"private/credentials/intake/{intake_name}"
        _print_plan("apply", plan, relative)
        try:
            if __package__:
                from . import host_state
            else:
                import host_state
            host_state.best_effort_refresh(
                handles.workspace,
                [item.candidate.host_id for item in plan.new_items],
            )
        except Exception:  # noqa: BLE001 - credential publication already succeeded
            return 0
        return 0
    except CredentialIntakeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileExistsError:
        print("error: a validated private path changed during apply", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {_filesystem_error(exc)}", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - prevent secret-bearing tracebacks at CLI boundary
        print("error: credential intake processing failed safely", file=sys.stderr)
        return 1
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if handles is not None:
            handles.close()


if __name__ == "__main__":
    raise SystemExit(main())
