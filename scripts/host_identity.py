"""Resolve canonical hosts and apply evidence-backed friendly filesystem labels."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)
HOST_FIELD_PATTERNS = {
    "host_id": re.compile(r"^- Host ID: `([^`\r\n]+)`$", re.MULTILINE),
    "ip": re.compile(r"^- IP address: `([^`\r\n]+)`$", re.MULTILINE),
    "hostname": re.compile(r"^- Hostname: `([^`\r\n]+)`$", re.MULTILINE),
}
LEDGER_NAME = "host_aliases.jsonl"
LOCK_NAME = ".host_aliases.lock"
MERGE_LEDGER_NAME = "host_merges.jsonl"
MERGE_LOCK_NAME = ".host_merges.lock"
MERGED_DIRECTORY_NAME = "_merged"
RENAME_NOREPLACE = 1
AT_FDCWD = -100


class HostIdentityError(ValueError):
    """A deterministic host-identity or relabel failure."""


@dataclass(frozen=True)
class HostRecord:
    """One canonical host with its current filesystem storage key."""

    host_id: str
    ip: str
    hostname: str
    storage_key: str
    path: Path

    @property
    def friendly(self) -> bool:
        return self.storage_key != self.host_id

    @property
    def display_name(self) -> str:
        return self.storage_key

    @property
    def evidence_prefix(self) -> str:
        if not self.friendly:
            return ""
        return f"{safe_name_component(self.hostname.split('.', 1)[0], 63)}-"


@dataclass(frozen=True)
class HostPaths:
    """Resolved paths for one canonical host."""

    record: HostRecord
    state: Path
    report: Path
    inbox: Path
    evidence: Path


@dataclass(frozen=True)
class AppliedMerge:
    """One applied source-host to active-host identity merge."""

    merge_id: str
    source_host_id: str
    destination_host_id: str
    source_storage_key: str
    destination_storage_key: str
    source_ip: str
    destination_primary_ip: str
    hostname: str
    source_evidence_id: str
    destination_evidence_id: str
    reason: str


@dataclass(frozen=True)
class MergePlan:
    """A fully validated read-only host merge plan."""

    workspace: Path
    source: HostRecord
    destination: HostRecord
    source_evidence_id: str
    destination_evidence_id: str
    reason: str
    archive_path: Path
    source_state_sha256: str
    destination_state_sha256: str
    source_metadata_sha256: str
    source_artifact_sha256: str
    destination_metadata_sha256: str
    destination_artifact_sha256: str


@dataclass(frozen=True)
class RenameItem:
    """One no-overwrite filesystem rename."""

    source: Path
    destination: Path


@dataclass(frozen=True)
class RelabelPlan:
    """A completely validated first-friendly-label plan."""

    workspace: Path
    host: HostRecord
    requested_hostname: str
    evidence_id: str
    target_storage_key: str
    root_renames: tuple[RenameItem, ...]
    evidence_renames: tuple[RenameItem, ...]
    automatic_relabel: bool

    @property
    def changes_storage(self) -> bool:
        return bool(self.root_renames)


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HostIdentityError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HostIdentityError(f"{label} must be a real non-symlink directory")


def _require_regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HostIdentityError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HostIdentityError(f"{label} must be a regular non-symlink file")


def validate_workspace(workspace: Path) -> Path:
    """Validate and return an absolute private workspace path."""
    if ".." in workspace.parts:
        raise HostIdentityError("workspace path must not contain parent traversal")
    root = workspace if workspace.is_absolute() else Path.cwd() / workspace
    _require_real_directory(root, "workspace")
    _require_real_directory(root / "hosts", "workspace hosts path")
    ledger = root / LEDGER_NAME
    if _lexists(ledger):
        _require_regular(ledger, LEDGER_NAME)
    merge_ledger = root / MERGE_LEDGER_NAME
    if _lexists(merge_ledger):
        _require_regular(merge_ledger, MERGE_LEDGER_NAME)
    return root


def safe_name_component(value: str, limit: int = 180) -> str:
    """Return a deterministic filename-safe component preserving useful case."""
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", value).strip("._-")
    if not sanitized:
        raise HostIdentityError("friendly name has no filesystem-safe characters")
    if len(sanitized) <= limit:
        return sanitized
    digest = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()[:10]
    return f"{sanitized[: limit - 11]}-{digest}"


def validate_hostname(value: str) -> str:
    """Validate one confirmed DNS-style hostname."""
    if value != value.strip() or not value or len(value) > 253:
        raise HostIdentityError("hostname must be canonical nonempty text")
    if HOSTNAME_RE.fullmatch(value) is None:
        raise HostIdentityError("hostname must be a valid DNS-style name")
    return value


def storage_key(hostname: str, ip: str, host_id: str) -> str:
    """Build the Explorer-visible storage key for one canonical host."""
    try:
        canonical_ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HostIdentityError("host requires a canonical IP before friendly relabel") from exc
    name_part = safe_name_component(hostname, 160)
    ip_part = safe_name_component(canonical_ip.replace(":", "_"), 64)
    return f"{name_part}-{ip_part}-{host_id}"


def host_id_from_stem(stem: str) -> str | None:
    if HOST_ID_RE.fullmatch(stem):
        return stem
    match = re.search(r"-(H(?:0[1-9]|[1-9]\d+))$", stem)
    return match.group(1) if match else None


def _read_host(path: Path) -> HostRecord:
    _require_regular(path, "host record")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise HostIdentityError("host record is unreadable or malformed") from exc
    values: dict[str, str] = {}
    filename_id = host_id_from_stem(path.stem)
    if filename_id is None:
        raise HostIdentityError("host record filename has no canonical Host ID")
    for field, pattern in HOST_FIELD_PATTERNS.items():
        matches = pattern.findall(text)
        if len(matches) > 1:
            raise HostIdentityError("host record has malformed identity fields")
        if matches:
            values[field] = matches[0]
    stored_id = values.get("host_id", filename_id)
    if filename_id != stored_id:
        raise HostIdentityError("host record filename and Host ID do not match")
    ip_field = values.get("ip", "unknown")
    hostname_field = values.get("hostname", "unknown")
    if path.stem != filename_id and (
        "host_id" not in values or "ip" not in values or "hostname" not in values
    ):
        raise HostIdentityError("friendly host record requires complete identity fields")
    if ip_field != "unknown":
        try:
            ip_value = str(ipaddress.ip_address(ip_field))
        except ValueError as exc:
            raise HostIdentityError("host record has an invalid IP address") from exc
    else:
        ip_value = "unknown"
    if hostname_field != "unknown":
        validate_hostname(hostname_field)
    return HostRecord(
        host_id=filename_id,
        ip=ip_value,
        hostname=hostname_field,
        storage_key=path.stem,
        path=path,
    )


def discover_hosts(workspace: Path) -> tuple[HostRecord, ...]:
    """Discover both legacy Hxx and friendly *-Hxx host records."""
    root = validate_workspace(workspace)
    records: list[HostRecord] = []
    by_id: dict[str, HostRecord] = {}
    for path in sorted((root / "hosts").iterdir()):
        if not path.name.endswith(".md"):
            continue
        host_id = host_id_from_stem(path.stem)
        if host_id is None:
            continue
        record = _read_host(path)
        if record.host_id in by_id:
            raise HostIdentityError(f"duplicate storage records for {record.host_id}")
        by_id[record.host_id] = record
        records.append(record)
    return tuple(sorted(records, key=lambda item: int(item.host_id[1:])))


def _read_jsonl_objects(path: Path, label: str) -> list[dict[str, Any]]:
    if not _lexists(path):
        return []
    _require_regular(path, label)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise HostIdentityError(f"{label} is unreadable") from exc
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise HostIdentityError(f"{label} contains a blank line at {line_number}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HostIdentityError(f"{label} contains invalid JSON") from exc
        if not isinstance(record, dict):
            raise HostIdentityError(f"{label} record must be an object")
        records.append(record)
    return records


def applied_merges(workspace: Path) -> tuple[AppliedMerge, ...]:
    """Return validated applied merges, rejecting chains, cycles and duplicates."""
    root = validate_workspace(workspace)
    events = _read_jsonl_objects(root / MERGE_LEDGER_NAME, MERGE_LEDGER_NAME)
    merges: list[AppliedMerge] = []
    planned: dict[str, tuple[str, ...]] = {}
    finalized: set[str] = set()
    seen_sources: set[str] = set()
    for event in events:
        required = {
            "merge_id", "source_host_id", "destination_host_id",
            "source_storage_key", "destination_storage_key", "source_ip",
            "destination_primary_ip", "hostname", "source_evidence_id",
            "destination_evidence_id", "reason", "rollback_status",
        }
        if any(not isinstance(event.get(name), str) for name in required):
            raise HostIdentityError("host merge ledger contains invalid event data")
        status = event.get("status")
        if status not in {"planned", "applied", "failed"}:
            raise HostIdentityError("host merge ledger contains an invalid status")
        merge_id = event["merge_id"]
        if re.fullmatch(r"HMG-\d{8}T\d{12}Z", merge_id) is None:
            raise HostIdentityError("host merge ledger contains an invalid merge ID")
        source = event["source_host_id"]
        destination = event["destination_host_id"]
        if (
            HOST_ID_RE.fullmatch(source) is None
            or HOST_ID_RE.fullmatch(destination) is None
            or source == destination
        ):
            raise HostIdentityError("host merge ledger contains invalid identities")
        for field in ("source_storage_key", "destination_storage_key"):
            value = event[field]
            if not value or Path(value).name != value or host_id_from_stem(value) is None:
                raise HostIdentityError("host merge ledger contains an invalid storage key")
        try:
            source_ip = str(ipaddress.ip_address(event["source_ip"]))
            destination_ip = str(ipaddress.ip_address(event["destination_primary_ip"]))
        except ValueError as exc:
            raise HostIdentityError("host merge ledger contains an invalid endpoint") from exc
        validate_hostname(event["hostname"])
        for field in ("source_evidence_id", "destination_evidence_id"):
            if EVIDENCE_ID_RE.fullmatch(event[field]) is None:
                raise HostIdentityError("host merge ledger contains invalid evidence identity")
        identity = tuple(event[name] for name in sorted(required - {"rollback_status"}))
        if status == "planned":
            if merge_id in planned or merge_id in finalized:
                raise HostIdentityError("host merge ledger duplicates a merge lifecycle")
            if event["rollback_status"] != "not-required":
                raise HostIdentityError("planned merge has invalid rollback state")
            planned[merge_id] = identity
            continue
        if merge_id not in planned or planned[merge_id] != identity or merge_id in finalized:
            raise HostIdentityError("host merge ledger has an invalid lifecycle")
        if status == "failed":
            if event["rollback_status"] not in {"completed", "operator-review"}:
                raise HostIdentityError("failed merge has invalid rollback state")
            finalized.add(merge_id)
            continue
        if event["rollback_status"] != "not-required" or source in seen_sources:
            raise HostIdentityError("host merge ledger contains invalid applied data")
        finalized.add(merge_id)
        seen_sources.add(source)
        merges.append(
            AppliedMerge(
                merge_id=merge_id,
                source_host_id=source,
                destination_host_id=destination,
                source_storage_key=event["source_storage_key"],
                destination_storage_key=event["destination_storage_key"],
                source_ip=source_ip,
                destination_primary_ip=destination_ip,
                hostname=event["hostname"],
                source_evidence_id=event["source_evidence_id"],
                destination_evidence_id=event["destination_evidence_id"],
                reason=event["reason"],
            )
        )
    source_ids = {item.source_host_id for item in merges}
    if any(item.destination_host_id in source_ids for item in merges):
        raise HostIdentityError("host merge chains and cycles are unsupported")
    active = {record.host_id: record for record in discover_hosts(root)}
    for item in merges:
        destination = active.get(item.destination_host_id)
        if destination is None or item.source_host_id in active:
            raise HostIdentityError("host merge active identities are inconsistent")
        if (
            destination.storage_key != item.destination_storage_key
            or destination.ip != item.destination_primary_ip
            or destination.hostname.casefold() != item.hostname.casefold()
        ):
            raise HostIdentityError("host merge destination no longer matches ledger")
        archived = (
            root / "hosts" / MERGED_DIRECTORY_NAME / f"{item.source_storage_key}.md"
        )
        source = _read_host(archived)
        if (
            source.host_id != item.source_host_id
            or source.ip != item.source_ip
            or source.hostname.casefold() != item.hostname.casefold()
        ):
            raise HostIdentityError("merged historical host record does not match ledger")
    return tuple(merges)


def known_host_ids(workspace: Path) -> set[str]:
    """Return active canonical IDs plus immutable merged legacy IDs."""
    active = {record.host_id for record in discover_hosts(workspace)}
    return active | {item.source_host_id for item in applied_merges(workspace)}


def historical_host_map(workspace: Path) -> dict[str, str]:
    """Map retained identities to active hosts for history views, not permits."""
    result = {record.host_id: record.host_id for record in discover_hosts(workspace)}
    result.update(
        (item.source_host_id, item.destination_host_id)
        for item in applied_merges(workspace)
    )
    return result


def canonical_host_id(workspace: Path, host_id: str) -> str:
    """Canonicalize an active or merged legacy Hxx identifier."""
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise HostIdentityError("invalid canonical host ID")
    mapping = {item.source_host_id: item.destination_host_id for item in applied_merges(workspace)}
    canonical = mapping.get(host_id, host_id)
    if canonical not in {record.host_id for record in discover_hosts(workspace)}:
        raise HostIdentityError("host selector does not match a registered host")
    return canonical


def host_endpoints(workspace: Path, host_id: str) -> tuple[str, ...]:
    """Return primary then merged endpoints for one active canonical host."""
    canonical = canonical_host_id(workspace, host_id)
    record = next(item for item in discover_hosts(workspace) if item.host_id == canonical)
    values = [record.ip]
    values.extend(
        item.source_ip
        for item in applied_merges(workspace)
        if item.destination_host_id == canonical and item.source_ip not in values
    )
    return tuple(values)


def merged_host_ids(workspace: Path, host_id: str) -> tuple[str, ...]:
    canonical = canonical_host_id(workspace, host_id)
    return tuple(
        item.source_host_id
        for item in applied_merges(workspace)
        if item.destination_host_id == canonical
    )


def evidence_roots(workspace: Path) -> tuple[tuple[str, Path], ...]:
    """Return active and historical host evidence roots without moving evidence."""
    root = validate_workspace(workspace)
    values = [
        (record.host_id, root / "evidence" / record.storage_key)
        for record in discover_hosts(root)
    ]
    values.extend(
        (item.source_host_id, root / "evidence" / item.source_storage_key)
        for item in applied_merges(root)
    )
    return tuple(values)


def historical_host_record(workspace: Path, host_id: str) -> HostRecord:
    """Return the immutable archived record for one merged legacy host ID."""
    root = validate_workspace(workspace)
    merge = next(
        (item for item in applied_merges(root) if item.source_host_id == host_id),
        None,
    )
    if merge is None:
        raise HostIdentityError("host ID is not a merged historical host")
    path = root / "hosts" / MERGED_DIRECTORY_NAME / f"{merge.source_storage_key}.md"
    record = _read_host(path)
    if record.host_id != host_id or record.storage_key != merge.source_storage_key:
        raise HostIdentityError("merged historical host record does not match ledger")
    return record


def _resolved_aliases(workspace: Path) -> dict[str, set[str]]:
    """Return applied alias names by host from the append-only ledger."""
    path = workspace / LEDGER_NAME
    aliases: dict[str, set[str]] = {}
    if not _lexists(path):
        return aliases
    _require_regular(path, LEDGER_NAME)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise HostIdentityError("host alias ledger is unreadable") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise HostIdentityError(
                f"host alias ledger contains a blank line at {line_number}"
            )
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HostIdentityError("host alias ledger contains invalid JSON") from exc
        if not isinstance(event, dict):
            raise HostIdentityError("host alias ledger record must be an object")
        if event.get("status") not in {"applied", "alias_recorded"}:
            continue
        host_id = event.get("host_id")
        hostname = event.get("hostname")
        if (
            not isinstance(host_id, str)
            or HOST_ID_RE.fullmatch(host_id) is None
            or not isinstance(hostname, str)
        ):
            raise HostIdentityError("host alias ledger contains invalid identity data")
        validate_hostname(hostname)
        aliases.setdefault(host_id, set()).add(hostname)
    return aliases


def resolve_host(workspace: Path, value: str) -> HostRecord:
    """Resolve a canonical ID, storage label, hostname, or canonical IP."""
    root = validate_workspace(workspace)
    records = discover_hosts(root)
    aliases = _resolved_aliases(root)
    merges = applied_merges(root)
    by_id = {record.host_id: record for record in records}
    matches: list[HostRecord] = []
    ip_candidate: str | None = None
    try:
        ip_candidate = str(ipaddress.ip_address(value))
    except ValueError:
        pass
    for record in records:
        if (
            value == record.host_id
            or value == record.storage_key
            or (
                record.hostname != "unknown"
                and value.casefold() == record.hostname.casefold()
            )
            or any(
                value.casefold() == alias.casefold()
                for alias in aliases.get(record.host_id, set())
            )
            or (ip_candidate is not None and ip_candidate in host_endpoints(root, record.host_id))
        ):
            matches.append(record)
    for merge in merges:
        if (
            value == merge.source_host_id
            or value == merge.source_storage_key
            or (ip_candidate is not None and ip_candidate == merge.source_ip)
        ):
            matches.append(by_id[merge.destination_host_id])
        for alias in aliases.get(merge.source_host_id, set()):
            if value.casefold() == alias.casefold():
                matches.append(by_id[merge.destination_host_id])
    unique = {item.host_id: item for item in matches}
    if not unique:
        raise HostIdentityError("host selector does not match a registered host")
    if len(unique) != 1:
        raise HostIdentityError("host selector is ambiguous")
    return next(iter(unique.values()))


def host_paths(workspace: Path, host_id: str) -> HostPaths:
    """Return current physical paths for one canonical host ID."""
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise HostIdentityError("invalid canonical host ID")
    root = validate_workspace(workspace)
    record = resolve_host(root, host_id)
    paths = HostPaths(
        record=record,
        state=record.path,
        report=root / "report" / f"{record.storage_key}.md",
        inbox=root / "inbox" / record.storage_key,
        evidence=root / "evidence" / record.storage_key,
    )
    return paths


def evidence_basename(record: HostRecord, evidence_id: str) -> str:
    """Return the Explorer-visible basename without extension."""
    if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        raise HostIdentityError("invalid evidence ID")
    return f"{record.evidence_prefix}{evidence_id}"


def locate_evidence_metadata(workspace: Path, host_id: str, evidence_id: str) -> Path:
    """Locate legacy or friendly evidence metadata by canonical ID."""
    root = validate_workspace(workspace)
    if EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        raise HostIdentityError("invalid evidence ID")
    merge = next(
        (item for item in applied_merges(root) if item.source_host_id == host_id),
        None,
    )
    if merge is None:
        evidence_dir = host_paths(root, host_id).evidence
    else:
        evidence_dir = root / "evidence" / merge.source_storage_key
    candidates = [
        path
        for path in evidence_dir.glob(f"*{evidence_id}.json")
        if path.is_file() and not path.is_symlink()
    ]
    valid: list[Path] = []
    for path in candidates:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(record, dict)
            and record.get("evidence_id") == evidence_id
            and record.get("host_id") == host_id
        ):
            valid.append(path)
    if len(valid) != 1:
        raise HostIdentityError("evidence metadata does not resolve uniquely")
    return valid[0]


def locate_evidence_artifact(metadata: Path, record: dict[str, Any]) -> Path:
    """Resolve the current artifact beside possibly relocated immutable metadata."""
    stored = record.get("artifact_path")
    if not isinstance(stored, str):
        raise HostIdentityError("evidence metadata has invalid artifact_path")
    suffix = Path(stored).suffix
    if not suffix:
        raise HostIdentityError("evidence metadata has invalid artifact extension")
    if suffix == ".json":
        relative = Path(stored)
        if (
            "\\" in stored
            or relative.is_absolute()
            or ".." in relative.parts
            or len(relative.parts) != 3
            or relative.parts[0] != "evidence"
            or not metadata.name.endswith(relative.name)
        ):
            raise HostIdentityError("legacy evidence metadata path is not canonical")
        artifact = metadata.with_suffix(".legacy")
        _require_regular(artifact, "legacy recovered evidence artifact")
        expected_size = record.get("size_bytes")
        expected_hash = record.get("sha256")
        if (
            not isinstance(expected_size, int)
            or expected_size < 0
            or artifact.stat().st_size != expected_size
            or not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
            or _file_sha256(artifact) != expected_hash
        ):
            raise HostIdentityError("legacy recovered evidence artifact is inconsistent")
        return artifact
    artifact = metadata.with_suffix(suffix)
    _require_regular(artifact, "evidence artifact")
    return artifact


def verify_evidence_artifact(metadata: Path, record: dict[str, Any]) -> Path:
    """Resolve and hash retained bytes, including legacy and relabeled evidence."""
    stored = record.get("artifact_path")
    evidence_id = record.get("evidence_id")
    if not isinstance(stored, str) or not isinstance(evidence_id, str):
        raise HostIdentityError("evidence metadata has invalid artifact identity")
    relative = Path(stored)
    if (
        "\\" in stored or relative.as_posix() != stored
        or relative.is_absolute() or ".." in relative.parts
        or len(relative.parts) != 3 or relative.parts[0] != "evidence"
        or host_id_from_stem(relative.parts[1]) != record.get("host_id")
        or host_id_from_stem(metadata.parent.name) != record.get("host_id")
        or EVIDENCE_ID_RE.fullmatch(evidence_id) is None
        or not relative.stem.endswith(evidence_id)
        or not metadata.stem.endswith(relative.stem)
        or re.fullmatch(r"\.[a-z0-9]{1,10}", relative.suffix) is None
    ):
        raise HostIdentityError("evidence artifact path is not canonical")
    expected_size, expected_hash = record.get("size_bytes"), record.get("sha256")
    if (
        type(expected_size) is not int or expected_size < 0
        or not isinstance(expected_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
    ):
        raise HostIdentityError("evidence metadata has invalid size or SHA-256")
    _require_real_directory(metadata.parent.parent, "evidence directory")
    _require_real_directory(metadata.parent, "host evidence directory")
    artifact = locate_evidence_artifact(metadata, record)
    try:
        descriptor = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise HostIdentityError("evidence artifact size validation failed")
            digest = hashlib.sha256()
            remaining = expected_size
            while remaining:
                block = handle.read(min(remaining, 1024 * 1024))
                if not block:
                    raise HostIdentityError("evidence artifact shrank during validation")
                digest.update(block)
                remaining -= len(block)
            if handle.read(1):
                raise HostIdentityError("evidence artifact grew during validation")
            after = os.fstat(handle.fileno())
        current = artifact.lstat()
    except OSError as exc:
        raise HostIdentityError("evidence artifact could not be verified") from exc
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields) or (
        current.st_dev, current.st_ino
    ) != (before.st_dev, before.st_ino):
        raise HostIdentityError("evidence artifact changed during validation")
    if digest.hexdigest() != expected_hash:
        raise HostIdentityError("evidence artifact SHA-256 validation failed")
    return artifact


def validate_evidence_reference(workspace: Path, host_id: str, reference: str) -> None:
    """Require one retained EVD-ID or its canonical metadata/artifact path."""
    history = historical_host_map(workspace)
    canonical = history.get(host_id)
    if canonical is None:
        raise HostIdentityError("evidence reference host is unknown")
    match = re.search(r"EVD-\d{8}T\d{12}Z", reference)
    if match is None:
        raise HostIdentityError("evidence reference must identify a canonical EVD-ID")
    evidence_id = match.group()
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for owner, directory in evidence_roots(workspace):
        if history.get(owner) != canonical:
            continue
        _require_real_directory(directory.parent, "evidence directory")
        _require_real_directory(directory, "host evidence directory")
        for metadata in directory.glob(f"*{evidence_id}.json"):
            _require_regular(metadata, "evidence metadata")
            record = _load_metadata(metadata)
            if record.get("host_id") == owner and record.get("evidence_id") == evidence_id:
                candidates.append((metadata, record))
    if len(candidates) != 1:
        raise HostIdentityError("evidence reference does not resolve uniquely on this host")
    metadata, record = candidates[0]
    artifact = verify_evidence_artifact(metadata, record)
    allowed = {
        evidence_id, record["artifact_path"],
        metadata.relative_to(workspace).as_posix(),
        artifact.relative_to(workspace).as_posix(),
        str(Path(record["artifact_path"]).with_suffix(".json")),
    }
    if reference not in allowed:
        raise HostIdentityError("evidence reference is not a canonical retained path")


def _load_metadata(path: Path) -> dict[str, Any]:
    if __package__:
        from . import ledger_io
    else:
        import ledger_io

    _require_regular(path, "evidence metadata")
    try:
        with path.open("rb") as handle:
            raw = handle.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise HostIdentityError("evidence metadata exceeds its size limit")
        record = ledger_io.loads_json(raw)
    except (OSError, ledger_io.LedgerIOError) as exc:
        raise HostIdentityError("evidence metadata is unreadable or malformed") from exc
    if not isinstance(record, dict):
        raise HostIdentityError("evidence metadata must contain an object")
    return record


def _planned_evidence_renames(
    evidence_dir: Path, prefix: str
) -> tuple[RenameItem, ...]:
    renames: list[RenameItem] = []
    for path in sorted(evidence_dir.iterdir()):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise HostIdentityError("host evidence contains an unsupported filesystem entry")
        if path.name.startswith(prefix):
            continue
        if not path.name.startswith("EVD-"):
            continue
        destination = path.with_name(f"{prefix}{path.name}")
        if _lexists(destination):
            raise HostIdentityError("friendly evidence destination already exists")
        renames.append(RenameItem(path, destination))
    return tuple(renames)


def build_relabel_plan(
    workspace: Path,
    host_id: str,
    hostname: str,
    evidence_id: str,
) -> RelabelPlan:
    """Build a read-only plan; only the first confirmed name changes storage."""
    root = validate_workspace(workspace)
    for name in ("report", "inbox", "evidence"):
        _require_real_directory(root / name, f"workspace {name} path")
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise HostIdentityError("invalid canonical host ID")
    requested = validate_hostname(hostname)
    paths = host_paths(root, host_id)
    _require_regular(paths.state, "host record")
    _require_regular(paths.report, "host report")
    _require_real_directory(paths.inbox, "host inbox")
    _require_real_directory(paths.evidence, "host evidence directory")
    metadata_path = locate_evidence_metadata(root, host_id, evidence_id)
    evidence_record = _load_metadata(metadata_path)
    locate_evidence_artifact(metadata_path, evidence_record)
    target = storage_key(requested, paths.record.ip, host_id)

    if paths.record.friendly:
        return RelabelPlan(
            root,
            paths.record,
            requested,
            evidence_id,
            paths.record.storage_key,
            (),
            (),
            False,
        )

    targets = (
        RenameItem(paths.state, root / "hosts" / f"{target}.md"),
        RenameItem(paths.report, root / "report" / f"{target}.md"),
        RenameItem(paths.inbox, root / "inbox" / target),
        RenameItem(paths.evidence, root / "evidence" / target),
    )
    for item in targets:
        if _lexists(item.destination):
            raise HostIdentityError("friendly host destination already exists")
    prefix = f"{safe_name_component(requested.split('.', 1)[0], 63)}-"
    evidence_renames = _planned_evidence_renames(paths.evidence, prefix)
    return RelabelPlan(
        root,
        paths.record,
        requested,
        evidence_id,
        target,
        targets,
        evidence_renames,
        True,
    )


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Use Linux renameat2(RENAME_NOREPLACE) to avoid destructive races."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise HostIdentityError("secure no-overwrite rename is unavailable")
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise HostIdentityError("relabel destination appeared during apply")
        raise OSError(error, os.strerror(error))


def _atomic_write(path: Path, data: bytes) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _replace_host_text(data: bytes, plan: RelabelPlan) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HostIdentityError("host Markdown is not valid UTF-8") from exc
    text = re.sub(
        r"(?m)^- Hostname: `[^`\r\n]+`$",
        f"- Hostname: `{plan.requested_hostname}`",
        text,
        count=1,
    )
    text = text.replace(
        f"# Host {plan.host.host_id}",
        f"# Host {plan.target_storage_key} (canonical: {plan.host.host_id})",
        1,
    )
    text = text.replace(
        f"# {plan.host.host_id} —",
        f"# {plan.target_storage_key} (canonical: {plan.host.host_id}) —",
        1,
    )
    old_dir = plan.host.storage_key
    new_dir = plan.target_storage_key
    prefix = f"{safe_name_component(plan.requested_hostname.split('.', 1)[0], 63)}-"
    text = text.replace(f"../evidence/{old_dir}/EVD-", f"../evidence/{new_dir}/{prefix}EVD-")
    text = text.replace(f"evidence/{old_dir}/EVD-", f"evidence/{new_dir}/{prefix}EVD-")
    text = text.replace("../evidence/Hxx/EVD-", f"../evidence/{new_dir}/{prefix}EVD-")
    return text.encode("utf-8")


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _append_event(path: Path, record: dict[str, Any]) -> None:
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _event(
    plan: RelabelPlan,
    alias_id: str,
    event_id: str,
    moment: datetime,
    status: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "alias_event_id": event_id,
        "alias_id": alias_id,
        "created_at_utc": _timestamp(moment),
        "status": status,
        "host_id": plan.host.host_id,
        "hostname": plan.requested_hostname,
        "evidence_ids": [plan.evidence_id],
        "previous_storage_key": plan.host.storage_key,
        "current_storage_key": plan.target_storage_key,
        "automatic_relabel": plan.automatic_relabel,
        "detail": detail,
    }


def apply_relabel_plan(plan: RelabelPlan, now: datetime | None = None) -> dict[str, Any]:
    """Re-plan under a lock and apply an auditable no-overwrite relabel."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    lock_path = plan.workspace / LOCK_NAME
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    completed: list[RenameItem] = []
    original_text: dict[Path, bytes] = {}
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = build_relabel_plan(
            plan.workspace,
            plan.host.host_id,
            plan.requested_hostname,
            plan.evidence_id,
        )
        if current != plan:
            raise HostIdentityError("host identity state changed after preview")
        alias_id = _identifier("HAL", moment)
        planned_time = moment
        _append_event(
            plan.workspace / LEDGER_NAME,
            _event(plan, alias_id, _identifier("HAE", planned_time), planned_time, "planned", "confirmed hostname accepted"),
        )
        if not plan.changes_storage:
            applied_time = moment + timedelta(microseconds=1)
            applied = _event(
                plan,
                alias_id,
                _identifier("HAE", applied_time),
                applied_time,
                "alias_recorded",
                "storage label retained; subsequent automatic relabel is disabled",
            )
            _append_event(plan.workspace / LEDGER_NAME, applied)
            return applied

        for item in plan.root_renames:
            _rename_noreplace(item.source, item.destination)
            completed.append(item)

        moved_evidence_dir = plan.workspace / "evidence" / plan.target_storage_key
        for item in plan.evidence_renames:
            relocated = RenameItem(
                moved_evidence_dir / item.source.name,
                moved_evidence_dir / item.destination.name,
            )
            _rename_noreplace(relocated.source, relocated.destination)
            completed.append(relocated)

        state_path = plan.workspace / "hosts" / f"{plan.target_storage_key}.md"
        report_path = plan.workspace / "report" / f"{plan.target_storage_key}.md"
        for path in (state_path, report_path):
            original_text[path] = path.read_bytes()
            _atomic_write(path, _replace_host_text(original_text[path], plan))

        applied_time = moment + timedelta(microseconds=1)
        applied = _event(
            plan,
            alias_id,
            _identifier("HAE", applied_time),
            applied_time,
            "applied",
            f"renamed {len(completed)} filesystem entries without changing canonical IDs",
        )
        _append_event(plan.workspace / LEDGER_NAME, applied)
        return applied
    except BaseException as exc:
        rollback_errors: list[str] = []
        for path, data in original_text.items():
            try:
                if _lexists(path):
                    _atomic_write(path, data)
            except OSError:
                rollback_errors.append("text")
        for item in reversed(completed):
            try:
                if _lexists(item.destination) and not _lexists(item.source):
                    _rename_noreplace(item.destination, item.source)
            except (OSError, HostIdentityError):
                rollback_errors.append("rename")
        try:
            failed_time = moment + timedelta(microseconds=2)
            alias_id = _identifier("HAL", moment)
            detail = "relabel failed and rollback completed"
            if rollback_errors:
                detail = "relabel failed; rollback requires operator review"
            _append_event(
                plan.workspace / LEDGER_NAME,
                _event(plan, alias_id, _identifier("HAE", failed_time), failed_time, "failed", detail),
            )
        except OSError:
            pass
        if isinstance(exc, HostIdentityError):
            raise
        raise HostIdentityError("host relabel failed") from exc
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


ENDPOINTS_BEGIN = "<!-- CYBER_CANONICAL_ENDPOINTS_BEGIN -->"
ENDPOINTS_END = "<!-- CYBER_CANONICAL_ENDPOINTS_END -->"


def _validate_merge_reason(value: str) -> str:
    if (
        value != value.strip()
        or not value
        or len(value) > 512
        or "\n" in value
        or "\r" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HostIdentityError("merge reason must be bounded printable single-line text")
    return value


def _file_sha256(path: Path) -> str:
    _require_regular(path, "hashed file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise HostIdentityError("file could not be hashed") from exc
    return digest.hexdigest()


def _validated_host_evidence(
    root: Path, host_id: str, evidence_id: str
) -> tuple[str, str]:
    metadata_path = locate_evidence_metadata(root, host_id, evidence_id)
    record = _load_metadata(metadata_path)
    if record.get("host_id") != host_id or record.get("evidence_id") != evidence_id:
        raise HostIdentityError("merge evidence does not belong to the selected host")
    artifact = locate_evidence_artifact(metadata_path, record)
    expected_hash = record.get("sha256")
    expected_size = record.get("size_bytes")
    if (
        not isinstance(expected_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        or not isinstance(expected_size, int)
        or expected_size < 0
        or artifact.stat().st_size != expected_size
    ):
        raise HostIdentityError("merge evidence metadata is inconsistent")
    artifact_hash = _file_sha256(artifact)
    if artifact_hash != expected_hash:
        raise HostIdentityError("merge evidence hash validation failed")
    return _file_sha256(metadata_path), artifact_hash


def build_merge_plan(
    workspace: Path,
    source_host_id: str,
    destination_host_id: str,
    source_evidence_id: str,
    destination_evidence_id: str,
    reason: str,
) -> MergePlan:
    """Build a read-only, evidence-backed source-to-destination merge plan."""
    root = validate_workspace(workspace)
    for name in ("report", "inbox", "evidence"):
        _require_real_directory(root / name, f"workspace {name} path")
    if (
        HOST_ID_RE.fullmatch(source_host_id) is None
        or HOST_ID_RE.fullmatch(destination_host_id) is None
        or source_host_id == destination_host_id
    ):
        raise HostIdentityError("merge requires two different active canonical host IDs")
    requested_reason = _validate_merge_reason(reason)
    existing_merges = applied_merges(root)
    merged_ids = {item.source_host_id for item in existing_merges}
    if source_host_id in merged_ids or destination_host_id in merged_ids:
        raise HostIdentityError("merge source and destination must both be active")
    records = {record.host_id: record for record in discover_hosts(root)}
    if source_host_id not in records or destination_host_id not in records:
        raise HostIdentityError("merge source and destination must both be active")
    source = records[source_host_id]
    destination = records[destination_host_id]
    if source.ip == "unknown" or destination.ip == "unknown" or source.ip == destination.ip:
        raise HostIdentityError("merge requires two different confirmed IP addresses")
    if (
        source.hostname == "unknown"
        or destination.hostname == "unknown"
        or source.hostname.casefold() != destination.hostname.casefold()
    ):
        raise HostIdentityError("merge requires matching confirmed hostnames")
    if source.ip in host_endpoints(root, destination_host_id):
        raise HostIdentityError("source endpoint is already assigned to destination")
    source_metadata_hash, source_artifact_hash = _validated_host_evidence(
        root, source_host_id, source_evidence_id
    )
    destination_metadata_hash, destination_artifact_hash = _validated_host_evidence(
        root, destination_host_id, destination_evidence_id
    )
    archive = root / "hosts" / MERGED_DIRECTORY_NAME / source.path.name
    if _lexists(archive):
        raise HostIdentityError("merged host archive destination already exists")
    return MergePlan(
        workspace=root,
        source=source,
        destination=destination,
        source_evidence_id=source_evidence_id,
        destination_evidence_id=destination_evidence_id,
        reason=requested_reason,
        archive_path=archive,
        source_state_sha256=_file_sha256(source.path),
        destination_state_sha256=_file_sha256(destination.path),
        source_metadata_sha256=source_metadata_hash,
        source_artifact_sha256=source_artifact_hash,
        destination_metadata_sha256=destination_metadata_hash,
        destination_artifact_sha256=destination_artifact_hash,
    )


def _endpoint_block(plan: MergePlan) -> str:
    previous = [
        item
        for item in applied_merges(plan.workspace)
        if item.destination_host_id == plan.destination.host_id
    ]
    lines = [
        ENDPOINTS_BEGIN,
        "## Canonical endpoints",
        "",
        f"- Primary: `{plan.destination.ip}`",
    ]
    for item in previous:
        lines.append(
            f"- Additional: `{item.source_ip}` — merged from `{item.source_host_id}`; "
            f"evidence `{item.source_evidence_id}`"
        )
    lines.append(
        f"- Additional: `{plan.source.ip}` — merged from `{plan.source.host_id}`; "
        f"evidence `{plan.source_evidence_id}`"
    )
    merged = [item.source_host_id for item in previous] + [plan.source.host_id]
    lines.extend(("", f"- Merged legacy IDs: `{', '.join(merged)}`", ENDPOINTS_END))
    return "\n".join(lines)


def _replace_endpoint_block(data: bytes, plan: MergePlan) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HostIdentityError("host Markdown is not valid UTF-8") from exc
    block = _endpoint_block(plan)
    if ENDPOINTS_BEGIN in text or ENDPOINTS_END in text:
        pattern = re.compile(
            re.escape(ENDPOINTS_BEGIN) + r".*?" + re.escape(ENDPOINTS_END),
            re.DOTALL,
        )
        if len(pattern.findall(text)) != 1:
            raise HostIdentityError("canonical endpoint block is malformed")
        text = pattern.sub(block, text, count=1)
    else:
        hostname_match = HOST_FIELD_PATTERNS["hostname"].search(text)
        if hostname_match is None:
            raise HostIdentityError("destination host record has malformed identity fields")
        position = hostname_match.end()
        text = text[:position] + "\n\n" + block + text[position:]
    return text.encode("utf-8")


def _merge_event(
    plan: MergePlan,
    merge_id: str,
    event_id: str,
    moment: datetime,
    status: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "merge_event_id": event_id,
        "merge_id": merge_id,
        "created_at_utc": _timestamp(moment),
        "status": status,
        "source_host_id": plan.source.host_id,
        "destination_host_id": plan.destination.host_id,
        "source_storage_key": plan.source.storage_key,
        "destination_storage_key": plan.destination.storage_key,
        "source_ip": plan.source.ip,
        "destination_primary_ip": plan.destination.ip,
        "hostname": plan.destination.hostname,
        "source_evidence_id": plan.source_evidence_id,
        "destination_evidence_id": plan.destination_evidence_id,
        "reason": plan.reason,
        "rollback_status": (
            "completed"
            if status == "failed" and "rollback completed" in detail
            else "operator-review"
            if status == "failed"
            else "not-required"
        ),
        "detail": detail,
    }


def apply_merge_plan(plan: MergePlan, now: datetime | None = None) -> dict[str, Any]:
    """Re-plan under locks and durably finish one evidence-backed host merge."""
    if __package__:
        from . import workspace_transaction
    else:
        import workspace_transaction
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        with workspace_transaction.write_guard(plan.workspace):
            descriptor = os.open(plan.workspace / MERGE_LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                current = build_merge_plan(
                    plan.workspace, plan.source.host_id, plan.destination.host_id,
                    plan.source_evidence_id, plan.destination_evidence_id, plan.reason,
                )
                if current != plan:
                    raise HostIdentityError("host merge state changed after preview")
                destination_bytes = _replace_endpoint_block(plan.destination.path.read_bytes(), plan)
                merge_id = _identifier("HMG", moment)
                planned = _merge_event(plan, merge_id, _identifier("HME", moment), moment, "planned",
                                       "evidence-backed active host merge accepted")
                applied_time = moment + timedelta(microseconds=1)
                applied = _merge_event(plan, merge_id, _identifier("HME", applied_time), applied_time, "applied",
                                       "source card archived; destination storage key retained; endpoint added")
                transaction = workspace_transaction.Transaction(
                    plan.workspace, "host-merge", references={"host_id": plan.destination.host_id},
                )
                ledger = plan.workspace / MERGE_LEDGER_NAME
                transaction.add("append", ledger, (json.dumps(planned, separators=(",", ":")) + "\n").encode())
                transaction.add("move", plan.source.path, destination=plan.archive_path)
                transaction.add("replace", plan.destination.path, destination_bytes)
                transaction.add("append", ledger, (json.dumps(applied, separators=(",", ":")) + "\n").encode())
                if (transaction.operations[1]["before_sha256"] != plan.source_state_sha256
                        or transaction.operations[2]["before_sha256"] != plan.destination_state_sha256):
                    raise HostIdentityError("host merge state changed during preparation")
                transaction.commit()
                return applied
            finally:
                os.close(descriptor)
    except (OSError, RuntimeError) as exc:
        raise HostIdentityError(f"host merge interrupted; inspect recovery journal: {exc}") from exc


def _print_plan(plan: RelabelPlan, apply: bool) -> None:
    print("Cyber-Operator confirmed host identity")
    print(f"  mode:             {'APPLY' if apply else 'PREVIEW'}")
    print(f"  host_id:          {plan.host.host_id}")
    print(f"  hostname:         {plan.requested_hostname}")
    print(f"  evidence_id:      {plan.evidence_id}")
    print(f"  current storage:  {plan.host.storage_key}")
    print(f"  target storage:   {plan.target_storage_key}")
    print(f"  automatic relabel:{' ON' if plan.automatic_relabel else ' OFF'}")
    print(f"  host paths:       {len(plan.root_renames)}")
    print(f"  evidence files:   {len(plan.evidence_renames)}")


def _print_merge_plan(plan: MergePlan, apply: bool) -> None:
    print("Cyber-Operator canonical host merge")
    print(f"  mode:                 {'APPLY' if apply else 'PREVIEW'}")
    print(f"  source_host_id:       {plan.source.host_id}")
    print(f"  destination_host_id:  {plan.destination.host_id}")
    print(f"  hostname:             {plan.destination.hostname}")
    print(f"  primary_ip:           {plan.destination.ip}")
    print(f"  additional_ip:        {plan.source.ip}")
    print(f"  destination_storage:  {plan.destination.storage_key}")
    print(f"  archived_source:      {plan.archive_path.relative_to(plan.workspace)}")
    print(f"  source_evidence:      {plan.source_evidence_id}")
    print(f"  destination_evidence: {plan.destination_evidence_id}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Resolve and label canonical Cyber-Operator hosts.")
    root.add_argument("--workspace", required=True)
    commands = root.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list canonical and friendly host names")
    listing.add_argument("--include-merged", action="store_true")
    listing.set_defaults(command="list")
    resolve = commands.add_parser("resolve", help="resolve a host selector")
    resolve.add_argument("selector")
    relabel = commands.add_parser(
        "confirm", help="record a confirmed hostname and automatically apply the first relabel"
    )
    relabel.add_argument("--host-id", required=True)
    relabel.add_argument("--hostname", required=True)
    relabel.add_argument("--evidence", required=True)
    relabel.add_argument("--apply", action="store_true")
    merge = commands.add_parser(
        "merge", help="merge one evidence-backed active host into another"
    )
    merge.add_argument("--source-host-id", required=True)
    merge.add_argument("--destination-host-id", required=True)
    merge.add_argument("--source-evidence", required=True)
    merge.add_argument("--destination-evidence", required=True)
    merge.add_argument("--reason", required=True)
    merge.add_argument("--apply", action="store_true")
    refresh = commands.add_parser(
        "refresh", help="preview or refresh managed host-state projections"
    )
    selection = refresh.add_mutually_exclusive_group(required=True)
    selection.add_argument("--host-id")
    selection.add_argument("--all", action="store_true")
    refresh.add_argument("--apply", action="store_true")
    return root


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        workspace = Path(args.workspace)
        if args.command == "list":
            for record in discover_hosts(workspace):
                endpoints = ",".join(host_endpoints(workspace, record.host_id))
                merged = ",".join(merged_host_ids(workspace, record.host_id)) or "none"
                print(
                    f"host_id={record.host_id} display={record.display_name} "
                    f"primary_ip={record.ip} endpoints={endpoints} "
                    f"merged_ids={merged} hostname={record.hostname}"
                )
            if args.include_merged:
                for item in applied_merges(workspace):
                    print(
                        f"host_id={item.source_host_id} status=merged_into "
                        f"canonical={item.destination_host_id} ip={item.source_ip} "
                        f"storage={item.source_storage_key}"
                    )
            return 0
        if args.command == "resolve":
            record = resolve_host(workspace, args.selector)
            print(f"host_id={record.host_id}")
            print(f"display={record.display_name}")
            if args.selector != record.host_id:
                print(f"resolved_from={args.selector}")
            return 0
        if args.command == "refresh":
            if __package__:
                from . import host_state
            else:
                import host_state
            try:
                result = host_state.refresh(
                    workspace,
                    host_id=args.host_id,
                    refresh_all=args.all,
                    apply=args.apply,
                    now=now,
                )
            except host_state.HostStateError as exc:
                raise HostIdentityError(str(exc)) from exc
            print(f"mode: {result['mode']}")
            print(f"hosts: {','.join(result['hosts'])}")
            print("global: refreshed" if args.apply else "global: planned")
            return 0
        if args.command == "merge":
            plan = build_merge_plan(
                workspace,
                args.source_host_id,
                args.destination_host_id,
                args.source_evidence,
                args.destination_evidence,
                args.reason,
            )
            _print_merge_plan(plan, args.apply)
            if args.apply:
                event = apply_merge_plan(plan, now=now)
                print(f"merge_id: {event['merge_id']}")
                print(f"status: {event['status']}")
            else:
                print("Preview only. Re-run with --apply after review.")
            return 0
        plan = build_relabel_plan(
            workspace,
            args.host_id,
            args.hostname,
            args.evidence,
        )
        _print_plan(plan, args.apply)
        if args.apply:
            event = apply_relabel_plan(plan, now=now)
            print(f"status: {event['status']}")
        else:
            print("Preview only. Re-run with --apply after review.")
        return 0
    except (HostIdentityError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
