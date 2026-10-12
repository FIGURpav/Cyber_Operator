"""Preview and apply bounded natural-text host mapping intake."""

import argparse
import hashlib
import ipaddress
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from . import host_identity
    from .new_host import (
        COMMON_DIRECTORY_NAMES,
        HOST_ID_PATTERN,
        HOSTNAME_PATTERN,
        BootstrapPlan,
        CreationTracker,
        WorkspaceLayoutError,
        apply_bootstrap_plan,
        build_host_paths,
        prepare_bootstrap,
        rollback_created,
        validate_workspace_layout,
    )
else:
    import host_identity  # type: ignore[no-redef]
    from new_host import (  # type: ignore[no-redef]
        COMMON_DIRECTORY_NAMES,
        HOST_ID_PATTERN,
        HOSTNAME_PATTERN,
        BootstrapPlan,
        CreationTracker,
        WorkspaceLayoutError,
        apply_bootstrap_plan,
        build_host_paths,
        prepare_bootstrap,
        rollback_created,
        validate_workspace_layout,
    )

MAX_INPUT_BYTES = 64 * 1024
MAX_HOST_RECORD_BYTES = 1024 * 1024
MAX_LABEL_LENGTH = 253
MAX_FILESYSTEM_ERROR_MESSAGE = 160
FILESYSTEM_ERROR_PREFIX = "filesystem operation failed"
SAFE_FILESYSTEM_ERROR_DETAILS = (
    "permission denied",
    "no space left on device",
    "read-only file system",
    "disk quota exceeded",
    "file too large",
    "too many open files",
    "input/output error",
    "device or resource busy",
    "synthetic post-write failure",
)
HOST_FIELD_PATTERNS = {
    "host_id": re.compile(r"^- Host ID: `([^`\r\n]+)`$", re.MULTILINE),
    "ip": re.compile(r"^- IP address: `([^`\r\n]+)`$", re.MULTILINE),
    "label": re.compile(r"^- Hostname: `([^`\r\n]+)`$", re.MULTILINE),
}


class IntakeError(Exception):
    """A safe operator-intake validation error."""


@dataclass(frozen=True)
class Mapping:
    """One normalized host identity mapping."""

    ip: str
    label: str

    @property
    def label_key(self) -> str:
        """Return the case-insensitive identity key for the operator label."""
        return self.label.casefold()


@dataclass(frozen=True)
class ExistingHost:
    """One canonical host record discovered from legacy or friendly Markdown."""

    host_id: str
    number: int
    mapping: Mapping | None
    additional_ips: tuple[str, ...] = ()
    merged_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlannedMapping:
    """One existing or newly assigned mapping in an intake plan."""

    status: str
    host_id: str
    mapping: Mapping


@dataclass(frozen=True)
class IntakePlan:
    """A fully validated host intake plan."""

    input_bytes: bytes
    input_sha256: str
    mappings: tuple[Mapping, ...]
    existing_hosts: tuple[ExistingHost, ...]
    planned: tuple[PlannedMapping, ...]

    @property
    def existing_count(self) -> int:
        """Return the number of input mappings already present."""
        return sum(item.status == "existing" for item in self.planned)

    @property
    def new_count(self) -> int:
        """Return the number of mappings requiring host creation."""
        return sum(item.status == "create" for item in self.planned)


def _safe_error(message: str) -> IntakeError:
    """Build an error that never includes raw operator input."""
    return IntakeError(message)


def _single_line_text(value: str, limit: int) -> str:
    """Return bounded printable text with controls and whitespace collapsed."""
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit].strip()


def _normalize_filesystem_error(exc: OSError) -> str:
    """Preserve only bounded, operator-safe filesystem failure meaning."""
    detail = ""
    if isinstance(exc.errno, int):
        try:
            detail = _single_line_text(os.strerror(exc.errno), MAX_FILESYSTEM_ERROR_MESSAGE)
        except (OverflowError, ValueError):
            detail = ""

    if not detail:
        candidate = _single_line_text(str(exc), MAX_FILESYSTEM_ERROR_MESSAGE * 4)
        candidate_key = candidate.casefold()
        detail = next(
            (
                safe_detail
                for safe_detail in SAFE_FILESYSTEM_ERROR_DETAILS
                if safe_detail in candidate_key
            ),
            "",
        )

    if not detail:
        return FILESYSTEM_ERROR_PREFIX
    available = MAX_FILESYSTEM_ERROR_MESSAGE - len(FILESYSTEM_ERROR_PREFIX) - 2
    bounded_detail = detail.casefold()[:available].rstrip()
    if not bounded_detail:
        return FILESYSTEM_ERROR_PREFIX
    return f"{FILESYSTEM_ERROR_PREFIX}: {bounded_detail}"


def _read_input(path_text: str) -> bytes:
    """Read a bounded regular non-symlink input file."""
    path = Path(path_text)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _safe_error("input file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise _safe_error("input file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise _safe_error("input file must be a regular file")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise _safe_error(f"input exceeds the {MAX_INPUT_BYTES}-byte limit")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _safe_error("input file could not be read") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise _safe_error(f"input exceeds the {MAX_INPUT_BYTES}-byte limit")
    return data


def _validate_workspace(path_text: str) -> Path:
    """Validate the supplied workspace without following a workspace symlink."""
    supplied = Path(path_text)
    if ".." in supplied.parts:
        raise _safe_error("workspace path must not contain parent traversal")
    absolute = supplied if supplied.is_absolute() else Path.cwd() / supplied
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise _safe_error("workspace path components must not be symlinks")
        if current.exists() and not current.is_dir():
            raise _safe_error("workspace path components must be directories")
    return absolute


def _decode_input(data: bytes) -> str:
    """Decode UTF-8 and reject controls other than line separators."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _safe_error("input must be valid UTF-8") from exc
    for index, character in enumerate(text):
        codepoint = ord(character)
        if character == "\n":
            continue
        if character == "\r" and index + 1 < len(text) and text[index + 1] == "\n":
            continue
        if codepoint < 32 or codepoint == 127:
            raise _safe_error("input contains a prohibited control character")
    if not text.strip():
        raise _safe_error("input contains no host mappings")
    return text


def _canonical_ip(value: str, record_number: int) -> str:
    """Return canonical address text without leaking invalid input in errors."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise _safe_error(f"record {record_number} does not contain a valid IP address") from exc


def _validate_label(value: str, record_number: int) -> str:
    """Validate a bounded DNS-style hostname or short system label."""
    if not value:
        raise _safe_error(f"record {record_number} is missing an operator label")
    if value != value.strip():
        raise _safe_error(f"record {record_number} has label boundary whitespace")
    if len(value) > MAX_LABEL_LENGTH:
        raise _safe_error(f"record {record_number} label exceeds {MAX_LABEL_LENGTH} characters")
    if HOSTNAME_PATTERN.fullmatch(value) is None:
        raise _safe_error(f"record {record_number} has an unsupported operator label")
    return value


def parse_mappings(data: bytes) -> tuple[Mapping, ...]:
    """Parse only supported one-line and two-line mapping records."""
    text = _decode_input(data)
    normalized_lines = text.replace("\r\n", "\n").split("\n")
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in normalized_lines:
        if not line:
            if current:
                blocks.append(current)
                current = []
            continue
        if line != line.strip():
            raise _safe_error("nonempty input lines must not have boundary whitespace")
        current.append(line)
    if current:
        blocks.append(current)
    if not blocks:
        raise _safe_error("input contains no host mappings")

    parsed: list[Mapping] = []
    for record_number, block in enumerate(blocks, start=1):
        if len(block) > 2:
            raise _safe_error(f"record {record_number} has more than two nonempty lines")
        if len(block) == 2:
            if len(block[0].split()) != 1 or len(block[1].split()) != 1:
                raise _safe_error(f"record {record_number} is not a supported two-line mapping")
            ip_value, label_value = block
        else:
            fields = block[0].split()
            if len(fields) != 2:
                raise _safe_error(f"record {record_number} is not a supported one-line mapping")
            ip_value, label_value = fields
        canonical_ip = _canonical_ip(ip_value, record_number)
        label = _validate_label(label_value, record_number)
        parsed.append(Mapping(ip=canonical_ip, label=label))

    unique: list[Mapping] = []
    by_ip: dict[str, Mapping] = {}
    by_label: dict[str, Mapping] = {}
    conflicts: list[str] = []
    for record_number, mapping in enumerate(parsed, start=1):
        ip_match = by_ip.get(mapping.ip)
        label_match = by_label.get(mapping.label_key)
        record_conflict = False
        if ip_match is not None and ip_match.label_key != mapping.label_key:
            conflicts.append(f"record {record_number} reuses an IP with a different label")
            record_conflict = True
        if label_match is not None and label_match.ip != mapping.ip:
            conflicts.append(f"record {record_number} reuses a label with a different IP")
            record_conflict = True
        if record_conflict:
            continue
        if ip_match is not None:
            continue
        by_ip[mapping.ip] = mapping
        by_label[mapping.label_key] = mapping
        unique.append(mapping)
    if conflicts:
        raise _safe_error(
            f"input conflicts detected ({len(conflicts)}): " + "; ".join(conflicts)
        )
    return tuple(unique)


def _read_host_record(path: Path) -> ExistingHost:
    """Read the fixed canonical identity fields from one host Markdown record."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _safe_error("an existing host record is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise _safe_error("an existing canonical host path is not a regular non-symlink file")
    if metadata.st_size > MAX_HOST_RECORD_BYTES:
        raise _safe_error("an existing canonical host record exceeds the size limit")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _safe_error("an existing canonical host record is unreadable or malformed") from exc

    values: dict[str, str] = {}
    for name, pattern in HOST_FIELD_PATTERNS.items():
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise _safe_error("an existing canonical host record has malformed identity fields")
        values[name] = matches[0]
    host_id = host_identity.host_id_from_stem(path.stem)
    if host_id is None:
        raise _safe_error("an existing canonical host record has an invalid filename")
    if HOST_ID_PATTERN.fullmatch(host_id) is None or values["host_id"] != host_id:
        raise _safe_error("an existing canonical host record has an invalid or mismatched host ID")
    number = int(host_id[1:])

    ip_value = values["ip"]
    label_value = values["label"]
    if ip_value == "unknown" and label_value == "unknown":
        return ExistingHost(host_id=host_id, number=number, mapping=None)
    if ip_value == "unknown" or label_value == "unknown":
        raise _safe_error("an existing canonical host record has incomplete identity fields")
    try:
        canonical_ip = str(ipaddress.ip_address(ip_value))
    except ValueError as exc:
        raise _safe_error("an existing canonical host record has an invalid IP address") from exc
    label = _validate_label(label_value, number)
    return ExistingHost(host_id=host_id, number=number, mapping=Mapping(canonical_ip, label))


def discover_hosts(workspace: Path) -> tuple[ExistingHost, ...]:
    """Discover and validate every canonical legacy or friendly host record."""
    if workspace.exists():
        if workspace.is_symlink() or not workspace.is_dir():
            raise _safe_error("workspace must be a non-symlink directory")
    else:
        return ()
    hosts_dir = workspace / "hosts"
    if not hosts_dir.exists():
        return ()
    if hosts_dir.is_symlink() or not hosts_dir.is_dir():
        raise _safe_error("workspace hosts path must be a non-symlink directory")

    records: list[ExistingHost] = []
    for path in sorted(hosts_dir.glob("*.md")):
        if host_identity.host_id_from_stem(path.stem) is not None:
            records.append(_read_host_record(path))

    seen_ids: set[int] = set()
    seen_ips: dict[str, str] = {}
    seen_labels: dict[str, str] = {}
    for record in records:
        if record.number in seen_ids:
            raise _safe_error("duplicate existing canonical host ID detected")
        seen_ids.add(record.number)
        if record.mapping is None:
            continue
        if record.mapping.ip in seen_ips:
            raise _safe_error("duplicate existing canonical host IP detected")
        if record.mapping.label_key in seen_labels:
            raise _safe_error("duplicate existing canonical host label detected")
        seen_ips[record.mapping.ip] = record.host_id
        seen_labels[record.mapping.label_key] = record.host_id
    by_id = {record.host_id: record for record in records}
    for merge in host_identity.applied_merges(workspace):
        destination = by_id.get(merge.destination_host_id)
        if destination is None:
            raise _safe_error("host merge destination is not active")
        by_id[merge.destination_host_id] = ExistingHost(
            host_id=destination.host_id,
            number=destination.number,
            mapping=destination.mapping,
            additional_ips=destination.additional_ips + (merge.source_ip,),
            merged_ids=destination.merged_ids + (merge.source_host_id,),
        )
    return tuple(by_id[record.host_id] for record in records)


def _format_host_id(number: int) -> str:
    """Format the deterministic canonical ID for a positive host number."""
    return f"H{number:02d}"


def build_plan(workspace: Path, data: bytes) -> IntakePlan:
    """Validate input and existing state, then calculate all assignments."""
    mappings = parse_mappings(data)
    try:
        validate_workspace_layout(workspace)
    except WorkspaceLayoutError as exc:
        raise _safe_error(str(exc)) from exc
    _validate_existing_operator_directory(workspace)
    existing_hosts = discover_hosts(workspace)
    by_ip: dict[str, ExistingHost] = {}
    for record in existing_hosts:
        if record.mapping is None:
            continue
        by_ip[record.mapping.ip] = record
        for endpoint in record.additional_ips:
            if endpoint in by_ip and by_ip[endpoint].host_id != record.host_id:
                raise _safe_error("duplicate existing canonical host IP detected")
            by_ip[endpoint] = record
    by_label = {
        record.mapping.label_key: record
        for record in existing_hosts
        if record.mapping is not None
    }
    conflicts: list[str] = []
    planned: list[PlannedMapping] = []
    reserved_numbers = {
        number
        for record in existing_hosts
        for number in (
            record.number,
            *(int(host_id[1:]) for host_id in record.merged_ids),
        )
    }
    next_number = max(reserved_numbers, default=0) + 1

    for record_number, mapping in enumerate(mappings, start=1):
        ip_match = by_ip.get(mapping.ip)
        label_match = by_label.get(mapping.label_key)
        record_conflict = False
        if (
            ip_match is not None
            and ip_match.mapping is not None
            and ip_match.mapping.label_key != mapping.label_key
        ):
            conflicts.append(f"record {record_number} conflicts with an existing IP")
            record_conflict = True
        if label_match is not None and (
            ip_match is None or label_match.host_id != ip_match.host_id
        ):
            conflicts.append(f"record {record_number} conflicts with an existing label")
            record_conflict = True
        if record_conflict:
            continue
        if ip_match is not None:
            planned.append(PlannedMapping("existing", ip_match.host_id, mapping))
            continue
        host_id = _format_host_id(next_number)
        next_number += 1
        planned.append(PlannedMapping("create", host_id, mapping))

    if conflicts:
        raise _safe_error(
            f"host mapping conflicts detected ({len(conflicts)}): " + "; ".join(conflicts)
        )

    planned_ids: set[str] = set()
    for item in planned:
        if item.status != "create":
            continue
        if item.host_id in planned_ids:
            raise _safe_error("planned host ID collision detected")
        planned_ids.add(item.host_id)
        for path in build_host_paths(workspace, item.host_id).values():
            if _path_entry_exists(path):
                raise _safe_error("a planned canonical host destination already exists")

    return IntakePlan(
        input_bytes=data,
        input_sha256=hashlib.sha256(data).hexdigest(),
        mappings=mappings,
        existing_hosts=existing_hosts,
        planned=tuple(planned),
    )


def _path_entry_exists(path: Path) -> bool:
    """Return whether an entry exists without following a final symlink."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _validate_existing_operator_directory(workspace: Path) -> None:
    """Validate the optional intake directory without creating or chmodding it."""
    inbox = workspace / "inbox"
    operator_dir = inbox / "operator"
    if _path_entry_exists(operator_dir):
        metadata = operator_dir.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise _safe_error(
                "operator intake directory must be a real non-symlink directory"
            )


def _validate_intake_target(workspace: Path, filename: str) -> Path:
    """Validate the exact intake destination after shared layout validation."""
    _validate_existing_operator_directory(workspace)
    operator_dir = workspace / "inbox" / "operator"
    destination = operator_dir / filename
    if _path_entry_exists(destination):
        raise _safe_error("planned intake destination already exists")
    return destination


def _nearest_existing_directory(path: Path) -> Path:
    """Return the nearest existing real directory at or above a planned parent."""
    current = path
    while not _path_entry_exists(current):
        if current.parent == current:
            raise _safe_error("no existing parent directory is available")
        current = current.parent
    metadata = current.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise _safe_error("a planned creation parent is not a real directory")
    return current


def _has_effective_write_search(path: Path) -> bool:
    """Check effective Unix write and search access for one existing directory."""
    try:
        return os.access(path, os.W_OK | os.X_OK, effective_ids=True)
    except TypeError:
        return os.access(path, os.W_OK | os.X_OK)


def _ensure_contained(workspace: Path, path: Path) -> None:
    """Reject a planned mutation outside the lexical workspace boundary."""
    if path == workspace or workspace.is_relative_to(path):
        return
    try:
        path.relative_to(workspace)
    except ValueError as exc:
        raise _safe_error("a planned creation path would escape the workspace") from exc


def _preflight_writability(
    workspace: Path,
    bootstrap: BootstrapPlan,
    operator_dir: Path,
    destination: Path,
) -> None:
    """Detect deterministic effective-permission failures before any apply write."""
    required_directories = [workspace]
    required_directories.extend(workspace / name for name in COMMON_DIRECTORY_NAMES)
    required_directories.append(operator_dir)
    creation_paths = [*bootstrap.directories, *(write.path for write in bootstrap.files)]
    creation_paths.extend((operator_dir, destination))

    checked: set[Path] = set()
    for path in required_directories:
        _ensure_contained(workspace, path)
        access_path = path if _path_entry_exists(path) else _nearest_existing_directory(path.parent)
        if access_path in checked:
            continue
        checked.add(access_path)
        if not _has_effective_write_search(access_path):
            raise _safe_error("a required workspace directory is not writable and searchable")

    for path in creation_paths:
        _ensure_contained(workspace, path)
        parent = _nearest_existing_directory(path.parent)
        if parent in checked:
            continue
        checked.add(parent)
        if not _has_effective_write_search(parent):
            raise _safe_error("a planned creation parent is not writable and searchable")


def _preserve_input(
    destination: Path,
    data: bytes,
    tracker: CreationTracker,
) -> None:
    """Preserve exact input bytes with restrictive local permissions."""
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    metadata: os.stat_result | None = None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            tracker.record(destination, metadata)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _create_directory(path: Path, tracker: CreationTracker) -> None:
    """Create and track one planned directory without implicit parents."""
    if _path_entry_exists(path):
        owned = any(created.path == path for created in tracker.created)
        if owned:
            return
        raise FileExistsError("a planned directory changed before apply")
    path.mkdir(mode=0o700)
    try:
        tracker.record(path)
    except BaseException:
        try:
            path.rmdir()
        except OSError:
            pass
        raise


def _intake_filename(now: datetime) -> str:
    """Return an INTAKE ID using the current UTC microsecond convention."""
    current = now.astimezone(UTC)
    return f"INTAKE-{current.strftime('%Y%m%dT%H%M%S%fZ')}.txt"


def _print_plan(mode: str, plan: IntakePlan, preserved_path: str | None = None) -> None:
    """Print bounded plan metadata without echoing full raw input."""
    print(f"mode: {mode}")
    print(f"input_sha256: {plan.input_sha256}")
    print(f"parsed_mappings: {len(plan.mappings)}")
    print(f"existing_mappings: {plan.existing_count}")
    print(f"new_mappings: {plan.new_count}")
    print("conflicts: 0")
    for item in plan.planned:
        print(
            f"mapping: status={item.status} host_id={item.host_id} "
            f"ip={item.mapping.ip} label={item.mapping.label}"
        )
    if mode == "apply":
        print(f"preserved_input: {preserved_path or '(none)'}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Preview or apply bounded host mapping intake.")
    parser.add_argument("--workspace", required=True, help="private workspace directory")
    parser.add_argument("--input-file", required=True, help="regular UTF-8 host mapping file")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preview", action="store_true", help="validate and print a read-only plan")
    modes.add_argument("--apply", action="store_true", help="validate, preserve input, and create new hosts")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    """CLI entry point."""
    try:
        args = parse_args(argv)
        workspace = _validate_workspace(args.workspace)
        data = _read_input(args.input_file)
        plan = build_plan(workspace, data)
        if args.preview:
            _print_plan("preview", plan)
            return 0

        if plan.new_count == 0:
            _print_plan("apply", plan)
            return 0

        current = now or datetime.now(UTC)
        filename = _intake_filename(current)
        script_dir = Path(__file__).resolve().parent
        new_hosts = tuple(
            (item.host_id, item.mapping.ip, item.mapping.label)
            for item in plan.planned
            if item.status == "create"
        )
        try:
            bootstrap = prepare_bootstrap(workspace, script_dir, new_hosts)
        except WorkspaceLayoutError as exc:
            raise _safe_error(str(exc)) from exc
        destination = _validate_intake_target(workspace, filename)
        operator_dir = destination.parent
        _preflight_writability(workspace, bootstrap, operator_dir, destination)

        tracker = CreationTracker()
        try:
            for path in bootstrap.directories:
                if workspace.is_relative_to(path) or path == workspace / "inbox":
                    _create_directory(path, tracker)
            if not _path_entry_exists(operator_dir):
                _create_directory(operator_dir, tracker)
            _preserve_input(destination, plan.input_bytes, tracker)
            apply_bootstrap_plan(bootstrap, tracker)
        except BaseException:
            rollback_created(tracker)
            raise
        relative_path = destination.relative_to(workspace).as_posix()
        _print_plan("apply", plan, relative_path)
        return 0
    except IntakeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileExistsError:
        print("error: a validated destination changed before apply completed", file=sys.stderr)
        return 1
    except WorkspaceLayoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {_normalize_filesystem_error(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
