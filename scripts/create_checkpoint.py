"""Create a timestamped local snapshot of an existing private workspace."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from . import artifact_io, operational_profile
    from .token_lifecycle import TokenLifecycleError, closure_readiness
else:
    import artifact_io  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    from token_lifecycle import (  # type: ignore[no-redef]
        TokenLifecycleError,
        closure_readiness,
    )

CHECKPOINT_DIR_PATTERN = re.compile(r"^CHK-\d{8}T\d{6}\d{6}Z$")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024

FIELD_ORDER = (
    "schema_version",
    "checkpoint_id",
    "timestamp_utc",
    "source_workspace",
    "operational_profile",
    "unresolved_session_token_count",
    "contains_ephemeral_session_secrets",
    "file_count",
    "total_bytes",
    "files",
    "directories",
)

REQUIRED_FILES = ("global.md", "loot.jsonl", "attempts.jsonl")
REQUIRED_DIRS = ("hosts", "queries", "evidence", "report")


class CheckpointError(Exception):
    """A user-facing checkpoint error that should not produce a traceback."""


class TraversalError(Exception):
    """A path traversal related error."""


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def has_traversal(path: Path) -> bool:
    """Return True if any path component is a parent reference."""
    return any(part == ".." for part in path.parts)


def resolve_path(path: Path) -> Path:
    """Resolve a path, but reject traversal syntax first."""
    if has_traversal(path):
        raise TraversalError(f"path must not contain '..': {path!s}")
    for part in (path, *path.parents):
        _reject_symlink(part, "path component")
    return path.resolve(strict=False)


def _reject_symlink(path: Path, label: str) -> None:
    """Raise if path is itself a symbolic link (missing paths are fine)."""
    try:
        is_link = path.is_symlink()
    except OSError:
        is_link = False
    if is_link:
        raise CheckpointError(f"symbolic link is not allowed for {label}: {path!s}")


def is_checkpoint_directory_name(name: str) -> bool:
    """Return True if name matches a checkpoint directory identifier."""
    return CHECKPOINT_DIR_PATTERN.fullmatch(name) is not None


def reject_workspace_inside_checkpoint(path: Path) -> None:
    """Raise if any ancestor directory name is a checkpoint identifier."""
    for part in path.parts:
        if is_checkpoint_directory_name(part):
            raise CheckpointError(
                f"workspace must not be inside an existing checkpoint directory: {path!s}"
            )


def validate_workspace(workspace: str) -> Path:
    """Validate the source workspace and return its absolute path."""
    path = Path(workspace)

    try:
        resolved = resolve_path(path)
    except TraversalError as exc:
        raise CheckpointError(str(exc)) from None

    _reject_symlink(path, "workspace")

    if not resolved.exists():
        raise CheckpointError(f"workspace does not exist: {workspace!r}")
    if not is_directory(resolved):
        raise CheckpointError(f"workspace is not a directory: {workspace!r}")

    reject_workspace_inside_checkpoint(resolved)

    for name in REQUIRED_FILES:
        item = resolved / name
        if not item.exists():
            raise CheckpointError(f"workspace is missing {name}: {workspace!r}")
        if not is_regular_file(item):
            raise CheckpointError(f"workspace item is not a regular file: {item!s}")

    for name in REQUIRED_DIRS:
        item = resolved / name
        if not item.exists():
            raise CheckpointError(f"workspace is missing {name}/: {workspace!r}")
        if not is_directory(item):
            raise CheckpointError(f"workspace item is not a directory: {item!s}")

    return resolved


def validate_destination(destination: str, source: Path) -> Path:
    """Validate the destination and return its absolute path."""
    path = Path(destination)

    try:
        dest = resolve_path(path)
    except TraversalError as exc:
        raise CheckpointError(str(exc)) from None

    _reject_symlink(path, "destination")

    if dest.exists() and not is_directory(dest):
        raise CheckpointError(f"destination is not a directory: {destination!r}")

    source_resolved = source.resolve(strict=True)

    try:
        dest.relative_to(source_resolved)
        raise CheckpointError("destination must not be inside the source workspace")
    except ValueError:
        pass

    try:
        source_resolved.relative_to(dest)
        raise CheckpointError("source workspace must not be inside the destination")
    except ValueError:
        pass

    return dest


def _lstat_mode(item: Path) -> int:
    """Return the st_mode from an lstat call."""
    return os.lstat(item).st_mode


def is_symlink(item: Path) -> bool:
    """Return True if item is a symbolic link."""
    return stat.S_ISLNK(_lstat_mode(item))


def is_regular_file(item: Path) -> bool:
    """Return True if item is a regular file (not a symlink)."""
    return stat.S_ISREG(_lstat_mode(item))


def is_directory(item: Path) -> bool:
    """Return True if item is a directory (not a symlink)."""
    return stat.S_ISDIR(_lstat_mode(item))


def scan_workspace(workspace: Path) -> tuple[list[Path], list[Path]]:
    """Return (files, directories) found under workspace, rejecting symlinks and specials."""
    if not is_directory(workspace):
        raise CheckpointError("snapshot workspace must be a real directory")
    files: list[Path] = []
    dirs: list[Path] = [workspace]

    for root, dirnames, filenames in os.walk(workspace, followlinks=False):
        root_path = Path(root)

        for name in dirnames + filenames:
            item = root_path / name

            if is_symlink(item):
                raise CheckpointError(f"symbolic link is not allowed: {item!s}")

            mode = _lstat_mode(item)
            if stat.S_ISDIR(mode):
                dirs.append(item)
            elif stat.S_ISREG(mode):
                files.append(item)
            else:
                raise CheckpointError(f"special file is not allowed: {item!s}")

    return files, dirs


def build_checkpoint_id(now: datetime) -> str:
    """Generate a checkpoint ID from a UTC datetime with microsecond precision."""
    return now.strftime("CHK-%Y%m%dT%H%M%S%fZ")


def build_timestamp(now: datetime) -> str:
    """Generate the canonical UTC timestamp string."""
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _file_digest(path: Path) -> tuple[int, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise CheckpointError("checkpoint input is not a regular file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = handle.read(min(remaining, 1024 * 1024))
            if not block:
                raise CheckpointError("file shrank while hashing checkpoint")
            digest.update(block)
            remaining -= len(block)
        if handle.read(1):
            raise CheckpointError("file grew while hashing checkpoint")
        after = os.fstat(handle.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise CheckpointError("file changed while creating checkpoint")
    return before.st_size, digest.hexdigest()


def inventory(root: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Describe every retained file and empty directory without following links."""
    files, directories = scan_workspace(root)
    entries: list[dict[str, object]] = []
    for path in sorted(files):
        size, digest = _file_digest(path)
        entries.append({"path": path.relative_to(root).as_posix(), "size_bytes": size, "sha256": digest})
    return entries, sorted(path.relative_to(root).as_posix() for path in directories)


def _copy_file(source: Path, destination: Path) -> None:
    """Copy through regular file descriptors, keeping the copy owner-only."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source_fd, "rb") as reader:
        before = os.fstat(reader.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise CheckpointError("checkpoint input is not a regular file")
        dest_fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
        with os.fdopen(dest_fd, "wb") as writer:
            os.fchmod(writer.fileno(), 0o600)
            remaining = before.st_size
            while remaining:
                block = reader.read(min(remaining, 1024 * 1024))
                if not block:
                    raise CheckpointError("source file shrank while copying")
                writer.write(block)
                remaining -= len(block)
            if reader.read(1):
                raise CheckpointError("source file grew while copying")
            writer.flush()
            os.fsync(writer.fileno())


def copy_workspace(source: Path, target: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Copy a quiescent workspace, rejecting any observed drift or copy corruption."""
    before = inventory(source)
    files, dirs = scan_workspace(source)
    workspace_target = target / "workspace"

    for directory in sorted(dirs):
        relative = directory.relative_to(source)
        (workspace_target / relative).mkdir(mode=0o700, parents=True, exist_ok=True)

    for src_file in sorted(files):
        relative = src_file.relative_to(source)
        dst_file = workspace_target / relative
        _copy_file(src_file, dst_file)

    if inventory(workspace_target) != before or inventory(source) != before:
        raise CheckpointError("workspace changed during checkpoint or copied bytes do not match")
    return before


def atomic_write_json(path: Path, data: dict[str, object]) -> None:
    """Write indented UTF-8 JSON atomically, terminated by one newline."""
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise CheckpointError("checkpoint manifest exceeds the verification size limit")
    artifact_io.publish_file(path, text)


def build_checkpoint_json(
    checkpoint_id: str,
    now: datetime,
    source: Path,
    profile: str,
    unresolved_session_token_count: int,
    contains_ephemeral_session_secrets: bool,
    file_count: int,
    total_bytes: int,
    files: list[dict[str, object]],
    directories: list[str],
) -> dict[str, object]:
    """Build the checkpoint manifest in the required field order."""
    record: dict[str, object] = {}
    record["schema_version"] = "1.2"
    record["checkpoint_id"] = checkpoint_id
    record["timestamp_utc"] = build_timestamp(now)
    record["source_workspace"] = str(source)
    record["operational_profile"] = profile
    record["unresolved_session_token_count"] = unresolved_session_token_count
    record["contains_ephemeral_session_secrets"] = contains_ephemeral_session_secrets
    record["file_count"] = file_count
    record["total_bytes"] = total_bytes
    record["files"] = files
    record["directories"] = directories
    return {key: record[key] for key in FIELD_ORDER}


@contextlib.contextmanager
def _snapshot_guard(source: Path):
    if __package__:
        from . import workspace_transaction
    else:
        import workspace_transaction
    lock = source / ".workspace_mutation.lock"
    descriptor = -1
    try:
        if lock.exists() or lock.is_symlink():
            descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CheckpointError("workspace mutation lock is not a dedicated regular file")
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            current = lock.lstat()
            if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                raise CheckpointError("workspace mutation lock changed during snapshot")
        if workspace_transaction.incomplete(source):
            raise CheckpointError("workspace has unfinished transactions; recover before checkpointing")
        yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def create_checkpoint(source: Path, destination: Path, now: datetime, **options) -> tuple[str, Path, int, int]:
    with _snapshot_guard(source):
        return _create_checkpoint_guarded(source, destination, now, **options)


def _create_checkpoint_guarded(
    source: Path,
    destination: Path,
    now: datetime,
    *,
    profile: str,
    unresolved_session_token_count: int,
    contains_ephemeral_session_secrets: bool,
) -> tuple[str, Path, int, int]:
    """Create a checkpoint snapshot and return its metadata."""
    checkpoint_id = build_checkpoint_id(now)
    checkpoint_dir = destination / checkpoint_id

    if checkpoint_dir.exists() or checkpoint_dir.is_symlink():
        raise CheckpointError(f"checkpoint already exists: {checkpoint_dir!s}")

    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{checkpoint_id}.", dir=destination))
    try:
        files, directories = copy_workspace(source, staging)
        file_count = len(files)
        total_bytes = sum(int(item["size_bytes"]) for item in files)
        manifest = build_checkpoint_json(
            checkpoint_id,
            now,
            source,
            profile,
            unresolved_session_token_count,
            contains_ephemeral_session_secrets,
            file_count,
            total_bytes,
            files,
            directories,
        )
        atomic_write_json(staging / "checkpoint.json", manifest)
        for name in directories:
            descriptor = os.open(staging / "workspace" / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        artifact_io.publish_directory(staging, checkpoint_dir)
    except Exception:
        _remove_tree(staging)
        raise

    return checkpoint_id, checkpoint_dir, file_count, total_bytes


def _remove_tree(path: Path) -> None:
    """Best-effort removal of a directory tree; ignore errors."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CheckpointError("checkpoint manifest contains duplicate JSON keys")
        result[key] = value
    return result


def verify_checkpoint(path: Path) -> dict[str, object]:
    """Verify a schema-1.2 snapshot independently of the live source workspace."""
    root = resolve_path(path)
    if not is_directory(root):
        raise CheckpointError("checkpoint is not a directory")
    if {item.name for item in root.iterdir()} != {"workspace", "checkpoint.json"}:
        raise CheckpointError("checkpoint contains missing or unexpected entries")
    manifest_path = root / "checkpoint.json"
    if not is_regular_file(manifest_path) or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise CheckpointError("checkpoint manifest is not a bounded regular file")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_members)
    except (ValueError, UnicodeError) as exc:
        raise CheckpointError("checkpoint manifest is malformed") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.2":
        raise CheckpointError("checkpoint has no supported per-file integrity manifest (requires 1.2)")
    if (
        set(manifest) != set(FIELD_ORDER) or manifest["checkpoint_id"] != root.name
        or not is_checkpoint_directory_name(root.name)
    ):
        raise CheckpointError("checkpoint manifest identity or fields are inconsistent")
    entries = manifest["files"]
    if not isinstance(entries, list) or any(
        not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}
        or type(item["size_bytes"]) is not int
        for item in entries
    ):
        raise CheckpointError("checkpoint file inventory is malformed")
    files, directories = scan_workspace(root)
    for item in directories:
        if stat.S_IMODE(item.stat().st_mode) != 0o700:
            raise CheckpointError("checkpoint directories must have mode 0700")
    for item in files:
        if stat.S_IMODE(item.stat().st_mode) != 0o600:
            raise CheckpointError("checkpoint files must have mode 0600")
    actual_files, actual_directories = inventory(root / "workspace")
    if (
        manifest["files"] != actual_files or manifest["directories"] != actual_directories
        or type(manifest["file_count"]) is not int or manifest["file_count"] != len(actual_files)
        or type(manifest["total_bytes"]) is not int
        or manifest["total_bytes"] != sum(int(item["size_bytes"]) for item in actual_files)
    ):
        raise CheckpointError("checkpoint integrity validation failed: inventory, size or SHA-256 mismatch")
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Create a timestamped local snapshot of an existing private workspace."
    )
    parser.add_argument(
        "--workspace", help="explicit private workspace directory"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--destination", help="destination directory for the checkpoint"
    )
    mode.add_argument("--verify", help="verify an existing schema-1.2 checkpoint without restoring it")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    if now is None:
        now = datetime.now(UTC)

    try:
        if args.verify is not None:
            manifest = verify_checkpoint(Path(args.verify))
            print(f"verified: {manifest['checkpoint_id']}")
            print(f"files: {manifest['file_count']}")
            return 0
        if args.workspace is None:
            raise CheckpointError("--workspace is required when creating a checkpoint")
        source = validate_workspace(args.workspace)
        profile = operational_profile.workspace_profile(source)
        token_state = closure_readiness(source)
        if token_state.blockers:
            raise CheckpointError(
                "unresolved session tokens block checkpoint: "
                + ",".join(token_state.blockers)
            )
        destination = validate_destination(args.destination, source)
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        checkpoint_id, checkpoint_dir, file_count, total_bytes = create_checkpoint(
            source,
            destination,
            now,
            profile=profile,
            unresolved_session_token_count=len(token_state.blockers),
            contains_ephemeral_session_secrets=token_state.active_secret_files > 0,
        )
    except CheckpointError as exc:
        fatal(str(exc))
    except TokenLifecycleError as exc:
        fatal(str(exc))
    except operational_profile.OperationalProfileError as exc:
        fatal(str(exc))
    except Exception as exc:  # noqa: BLE001 - defensive top-level handler
        fatal(f"unexpected error: {exc}")

    print(checkpoint_id)
    print(checkpoint_dir)
    print(f"files: {file_count}")
    print(f"bytes: {total_bytes}")
    print(f"operational_profile: {profile}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
