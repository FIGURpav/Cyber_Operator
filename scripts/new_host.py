"""Initialize a private Cyber-Operator workspace and create host records."""

import argparse
import errno
import ipaddress
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from . import host_identity
else:
    import host_identity  # type: ignore[no-redef]

HOST_ID_PATTERN = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
HOSTNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)
COMMON_DIRECTORY_NAMES = (
    "hosts",
    "inbox",
    "evidence",
    "execution_runs",
    "report",
    "queries",
    "checkpoints",
)
SCREENSHOT_DIRECTORY_PATHS = (
    Path("inbox/screenshots"),
    Path("inbox/screenshots/pending"),
    Path("inbox/screenshots/processed"),
    Path("inbox/screenshots/invalid"),
)
PRIVATE_DIRECTORY_PATHS = (
    Path("private"),
    Path("private/local_processing"),
)
COMMON_FILE_NAMES = (
    "global.md",
    "loot.jsonl",
    "attempts.jsonl",
    "observations.jsonl",
    "findings.jsonl",
    "work_items.jsonl",
    "local_artifacts.jsonl",
    "workspace_lifecycle.jsonl",
    "host_aliases.jsonl",
    "host_merges.jsonl",
    "standing_authorizations.jsonl",
    "plaintext_report_policy.jsonl",
    "plaintext_report_exports.jsonl",
    "authorizations.jsonl",
    "changes.jsonl",
    "attack_paths.jsonl",
    "report_steps.jsonl",
    "execution_runs.jsonl",
    "claims.jsonl",
    "screenshot_requests.jsonl",
)


class WorkspaceLayoutError(ValueError):
    """A deterministic workspace path or type validation failure."""


@dataclass(frozen=True)
class FileWrite:
    """One fully prepared canonical text-file write."""

    path: Path
    content: str


@dataclass(frozen=True)
class BootstrapPlan:
    """A read-only prepared set of bootstrap mutations."""

    directories: tuple[Path, ...]
    files: tuple[FileWrite, ...]


@dataclass(frozen=True)
class CreatedPath:
    """Identity of one path created by the active transaction."""

    path: Path
    device: int
    inode: int
    is_directory: bool


class CreationTracker:
    """Track exact filesystem objects created by one apply operation."""

    def __init__(self) -> None:
        self.created: list[CreatedPath] = []

    def record(self, path: Path, metadata: os.stat_result | None = None) -> None:
        """Record the post-creation identity of a regular file or directory."""
        metadata = metadata or path.lstat()
        is_directory = stat.S_ISDIR(metadata.st_mode)
        if not is_directory and not stat.S_ISREG(metadata.st_mode):
            raise OSError("created path has an unexpected filesystem type")
        self.created.append(
            CreatedPath(path, metadata.st_dev, metadata.st_ino, is_directory)
        )


def fatal(message: str) -> None:
    """Print an error and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def validate_host_id(host_id: str) -> None:
    """Validate a canonical Hxx host ID, allowing growth beyond H99."""
    if not host_id:
        fatal("host ID is required")
    if HOST_ID_PATTERN.fullmatch(host_id) is None:
        fatal(
            "invalid host ID; expected canonical Hxx form, e.g. H01 or H100, "
            f"got {host_id!r}"
        )


def validate_ip(ip: str | None) -> str:
    """Validate an IPv4 or IPv6 address; return 'unknown' when omitted."""
    if ip is None:
        return "unknown"
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        fatal(f"invalid IP address: {ip!r} ({exc})")
    return ip


def validate_hostname(hostname: str | None) -> str:
    """Validate a DNS-like hostname; return 'unknown' when omitted."""
    if hostname is None:
        return "unknown"
    if len(hostname) > 253:
        fatal(f"hostname too long: {hostname!r}")
    if HOSTNAME_PATTERN.fullmatch(hostname) is None:
        fatal(f"invalid hostname: {hostname!r}")
    return hostname


def _lexists(path: Path) -> bool:
    """Return whether a path entry exists without following a final symlink."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _missing_directory_chain(path: Path) -> list[Path]:
    """Return missing directories from the nearest existing parent downward."""
    missing: list[Path] = []
    current = path
    while not _lexists(current):
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    missing.reverse()
    return missing


def validate_workspace_path(workspace: Path) -> None:
    """Validate every existing workspace component without following symlinks."""
    absolute = workspace.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise WorkspaceLayoutError(
                "workspace path components must be real non-symlink directories"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceLayoutError("workspace path components must be directories")


def validate_workspace_layout(workspace: Path) -> None:
    """Read-only validation of every existing canonical common workspace path."""
    validate_workspace_path(workspace)
    if not _lexists(workspace):
        return

    for name in COMMON_DIRECTORY_NAMES:
        path = workspace / name
        if not _lexists(path):
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceLayoutError(
                f"workspace {name} path must be a real non-symlink directory"
            )

    for relative in SCREENSHOT_DIRECTORY_PATHS:
        path = workspace / relative
        if not _lexists(path):
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceLayoutError(
                f"workspace {relative} path must be a real non-symlink directory"
            )

    for relative in PRIVATE_DIRECTORY_PATHS:
        path = workspace / relative
        if not _lexists(path):
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceLayoutError(
                f"workspace {relative} path must be a real non-symlink directory"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise WorkspaceLayoutError(
                f"workspace {relative} path must use private mode 0700"
            )

    for name in COMMON_FILE_NAMES:
        path = workspace / name
        if not _lexists(path):
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise WorkspaceLayoutError(
                f"workspace {name} path must be a real non-symlink regular file"
            )

    screenshot_index = workspace / "report" / "SCREENSHOT_INDEX.md"
    if _lexists(screenshot_index):
        metadata = screenshot_index.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise WorkspaceLayoutError(
                "workspace screenshot index must be a real non-symlink regular file"
            )


def validate_workspace(workspace: str) -> Path:
    """Return a safe, absolute workspace path or exit on misuse."""
    path = Path(workspace)
    if ".." in path.parts:
        fatal(f"workspace path must not contain '..': {workspace!r}")
    absolute = path if path.is_absolute() else Path.cwd() / path
    if _lexists(absolute):
        metadata = absolute.lstat()
        if stat.S_ISREG(metadata.st_mode):
            fatal(f"workspace path is an existing file: {workspace!r}")
    try:
        validate_workspace_path(absolute)
    except WorkspaceLayoutError as exc:
        fatal(str(exc))
    return absolute


def ensure_host_paths_contained(workspace: Path, host_id: str) -> Path:
    """Return the host directory and verify it stays inside the workspace."""
    host_root = workspace / "hosts" / host_id
    try:
        host_root.relative_to(workspace)
    except ValueError as exc:
        raise WorkspaceLayoutError("host path would escape workspace") from exc
    return host_root


def build_host_paths(workspace: Path, host_id: str) -> dict[str, Path]:
    """Return all paths that will be created for a host."""
    if _lexists(workspace / "hosts"):
        try:
            current = host_identity.host_paths(workspace, host_id)
        except host_identity.HostIdentityError:
            pass
        else:
            return {
                "host_state": current.state,
                "host_report": current.report,
                "host_inbox": current.inbox,
                "host_evidence": current.evidence,
            }
    return {
        "host_state": workspace / "hosts" / f"{host_id}.md",
        "host_report": workspace / "report" / f"{host_id}.md",
        "host_inbox": workspace / "inbox" / host_id,
        "host_evidence": workspace / "evidence" / host_id,
    }


def render_template(template_path: Path, host_id: str, ip: str, hostname: str) -> str:
    """Render a Markdown template using safe string replacement."""
    text = template_path.read_text(encoding="utf-8")
    return (
        text.replace("{{HOST_ID}}", host_id)
        .replace("{{IP_ADDRESS}}", ip)
        .replace("{{HOSTNAME}}", hostname)
    )


def _fsync_file(descriptor: int) -> None:
    """Flush a regular file where the local filesystem supports fsync."""
    try:
        os.fsync(descriptor)
    except OSError as exc:
        unsupported = {errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)}
        if exc.errno not in unsupported:
            raise


def atomic_write_text(
    path: Path,
    content: str,
    tracker: CreationTracker | None = None,
) -> None:
    """Securely create one complete canonical text file without overwriting."""
    if _lexists(path):
        raise FileExistsError(f"destination already exists: {path}")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=False,
    )
    temporary_path: Path | None = Path(temporary_name)
    temporary_metadata: os.stat_result | None = None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content.encode("utf-8"))
            handle.flush()
            _fsync_file(handle.fileno())
            temporary_metadata = os.fstat(handle.fileno())

        if _lexists(path):
            raise FileExistsError(f"destination already exists: {path}")
        if tracker is not None:
            tracker.record(path, temporary_metadata)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def prepare_bootstrap(
    workspace: Path,
    script_dir: Path,
    hosts: tuple[tuple[str, str, str], ...],
) -> BootstrapPlan:
    """Validate and render all bootstrap work without mutating the workspace."""
    validate_workspace_layout(workspace)
    directories: list[Path] = []
    files: list[FileWrite] = []

    directories.extend(_missing_directory_chain(workspace))
    for name in COMMON_DIRECTORY_NAMES:
        directory = workspace / name
        if not _lexists(directory):
            directories.append(directory)
    for relative in SCREENSHOT_DIRECTORY_PATHS:
        directory = workspace / relative
        if not _lexists(directory):
            directories.append(directory)
    global_path = workspace / "global.md"
    if not _lexists(global_path):
        global_template = script_dir.parent / "templates" / "global.md"
        files.append(
            FileWrite(
                global_path,
                render_template(global_template, "unknown", "unknown", "unknown"),
            )
        )
    for ledger_name in COMMON_FILE_NAMES[1:]:
        ledger_path = workspace / ledger_name
        if not _lexists(ledger_path):
            files.append(FileWrite(ledger_path, ""))

    screenshot_index = workspace / "report" / "SCREENSHOT_INDEX.md"
    if not _lexists(screenshot_index):
        files.append(
            FileWrite(
                screenshot_index,
                "# Screenshot Evidence Index\n\n"
                "Generated from the append-only screenshot request ledger.\n\n"
                "No screenshot requests recorded.\n",
            )
        )

    host_template = script_dir.parent / "templates" / "host.md"
    report_template = script_dir.parent / "templates" / "report-host.md"
    planned_paths: set[Path] = set()
    for host_id, ip, hostname in hosts:
        ensure_host_paths_contained(workspace, host_id)
        paths = build_host_paths(workspace, host_id)
        execution_path = workspace / "execution_runs" / host_id
        for path in (*paths.values(), execution_path):
            if path in planned_paths:
                raise FileExistsError("duplicate planned host destination")
            planned_paths.add(path)
            if _lexists(path):
                raise FileExistsError(f"host {host_id} already exists: {path}")
        files.extend(
            (
                FileWrite(
                    paths["host_state"],
                    render_template(host_template, host_id, ip, hostname),
                ),
                FileWrite(
                    paths["host_report"],
                    render_template(report_template, host_id, ip, hostname),
                ),
            )
        )
        directories.extend(
            (paths["host_inbox"], paths["host_evidence"], execution_path)
        )

    return BootstrapPlan(tuple(directories), tuple(files))


def apply_bootstrap_plan(
    plan: BootstrapPlan,
    tracker: CreationTracker | None = None,
) -> list[str]:
    """Apply one prepared bootstrap plan and return the exact created paths."""
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    for destination in (*plan.directories, *(item.path for item in plan.files)):
        restore_checkpoint.require_path_instance(destination)
    active_tracker = tracker or CreationTracker()
    start = len(active_tracker.created)
    for directory in plan.directories:
        if _lexists(directory):
            owned = any(created.path == directory for created in active_tracker.created)
            if owned:
                continue
            raise FileExistsError(f"planned directory already exists: {directory}")
        directory.mkdir(mode=0o700)
        try:
            active_tracker.record(directory)
        except BaseException:
            try:
                directory.rmdir()
            except OSError:
                pass
            raise

    for write in plan.files:
        atomic_write_text(write.path, write.content, active_tracker)

    return [str(item.path) for item in active_tracker.created[start:]]


def rollback_created(tracker: CreationTracker) -> None:
    """Best-effort removal of unchanged objects created by this transaction."""
    for created in reversed(tracker.created):
        try:
            metadata = created.path.lstat()
        except OSError:
            continue
        if metadata.st_dev != created.device or metadata.st_ino != created.inode:
            continue
        try:
            if created.is_directory and stat.S_ISDIR(metadata.st_mode):
                created.path.rmdir()
            elif not created.is_directory and stat.S_ISREG(metadata.st_mode):
                created.path.unlink()
        except OSError:
            continue


def initialize_workspace(workspace: Path, script_dir: Path) -> list[str]:
    """Create only missing common workspace state after read-only preflight."""
    plan = prepare_bootstrap(workspace, script_dir, ())
    tracker = CreationTracker()
    try:
        return apply_bootstrap_plan(plan, tracker)
    except BaseException:
        rollback_created(tracker)
        raise


def create_host(
    workspace: Path,
    script_dir: Path,
    host_id: str,
    ip: str,
    hostname: str,
) -> list[str]:
    """Create one host plus any missing common workspace state."""
    return bootstrap_host(workspace, script_dir, host_id, ip, hostname)


def bootstrap_host(
    workspace: Path,
    script_dir: Path,
    host_id: str,
    ip: str,
    hostname: str,
) -> list[str]:
    """Prepare and atomically-as-practical create one canonical host."""
    plan = prepare_bootstrap(workspace, script_dir, ((host_id, ip, hostname),))
    tracker = CreationTracker()
    try:
        return apply_bootstrap_plan(plan, tracker)
    except BaseException:
        rollback_created(tracker)
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Initialize a private Cyber-Operator workspace and create one host record."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="explicit private workspace directory",
    )
    parser.add_argument("--host-id", required=True, help="host identifier, e.g. H01")
    parser.add_argument("--ip", default=None, help="IPv4 or IPv6 address")
    parser.add_argument("--hostname", default=None, help="DNS-like hostname")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    validate_host_id(args.host_id)
    ip = validate_ip(args.ip)
    hostname = validate_hostname(args.hostname)
    workspace = validate_workspace(args.workspace)
    script_dir = Path(__file__).resolve().parent

    try:
        created = bootstrap_host(workspace, script_dir, args.host_id, ip, hostname)
    except (FileExistsError, WorkspaceLayoutError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    workspace_str = str(workspace)
    print(f"Initialized workspace: {workspace_str}")
    print(f"Created host {args.host_id}:")
    for item in created:
        if item.startswith(workspace_str):
            display = item[len(workspace_str) :].lstrip("/") or "."
        else:
            display = item
        print(f"  {display}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
