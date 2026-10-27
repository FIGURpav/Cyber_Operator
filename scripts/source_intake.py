#!/usr/bin/env python3
"""Safely route untrusted lab source material across Cyber-Operator trust boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from . import artifact_handling, runtime_config
else:
    import artifact_handling  # type: ignore[no-redef]
    import runtime_config

DEFAULT_RW_ROOT = runtime_config.source_root(readonly=False)
DEFAULT_RO_ROOT = runtime_config.source_root()
DEFAULT_TASK_ROOT = runtime_config.workspace_root()
LAB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SENSITIVE_NAMES = re.compile(
    r"(^|[._-])(credential|credentials|password|passwd|secret|token|api[_-]?key|id_rsa)([._-]|$)",
    re.IGNORECASE,
)
SENSITIVE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
SENSITIVE_ASSIGNMENT = re.compile(
    rb"(?im)^\s*(password|passwd|secret|token|api[_-]?key)\s*[:=]"
)
TASK_SOURCE_DESTINATION = Path("inbox/source")
MAX_TASK_SOURCE_FILES = 10_000
MAX_TASK_SOURCE_BYTES = 1024 * 1024 * 1024


class IntakeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Item:
    path: Path
    relative: Path
    kind: str
    size: int


@dataclass(frozen=True)
class AddPlan:
    lab: str
    rw_root: Path
    source: Path
    destination: Path
    ro_destination: Path
    items: tuple[Item, ...]
    digest: str
    size: int
    sensitive_hits: tuple[str, ...]
    source_kind: str | None = None
    origin: str | None = None
    assessment_reference: str | None = None


@dataclass(frozen=True)
class TaskBootstrapPlan:
    """One bounded RO-source to private-task-workspace import plan."""

    source_task: Path
    source: Path
    task_root: Path
    destination: Path
    items: tuple[Item, ...]
    digest: str
    size: int
    sensitive_hits: tuple[str, ...]
    existing_match: bool
    artifact_handling: str


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _safe_relative(value: str) -> Path:
    rel = Path(value)
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        raise IntakeError("--dest must be a non-empty relative path without '.' or '..'")
    return rel


def _reject_symlink_ancestors(path: Path, stop: Path) -> None:
    """Reject an existing symlink from stop through path's parent."""
    current = path.parent
    while True:
        if current.exists() and current.is_symlink():
            raise IntakeError(f"destination ancestor is a symlink: {current}")
        if current == stop:
            return
        if current.parent == current or not _inside(current, stop):
            raise IntakeError("destination ancestor escapes CYBER_SOURCE_RW")
        current = current.parent


def inspect_source(source: Path) -> tuple[Item, ...]:
    if source.is_symlink():
        raise IntakeError(f"symlinks are not accepted: {source}")
    try:
        source_stat = source.lstat()
    except FileNotFoundError as exc:
        raise IntakeError(f"source does not exist: {source}") from exc

    if stat.S_ISREG(source_stat.st_mode):
        return (Item(source, Path("."), "file", source_stat.st_size),)
    if not stat.S_ISDIR(source_stat.st_mode):
        raise IntakeError(f"source must be a regular file or directory: {source}")

    items: list[Item] = [Item(source, Path("."), "directory", 0)]
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in sorted(dirs):
            path = root_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise IntakeError(f"symlinks are not accepted: {path}")
            if not stat.S_ISDIR(info.st_mode):
                raise IntakeError(f"special filesystem entry is not accepted: {path}")
            items.append(Item(path, path.relative_to(source), "directory", 0))
        for name in sorted(files):
            path = root_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise IntakeError(f"symlinks are not accepted: {path}")
            if not stat.S_ISREG(info.st_mode):
                raise IntakeError(f"special filesystem entry is not accepted: {path}")
            items.append(Item(path, path.relative_to(source), "file", info.st_size))
    return tuple(items)


def tree_digest(source: Path, items: tuple[Item, ...]) -> str:
    digest = hashlib.sha256()
    for item in sorted(items, key=lambda entry: entry.relative.as_posix()):
        rel = item.relative.as_posix().encode("utf-8", "surrogateescape")
        digest.update(item.kind.encode("ascii") + b"\0" + rel + b"\0")
        if item.kind == "file":
            with item.path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def sensitive_hits(items: tuple[Item, ...]) -> tuple[str, ...]:
    hits: set[str] = set()
    for item in items:
        if item.kind != "file":
            continue
        rel = item.relative.as_posix()
        if SENSITIVE_NAMES.search(item.path.name):
            hits.add(f"sensitive filename: {rel}")
        if item.size <= 2 * 1024 * 1024:
            try:
                with item.path.open("rb") as handle:
                    prefix = handle.read(2 * 1024 * 1024)
            except OSError:
                continue
            if any(marker in prefix for marker in SENSITIVE_MARKERS):
                hits.add(f"private-key marker: {rel}")
            if SENSITIVE_ASSIGNMENT.search(prefix):
                hits.add(f"possible secret assignment: {rel}")
    return tuple(sorted(hits))


def _validate_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise IntakeError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise IntakeError(f"{label} must be a real non-symlink directory: {path}")


def _validate_relative_chain(root: Path, relative: Path, label: str) -> Path:
    """Resolve an existing relative chain without accepting symlinks."""
    current = root
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise IntakeError(f"{label} does not exist: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise IntakeError(f"{label} contains a symlink: {current}")
    return current


def _validate_task_workspace(task_root: Path) -> None:
    _validate_real_directory(task_root, "task workspace")
    context = task_root / "TASK_CONTEXT.md"
    try:
        context_metadata = context.lstat()
    except FileNotFoundError as exc:
        raise IntakeError(f"task workspace is missing TASK_CONTEXT.md: {context}") from exc
    if stat.S_ISLNK(context_metadata.st_mode) or not stat.S_ISREG(context_metadata.st_mode):
        raise IntakeError("TASK_CONTEXT.md must be a real non-symlink regular file")
    inbox = task_root / "inbox"
    _validate_real_directory(inbox, "task workspace inbox")


def resolve_task_workspace(task_root: Path) -> Path:
    """Resolve either one canonical workspace or a collection ACTIVE_TASK child."""
    task_root = task_root.expanduser().absolute()
    if _lexists(task_root / "TASK_CONTEXT.md"):
        _validate_task_workspace(task_root)
        return task_root

    _validate_real_directory(task_root, "task collection")
    marker = task_root / "ACTIVE_TASK"
    try:
        marker_metadata = marker.lstat()
    except FileNotFoundError as exc:
        raise IntakeError(
            "task root has neither TASK_CONTEXT.md nor ACTIVE_TASK"
        ) from exc
    if stat.S_ISLNK(marker_metadata.st_mode) or not stat.S_ISREG(
        marker_metadata.st_mode
    ):
        raise IntakeError("ACTIVE_TASK must be a real regular file")
    if marker_metadata.st_size > 256:
        raise IntakeError("ACTIVE_TASK is unexpectedly large")
    try:
        active_value = marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise IntakeError("ACTIVE_TASK is unreadable") from exc
    active = _safe_relative(active_value)
    if len(active.parts) != 1:
        raise IntakeError("ACTIVE_TASK must name one direct module workspace")
    workspace = task_root / active
    _validate_task_workspace(workspace)
    return workspace


def _validate_destination_ancestors(destination: Path, task_root: Path) -> None:
    current = destination.parent
    while current != task_root:
        if _lexists(current):
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise IntakeError(
                    f"task destination ancestor must be a real directory: {current}"
                )
        if current.parent == current or not _inside(current, task_root):
            raise IntakeError("task destination escapes CYBER_WORKSPACE_ROOT")
        current = current.parent


def build_task_bootstrap_plan(
    *, source_task_value: str, ro_root: Path, task_root: Path,
) -> TaskBootstrapPlan:
    """Build a read-only plan for one explicit task subtree."""
    source_task = _safe_relative(source_task_value)
    if len(source_task.parts) != 1:
        raise IntakeError("--source-task must name one direct child of the RO root")
    ro_root = ro_root.expanduser().absolute()
    task_root = resolve_task_workspace(task_root)
    try:
        artifact_mode = artifact_handling.workspace_mode(task_root)
    except artifact_handling.ArtifactHandlingError as exc:
        raise IntakeError(str(exc)) from exc
    _validate_real_directory(ro_root, "active lab source root")

    source = _validate_relative_chain(ro_root, source_task, "task source")
    source_metadata = source.lstat()
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise IntakeError("task source must be a directory")

    items = inspect_source(source)
    file_count = sum(item.kind == "file" for item in items)
    size = sum(item.size for item in items)
    if file_count > MAX_TASK_SOURCE_FILES:
        raise IntakeError(
            f"task source exceeds file limit ({file_count} > {MAX_TASK_SOURCE_FILES})"
        )
    if size > MAX_TASK_SOURCE_BYTES:
        raise IntakeError(
            f"task source exceeds byte limit ({size} > {MAX_TASK_SOURCE_BYTES})"
        )

    destination = task_root / TASK_SOURCE_DESTINATION / source_task
    if not _inside(destination, task_root / TASK_SOURCE_DESTINATION):
        raise IntakeError("task source destination escapes inbox/source")
    _validate_destination_ancestors(destination, task_root)

    digest = tree_digest(source, items)
    existing_match = False
    if _lexists(destination):
        destination_metadata = destination.lstat()
        if stat.S_ISLNK(destination_metadata.st_mode) or not stat.S_ISDIR(
            destination_metadata.st_mode
        ):
            raise IntakeError("existing task source destination is not a real directory")
        existing_items = inspect_source(destination)
        if tree_digest(destination, existing_items) != digest:
            raise IntakeError(
                "task source destination already exists with different content; "
                "no overwrite is allowed"
            )
        existing_match = True

    return TaskBootstrapPlan(
        source_task=source_task,
        source=source,
        task_root=task_root,
        destination=destination,
        items=items,
        digest=digest,
        size=size,
        sensitive_hits=sensitive_hits(items),
        existing_match=existing_match,
        artifact_handling=artifact_mode,
    )


def build_plan(
    *, lab: str, source_value: str, dest_value: str | None,
    rw_root: Path, ro_root: Path, source_kind: str | None = None,
    origin: str | None = None, assessment_reference: str | None = None,
) -> AddPlan:
    if source_kind is not None and source_kind not in {'application-code','documentation','specification','operator-output'}:
        raise IntakeError('unsupported source kind')
    if origin is not None and origin not in {'preexisting-nontarget','operator-generated'}:
        raise IntakeError('target files require origin-aware assessment evidence intake, not the source collection')
    if (source_kind is None)!=(origin is None):
        raise IntakeError('source kind and origin must be supplied together')
    if assessment_reference is not None and (not isinstance(assessment_reference,str) or not assessment_reference.strip() or len(assessment_reference)>512 or any(ord(c)<32 for c in assessment_reference)):
        raise IntakeError('assessment reference must be bounded printable text')
    if not LAB_RE.fullmatch(lab):
        raise IntakeError("invalid assessment source name; use letters, digits, '.', '_' or '-'")
    source = Path(source_value).expanduser().resolve(strict=False)
    rw_root = rw_root.expanduser().resolve(strict=False)
    ro_root = ro_root.expanduser().resolve(strict=False)
    if source == rw_root or _inside(source, rw_root):
        raise IntakeError("source is already inside CYBER_SOURCE_RW; refusing recursive/self import")
    if _inside(rw_root, source):
        raise IntakeError("source contains CYBER_SOURCE_RW; refusing recursive import")

    items = inspect_source(source)
    destination_name = _safe_relative(dest_value) if dest_value else Path(source.name)
    destination = rw_root / lab / destination_name
    ro_destination = ro_root / lab / destination_name
    if not _inside(destination, rw_root / lab):
        raise IntakeError("destination escapes the selected lab")
    if destination.exists() or destination.is_symlink():
        raise IntakeError(f"destination already exists; no overwrite is allowed: {destination}")
    _reject_symlink_ancestors(destination, rw_root)
    return AddPlan(
        lab=lab,
        rw_root=rw_root,
        source=source,
        destination=destination,
        ro_destination=ro_destination,
        items=items,
        digest=tree_digest(source, items),
        size=sum(item.size for item in items),
        sensitive_hits=sensitive_hits(items),
        source_kind=source_kind,origin=origin,assessment_reference=assessment_reference,
    )


def check_ro_mount(ro_root: Path, rw_root: Path) -> None:
    result = subprocess.run(
        ["findmnt", "-n", "-o", "TARGET,FSROOT,OPTIONS", "-T", str(ro_root)],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise IntakeError(f"cannot verify RO mount with findmnt: {result.stderr.strip()}")
    fields = result.stdout.strip().split(maxsplit=2)
    if len(fields) != 3 or Path(fields[0]) != ro_root:
        raise IntakeError(f"RO path is not the mount target: {ro_root}")
    mounted_fsroot = Path(fields[1]).resolve(strict=False)
    if mounted_fsroot != rw_root.resolve(strict=False):
        raise IntakeError(
            f"RO view exposes {mounted_fsroot}, expected the full RW root {rw_root}; "
            "fix the bind mount before importing"
        )
    options = set(fields[2].split(","))
    if "ro" not in options:
        raise IntakeError(f"source view is not read-only: {ro_root}")


def apply_plan(plan: AddPlan, *, task_root: Path, ro_root: Path) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(task_root)
    if plan.sensitive_hits:
        formatted = "\n  - ".join(plan.sensitive_hits)
        raise IntakeError(
            "possible credentials/private key detected; route them through private credential intake "
            f"or inspect manually:\n  - {formatted}"
        )
    check_ro_mount(ro_root, plan.rw_root)
    lab_root = plan.destination.parent
    lab_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    temp_parent = Path(tempfile.mkdtemp(prefix=".cyber-source-", dir=lab_root))
    staged = temp_parent / plan.destination.name
    try:
        if plan.source.is_dir():
            shutil.copytree(plan.source, staged, symlinks=False, copy_function=shutil.copy2)
        else:
            shutil.copy2(plan.source, staged)
        staged_items = inspect_source(staged)
        staged_digest = tree_digest(staged, staged_items)
        if staged_digest != plan.digest:
            raise IntakeError("copied data failed SHA-256 verification")
        staged.rename(plan.destination)
    finally:
        shutil.rmtree(temp_parent, ignore_errors=True)

    if not plan.ro_destination.exists():
        raise IntakeError(
            "copy succeeded in RW source store, but it is not visible through the RO view; "
            "verify that CYBER_SOURCE_RO bind-mounts the full CYBER_SOURCE_RW root"
        )
    visible_items = inspect_source(plan.ro_destination)
    if tree_digest(plan.ro_destination, visible_items) != plan.digest:
        raise IntakeError("RO view content does not match the imported source")

    manifest_dir = task_root.expanduser() / "intake"
    manifest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = manifest_dir / "source_manifest.jsonl"
    record = {
        "schema": 1,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "action": "source_add",
        "lab": plan.lab,
        "source": str(plan.source),
        "destination_rw": str(plan.destination),
        "destination_ro": str(plan.ro_destination),
        "sha256_tree": plan.digest,
        "bytes": plan.size,
        "file_count": sum(item.kind == "file" for item in plan.items),
    }
    if plan.source_kind is not None:
        record.update(schema=2,assessment=plan.lab,source_kind=plan.source_kind,origin=plan.origin,
                      assessment_reference=plan.assessment_reference,destination_policy='verified-source-store-with-readonly-view')
    descriptor = os.open(manifest, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _copy_private_file(source: Path, destination: Path, expected_size: int) -> None:
    """Copy one verified regular file into a mode-0600 destination."""
    source_descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    destination_descriptor: int | None = None
    try:
        source_metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_metadata.st_mode):
            raise IntakeError(f"source changed type during copy: {source}")
        if source_metadata.st_size != expected_size:
            raise IntakeError(f"source changed size during copy: {source}")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _append_task_manifest(
    plan: TaskBootstrapPlan,
    *,
    source_origin_attested: bool,
) -> bool:
    manifest_dir = plan.task_root / "intake"
    if _lexists(manifest_dir):
        _validate_real_directory(manifest_dir, "task intake directory")
    else:
        manifest_dir.mkdir(mode=0o700)
    os.chmod(manifest_dir, 0o700)

    manifest = manifest_dir / "source_manifest.jsonl"
    if _lexists(manifest):
        metadata = manifest.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise IntakeError("source manifest must be a real regular file")
        try:
            existing_records = [
                json.loads(line)
                for line in manifest.read_text(encoding="utf-8").splitlines()
                if line
            ]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntakeError("source manifest is unreadable or malformed") from exc
        for existing in existing_records:
            if (
                existing.get("action") == "task_source_bootstrap"
                and existing.get("source_task") == plan.source_task.as_posix()
                and existing.get("destination")
                == plan.destination.relative_to(plan.task_root).as_posix()
                and existing.get("sha256_tree") == plan.digest
                and (
                    plan.artifact_handling != artifact_handling.NO_DOWNLOAD
                    or existing.get("source_origin_attested") is True
                )
            ):
                return False
    record = {
        "schema": 1,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "action": "task_source_bootstrap",
        "source_task": plan.source_task.as_posix(),
        "destination": plan.destination.relative_to(plan.task_root).as_posix(),
        "sha256_tree": plan.digest,
        "bytes": plan.size,
        "file_count": sum(item.kind == "file" for item in plan.items),
        "source_origin_attested": source_origin_attested,
    }
    descriptor = os.open(
        manifest,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    try:
        payload = (
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(manifest, 0o600)
    return True


def apply_task_bootstrap(
    plan: TaskBootstrapPlan,
    *,
    attest_preexisting_nontarget_source: bool = False,
) -> str:
    """Copy and verify one explicit RO task tree into the private workspace."""
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(plan.task_root)
    try:
        current_artifact_handling = artifact_handling.workspace_mode(plan.task_root)
    except artifact_handling.ArtifactHandlingError as exc:
        raise IntakeError(str(exc)) from exc
    if current_artifact_handling != plan.artifact_handling:
        raise IntakeError(
            "artifact handling changed after preview; build a new plan"
        )
    if (
        plan.artifact_handling == artifact_handling.NO_DOWNLOAD
        and not attest_preexisting_nontarget_source
    ):
        raise IntakeError(
            "no-download source bootstrap requires "
            "--attest-preexisting-nontarget-source"
        )
    if plan.sensitive_hits:
        formatted = "\n  - ".join(plan.sensitive_hits)
        raise IntakeError(
            "possible credential/private key detected; route it through private "
            f"credential intake before task bootstrap:\n  - {formatted}"
        )
    current_items = inspect_source(plan.source)
    if tree_digest(plan.source, current_items) != plan.digest:
        raise IntakeError("task source changed after preview; build a new plan")
    if plan.existing_match:
        destination_items = inspect_source(plan.destination)
        if tree_digest(plan.destination, destination_items) != plan.digest:
            raise IntakeError(
                "task source destination changed after preview; build a new plan"
            )
        return (
            "recorded"
            if _append_task_manifest(
                plan,
                source_origin_attested=attest_preexisting_nontarget_source,
            )
            else "existing"
        )

    destination_parent = plan.destination.parent
    destination_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_destination_ancestors(plan.destination, plan.task_root)
    os.chmod(plan.task_root / "inbox" / "source", 0o700)

    temporary_root = Path(
        tempfile.mkdtemp(prefix=".task-source-", dir=destination_parent)
    )
    staged = temporary_root / plan.destination.name
    staged.mkdir(mode=0o700)
    try:
        for item in sorted(plan.items, key=lambda entry: entry.relative.as_posix()):
            if item.relative == Path("."):
                continue
            staged_path = staged / item.relative
            if item.kind == "directory":
                staged_path.mkdir(mode=0o700)
            else:
                _copy_private_file(item.path, staged_path, item.size)

        staged_items = inspect_source(staged)
        if tree_digest(staged, staged_items) != plan.digest:
            raise IntakeError("private task copy failed SHA-256 tree verification")
        if _lexists(plan.destination):
            raise IntakeError("task source destination appeared during apply")
        staged.rename(plan.destination)
        _append_task_manifest(
            plan,
            source_origin_attested=attest_preexisting_nontarget_source,
        )
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    return "copied"


def print_plan(plan: AddPlan, *, apply: bool) -> None:
    print("Cyber-Operator source intake")
    print(f"  mode:        {'APPLY' if apply else 'PREVIEW'}")
    print(f"  assessment:  {plan.lab}")
    if plan.source_kind is not None:
        print(f"  source kind: {plan.source_kind}; origin: {plan.origin}")
        print(f"  reference:   {plan.assessment_reference or '(none)'}")
    print(f"  source:      {plan.source}")
    print(f"  destination: {plan.destination}")
    print(f"  RO view:     {plan.ro_destination}")
    print(f"  files:       {sum(item.kind == 'file' for item in plan.items)}")
    print(f"  bytes:       {plan.size}")
    print(f"  SHA-256:     {plan.digest}")
    if plan.sensitive_hits:
        print("  WARNING: possible sensitive material detected")
        for hit in plan.sensitive_hits:
            print(f"    - {hit}")


def print_task_bootstrap_plan(
    plan: TaskBootstrapPlan,
    *,
    apply: bool,
    source_origin_attested: bool,
) -> None:
    print("Cyber-Operator task source bootstrap")
    print(f"  mode:        {'APPLY' if apply else 'PREVIEW'}")
    print(f"  source task: {plan.source_task.as_posix()}")
    print(f"  source:      {plan.source}")
    print(f"  destination: {plan.destination}")
    print(f"  files:       {sum(item.kind == 'file' for item in plan.items)}")
    print(f"  bytes:       {plan.size}")
    print(f"  SHA-256:     {plan.digest}")
    print(f"  state:       {'existing-match' if plan.existing_match else 'new'}")
    print(f"  artifact handling: {plan.artifact_handling}")
    if plan.artifact_handling == artifact_handling.NO_DOWNLOAD:
        print(
            "  source origin attestation: "
            + ("PROVIDED" if source_origin_attested else "REQUIRED")
        )
    if plan.sensitive_hits:
        print("  WARNING: possible sensitive material detected")
        for hit in plan.sensitive_hits:
            print(f"    - {hit}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cyber-source")
    root.set_defaults(command=None)
    sub = root.add_subparsers(dest="command")
    add = sub.add_parser("add", help="preview or copy one file/directory into an assessment source")
    add.add_argument("--assessment", "--lab", dest="lab", required=True, help="source collection name; --lab is a compatibility alias")
    add.add_argument('--source-kind',choices=('application-code','documentation','specification','operator-output'))
    add.add_argument('--origin',choices=('preexisting-nontarget','operator-generated'))
    add.add_argument('--assessment-reference')
    add.add_argument("--path", required=True, dest="source_path")
    add.add_argument("--dest", help="relative destination inside the source collection; defaults to source basename")
    add.add_argument("--apply", action="store_true", help="perform the copy; otherwise preview only")
    add.add_argument("--rw-root", default=os.getenv("CYBER_SOURCE_RW", str(DEFAULT_RW_ROOT)))
    add.add_argument("--ro-root", default=os.getenv("CYBER_SOURCE_RO", str(DEFAULT_RO_ROOT)))
    add.add_argument("--task-root", default=os.getenv("CYBER_WORKSPACE_ROOT", str(DEFAULT_TASK_ROOT)))
    bootstrap = sub.add_parser(
        "bootstrap-task",
        help="preview or copy one explicit RO task subtree into the private workspace",
    )
    bootstrap.add_argument("--source-task", required=True)
    bootstrap.add_argument(
        "--apply",
        action="store_true",
        help="perform the verified copy; otherwise preview only",
    )
    bootstrap.add_argument(
        "--ro-root",
        default=os.getenv("CYBER_SOURCE_RO", str(DEFAULT_RO_ROOT)),
    )
    bootstrap.add_argument(
        "--task-root",
        default=os.getenv("CYBER_WORKSPACE_ROOT", str(DEFAULT_TASK_ROOT)),
    )
    bootstrap.add_argument(
        "--attest-preexisting-nontarget-source",
        action="store_true",
        help=(
            "attest that the selected tree predates target collection and is "
            "operator-provided source material"
        ),
    )
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command is None:
        parser().print_help(sys.stderr)
        return 2
    try:
        if args.command == "add":
            plan = build_plan(
                lab=args.lab,
                source_value=args.source_path,
                dest_value=args.dest,
                rw_root=Path(args.rw_root),
                ro_root=Path(args.ro_root),
                source_kind=args.source_kind,origin=args.origin,assessment_reference=args.assessment_reference,
            )
            print_plan(plan, apply=args.apply)
            if not args.apply:
                print("Preview only. Re-run with --apply to copy.")
                return 0
            apply_plan(
                plan,
                task_root=Path(args.task_root),
                ro_root=Path(args.ro_root).resolve(),
            )
            print("Import completed and verified through the read-only view.")
            return 0
        if args.command == "bootstrap-task":
            task_plan = build_task_bootstrap_plan(
                source_task_value=args.source_task,
                ro_root=Path(args.ro_root),
                task_root=Path(args.task_root),
            )
            print_task_bootstrap_plan(
                task_plan,
                apply=args.apply,
                source_origin_attested=(
                    args.attest_preexisting_nontarget_source
                ),
            )
            if not args.apply:
                print("Preview only. Re-run with --apply to copy.")
                return 0
            status = apply_task_bootstrap(
                task_plan,
                attest_preexisting_nontarget_source=(
                    args.attest_preexisting_nontarget_source
                ),
            )
            if status == "existing":
                print("Task source already exists with the verified tree hash; no write.")
            elif status == "recorded":
                print("Verified existing task source and appended its missing manifest record.")
            else:
                print("Task source copied into the private workspace and verified.")
            return 0
        raise IntakeError(f"unsupported command: {args.command}")
    except IntakeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
