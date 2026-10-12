#!/usr/bin/env python3
"""Manage a human-readable collection of independent Cyber-Operator task workspaces."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from . import (
        artifact_handling,
        engagement_config,
        new_host,
        operational_profile,
        remote_storage,
        runtime_config,
        workspace_lifecycle,
    )
else:
    import artifact_handling  # type: ignore[no-redef]
    import engagement_config
    import new_host  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import remote_storage
    import runtime_config
    import workspace_lifecycle  # type: ignore[no-redef]

DEFAULT_COLLECTION_ROOT = runtime_config.workspace_root()
MODULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ACTIVE_MARKER = "ACTIVE_TASK"
TASK_CONTEXT_LOCK = ".TASK_CONTEXT.lock"
SOURCE_INTAKE = "source"
CHAT_INTAKE = "chat"
INTAKE_MODES = (SOURCE_INTAKE, CHAT_INTAKE)
INTAKE_MODE_RE = re.compile(r"(?m)^- Intake mode: ([^\r\n]+)$")
ACTIVE_SOURCE_RE = re.compile(r"(?m)^- Active source task: ([^\r\n]+)$")
LEGACY_ROOT_ENTRIES = {
    "engagement.json",
    "engagement_events.jsonl",
    "TASK_CONTEXT.md",
    "attempts.jsonl",
    "checkpoints",
    "evidence",
    "execution_runs",
    "execution_runs.jsonl",
    "claims.jsonl",
    "global.md",
    "hosts",
    "inbox",
    "loot.jsonl",
    "observations.jsonl",
    "findings.jsonl",
    "work_items.jsonl",
    "local_artifacts.jsonl",
    "workspace_lifecycle.jsonl",
    "queries",
    "report",
    "screenshot_requests.jsonl",
    "standing_authorizations.jsonl",
    "plaintext_report_policy.jsonl",
    "plaintext_report_exports.jsonl",
    "workbench",
}
RESERVED_NAMES = {"_archive", "intake", "private", ACTIVE_MARKER, *LEGACY_ROOT_ENTRIES}


class CollectionError(RuntimeError):
    """Deterministic collection layout or selection failure."""


@dataclass(frozen=True)
class ModulePlan:
    module: str
    root: Path
    destination: Path
    exists: bool
    profile: str
    intake_mode: str
    artifact_handling: str
    remote: remote_storage.Settings = remote_storage.DISABLED


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def validate_module_name(module: str) -> str:
    if not MODULE_RE.fullmatch(module) or module in RESERVED_NAMES:
        raise CollectionError(
            "invalid module name; use a non-reserved direct name containing only "
            "letters, digits, '.', '_' or '-'"
        )
    return module


def validate_intake_mode(intake_mode: str) -> str:
    """Return one supported task intake mode."""
    if intake_mode not in INTAKE_MODES:
        raise CollectionError(
            f"invalid intake mode; expected one of {', '.join(INTAKE_MODES)}"
        )
    return intake_mode


def parse_intake_mode_text(text: str) -> str:
    """Read the canonical intake mode, defaulting legacy contexts to source."""
    matches = INTAKE_MODE_RE.findall(text)
    if not matches:
        return SOURCE_INTAKE
    if len(matches) != 1:
        raise CollectionError("TASK_CONTEXT.md must contain exactly one Intake mode")
    intake_mode = validate_intake_mode(matches[0].strip())
    source_matches = ACTIVE_SOURCE_RE.findall(text)
    if len(source_matches) != 1:
        raise CollectionError(
            "TASK_CONTEXT.md must contain exactly one Active source task"
        )
    active_source = source_matches[0].strip()
    if intake_mode == CHAT_INTAKE and active_source != "none":
        raise CollectionError("chat intake requires Active source task: none")
    if intake_mode == SOURCE_INTAKE and active_source == "none":
        raise CollectionError("source intake requires a named Active source task")
    return intake_mode


def validate_collection_root(root: Path, *, allow_legacy: bool = False) -> Path:
    root = root.expanduser().absolute()
    try:
        metadata = root.lstat()
    except FileNotFoundError as exc:
        raise CollectionError(f"collection root does not exist: {root}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CollectionError("collection root must be a real non-symlink directory")
    if not allow_legacy:
        legacy = sorted(name for name in LEGACY_ROOT_ENTRIES if _lexists(root / name))
        if legacy:
            raise CollectionError(
                "collection root still contains legacy canonical entries: "
                + ", ".join(legacy)
            )
    return root


def module_path(root: Path, module: str) -> Path:
    validate_module_name(module)
    destination = root / module
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise CollectionError("module destination escapes collection root") from exc
    return destination


def _validate_module_workspace(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CollectionError(f"module workspace does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CollectionError("module workspace must be a real non-symlink directory")
    context = path / "TASK_CONTEXT.md"
    try:
        context_metadata = context.lstat()
    except FileNotFoundError as exc:
        raise CollectionError(f"module workspace is missing TASK_CONTEXT.md: {path}") from exc
    if stat.S_ISLNK(context_metadata.st_mode) or not stat.S_ISREG(context_metadata.st_mode):
        raise CollectionError("module TASK_CONTEXT.md must be a real regular file")
    try:
        context_text = operational_profile.read_context(context)
        operational_profile.parse_profile_text(context_text)
        artifact_handling.parse_mode_text(context_text)
        remote_storage.parse(context_text)
        artifact_handling.validate_local_processing(path)
        parse_intake_mode_text(context_text)
        engagement_config.load(path)
    except (
        artifact_handling.ArtifactHandlingError,
        remote_storage.RemoteStorageError,
        operational_profile.OperationalProfileError,
        engagement_config.ConfigurationError,
    ) as exc:
        raise CollectionError(str(exc)) from exc
    try:
        new_host.validate_workspace_layout(path)
    except new_host.WorkspaceLayoutError as exc:
        raise CollectionError(str(exc)) from exc


def _module_settings(path: Path) -> tuple[str, str, str]:
    """Return validated profile, intake mode, and artifact handling."""
    try:
        text = operational_profile.read_context(path / "TASK_CONTEXT.md")
        profile = operational_profile.parse_profile_text(text)
        mode = artifact_handling.parse_mode_text(text)
        intake_mode = parse_intake_mode_text(text)
    except (
        artifact_handling.ArtifactHandlingError,
        remote_storage.RemoteStorageError,
        operational_profile.OperationalProfileError,
    ) as exc:
        raise CollectionError(str(exc)) from exc
    return profile, intake_mode, mode


def build_module_plan(
    root: Path,
    module: str,
    profile: str = operational_profile.STRICT,
    intake_mode: str = SOURCE_INTAKE,
    artifact_handling_mode: str = artifact_handling.STANDARD,
    remote: remote_storage.Settings = remote_storage.DISABLED,
) -> ModulePlan:
    remote.validate()
    root = validate_collection_root(root)
    try:
        profile = operational_profile.validate_profile(profile)
    except operational_profile.OperationalProfileError as exc:
        raise CollectionError(str(exc)) from exc
    intake_mode = validate_intake_mode(intake_mode)
    try:
        artifact_handling_mode = artifact_handling.validate_mode(
            artifact_handling_mode
        )
    except artifact_handling.ArtifactHandlingError as exc:
        raise CollectionError(str(exc)) from exc
    destination = module_path(root, module)
    exists = _lexists(destination)
    if exists:
        _validate_module_workspace(destination)
        current = _module_settings(destination)
        requested = (profile, intake_mode, artifact_handling_mode)
        if remote_storage.parse(operational_profile.read_context(destination / "TASK_CONTEXT.md")) != remote:
            raise CollectionError("existing module has different remote storage settings")
        if current != requested:
            raise CollectionError(
                "module already exists with profile/intake/artifact handling "
                f"{current[0]}/{current[1]}/{current[2]}; init requested "
                f"{requested[0]}/{requested[1]}/{requested[2]}. init never "
                "changes an existing module; use the dedicated setters"
            )
    return ModulePlan(
        module,
        root,
        destination,
        exists,
        profile,
        intake_mode,
        artifact_handling_mode,
        remote,
    )


def render_task_context(
    module: str,
    profile: str = operational_profile.STRICT,
    intake_mode: str = SOURCE_INTAKE,
    artifact_handling_mode: str = artifact_handling.STANDARD,
    collection_root: Path | None = None,
    remote: remote_storage.Settings = remote_storage.DISABLED,
) -> str:
    root = (collection_root or runtime_config.workspace_root()).expanduser().absolute()
    operational_profile.validate_profile(profile)
    validate_intake_mode(intake_mode)
    artifact_handling.validate_mode(artifact_handling_mode)
    active_source = module if intake_mode == SOURCE_INTAKE else "none"
    source_boundary = (
        "read-only and untrusted"
        if intake_mode == SOURCE_INTAKE
        else "not required for chat intake"
    )
    return remote_storage.render((
        f"- Current task: {module}\n"
        f"- Active source task: {active_source}\n"
        f"- Operational profile: {profile}\n"
        f"- Intake mode: {intake_mode}\n"
        f"- Artifact handling: {artifact_handling_mode}\n"
        f"- Active source alias: `{runtime_config.source_root()}`\n"
        f"- Active task collection: `{root}`\n"
        f"- Active module workspace: "
        f"`{root / module}`\n"
        f"- Source mount: {source_boundary}\n"
        "- Module workspace: private and write-allowed\n"
    ), remote)


def _ensure_local_processing_layout(path: Path) -> tuple[Path, ...]:
    """Create the optional owner-only local-processing route when absent."""
    created: list[Path] = []
    try:
        for directory in (path / "private", path / "private" / "local_processing"):
            if _lexists(directory):
                continue
            directory.mkdir(mode=0o700)
            created.append(directory)
        new_host.validate_workspace_layout(path)
    except (FileExistsError, OSError, new_host.WorkspaceLayoutError) as exc:
        for directory in reversed(created):
            try:
                directory.rmdir()
            except OSError:
                pass
        if isinstance(exc, new_host.WorkspaceLayoutError):
            raise CollectionError(str(exc)) from exc
        raise
    return tuple(created)


def apply_module_plan(plan: ModulePlan, script_dir: Path, *, intake_payload: str | None = None, engagement_definition: dict | None = None) -> str:
    if plan.exists:
        _validate_module_workspace(plan.destination)
        current = _module_settings(plan.destination)
        expected = (plan.profile, plan.intake_mode, plan.artifact_handling)
        if remote_storage.parse(operational_profile.read_context(plan.destination / "TASK_CONTEXT.md")) != plan.remote:
            raise CollectionError("remote storage settings changed after preview")
        if current != expected:
            raise CollectionError(
                "existing module configuration changed after preview"
            )
        return "existing"
    temporary = Path(tempfile.mkdtemp(prefix=".cyber-module-", dir=plan.root))
    try:
        new_host.initialize_workspace(temporary, script_dir)
        if plan.artifact_handling == artifact_handling.NO_DOWNLOAD:
            _ensure_local_processing_layout(temporary)
        new_host.atomic_write_text(
            temporary / "TASK_CONTEXT.md",
            render_task_context(
                plan.module,
                plan.profile,
                plan.intake_mode,
                plan.artifact_handling,
                plan.root,
                plan.remote,
            ),
        )
        if intake_payload is not None:
            new_host.atomic_write_text(temporary / "engagement_intake.json", intake_payload)
        if engagement_definition is not None:
            engagement_config.bootstrap(temporary, engagement_definition)
        if _lexists(plan.destination):
            raise CollectionError("module destination appeared during apply")
        temporary.rename(plan.destination)
    finally:
        if _lexists(temporary):
            try:
                shutil.rmtree(temporary)
            except OSError:
                pass
    return "created"


def read_active_module(root: Path) -> str:
    root = validate_collection_root(root)
    marker = root / ACTIVE_MARKER
    try:
        metadata = marker.lstat()
    except FileNotFoundError as exc:
        raise CollectionError("collection has no ACTIVE_TASK selection") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CollectionError("ACTIVE_TASK must be a real regular file")
    if metadata.st_size > 256:
        raise CollectionError("ACTIVE_TASK is unexpectedly large")
    try:
        value = marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise CollectionError("ACTIVE_TASK is unreadable") from exc
    validate_module_name(value)
    _validate_module_workspace(root / value)
    return value


def write_active_module(root: Path, module: str) -> None:
    root = validate_collection_root(root)
    validate_module_name(module)
    _validate_module_workspace(root / module)
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    record = restore_checkpoint.state(root / module)
    if record is not None and record["status"] != "active":
        raise CollectionError("restored workspace is inactive; activate it before selecting")
    with restore_checkpoint.collection_lock(root):
        _write_active_marker(root, module)


def _write_active_marker(root: Path, module: str) -> None:
    marker = root / ACTIVE_MARKER
    if _lexists(marker):
        metadata = marker.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CollectionError("ACTIVE_TASK must be a real regular file")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=root, prefix=".ACTIVE_TASK.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, f"{module}\n".encode())
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, marker)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_module_profile(root: Path, module: str) -> str:
    """Return the validated profile for one existing module workspace."""
    root = validate_collection_root(root)
    path = module_path(root, module)
    _validate_module_workspace(path)
    try:
        return operational_profile.workspace_profile(path)
    except operational_profile.OperationalProfileError as exc:
        raise CollectionError(str(exc)) from exc


def read_module_intake_mode(root: Path, module: str) -> str:
    """Return the validated intake mode for one existing module workspace."""
    root = validate_collection_root(root)
    path = module_path(root, module)
    _validate_module_workspace(path)
    try:
        return parse_intake_mode_text(
            operational_profile.read_context(path / "TASK_CONTEXT.md")
        )
    except operational_profile.OperationalProfileError as exc:
        raise CollectionError(str(exc)) from exc


def read_module_artifact_handling(root: Path, module: str) -> str:
    """Return the validated target-artifact handling mode for one module."""
    root = validate_collection_root(root)
    path = module_path(root, module)
    _validate_module_workspace(path)
    try:
        return artifact_handling.workspace_mode(path)
    except artifact_handling.ArtifactHandlingError as exc:
        raise CollectionError(str(exc)) from exc


def _atomic_replace_task_context(
    path: Path,
    context: Path,
    before_metadata: os.stat_result,
    before: str,
    replacement: str,
    changed_message: str,
) -> None:
    """Publish one already validated TASK_CONTEXT.md field replacement."""
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path, prefix=".TASK_CONTEXT.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, replacement.encode("utf-8"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        current_metadata = context.lstat()
        if (
            current_metadata.st_dev != before_metadata.st_dev
            or current_metadata.st_ino != before_metadata.st_ino
            or operational_profile.read_context(context) != before
        ):
            raise CollectionError(changed_message)
        os.replace(temporary, context)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def _task_context_lock(path: Path) -> Iterator[None]:
    """Serialize cooperating TASK_CONTEXT.md writers through one stable lock."""
    lock_path = path / TASK_CONTEXT_LOCK
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        current = lock_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
        ):
            raise CollectionError("TASK_CONTEXT lock must be one stable regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CollectionError("TASK_CONTEXT lock must use private permissions")
        yield
    finally:
        os.close(descriptor)


def write_module_profile(root: Path, module: str, profile: str) -> tuple[str, str]:
    """Atomically replace only the canonical profile line in TASK_CONTEXT.md."""
    root = validate_collection_root(root)
    path = module_path(root, module)
    engagement_config.reject_legacy_mutation(path)
    _validate_module_workspace(path)
    with _task_context_lock(path):
        _validate_module_workspace(path)
        try:
            profile = operational_profile.validate_profile(profile)
            context = path / "TASK_CONTEXT.md"
            before_metadata = context.lstat()
            before = operational_profile.read_context(context)
            current = operational_profile.parse_profile_text(before)
            replacement = operational_profile.render_profile_text(before, profile)
        except operational_profile.OperationalProfileError as exc:
            raise CollectionError(str(exc)) from exc
        if replacement == before:
            return current, profile
        _atomic_replace_task_context(
            path,
            context,
            before_metadata,
            before,
            replacement,
            "TASK_CONTEXT.md changed during profile update",
        )
    return current, profile


def write_module_artifact_handling(
    root: Path,
    module: str,
    mode: str,
    *,
    acknowledge_local_full_file_risk: bool = False,
) -> tuple[str, str]:
    """Atomically replace only the canonical artifact-handling context line."""
    root = validate_collection_root(root)
    path = module_path(root, module)
    engagement_config.reject_legacy_mutation(path)
    _validate_module_workspace(path)
    with _task_context_lock(path):
        _validate_module_workspace(path)
        try:
            mode = artifact_handling.validate_mode(mode)
            context = path / "TASK_CONTEXT.md"
            before_metadata = context.lstat()
            before = operational_profile.read_context(context)
            current = artifact_handling.parse_mode_text(before)
            replacement = artifact_handling.render_mode_text(before, mode)
        except (
            artifact_handling.ArtifactHandlingError,
        remote_storage.RemoteStorageError,
            operational_profile.OperationalProfileError,
        ) as exc:
            raise CollectionError(str(exc)) from exc
        relaxing = (
            current == artifact_handling.NO_DOWNLOAD
            and mode == artifact_handling.STANDARD
        )
        if relaxing and not acknowledge_local_full_file_risk:
            raise CollectionError(
                "relaxing no-download requires "
                "--ack-local-full-file-risk"
            )
        created: tuple[Path, ...] = ()
        try:
            if mode == artifact_handling.NO_DOWNLOAD:
                created = _ensure_local_processing_layout(path)
            if replacement == before:
                return current, mode
            _atomic_replace_task_context(
                path,
                context,
                before_metadata,
                before,
                replacement,
                "TASK_CONTEXT.md changed during artifact handling update",
            )
        except BaseException:
            for directory in reversed(created):
                try:
                    directory.rmdir()
                except OSError:
                    pass
            raise
    return current, mode


def list_modules(root: Path) -> list[str]:
    root = validate_collection_root(root)
    modules: list[str] = []
    for entry in root.iterdir():
        if entry.name.startswith("_") or entry.name == ACTIVE_MARKER:
            continue
        if not MODULE_RE.fullmatch(entry.name):
            continue
        try:
            _validate_module_workspace(entry)
        except CollectionError:
            continue
        modules.append(entry.name)
    return sorted(modules)


def _print_artifact_policy(mode: str) -> None:
    for label, state in artifact_handling.policy_matrix(mode):
        print(f"    {label}: {state}")


def parser() -> argparse.ArgumentParser:
    root_parser = argparse.ArgumentParser(prog="cyber-workspace")
    root_parser.add_argument(
        "--root",
        default=os.getenv("CYBER_WORKSPACE_ROOT", str(DEFAULT_COLLECTION_ROOT)),
    )
    sub = root_parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="preview or initialize one module workspace")
    init.add_argument("--module", required=True)
    init.add_argument(
        "--profile",
        choices=operational_profile.PROFILES,
        required=True,
    )
    init.add_argument(
        "--intake-mode",
        choices=INTAKE_MODES,
        default=SOURCE_INTAKE,
        help="source-backed (default) or source-free chat intake",
    )
    init.add_argument(
        "--artifact-handling",
        choices=artifact_handling.MODES,
        required=True,
        help="target-artifact workflow for the new module",
    )
    init.add_argument("--remote-storage", choices=remote_storage.MODES, default="disabled")
    init.add_argument("--remote-location", default="none")
    init.add_argument("--remote-approval", default="none")
    init.add_argument("--apply", action="store_true")
    select = sub.add_parser("select", help="preview or select the active module")
    select.add_argument("--module", required=True)
    select.add_argument("--apply", action="store_true")
    profile = sub.add_parser("profile", help="preview or change a module profile")
    profile.add_argument("--module", required=True)
    profile.add_argument("--set", required=True, choices=operational_profile.PROFILES)
    profile.add_argument("--apply", action="store_true")
    artifact_mode = sub.add_parser(
        "artifact-handling",
        help="preview or change a module target-artifact handling mode",
    )
    artifact_mode.add_argument("--module", required=True)
    artifact_mode.add_argument(
        "--set", required=True, choices=artifact_handling.MODES
    )
    artifact_mode.add_argument(
        "--ack-local-full-file-risk",
        action="store_true",
        help="acknowledge relaxing no-download to standard",
    )
    artifact_mode.add_argument("--apply", action="store_true")
    remote = sub.add_parser("remote-storage", help="register approved storage metadata; performs no transfer")
    remote.add_argument("--module", required=True)
    remote.add_argument("--set", choices=remote_storage.MODES, required=True)
    remote.add_argument("--location", default="none")
    remote.add_argument("--approval", default="none")
    remote.add_argument("--apply", action="store_true")
    resolve = sub.add_parser("resolve", help="print the active module workspace path")
    resolve.add_argument("--check-write", action="store_true", help="refuse resolution when local writer prerequisites are not ready")
    doctor = sub.add_parser("doctor", help="read-only local runtime, recovery and writer-lease diagnostics")
    doctor.add_argument("--module", help="inspect a named module instead of ACTIVE_TASK")
    doctor.add_argument("--json", action="store_true", help="print bounded structured diagnostics")
    close = sub.add_parser(
        "close", help="preview or close target actions for one module"
    )
    close.add_argument("--module", required=True)
    close.add_argument("--reason", required=True)
    close.add_argument("--close-plan-sha256")
    close.add_argument("--ack-operator-requested-close", action="store_true")
    close.add_argument("--ack-retain-active-state", action="store_true")
    close.add_argument("--apply", action="store_true")
    reopen = sub.add_parser(
        "reopen", help="preview or explicitly reopen target actions for one module"
    )
    reopen.add_argument("--module", required=True)
    reopen.add_argument("--reason", required=True)
    reopen.add_argument("--ack-operator-requested-reopen", action="store_true")
    reopen.add_argument("--apply", action="store_true")
    sub.add_parser("list", help="list valid module workspaces")
    return root_parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        root = Path(args.root)
        if args.command == "remote-storage":
            settings = remote_storage.Settings(args.set, args.location, args.approval).validate()
            path = module_path(validate_collection_root(root), args.module)
            engagement_config.reject_legacy_mutation(path)
            _validate_module_workspace(path)
            context = path / "TASK_CONTEXT.md"
            with _task_context_lock(path):
                _validate_module_workspace(path)
                metadata = context.lstat()
                before = operational_profile.read_context(context)
                replacement = remote_storage.render(before, settings)
                if args.apply and replacement != before:
                    _atomic_replace_task_context(path, context, metadata, before, replacement, "storage settings changed during update")
            print(f"remote storage: {settings.mode}; location: {settings.location}; {'APPLY' if args.apply else 'PREVIEW'}")
            return 0
        if args.command == "init":
            plan = build_module_plan(
                root,
                args.module,
                args.profile,
                args.intake_mode,
                args.artifact_handling,
                remote_storage.Settings(args.remote_storage, args.remote_location, args.remote_approval),
            )
            print("Cyber-Operator module workspace")
            print(f"  mode:        {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"  module:      {plan.module}")
            print(f"  destination: {plan.destination}")
            print(f"  state:       {'existing' if plan.exists else 'new'}")
            print(f"  profile:     {plan.profile}")
            print(f"  intake mode: {plan.intake_mode}")
            print(f"  artifact handling: {plan.artifact_handling}")
            print(f"  remote storage: {plan.remote.mode}; location: {plan.remote.location}")
            print("  artifact policy:")
            _print_artifact_policy(plan.artifact_handling)
            if plan.exists:
                print(
                    "  note: init never changes an existing module; use the "
                    "artifact-handling subcommand"
                )
            if args.apply:
                status = apply_module_plan(plan, Path(__file__).resolve().parent)
                print(f"Module workspace status: {status}")
            else:
                print("Preview only. Re-run with --apply to initialize.")
            return 0
        if args.command == "select":
            root = validate_collection_root(root)
            validate_module_name(args.module)
            _validate_module_workspace(root / args.module)
            print("Cyber-Operator active module selection")
            print(f"  mode:   {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"  module: {args.module}")
            if args.apply:
                write_active_module(root, args.module)
                print("Active module updated.")
            else:
                print("Preview only. Re-run with --apply to select.")
            return 0
        if args.command == "profile":
            root = validate_collection_root(root)
            current = read_module_profile(root, args.module)
            print("Cyber-Operator module operational profile")
            print(f"  mode:      {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"  module:    {args.module}")
            print(f"  current:   {current}")
            print(f"  requested: {args.set}")
            if args.apply:
                write_module_profile(root, args.module, args.set)
                print("Operational profile updated.")
            else:
                print("Preview only. Re-run with --apply to update.")
            return 0
        if args.command == "artifact-handling":
            root = validate_collection_root(root)
            current = read_module_artifact_handling(root, args.module)
            relaxing = (
                current == artifact_handling.NO_DOWNLOAD
                and args.set == artifact_handling.STANDARD
            )
            print("Cyber-Operator module artifact handling")
            print(f"  mode:      {'APPLY' if args.apply else 'PREVIEW'}")
            print(f"  module:    {args.module}")
            print(f"  current:   {current}")
            print(f"  requested: {args.set}")
            print("  artifact policy:")
            _print_artifact_policy(args.set)
            if relaxing:
                print(
                    "  warning: standard removes the framework no-download "
                    "guardrail; external engagement rules still apply"
                )
            if args.apply:
                write_module_artifact_handling(
                    root,
                    args.module,
                    args.set,
                    acknowledge_local_full_file_risk=(
                        args.ack_local_full_file_risk
                    ),
                )
                print("Artifact handling updated.")
            else:
                print("Preview only. Re-run with --apply to update.")
            return 0
        if args.command in {"close", "reopen"}:
            root = validate_collection_root(root)
            validate_module_name(args.module)
            workspace = root / args.module
            _validate_module_workspace(workspace)
            if args.command == "reopen":
                record = workspace_lifecycle.reopen(
                    workspace,
                    operator_acknowledged=args.ack_operator_requested_reopen,
                    reason=args.reason,
                    apply=args.apply,
                )
                print(f"mode: {'APPLY' if args.apply else 'PREVIEW'}")
                print(f"workspace_state: {'open' if args.apply else 'closed'}")
                print(f"workspace_event_id: {record['workspace_event_id']}")
                print("standing_authorization_restored: no")
                return 0
            plan = workspace_lifecycle.build_close_plan(workspace)
            if args.apply:
                workspace_lifecycle.apply_close(
                    plan,
                    supplied_plan_sha256=args.close_plan_sha256 or "",
                    operator_acknowledged=args.ack_operator_requested_close,
                    retain_active_state=args.ack_retain_active_state,
                    reason=args.reason,
                )
            workspace_lifecycle.print_close_plan(plan, apply=args.apply)
            return 0
        if args.command in {"resolve", "doctor"}:
            if __package__:
                from . import workspace_health
            else:
                import workspace_health
            root = validate_collection_root(root)
            selected = getattr(args, "module", None)
            if selected is None:
                selected = read_active_module(root)
            else:
                validate_module_name(selected)
                _validate_module_workspace(root / selected)
            workspace = root / selected
            health = workspace_health.snapshot(workspace)
            if args.command == "doctor":
                if args.json:
                    print(json.dumps(health, sort_keys=True))
                else:
                    print("\n".join(workspace_health.render(health)))
                return 0 if health["write_ready"] else 2
            if not health["write_ready"]:
                print("\n".join(workspace_health.render(health)), file=sys.stderr)
                if args.check_write:
                    return 2
            print(workspace)
            return 0
        if args.command == "list":
            root = validate_collection_root(root)
            active = None
            try:
                active = read_active_module(root)
            except CollectionError:
                pass
            for module in list_modules(root):
                marker = "*" if module == active else " "
                print(f"{marker} {module}")
            return 0
        raise CollectionError(f"unsupported command: {args.command}")
    except (
        remote_storage.RemoteStorageError,
        CollectionError,
        engagement_config.ConfigurationError,
        workspace_lifecycle.WorkspaceLifecycleError,
        FileExistsError,
        OSError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
