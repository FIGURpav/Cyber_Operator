"""Restore verified checkpoints as new, initially inactive private modules."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import (
        artifact_io,
        create_checkpoint,
        ledger_io,
        runtime_config,
        task_collection,
    )
else:
    import artifact_io
    import create_checkpoint
    import ledger_io
    import runtime_config
    import task_collection

STATE = ".restore_state.json"


class RestoreError(OSError):
    """A restore, activation or stale runtime refusal."""


def state(workspace: Path) -> dict[str, Any] | None:
    path = workspace / STATE
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise RestoreError("restore state is not a bounded regular file")
    record = ledger_io.loads_json(path.read_bytes())
    if (
        not isinstance(record, dict) or record.get("schema_version") != "1.0"
        or record.get("status") not in ("inactive", "active")
        or not isinstance(record.get("instance_id"), str)
        or re.fullmatch(r"WSI-[0-9a-f]{32}", record["instance_id"]) is None
        or not isinstance(record.get("inherited_authorization_ids"), list)
        or not all(isinstance(item, str) for item in record["inherited_authorization_ids"])
        or not isinstance(record.get("inherited_token_event_ids"), list)
        or not all(isinstance(item, str) for item in record["inherited_token_event_ids"])
        or not isinstance(record.get("inherited_validation_refs"), list)
        or not all(isinstance(item, str) for item in record["inherited_validation_refs"])
        or not isinstance(record.get("checkpoint_manifest_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["checkpoint_manifest_sha256"]) is None
        or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        raise RestoreError("restore state is malformed")
    return record


def require_write_instance(workspace: Path) -> None:
    record = state(workspace)
    if record is None:
        return
    if record["status"] != "active":
        raise RestoreError("restored workspace is inactive; review and activate it first")
    if os.environ.get("CYBER_WORKSPACE_INSTANCE") != record["instance_id"]:
        raise RestoreError("stale workspace runtime; set CYBER_WORKSPACE_INSTANCE to the activated instance")


def require_path_instance(path: Path) -> None:
    """Fence writes by supported storage helpers; this is not an OS sandbox."""
    for parent in (path.absolute(), *path.absolute().parents):
        if (parent / STATE).exists() or (parent / STATE).is_symlink():
            require_write_instance(parent)
            return


def require_current_authorization(workspace: Path, identifier: str) -> None:
    if historical_authorization(workspace, identifier):
        raise RestoreError("authorization is historical after restore; record a new authorization")


def require_current_token_validation(workspace: Path, token_state: dict[str, Any]) -> None:
    record = state(workspace)
    if record and token_state["event_id"] in record["inherited_token_event_ids"]:
        raise RestoreError("token validation is historical after restore; revalidate in the new instance")


def require_new_validation_refs(workspace: Path, evidence_id: str | None, attempt_id: str | None) -> None:
    record = state(workspace)
    if record is None:
        return
    refs = [value for value in (evidence_id, attempt_id) if value is not None]
    if not refs or any(value in record["inherited_validation_refs"] for value in refs):
        raise RestoreError("token revalidation after restore requires new evidence or attempt provenance")


@contextlib.contextmanager
def collection_lock(collection: Path):
    descriptor = os.open(collection / ".restore.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        info = os.fstat(descriptor)
        current = (collection / ".restore.lock").lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise RestoreError("invalid collection lock")
        os.fchmod(descriptor, 0o600)
        yield
    finally:
        os.close(descriptor)


def _safe_collection(collection: Path) -> Path:
    if ".." in collection.parts:
        raise RestoreError("restore collection path must be canonical")
    root = task_collection.validate_collection_root(collection)
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise RestoreError("restore collection path contains a symlink")
        if parent.name == "_archive" or ((parent / "global.md").is_file() and (parent / "hosts").is_dir()):
            raise RestoreError("restore collection must not be nested in an archive or module")
        if (parent / ".git").exists():
            raise RestoreError("restore destination must be outside Git work trees")
    forbidden = (
        Path(__file__).resolve().parents[1],
        runtime_config.source_root(),
    )
    if any(root.is_relative_to(path) for path in forbidden):
        raise RestoreError("restore collection is not a private task destination")
    if stat.S_IMODE(root.stat().st_mode) != 0o700 or root.stat().st_uid != os.geteuid():
        raise RestoreError("restore collection must use mode 0700")
    return root


def historical_authorization(workspace: Path, identifier: str) -> bool:
    record = state(workspace)
    return record is not None and identifier in record["inherited_authorization_ids"]


def _authorization_ids(workspace: Path) -> list[str]:
    result: set[str] = set()
    for name in ("standing_authorizations.jsonl", "authorizations.jsonl"):
        path = workspace / name
        if not path.exists():
            continue
        for line in path.read_bytes().splitlines():
            value = ledger_io.loads_json(line)
            for key in ("standing_authorization_id", "authorization_id"):
                if isinstance(value.get(key), str):
                    result.add(value[key])
    return sorted(result)


def validate_restored(workspace: Path) -> None:
    """Check structure and historical references, without requiring a finished report."""
    if __package__:
        from . import (
            engagement_policy,
            execution_provenance,
            host_identity,
            operational_trace,
            report_contract,
            screenshot_workflow,
            token_lifecycle,
            workspace_transaction,
        )
    else:
        import engagement_policy
        import execution_provenance
        import host_identity
        import operational_trace
        import report_contract
        import screenshot_workflow
        import token_lifecycle
        import workspace_transaction
    task_collection._validate_module_workspace(workspace)
    host_identity.applied_merges(workspace)
    # These readers validate historical state without activating a capability.
    operational_trace._attempt_index(workspace)
    operational_trace.load_authorizations(workspace)
    operational_trace.load_changes(workspace)
    operational_trace.load_attack_paths(workspace, validate_credentials=True)
    engagement_policy.load_standing_authorizations(workspace)
    token_lifecycle.closure_readiness(workspace)
    if workspace_transaction.incomplete(workspace):
        raise RestoreError("checkpoint contains unfinished transactions; recover the source before checkpointing")
    context = report_contract.ValidationContext(workspace)
    _ = context.evidence
    context.query_index(verify_hashes=True)
    _, states = report_contract.load_steps(workspace, context=context)
    if (workspace / execution_provenance.RUN_LEDGER).exists():
        runs = execution_provenance._load_runs_with_context(workspace, states, context, verify_artifacts=True)
        execution_provenance._load_claims_with_context(workspace, states, runs, context)
    ledger = workspace / screenshot_workflow.LEDGER_NAME
    if ledger.exists():
        for value in screenshot_workflow._effective(screenshot_workflow._load_events(ledger)).values():
            if screenshot_workflow._status(value) == "captured":
                screenshot_workflow._verify_evidence(workspace, value["request"], value["transition"])


def restore(checkpoint: Path, collection: Path, module: str, *, apply: bool) -> dict[str, Any]:
    collection = _safe_collection(collection)
    if apply:
        with collection_lock(collection):
            return _restore_locked(checkpoint, collection, module, apply=True)
    return _restore_locked(checkpoint, collection, module, apply=False)


def _restore_locked(checkpoint: Path, collection: Path, module: str, *, apply: bool) -> dict[str, Any]:
    manifest = create_checkpoint.verify_checkpoint(checkpoint)
    if collection.is_relative_to(checkpoint.absolute()) or checkpoint.absolute().is_relative_to(collection / module):
        raise RestoreError("checkpoint and restore destination must not contain each other")
    destination = task_collection.module_path(collection, module)
    if destination.exists() or destination.is_symlink():
        existing = state(destination) if destination.is_dir() else None
        if destination.is_symlink():
            raise RestoreError("restore destination is a symlink")
        if existing and existing.get("checkpoint_manifest_sha256") == _manifest_hash(checkpoint):
            validate_restored(destination)
            return {"status": "already-restored", "destination": str(destination), "instance_id": existing["instance_id"]}
        raise RestoreError("restore destination already exists")
    source = checkpoint.resolve() / "workspace"
    validate_restored(source)
    result = {"status": "preview", "destination": str(destination), "checkpoint_id": manifest["checkpoint_id"], "profile": manifest["operational_profile"]}
    if not apply:
        return result
    archive = collection / "_archive"
    if archive.is_symlink():
        raise RestoreError("restore archive is a symlink")
    archive.mkdir(mode=0o700, exist_ok=True)
    if stat.S_IMODE(archive.stat().st_mode) != 0o700:
        raise RestoreError("restore archive must use mode 0700")
    operation = archive / ("RST-" + uuid.uuid4().hex)
    operation.mkdir(mode=0o700)
    _sync_directory(collection)
    _sync_directory(archive)
    instance_id = "WSI-" + uuid.uuid4().hex
    plan = {**result, "instance_id": instance_id, "checkpoint": str(checkpoint.resolve()), "checkpoint_manifest_sha256": _manifest_hash(checkpoint)}
    artifact_io.publish_file(operation / "plan.json", json.dumps(plan, sort_keys=True))
    _finish_restore(operation, plan)
    return {**result, "status": "restored-inactive", "instance_id": instance_id}


def _manifest_hash(checkpoint: Path) -> str:
    return hashlib.sha256((checkpoint / "checkpoint.json").read_bytes()).hexdigest()


def _finish_restore(operation: Path, plan: dict[str, Any]) -> None:
    expected = {"status", "destination", "checkpoint_id", "profile", "instance_id", "checkpoint", "checkpoint_manifest_sha256"}
    if (not isinstance(plan, dict) or set(plan) != expected
            or not all(isinstance(value, str) for value in plan.values())
            or re.fullmatch(r"WSI-[0-9a-f]{32}", plan["instance_id"]) is None):
        raise RestoreError("restore plan is malformed")
    _safe_collection(operation.parent.parent)
    if any(path.is_symlink() for path in (operation, operation.parent)):
        raise RestoreError("restore operation path contains a symlink")
    checkpoint, destination = Path(plan["checkpoint"]), Path(plan["destination"])
    if destination.is_symlink():
        raise RestoreError("restore destination is a symlink")
    if destination.parent != operation.parent.parent or task_collection.validate_module_name(destination.name) != destination.name:
        raise RestoreError("restore plan destination is outside its collection")
    manifest = create_checkpoint.verify_checkpoint(checkpoint)
    if plan["checkpoint_id"] != manifest["checkpoint_id"] or plan["profile"] != manifest["operational_profile"]:
        raise RestoreError("restore plan does not match checkpoint identity or profile")
    if _manifest_hash(checkpoint) != plan["checkpoint_manifest_sha256"]:
        raise RestoreError("checkpoint changed after restore preview")
    if destination.exists():
        current = state(destination)
        if current is None or current["instance_id"] != plan["instance_id"] or current["checkpoint_manifest_sha256"] != plan["checkpoint_manifest_sha256"]:
            raise RestoreError("restore destination conflicts with prepared operation")
        validate_restored(destination)
    else:
        # An interrupted private copy is retained; retry uses a new staging tree.
        staging = operation / ("copy-" + uuid.uuid4().hex)
        staging.mkdir(mode=0o700)
        create_checkpoint.copy_workspace(checkpoint / "workspace", staging)
        candidate = staging / "workspace"
        validate_restored(candidate)
        original_context = (candidate / "TASK_CONTEXT.md").read_bytes()
        history = candidate / "private/restore_source"
        history.parent.mkdir(mode=0o700, exist_ok=True)
        if history.exists():
            history = history.parent / ("restore_source_" + uuid.uuid4().hex)
        history.mkdir(mode=0o700)
        for name in ("private/coordination", STATE):
            source = candidate / name
            if source.exists() or source.is_symlink():
                if source.is_symlink():
                    raise RestoreError("restored runtime state contains a symlink")
                os.rename(source, history / source.name)
        artifact_io.publish_file(history / "TASK_CONTEXT.md", original_context)
        context = original_context.decode("utf-8")
        for label, value in (
            ("Current task", destination.name),
            ("Active task collection", f"`{destination.parent}`"),
            ("Active module workspace", f"`{destination}`"),
        ):
            pattern = rf"(?m)^- {re.escape(label)}:.*$"
            matches = list(re.finditer(pattern, context))
            if len(matches) > 1:
                raise RestoreError("restored task context has ambiguous location fields")
            replacement = f"- {label}: {value}"
            if matches:
                context = re.sub(pattern, lambda _, text=replacement: text, context)
            else:
                context = context.rstrip() + "\n" + replacement + "\n"
        _replace_state_file(candidate / "TASK_CONTEXT.md", context.encode("utf-8"))
        record = {
            "schema_version": "1.0", "status": "inactive", "instance_id": plan["instance_id"],
            "checkpoint_id": plan["checkpoint_id"], "checkpoint_manifest_sha256": plan["checkpoint_manifest_sha256"],
            "restored_at_utc": datetime.now(UTC).isoformat(),
            "inherited_authorization_ids": _authorization_ids(candidate),
            "inherited_token_event_ids": _token_event_ids(candidate),
            "inherited_validation_refs": _validation_refs(candidate),
        }
        artifact_io.publish_file(candidate / STATE, json.dumps(record, sort_keys=True))
        validate_restored(candidate)
        # Validate and durably flush the complete candidate before publication.
        _sync_tree(candidate)
        artifact_io.publish_directory(candidate, destination)
    receipt = {"instance_id": plan["instance_id"], "plan_sha256": hashlib.sha256((operation / "plan.json").read_bytes()).hexdigest()}
    committed = operation / "COMMITTED.json"
    if committed.exists():
        if committed.is_symlink() or ledger_io.loads_json(committed.read_bytes()) != receipt:
            raise RestoreError("restore completion receipt is invalid")
    else:
        artifact_io.publish_file(committed, json.dumps(receipt))


def _validation_refs(workspace: Path) -> list[str]:
    if __package__:
        from . import operational_trace
    else:
        import operational_trace
    return sorted(set(operational_trace._attempt_index(workspace)) | operational_trace._evidence_ids(workspace))


def _token_event_ids(workspace: Path) -> list[str]:
    if __package__:
        from . import token_lifecycle
    else:
        import token_lifecycle
    return sorted(item["event_id"] for item in token_lifecycle._load_events(workspace))


def _replace_state_file(path: Path, raw: bytes) -> None:
    temporary = path.with_name(".restore-write-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_tree(root: Path) -> None:
    files, directories = create_checkpoint.scan_workspace(root)
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, reverse=True):
        _sync_directory(path)
    _sync_directory(root)


def resume(operation: Path) -> None:
    if operation.is_symlink() or operation.parent.is_symlink() or operation.parent.name != "_archive" or not re.fullmatch(r"RST-[0-9a-f]{32}", operation.name):
        raise RestoreError("invalid restore operation path")
    plan_path = operation / "plan.json"
    if plan_path.is_symlink() or plan_path.stat().st_size > 1024 * 1024:
        raise RestoreError("invalid restore plan")
    collection = _safe_collection(operation.parent.parent)
    with collection_lock(collection):
        _finish_restore(operation, ledger_io.loads_json(plan_path.read_bytes()))


def activate(workspace: Path, *, apply: bool, acknowledge: bool) -> dict[str, Any]:
    workspace = workspace.absolute()
    if apply:
        with collection_lock(_safe_collection(workspace.parent)):
            return _activate_locked(workspace, apply=True, acknowledge=acknowledge)
    return _activate_locked(workspace, apply=False, acknowledge=acknowledge)


def _activate_locked(workspace: Path, *, apply: bool, acknowledge: bool) -> dict[str, Any]:
    record = state(workspace)
    if record is None:
        raise RestoreError("workspace is not a restored module")
    validate_restored(workspace)
    if apply:
        if not acknowledge:
            raise RestoreError("activation requires --ack-new-runtime; old sessions and authorizations remain historical")
        if record["status"] != "active":
            record = {**record, "status": "active"}
            _replace_state_file(workspace / STATE, json.dumps(record, sort_keys=True).encode())
    return {"status": record["status"], "instance_id": record["instance_id"], "environment": f"CYBER_WORKSPACE_INSTANCE={record['instance_id']}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("--checkpoint", type=Path, required=True)
    restore_parser.add_argument("--collection", type=Path, required=True)
    restore_parser.add_argument("--module", required=True)
    activation = commands.add_parser("activate")
    activation.add_argument("--workspace", type=Path, required=True)
    activation.add_argument("--ack-new-runtime", action="store_true")
    for command in (restore_parser, activation):
        mode = command.add_mutually_exclusive_group(required=True)
        mode.add_argument("--preview", action="store_true")
        mode.add_argument("--apply", action="store_true")
    recovery = commands.add_parser("resume")
    recovery.add_argument("--operation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "restore":
            result = restore(args.checkpoint, args.collection, args.module, apply=args.apply)
        elif args.command == "activate":
            result = activate(args.workspace, apply=args.apply, acknowledge=args.ack_new_runtime)
        else:
            resume(args.operation)
            result = {"status": "restored-inactive"}
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, RuntimeError, ledger_io.LedgerIOError, create_checkpoint.CheckpointError, create_checkpoint.TraversalError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
