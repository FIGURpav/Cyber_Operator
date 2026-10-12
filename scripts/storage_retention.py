"""Account for private recovery storage and prune explicitly reviewed duplicate bytes."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import (
        artifact_io,
        create_checkpoint,
        host_identity,
        restore_checkpoint,
        workspace_health,
    )
    from . import workspace_transaction as tx
else:
    import artifact_io
    import create_checkpoint
    import host_identity
    import restore_checkpoint
    import workspace_health
    import workspace_transaction as tx

RST_RE = re.compile(r"RST-[0-9a-f]{32}")
COPY_RE = re.compile(r"copy-[0-9a-f]{32}")
MAX_ENTRIES = 50000
MAX_HASH_BYTES = 2 * 1024**3


class RetentionError(OSError):
    """A retention conflict; canonical data and unknown files must remain intact."""


def _encoded(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _private(path: Path, *, directory: bool) -> os.stat_result:
    metadata = path.lstat()
    valid = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (not valid or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != (0o700 if directory else 0o600)
            or (not directory and metadata.st_nlink != 1)):
        raise RetentionError("retention requires dedicated owner-only regular files and real directories")
    return metadata


def _walk(root: Path, budget: list[int] | None = None) -> list[tuple[Path, os.stat_result]]:
    """Inventory metadata without following links, mounts or unbounded trees."""
    base = _private(root, directory=True)
    budget = [MAX_ENTRIES] if budget is None else budget
    pending, result = [root], []
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                if budget[0] <= 0:
                    raise RetentionError("storage inventory exceeds its entry limit")
                budget[0] -= 1
                path = Path(entry.path)
                metadata = _private(path, directory=entry.is_dir(follow_symlinks=False))
                if metadata.st_dev != base.st_dev:
                    raise RetentionError("storage inventory crosses a filesystem boundary")
                result.append((path, metadata))
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
    return sorted(result)


def _measure(root: Path, budget: list[int]) -> dict[str, int]:
    entries = _walk(root, budget)
    return {
        "logical_bytes": sum(info.st_size for _, info in entries if stat.S_ISREG(info.st_mode)),
        "allocated_bytes": sum(info.st_blocks * 512 for _, info in entries) + root.stat().st_blocks * 512,
        "file_count": sum(stat.S_ISREG(info.st_mode) for _, info in entries),
    }


def _children(root: Path, pattern: re.Pattern, budget: list[int]) -> list[Path]:
    if not root.exists() and not root.is_symlink():
        return []
    _private(root, directory=True)
    result = []
    with os.scandir(root) as entries:
        for entry in entries:
            if budget[0] <= 0:
                raise RetentionError("storage inventory exceeds its entry limit")
            budget[0] -= 1
            if pattern.fullmatch(entry.name):
                path = Path(entry.path)
                _private(path, directory=True)
                result.append(path)
    return sorted(result)


def _volume(root: Path) -> dict[str, int]:
    info = os.statvfs(root)
    return {"available_bytes": info.f_bavail * info.f_frsize, "total_bytes": info.f_blocks * info.f_frsize}


def inventory(workspace: Path, collection: Path | None = None) -> dict[str, Any]:
    workspace = host_identity.validate_workspace(workspace)
    records = []
    budget = [MAX_ENTRIES]
    with workspace_health._existing_read_lock(workspace / ".workspace_mutation.lock"):
        for category, relative in (("journal", tx.DIRECTORY), ("quarantine", Path("private/transaction_orphans"))):
            root = tx.safe_path(workspace, relative.as_posix())
            for directory in _children(root, tx.ID_RE, budget):
                state = "quarantined" if category == "quarantine" else "pending"
                if category == "journal" and (directory / "COMMITTED.json").exists():
                    state = "committed"
                    if (directory / "COMPACTION.json").exists():
                        state = "compacted" if (directory / "COMPACTED.json").exists() else "compacting"
                records.append({"category": category, "id": directory.name, "state": state, **_measure(directory, budget)})
    result = {"schema_version": "1.0", "workspace_volume": _volume(workspace), "items": records}
    if collection is not None:
        collection = restore_checkpoint._safe_collection(collection)
        with workspace_health._existing_read_lock(collection / ".restore.lock"):
            for operation in _children(collection / "_archive", RST_RE, budget):
                for directory in _children(operation, COPY_RE, budget):
                    records.append({"category": "restore-copy", "operation": operation.name,
                                    "id": directory.name, "state": "retained", **_measure(directory, budget)})
        result["collection_volume"] = _volume(collection)
    result["logical_bytes"] = sum(item["logical_bytes"] for item in records)
    result["allocated_bytes"] = sum(item["allocated_bytes"] for item in records)
    result["item_count"] = len(records)
    result["details_truncated"] = len(records) > 50
    result["items"] = sorted(records, key=lambda item: item["logical_bytes"], reverse=True)[:50]
    return result


def _signature(path: Path) -> dict[str, Any]:
    before = _private(path, directory=False)
    if before.st_size > MAX_HASH_BYTES:
        raise RetentionError("retention hashing exceeds its byte limit")
    size, digest = create_checkpoint._file_digest(path)
    after = _private(path, directory=False)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise RetentionError("retention candidate changed during verification")
    return {"size_bytes": size, "sha256": digest, "device": after.st_dev,
            "inode": after.st_ino, "mtime_ns": after.st_mtime_ns}


def _age(receipt: Path, days: int) -> None:
    if not 0 <= days <= 36500:
        raise RetentionError("minimum age must be between 0 and 36500 days")
    if datetime.now(UTC).timestamp() - receipt.stat().st_mtime < days * 86400:
        raise RetentionError("operation is younger than the selected minimum age")


def _job(base: Path, path: Path, kind: str, source_hash: str, candidates: list[dict[str, Any]] | None,
         days: int) -> dict[str, Any]:
    if path.exists() or path.is_symlink():
        _private(path, directory=False)
        job = tx._json(path)
    else:
        job = {"schema_version": "1.0", "kind": kind, "source_sha256": source_hash,
               "target_id": base.name, "min_age_days": days, "files": candidates}
    if (set(job) != {"schema_version", "kind", "source_sha256", "target_id", "min_age_days", "files"}
            or job["schema_version"] != "1.0" or job["kind"] != kind or job["target_id"] != base.name
            or job["source_sha256"] != source_hash or job["min_age_days"] != days
            or type(job["min_age_days"]) is not int or not 0 <= job["min_age_days"] <= 36500
            or not isinstance(job["files"], list) or len(job["files"]) > MAX_ENTRIES):
        raise RetentionError("retention plan does not match the selected operation")
    seen = set()
    for item in job["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256", "device", "inode", "mtime_ns"}:
            raise RetentionError("retention file record is malformed")
        tx.safe_path(base, item["path"])
        if item["path"] in seen or any(type(item[key]) is not int or item[key] < 0 for key in ("size_bytes", "device", "inode", "mtime_ns")):
            raise RetentionError("retention file identity is malformed")
        if not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise RetentionError("retention file hash is malformed")
        seen.add(item["path"])
    if len(_encoded(job)) > tx.MAX_PLAN:
        raise RetentionError("retention plan exceeds its metadata limit")
    return job


def _trash(path: Path, plan_hash: str) -> Path:
    digest = hashlib.sha256((path.name + plan_hash).encode()).hexdigest()
    return path.with_name(".retention-" + digest)


def _after_quarantine(_path: Path) -> None:
    """Synthetic process-death test seam."""


def _unlink_candidate(path: Path, item: dict[str, Any], plan_hash: str) -> None:
    trash = _trash(path, plan_hash)
    expected = {key: value for key, value in item.items() if key != "path"}
    if not trash.exists():
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (item["device"], item["inode"]):
                raise RetentionError("retention source identity changed before quarantine")
            libc = ctypes.CDLL(None, use_errno=True)
            rename = getattr(libc, "renameat2", None)
            if rename is None or rename(descriptor, os.fsencode(path.name), descriptor, os.fsencode(trash.name), 1) != 0:
                raise RetentionError("cannot quarantine retention candidate without replacement")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _after_quarantine(trash)
    if _signature(trash) != expected:
        raise RetentionError("quarantined entry changed; preserve it for manual review")
    trash.unlink()
    tx._sync_directory(trash.parent)
    _after_unlink(path)


def _after_unlink(_path: Path) -> None:
    """Synthetic process-death test seam."""


def _prune(base: Path, plan_path: Path, completion: Path, job: dict[str, Any], *, apply: bool,
           expected_hash: str | None) -> dict[str, Any]:
    plan_hash = tx.digest(_encoded(job))
    receipt = {"plan_sha256": plan_hash, "target_id": base.name}
    if completion.exists() or completion.is_symlink():
        _private(completion, directory=False)
        if tx._json(completion) != receipt:
            raise RetentionError("retention completion receipt is invalid")
        return {"status": "already-pruned", "plan_hash": plan_hash, "removed_files": len(job["files"])}
    pending = []
    for item in job["files"]:
        path = tx.safe_path(base, item["path"])
        trash = _trash(path, plan_hash)
        if trash.is_symlink() or path.is_symlink():
            raise RetentionError("retention candidate is a symlink")
        if path.exists() and trash.exists():
            raise RetentionError("retention source and quarantine name both exist")
        candidate = trash if trash.exists() else path
        if candidate.exists():
            if _signature(candidate) != {key: value for key, value in item.items() if key != "path"}:
                raise RetentionError("retention candidate changed after preview")
            pending.append((path, item))
        elif not plan_path.exists():
            raise RetentionError("retention candidate disappeared before preparation")
    result = {"status": "preview", "plan_hash": plan_hash, "candidate_files": len(pending),
              "candidate_bytes": sum(item["size_bytes"] for _, item in pending),
              "retained_audit": True}
    if not apply:
        return result
    if expected_hash != plan_hash:
        raise RetentionError("apply requires the exact --plan-hash returned by preview")
    if not plan_path.exists():
        artifact_io.publish_file(plan_path, _encoded(job))
    for path, item in pending:
        _unlink_candidate(path, item, plan_hash)
    artifact_io.publish_file(completion, _encoded(receipt))
    return {**result, "status": "pruned"}


def _committed(workspace: Path, identifier: str) -> tuple[Path, dict[str, Any], str]:
    directory, plan = tx._load_plan(workspace, identifier, verify_payloads=False, relocated=True)
    _private(directory, directory=True)
    _private(directory / "plan.json", directory=False)
    _private(directory / "COMMITTED.json", directory=False)
    plan_hash = tx.digest(tx.read_file(directory / "plan.json", tx.MAX_PLAN))
    if tx._json(directory / "COMMITTED.json") != {"transaction_id": identifier, "plan_sha256": plan_hash}:
        raise RetentionError("only verified committed transactions can be compacted")
    return directory, plan, plan_hash


def validate_compaction(workspace: Path, identifier: str) -> dict[str, Any]:
    directory, plan, source_hash = _committed(workspace, identifier)
    stored = tx._json(directory / "COMPACTION.json")
    job = _job(directory, directory / "COMPACTION.json", "transaction", source_hash, None, stored.get("min_age_days"))
    expected = {item["payload"]: (item["size"], item["sha256"]) for item in plan["operations"]}
    actual = {item["path"]: (item["size_bytes"], item["sha256"]) for item in job["files"]}
    if actual != expected:
        raise RetentionError("compaction must match the original transaction payloads exactly")
    receipt = directory / "COMPACTED.json"
    if receipt.exists() or receipt.is_symlink():
        _private(receipt, directory=False)
        if tx._json(receipt) != {"plan_sha256": tx.digest(_encoded(job)), "target_id": directory.name}:
            raise RetentionError("compaction completion receipt is invalid")
    for item in job["files"]:
        path = tx.safe_path(directory, item["path"])
        trash = _trash(path, tx.digest(_encoded(job)))
        if path.exists() and trash.exists():
            raise RetentionError("compaction source and quarantine name both exist")
        for candidate in (path, trash):
            if candidate.exists() or candidate.is_symlink():
                # A verified restore changes inode/timestamps. Replay is read-only
                # for committed journals; deletion still requires exact identity.
                signature = _signature(candidate)
                if (signature["size_bytes"], signature["sha256"]) != (item["size_bytes"], item["sha256"]):
                    raise RetentionError("remaining compacted payload has changed")
    return job


def _retained_operation(workspace: Path, operation: dict[str, Any]) -> None:
    path = tx.safe_path(workspace, operation["destination"] if operation["action"] == "move" else operation["path"])
    raw = tx.read_file(path)
    if operation["action"] == "append":
        size = operation["before_size"]
        raw = raw[size:size + operation["size"]]
    if len(raw) != operation["size"] or tx.digest(raw) != operation["sha256"]:
        raise RetentionError("payload has no identical retained canonical copy; keep this journal")


def compact(workspace: Path, identifier: str, *, apply: bool, expected_hash: str | None = None,
            min_age_days: int = 7) -> dict[str, Any]:
    workspace = host_identity.validate_workspace(workspace)
    guard = tx.write_guard(workspace) if apply else workspace_health._existing_read_lock(workspace / ".workspace_mutation.lock")
    with guard:
        if __package__:
            from . import retention_policy
        else:
            import retention_policy
        retention_policy.require_clear(workspace,identifier)
        directory, plan, source_hash = _committed(workspace, identifier)
        _private(directory, directory=True)
        plan_path = directory / "COMPACTION.json"
        candidates = None
        if not plan_path.exists():
            _age(directory / "COMMITTED.json", min_age_days)
            tx._load_plan(workspace, identifier, relocated=True)
            candidates = [{"path": item["payload"], **_signature(directory / item["payload"])} for item in plan["operations"]]
        job = _job(directory, plan_path, "transaction", source_hash, candidates, min_age_days)
        expected = {item["payload"]: (item["size"], item["sha256"]) for item in plan["operations"]}
        if {item["path"]: (item["size_bytes"], item["sha256"]) for item in job["files"]} != expected:
            raise RetentionError("compaction does not match retained transaction")
        for operation in plan["operations"]:
            if ((directory / operation["payload"]).exists()
                    or _trash(directory / operation["payload"], tx.digest(_encoded(job))).exists()):
                _retained_operation(workspace, operation)
        return _prune(directory, plan_path, directory / "COMPACTED.json", job, apply=apply, expected_hash=expected_hash)


def prune_restore(collection: Path, operation_id: str, copy_id: str, *, apply: bool,
                  expected_hash: str | None = None, min_age_days: int = 7) -> dict[str, Any]:
    collection = restore_checkpoint._safe_collection(collection)
    if RST_RE.fullmatch(operation_id) is None or COPY_RE.fullmatch(copy_id) is None:
        raise RetentionError("invalid restore operation or copy ID")
    guard = restore_checkpoint.collection_lock(collection) if apply else workspace_health._existing_read_lock(collection / ".restore.lock")
    with guard:
        operation = tx.safe_path(collection, f"_archive/{operation_id}")
        directory = tx.safe_path(collection, f"_archive/{operation_id}/{copy_id}")
        _private(operation, directory=True)
        _private(operation / "plan.json", directory=False)
        _private(operation / "COMMITTED.json", directory=False)
        plan = tx._json(operation / "plan.json")
        fields = {"status", "destination", "checkpoint_id", "profile", "instance_id", "checkpoint", "checkpoint_manifest_sha256"}
        if (set(plan) != fields or not all(isinstance(value, str) for value in plan.values())
                or re.fullmatch(r"WSI-[0-9a-f]{32}", plan["instance_id"]) is None
                or Path(plan["destination"]).parent != collection
                or not Path(plan["checkpoint"]).is_absolute()):
            raise RetentionError("restore retention plan has invalid identity or schema")
        source_hash = tx.digest(tx.read_file(operation / "plan.json", tx.MAX_PLAN))
        if tx._json(operation / "COMMITTED.json") != {"instance_id": plan.get("instance_id"), "plan_sha256": source_hash}:
            raise RetentionError("restore must be committed before staging can be pruned")
        checkpoint = Path(plan["checkpoint"])
        if __package__:
            from . import retention_policy
        else:
            import retention_policy
        for retained_workspace in (Path(plan['destination']),checkpoint / 'workspace'):
            if retained_workspace.exists():
                retention_policy.require_clear(retained_workspace)
        manifest = create_checkpoint.verify_checkpoint(checkpoint)
        if plan["checkpoint_id"] != manifest["checkpoint_id"] or plan["profile"] != manifest["operational_profile"]:
            raise RetentionError("retained checkpoint identity or profile differs from restore")
        if restore_checkpoint._manifest_hash(checkpoint) != plan["checkpoint_manifest_sha256"]:
            raise RetentionError("retained checkpoint differs from the restore source")
        retained = {"workspace/" + item["path"]: item for item in manifest["files"]}
        entries = _walk(directory)
        if sum(info.st_size for _, info in entries if stat.S_ISREG(info.st_mode)) > MAX_HASH_BYTES:
            raise RetentionError("restore staging exceeds the retention hashing budget")
        plan_path = operation / f"PRUNE-{copy_id}.json"
        candidates = None
        if not plan_path.exists():
            _age(operation / "COMMITTED.json", min_age_days)
            candidates = []
            for path, info in entries:
                relative = path.relative_to(directory).as_posix()
                original = retained.get(relative)
                if not stat.S_ISREG(info.st_mode) or original is None:
                    continue
                signature = _signature(path)
                if signature["size_bytes"] == original["size_bytes"] and signature["sha256"] == original["sha256"]:
                    candidates.append({"path": relative, **signature})
        job = _job(directory, plan_path, "restore-copy", source_hash, candidates, min_age_days)
        for item in job["files"]:
            original = retained.get(item["path"])
            if original is None or (item["size_bytes"], item["sha256"]) != (original["size_bytes"], original["sha256"]):
                raise RetentionError("restore cleanup includes bytes not retained in the verified checkpoint")
        return _prune(directory, plan_path, operation / f"PRUNED-{copy_id}.json", job, apply=apply, expected_hash=expected_hash)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    usage = sub.add_parser("usage", help="read-only recovery-storage inventory")
    usage.add_argument("--workspace", type=Path, required=True)
    usage.add_argument("--collection", type=Path)
    compact_parser = sub.add_parser("compact", help="remove duplicate payloads from one committed journal")
    compact_parser.add_argument("--workspace", type=Path, required=True)
    compact_parser.add_argument("--transaction", required=True)
    prune = sub.add_parser("prune-restore", help="remove checkpoint-identical files from one completed restore's staging copy")
    prune.add_argument("--collection", type=Path, required=True)
    prune.add_argument("--operation", required=True)
    prune.add_argument("--copy", required=True)
    for command in (compact_parser, prune):
        mode = command.add_mutually_exclusive_group(required=True)
        mode.add_argument("--preview", action="store_true")
        mode.add_argument("--apply", action="store_true")
        command.add_argument("--plan-hash")
        command.add_argument("--min-age-days", type=int, default=7)
    args = parser.parse_args(argv)
    try:
        if args.command == "usage":
            result = inventory(args.workspace, args.collection)
        else:
            options = {"apply": args.apply, "expected_hash": args.plan_hash, "min_age_days": args.min_age_days}
            result = compact(args.workspace, args.transaction, **options) if args.command == "compact" else prune_restore(args.collection, args.operation, args.copy, **options)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError,
            create_checkpoint.CheckpointError, create_checkpoint.TraversalError) as exc:
        # A malformed private path/record must never echo arbitrary secret-bearing values.
        message = str(exc) if isinstance(exc, RetentionError) else "storage state could not be verified; preserve it and inspect the selected operation"
        print(f"error: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
