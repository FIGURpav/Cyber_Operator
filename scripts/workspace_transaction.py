"""Durable, resumable local file transactions; never execute journal content."""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

if __package__:
    from . import artifact_io, ledger_io
else:
    import artifact_io
    import ledger_io

DIRECTORY = Path("private/transactions")
ID_RE = re.compile(r"^TXN-[0-9a-f]{32}$")
MAX_PLAN = 4 * 1024 * 1024
MAX_PAYLOAD = 64 * 1024 * 1024
KINDS = {"evidence", "screenshot", "host-merge", "engagement-config", "assessment-record", "assessment-report", "assessment-activity", "workspace-vault", "vault-disclosure"}
_HELD: contextvars.ContextVar[tuple[Path, ...]] = contextvars.ContextVar("transaction_locks", default=())


class TransactionError(RuntimeError):
    """An incomplete or conflicting local transaction needs recovery."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise TransactionError("transaction path must be text")
    path = Path(relative)
    if (
        not relative or path.is_absolute() or path.as_posix() != relative
        or ".." in path.parts or "\\" in relative or relative == "."
    ):
        raise TransactionError("transaction path is not canonical")
    target = root / path
    for component in (root, *root.parents, *[root / Path(*path.parts[:n]) for n in range(1, len(path.parts) + 1)]):
        if component.is_symlink():
            raise TransactionError("transaction path contains a symlink")
    return target


def read_file(path: Path, maximum: int = MAX_PAYLOAD) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise TransactionError("transaction file is not a bounded regular file")
        raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise TransactionError("transaction file grew beyond its limit")
        return raw


def _json(path: Path) -> dict[str, Any]:
    value = ledger_io.loads_json(read_file(path, MAX_PLAN))
    if not isinstance(value, dict):
        raise TransactionError("transaction record must be an object")
    return value


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise TransactionError("private transaction directory is a symlink")
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise TransactionError("transaction directory must use mode 0700")
    _sync_directory(path.parent)


def held(workspace: Path) -> bool:
    return workspace.absolute() in _HELD.get()


def incomplete(workspace: Path) -> list[str]:
    directory = safe_path(workspace, DIRECTORY.as_posix())
    if not directory.exists():
        return []
    if not directory.is_dir():
        raise TransactionError("transaction root is not a directory")
    result = []
    for path in sorted(directory.iterdir()):
        if ID_RE.fullmatch(path.name) is None:
            raise TransactionError("unexpected transaction directory entry")
        if path.is_symlink() or not path.is_dir():
            raise TransactionError("transaction entry must be a real directory")
        receipt = path / "COMMITTED.json"
        if receipt.exists() or receipt.is_symlink():
            expected = {"transaction_id": path.name, "plan_sha256": digest(read_file(path / "plan.json", MAX_PLAN))}
            if _json(receipt) != expected:
                raise TransactionError("transaction completion receipt is invalid")
        else:
            result.append(path.name)
    return result


@contextlib.contextmanager
def write_guard(workspace: Path, *, recovery: bool = False) -> Iterator[None]:
    root = workspace.absolute()
    if held(root):
        yield
        return
    if __package__:
        from . import restore_checkpoint, stream_coordination
    else:
        import restore_checkpoint
        import stream_coordination
    restore_checkpoint.require_write_instance(root)
    if root.is_symlink() or not root.is_dir():
        raise TransactionError("workspace must be a real directory")
    descriptor = os.open(root / ".workspace_mutation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    token = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        info = os.fstat(descriptor)
        current = (root / ".workspace_mutation.lock").lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise TransactionError("workspace lock identity is invalid")
        os.fchmod(descriptor, 0o600)
        if not recovery and incomplete(root):
            raise TransactionError("workspace has an unfinished transaction; use cyber-recovery inspect/apply")
        coordination = root / stream_coordination.COORDINATION_RELATIVE / stream_coordination.SESSION_FILE
        guard = stream_coordination.writer_guard_from_environment(root) if coordination.exists() else contextlib.nullcontext()
        with guard:
            token = _HELD.set((*_HELD.get(), root))
            yield
    finally:
        if token is not None:
            _HELD.reset(token)
        os.close(descriptor)


def _allowed(kind: str, operation: dict[str, Any]) -> bool:
    path = operation["path"]
    action = operation["action"]
    destination = operation["destination"]
    if not isinstance(path, str) or not isinstance(action, str):
        return False
    if action == "move":
        if not isinstance(destination, str):
            return False
    elif destination is not None:
        return False
    if kind == "engagement-config":
        return (
            (action == "append" and path == "engagement_events.jsonl")
            or (action in {"create", "replace"} and path == "engagement.json")
            or (action == "replace" and path == "TASK_CONTEXT.md")
        )
    if kind == 'assessment-record':
        return action == 'append' and path == 'assessment_events.jsonl'
    if kind == 'workspace-vault':
        return ((action=='append' and path=='private/vault/credentials.jsonl')
                or (action=='create' and bool(re.fullmatch(r'private/vault/(?:values/SEC-[0-9a-f]{32}\.secret|checkpoints/[0-9a-f]{64}\.jsonl)',path))))
    if kind == 'vault-disclosure':
        return ((action=='append' and path=='assessment_events.jsonl')
                or (action=='create' and bool(re.fullmatch(r'private/vault/exports/EXP-[0-9a-f]{32}\.json',path))))
    if kind == 'assessment-activity':
        return action == 'append' and path in {'assessment_events.jsonl','attempts.jsonl','work_items.jsonl','local_artifacts.jsonl'}
    if kind == 'assessment-report':
        return action == 'create' and bool(re.fullmatch(r'report/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:html|json|svg)',path))
    if kind == "evidence":
        return action == "create" and path.startswith("evidence/")
    if kind == "screenshot":
        return (
            (action == "create" and path.startswith("evidence/"))
            or (action == "append" and path == "screenshot_requests.jsonl")
            or (action == "move" and path.startswith("inbox/screenshots/pending/")
                and operation["destination"].startswith(("inbox/screenshots/processed/", "inbox/screenshots/invalid/")))
        )
    return (
        (action == "append" and path == "host_merges.jsonl")
        or (action == "replace" and path.startswith("hosts/") and len(Path(path).parts) == 2)
        or (action == "move" and path.startswith("hosts/") and len(Path(path).parts) == 2
            and operation["destination"].startswith("hosts/_merged/"))
    )


class Transaction:
    def __init__(self, workspace: Path, kind: str, *, references: dict[str, Any] | None = None) -> None:
        if kind not in KINDS or not held(workspace):
            raise TransactionError("transaction requires a recognized kind and workspace writer guard")
        self.workspace = workspace.absolute()
        self.identifier = "TXN-" + uuid.uuid4().hex
        self.kind = kind
        self.references = references or {}
        self.operations: list[dict[str, Any]] = []
        self.payloads: list[bytes] = []

    def add(self, action: str, path: Path, raw: bytes | None = None, *, destination: Path | None = None) -> None:
        relative = path.relative_to(self.workspace).as_posix()
        target = safe_path(self.workspace, relative)
        existing = read_file(target) if target.exists() else None
        # Appends to the same ledger have sequential expected prefixes.
        for earlier, payload in zip(self.operations, self.payloads, strict=True):
            if earlier["path"] == relative and earlier["action"] == "append":
                existing = (existing or b"") + payload
        if action == "create" and (existing is not None or target.is_symlink()):
            raise TransactionError("transaction destination already exists")
        if action in {"move", "replace"} and existing is None:
            raise TransactionError("transaction source is missing")
        if action == "move" and raw is not None and raw != existing:
            raise TransactionError("transaction move source changed after review")
        payload = existing if action == "move" else raw
        if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
            raise TransactionError("transaction payload is missing or too large")
        operation = {
            "action": action, "path": relative,
            "before_sha256": digest(existing) if existing is not None else None,
            "before_size": len(existing) if existing is not None else 0,
            "payload": f"{len(self.payloads):04d}.bin", "sha256": digest(payload), "size": len(payload),
            "destination": destination.relative_to(self.workspace).as_posix() if destination else None,
        }
        if destination is not None:
            dest = safe_path(self.workspace, operation["destination"])
            if dest.exists():
                raise TransactionError("transaction move destination already exists")
        if not _allowed(self.kind, operation):
            raise TransactionError("transaction operation is outside its typed storage scope")
        self.operations.append(operation)
        self.payloads.append(payload)

    def commit(self) -> str:
        directory = self.workspace / DIRECTORY
        _private_directory(self.workspace / "private")
        _private_directory(directory)
        staging = directory / self.identifier
        _private_directory(staging)
        for operation, payload in zip(self.operations, self.payloads, strict=True):
            artifact_io.publish_file(staging / operation["payload"], payload)
        plan = {
            "schema_version": "1.0", "transaction_id": self.identifier,
            "workspace": str(self.workspace), "kind": self.kind,
            "references": self.references, "operations": self.operations,
        }
        artifact_io.publish_file(staging / "plan.json", json.dumps(plan, sort_keys=True))
        return replay(self.workspace, self.identifier)


def _load_plan(workspace: Path, identifier: str, *, verify_payloads: bool = True, relocated: bool = False) -> tuple[Path, dict[str, Any]]:
    if ID_RE.fullmatch(identifier) is None:
        raise TransactionError("invalid TXN-ID")
    directory = safe_path(workspace, (DIRECTORY / identifier).as_posix())
    plan = _json(directory / "plan.json")
    if (
        set(plan) != {"schema_version", "transaction_id", "workspace", "kind", "references", "operations"}
        or plan["schema_version"] != "1.0" or plan["transaction_id"] != identifier
        or (not relocated and plan["workspace"] != str(workspace.absolute()))
        or not isinstance(plan["kind"], str) or plan["kind"] not in KINDS
        or not isinstance(plan["operations"], list) or not 1 <= len(plan["operations"]) <= 16
        or not isinstance(plan["references"], dict)
    ):
        raise TransactionError("transaction plan has invalid identity or schema")
    for index, operation in enumerate(plan["operations"]):
        if not isinstance(operation, dict) or set(operation) != {
            "action", "path", "before_sha256", "before_size", "payload", "sha256", "size", "destination",
        }:
            raise TransactionError("transaction operation has invalid schema")
        if (
            type(operation["size"]) is not int or not 0 <= operation["size"] <= MAX_PAYLOAD
            or type(operation["before_size"]) is not int or not 0 <= operation["before_size"] <= MAX_PAYLOAD
            or not isinstance(operation["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", operation["sha256"]) is None
            or (operation["before_sha256"] is not None and (not isinstance(operation["before_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", operation["before_sha256"]) is None))
        ):
            raise TransactionError("transaction hashes or sizes are malformed")
        if operation["payload"] != f"{index:04d}.bin" or not _allowed(plan["kind"], operation):
            raise TransactionError("transaction operation is outside its typed storage scope")
        safe_path(workspace, operation["path"])
        if operation["destination"] is not None:
            safe_path(workspace, operation["destination"])
        if verify_payloads:
            raw = read_file(directory / operation["payload"])
            if len(raw) != operation["size"] or digest(raw) != operation["sha256"]:
                raise TransactionError("transaction payload integrity failure")
    if verify_payloads:
        _validate_payload_contract(directory, plan)
    return directory, plan


def _validate_payload_contract(directory: Path, plan: dict[str, Any]) -> None:
    creates = {item["path"]: read_file(directory / item["payload"]) for item in plan["operations"] if item["action"] == "create"}
    for path, raw in creates.items():
        if path.startswith("evidence/") and path.endswith(".json"):
            metadata = ledger_io.loads_json(raw)
            if not isinstance(metadata, dict) or metadata.get("artifact_path") not in creates:
                raise TransactionError("evidence metadata has no prepared artifact")
            artifact = creates[metadata["artifact_path"]]
            if metadata.get("sha256") != digest(artifact) or metadata.get("size_bytes") != len(artifact):
                raise TransactionError("evidence metadata differs from prepared bytes")
    for operation in plan["operations"]:
        if operation["action"] != "append":
            continue
        payload = read_file(directory / operation["payload"])
        if not payload.endswith(b"\n") or len(payload.splitlines()) != 1:
            raise TransactionError("transaction ledger payload must be exactly one terminated JSON record")
        record = ledger_io.loads_json(payload)
        if not isinstance(record, dict):
            raise TransactionError("transaction ledger record must be an object")
        if plan['kind'] in {'assessment-record','assessment-activity','vault-disclosure'} and operation['path']=='assessment_events.jsonl':
            if __package__:
                from . import assessment_journal
            else:
                import assessment_journal
            assessment_journal.validate_event(record)
        if plan["kind"] == "engagement-config":
            if __package__:
                from . import engagement_config
            else:
                import engagement_config
            unhashed = {key: value for key, value in record.items() if key != "event_sha256"}
            if record.get("event_sha256") != engagement_config.digest(unhashed):
                raise TransactionError("configuration event hash differs from prepared bytes")
            writes = {item["path"]: read_file(directory / item["payload"]) for item in plan["operations"] if item["action"] in {"create", "replace"}}
            if record.get("event") in {"created", "approved"}:
                definition = engagement_config.validate(record.get("definition"))
                if set(writes) != {"engagement.json", "TASK_CONTEXT.md"} or ledger_io.loads_json(writes["engagement.json"]) != definition:
                    raise TransactionError("configuration snapshot differs from the prepared event")
                context = writes["TASK_CONTEXT.md"].decode("utf-8")
                if engagement_config.render_context(context, definition) != context:
                    raise TransactionError("configuration context differs from the prepared snapshot")
            elif writes:
                raise TransactionError("an unapproved event cannot replace the configuration")
        if plan["kind"] == "screenshot":
            if __package__:
                from . import screenshot_workflow
            else:
                import screenshot_workflow
            screenshot_workflow._validate_event(record, 1)
            if not any(item["action"] == "move" and item["sha256"] == record["sha256"] for item in plan["operations"]):
                raise TransactionError("screenshot move differs from reviewed bytes")
            if record["event"] == "captured":
                refs = plan["references"]
                if (refs.get("visual_reviewed") is not True or refs.get("reviewed_png_sha256") != record["sha256"]
                        or (record.get("contains_secrets") and refs.get("secret_scope_reviewed") is not True)):
                    raise TransactionError("screenshot transaction has no matching retained review")
                if not any(digest(raw) == record["sha256"] for name, raw in creates.items() if name.endswith(".png")):
                    raise TransactionError("reviewed PNG is missing from screenshot transaction")


def _after_operation(_identifier: str, _index: int) -> None:
    """Fault-injection seam used only by synthetic subprocess tests."""


def _apply(workspace: Path, directory: Path, operation: dict[str, Any]) -> None:
    path = safe_path(workspace, operation["path"])
    payload = read_file(directory / operation["payload"])
    current = read_file(path) if path.exists() else None
    action = operation["action"]
    if action == "append":
        size = operation["before_size"]
        before_hash = operation["before_sha256"]
        raw = current or b""
        if len(raw) < size or digest(raw[:size]) != (before_hash or digest(b"")):
            raise TransactionError("ledger prefix conflicts with the prepared transaction")
        tail = raw[size:]
        if tail.startswith(payload):
            return
        if not payload.startswith(tail):
            raise TransactionError("ledger tail conflicts with the prepared transaction")
        ledger_io.loads_json(payload)
        if path.exists() and path.stat().st_nlink != 1:
            raise TransactionError("ledger must not have external hardlinks")
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(payload[len(tail):])
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(path.parent)
        return
    if action == "move":
        destination = safe_path(workspace, operation["destination"])
        if destination.exists():
            if read_file(destination) != payload:
                raise TransactionError("move destination conflicts with the prepared transaction")
            if current is None:
                return
        elif current == payload:
            _private_directory(destination.parent)
            os.link(path, destination, follow_symlinks=False)
            _sync_directory(destination.parent)
        else:
            raise TransactionError("transaction move source is missing or changed")
        if current != payload:
            raise TransactionError("transaction move source changed")
        path.unlink()
        _sync_directory(destination.parent)
        _sync_directory(path.parent)
        return
    if current == payload:
        return
    if (digest(current) if current is not None else None) != operation["before_sha256"]:
        raise TransactionError("file conflicts with the prepared transaction")
    if action == "create":
        artifact_io.publish_file(path, payload)
    elif action == "replace":
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            artifact_io.publish_file(temporary, payload)
            os.replace(temporary, path)
            _sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        raise TransactionError("unknown transaction action")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rebuild(workspace: Path, plan: dict[str, Any]) -> None:
    if plan["kind"] in {"screenshot", "host-merge"}:
        if __package__:
            from . import screenshot_workflow
        else:
            import screenshot_workflow
        ledger = workspace / screenshot_workflow.LEDGER_NAME
        if ledger.exists():
            events = screenshot_workflow._load_events(ledger)
            if events:
                screenshot_workflow._rebuild_index(workspace, events)
                host_id = plan["references"].get("host_id")
                if isinstance(host_id, str):
                    screenshot_workflow._update_host_report(workspace, host_id, events)


def replay(workspace: Path, identifier: str) -> str:
    with write_guard(workspace, recovery=True):
        if ID_RE.fullmatch(identifier) is None:
            raise TransactionError("invalid TXN-ID")
        directory = safe_path(workspace, (DIRECTORY / identifier).as_posix())
        if (directory / "COMPACTION.json").exists() or (directory / "COMPACTION.json").is_symlink():
            if __package__:
                from . import storage_retention
            else:
                import storage_retention
            storage_retention.validate_compaction(workspace, identifier)
            return identifier
        directory, plan = _load_plan(workspace, identifier)
        receipt = directory / "COMMITTED.json"
        plan_hash = digest(read_file(directory / "plan.json", MAX_PLAN))
        if receipt.exists():
            if _json(receipt) != {"transaction_id": identifier, "plan_sha256": plan_hash}:
                raise TransactionError("transaction completion receipt is invalid")
            return identifier
        # Validate every payload before any replay writes. Disk effects are checked per operation.
        for index, operation in enumerate(plan["operations"]):
            _apply(workspace, directory, operation)
            _after_operation(identifier, index)
        _rebuild(workspace, plan)
        artifact_io.publish_file(receipt, json.dumps({"transaction_id": identifier, "plan_sha256": plan_hash}))
        return identifier


def quarantine_staging(workspace: Path, identifier: str) -> None:
    """Retain a preparation interrupted before its immutable plan was published."""
    if ID_RE.fullmatch(identifier) is None:
        raise TransactionError("invalid TXN-ID")
    with write_guard(workspace, recovery=True):
        source = safe_path(workspace, (DIRECTORY / identifier).as_posix())
        if (source / "plan.json").exists() or (source / "plan.json").is_symlink():
            raise TransactionError("prepared transactions must be recovered, not quarantined")
        _private_directory(workspace / "private/transaction_orphans")
        destination = workspace / "private/transaction_orphans" / identifier
        artifact_io.publish_directory(source, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "apply", "quarantine-staging"))
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--transaction")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            for identifier in incomplete(args.workspace):
                path = args.workspace / DIRECTORY / identifier / "plan.json"
                print(f"{identifier} {'prepared' if path.exists() else 'unprepared-staging'}")
        else:
            if args.transaction is None:
                parser.error("apply requires --transaction")
            if args.command == "apply":
                print(f"committed: {replay(args.workspace, args.transaction)}")
            else:
                quarantine_staging(args.workspace, args.transaction)
                print(f"quarantined: {args.transaction}")
    except (OSError, ValueError, RuntimeError, ledger_io.LedgerIOError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
