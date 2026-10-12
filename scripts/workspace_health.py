"""Bounded, read-only diagnostics for local writer prerequisites, not authorization."""

from __future__ import annotations

import contextlib
import fcntl
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import (
        ledger_io,
        restore_checkpoint,
        stream_coordination,
        workspace_transaction,
    )
else:
    import ledger_io
    import restore_checkpoint
    import stream_coordination
    import workspace_transaction

MAX_ENTRIES = 4096
MAX_METADATA_BYTES = 16 * 1024 * 1024
DETAIL_LIMIT = 20


@contextlib.contextmanager
def _existing_read_lock(path: Path):
    """Never create a lock, wait for a writer, or change permissions."""
    descriptor = -1
    try:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            yield
            return
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError("invalid diagnostic lock")
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        current = path.lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("diagnostic lock changed")
        yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _transactions(root: Path) -> tuple[list[dict[str, str]], int]:
    directory = workspace_transaction.safe_path(root, "private/transactions")
    if not directory.exists():
        return [], 0
    entries: list[Path] = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            if len(entries) >= MAX_ENTRIES:
                raise OverflowError("diagnostic limit")
            if workspace_transaction.ID_RE.fullmatch(entry.name) is None or not entry.is_dir(follow_symlinks=False):
                raise ValueError("invalid transaction entry")
            entries.append(Path(entry.path))
    budget = MAX_METADATA_BYTES

    def read(path: Path) -> tuple[bytes, dict[str, Any]]:
        nonlocal budget
        if path.lstat().st_size > budget:
            raise OverflowError("diagnostic limit")
        raw = workspace_transaction.read_file(path, min(workspace_transaction.MAX_PLAN, budget))
        budget -= len(raw)
        if budget <= 0:
            raise OverflowError("diagnostic limit")
        record = ledger_io.loads_json(raw)
        if not isinstance(record, dict):
            raise TypeError("invalid diagnostic record")
        return raw, record

    pending = []
    for entry in sorted(entries):
        plan_path, receipt_path = entry / "plan.json", entry / "COMMITTED.json"
        if not plan_path.exists() and not plan_path.is_symlink():
            if receipt_path.exists() or receipt_path.is_symlink():
                raise ValueError("completion without plan")
            pending.append({"transaction_id": entry.name, "state": "unprepared-staging"})
            continue
        raw, plan = read(plan_path)
        if (plan.get("schema_version") != "1.0" or plan.get("transaction_id") != entry.name
                or plan.get("kind") not in workspace_transaction.KINDS
                or not isinstance(plan.get("operations"), list)):
            raise ValueError("invalid transaction metadata")
        if receipt_path.exists() or receipt_path.is_symlink():
            _, receipt = read(receipt_path)
            if receipt != {"transaction_id": entry.name, "plan_sha256": workspace_transaction.digest(raw)}:
                raise ValueError("invalid completion receipt")
        else:
            if plan.get("workspace") != str(root):
                raise ValueError("foreign pending transaction")
            pending.append({"transaction_id": entry.name, "state": "prepared"})
    return pending, len(entries)


def _lease(root: Path, moment: datetime) -> str:
    relative = stream_coordination.COORDINATION_RELATIVE
    directory = workspace_transaction.safe_path(root, relative.as_posix())
    if not directory.exists():
        return "not-configured"
    with _existing_read_lock(directory / ".coordination.lock"):
        for name in (stream_coordination.SESSION_FILE, stream_coordination.LEASE_LEDGER,
                     stream_coordination.LEASE_SNAPSHOT.as_posix()):
            workspace_transaction.safe_path(root, (relative / name).as_posix())
        stream_coordination._coordination_root(root, initialized=True)
        stream_coordination._session(directory)
        lease = stream_coordination._lease_snapshot(directory, missing_ok=True)
        if lease is None:
            return "missing"
        if lease["state"] == "released":
            return "released"
        if not stream_coordination._lease_is_live(lease, moment):
            return "expired"
        writer = os.environ.get("CYBER_STREAM_ID")
        identifier = os.environ.get("CYBER_WRITER_LEASE_ID")
        token = os.environ.get("CYBER_WRITER_FENCING_TOKEN")
        if any(value is None for value in (writer, identifier, token)):
            return "environment-missing"
        if (writer != lease["writer_stream_id"] or identifier != lease["lease_id"]
                or token != str(lease["fencing_token"])):
            return "identity-mismatch"
        workspace_transaction.safe_path(root, (relative / "streams" / f"{writer}.json").as_posix())
        stream_coordination._stream(directory, writer)
        return "valid"


def snapshot(workspace: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Inspect only control metadata; errors never echo untrusted record values."""
    root = workspace.absolute()
    result: dict[str, Any] = {
        "schema_version": "1.0", "write_ready": False, "history_readable": True,
        "runtime": "unchecked", "lease": "unchecked", "transaction_count": None,
        "pending_count": None, "transactions": [], "details_truncated": False, "blockers": [],
    }

    def block(code: str, next_step: str, *, history: bool = False) -> None:
        result["blockers"].append({"code": code, "next_step": next_step})
        if history:
            result["history_readable"] = False

    try:
        workspace_transaction.safe_path(root, "private")
        if (".." in root.parts or not root.is_dir()
                or not workspace_transaction.safe_path(root, "global.md").is_file()
                or not workspace_transaction.safe_path(root, "hosts").is_dir()):
            raise ValueError("invalid root")
        guard = contextlib.nullcontext() if workspace_transaction.held(root) else _existing_read_lock(root / ".workspace_mutation.lock")
        with guard:
            try:
                restored = restore_checkpoint.state(root)
                if restored is None:
                    result["runtime"] = "original"
                elif restored["status"] == "inactive":
                    result["runtime"] = "inactive"
                    block("restore-inactive", "Review cyber-checkpoint activate --preview; activation and module selection are separate.")
                elif os.environ.get("CYBER_WORKSPACE_INSTANCE") != restored["instance_id"]:
                    result["runtime"] = "instance-mismatch"
                    block("runtime-instance-mismatch", "Start a new writer with the WSI returned by explicit activation; do not reuse archived sessions.")
                else:
                    result["runtime"] = "active"
            except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                result["runtime"] = "invalid"
                block("restore-state-invalid", "Review restore state and its retained operation; do not remove the runtime fence.", history=True)
            try:
                pending, count = _transactions(root)
                result.update(transaction_count=count, pending_count=len(pending),
                              transactions=pending[:DETAIL_LIMIT], details_truncated=len(pending) > DETAIL_LIMIT)
                if pending:
                    block("unfinished-transactions", "Run cyber-recovery inspect for this module before resuming local writes.", history=True)
            except OverflowError:
                result["details_truncated"] = True
                block("diagnostic-limit", "Control metadata exceeds the diagnostic budget; inspect recovery state deliberately.", history=True)
            except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                block("transaction-state-invalid", "Run cyber-recovery inspect; preserve conflicting files and resolve the journal state.", history=True)
            if result["history_readable"]:
                if __package__:
                    from . import engagement_config
                else:
                    import engagement_config
                try:
                    if engagement_config.is_managed(root):
                        result["assessment_configuration"] = engagement_config.status(root, now=now)
                except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                    block("engagement-configuration-invalid", "Review the configuration history and generated context; preserve files before recovery.", history=True)
            try:
                result["lease"] = _lease(root, now or datetime.now(UTC))
                if result["lease"] not in {"valid", "not-configured"}:
                    block("writer-lease-" + result["lease"], "Use cyber-stream to inspect/register the intended writer and obtain its valid lease environment.")
            except BlockingIOError:
                result["lease"] = "busy"
                block("coordination-busy", "A coordination writer is active; retry diagnostics after it finishes.")
            except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                result["lease"] = "invalid"
                block("coordination-state-invalid", "Review coordination state; do not replace it or bypass its lease automatically.")
    except BlockingIOError:
        block("workspace-busy", "A workspace writer is active; retry diagnostics after it finishes.", history=True)
    except (OSError, ValueError, RuntimeError):
        block("workspace-state-invalid", "Review the workspace path and mutation lock without changing unrelated files.", history=True)
    result["write_ready"] = not result["blockers"]
    return result


def render(result: dict[str, Any]) -> list[str]:
    lines = [
        f"Local writer ready: {'yes' if result['write_ready'] else 'no'}",
        f"Runtime: {result['runtime']}", f"Writer lease: {result['lease']}",
        f"Pending local transactions: {result['pending_count'] if result['pending_count'] is not None else 'unknown'}",
    ]
    for item in result["transactions"]:
        lines.append(f"  {item['transaction_id']}: {item['state']}")
    if result["details_truncated"]:
        lines.append("Diagnostic details limited; this is not a complete inventory.")
    for item in result["blockers"]:
        lines.append(f"  {item['code']}: {item['next_step']}")
    lines.append("Local prerequisites only; this does not authorize target actions or certify evidence integrity.")
    return lines
