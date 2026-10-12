"""Small, advisory-lock helpers for append-only JSONL ledgers."""

from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class LedgerIOError(RuntimeError):
    """A bounded ledger locking or append failure."""


class _StrictJSONError(ValueError):
    """Internal marker for JSON extensions forbidden by the ledger contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _StrictJSONError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise _StrictJSONError("non-finite numeric constant")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise _StrictJSONError("numeric value exceeds finite float range")
    return result


def loads_json(payload: str | bytes | bytearray) -> Any:
    """Decode strict ledger JSON without non-finite numbers or duplicate keys."""
    try:
        return json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (
        UnicodeDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        raise LedgerIOError("invalid strict JSON") from exc


def _lock_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f".{ledger_path.stem}.lock")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


@contextlib.contextmanager
def exclusive_ledger_lock(ledger_path: Path) -> Iterator[None]:
    """Serialize cooperating writers for one ledger using a private sidecar lock."""
    lock_path = _lock_path(ledger_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LedgerIOError(f"cannot open lock for {ledger_path.name}") from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            opened = os.fstat(descriptor)
            current = lock_path.lstat()
        except OSError as exc:
            raise LedgerIOError(f"cannot lock {ledger_path.name}") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or not _same_identity(opened, current)
            or opened.st_nlink != 1
        ):
            raise LedgerIOError(
                f"lock for {ledger_path.name} is not a stable regular file"
            )
        if stat.S_IMODE(opened.st_mode) & 0o077:
            raise LedgerIOError(f"lock for {ledger_path.name} is not private")
        yield
    finally:
        os.close(descriptor)


def _ensure_ledger(ledger_path: Path, *, create: bool) -> None:
    try:
        current = ledger_path.lstat()
    except FileNotFoundError:
        if not create:
            raise LedgerIOError(f"ledger does not exist: {ledger_path.name}") from None
    except OSError as exc:
        raise LedgerIOError(f"cannot inspect {ledger_path.name}") from exc
    else:
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
        ):
            raise LedgerIOError(
                f"{ledger_path.name} must be a dedicated real regular file"
            )
        return

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(ledger_path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except FileExistsError:
        try:
            current = ledger_path.lstat()
        except OSError as exc:
            raise LedgerIOError(f"cannot inspect {ledger_path.name}") from exc
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
        ):
            raise LedgerIOError(
                f"{ledger_path.name} must be a dedicated real regular file"
            )
    except OSError as exc:
        raise LedgerIOError(f"cannot create {ledger_path.name}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _coordination_workspace(ledger_path: Path) -> Path | None:
    """Return the nearest coordinated workspace, excluding its own state."""
    absolute = ledger_path.absolute()
    for candidate in (absolute.parent, *absolute.parents):
        coordination = candidate / "private" / "coordination"
        session = coordination / "session.json"
        if session.exists() or session.is_symlink():
            try:
                absolute.relative_to(coordination)
            except ValueError:
                return candidate
            return None
    return None


def append_json_record(
    ledger_path: Path,
    record: dict[str, Any],
    *,
    create: bool,
    maximum_bytes: int | None = None,
) -> None:
    """Append one JSON line, enforcing an active writer lease when configured."""
    if __package__:
        from . import restore_checkpoint, workspace_transaction
    else:
        import restore_checkpoint
        import workspace_transaction
    # Coordination's own lease ledger cannot take the workspace lock while
    # holding its coordination lock. All other appends share the outer guard.
    root = next((path for path in ledger_path.absolute().parents
                 if (path / "global.md").is_file() and (path / "hosts").is_dir()), None)
    if root is not None:
        try:
            restore_checkpoint.require_write_instance(root)
            coordination = root / "private/coordination"
            if not ledger_path.absolute().is_relative_to(coordination):
                with workspace_transaction.write_guard(root):
                    _append_json_record_uncoordinated(
                        ledger_path, record, create=create, maximum_bytes=maximum_bytes,
                    )
                return
        except (workspace_transaction.TransactionError, restore_checkpoint.RestoreError) as exc:
            raise LedgerIOError(str(exc)) from exc
    workspace = _coordination_workspace(ledger_path)
    if workspace is None:
        _append_json_record_uncoordinated(
            ledger_path,
            record,
            create=create,
            maximum_bytes=maximum_bytes,
        )
        return
    if __package__:
        from . import stream_coordination
    else:
        import stream_coordination  # type: ignore[no-redef]

    with stream_coordination.writer_guard_from_environment(workspace):
        _append_json_record_uncoordinated(
            ledger_path,
            record,
            create=create,
            maximum_bytes=maximum_bytes,
        )


def append_json_records(
    ledger_path: Path,
    records: list[dict[str, Any]],
    *,
    create: bool,
    maximum_record_bytes: int | None = None,
    maximum_total_bytes: int | None = None,
) -> None:
    """Append a fully validated record batch with one lock, write, and fsync."""
    if not records:
        return
    if __package__:
        from . import restore_checkpoint, workspace_transaction
    else:
        import restore_checkpoint
        import workspace_transaction
    root = next(
        (
            path
            for path in ledger_path.absolute().parents
            if (path / "global.md").is_file() and (path / "hosts").is_dir()
        ),
        None,
    )
    if root is not None:
        try:
            restore_checkpoint.require_write_instance(root)
            coordination = root / "private/coordination"
            if not ledger_path.absolute().is_relative_to(coordination):
                with workspace_transaction.write_guard(root):
                    _append_json_records_uncoordinated(
                        ledger_path,
                        records,
                        create=create,
                        maximum_record_bytes=maximum_record_bytes,
                        maximum_total_bytes=maximum_total_bytes,
                    )
                return
        except (
            workspace_transaction.TransactionError,
            restore_checkpoint.RestoreError,
        ) as exc:
            raise LedgerIOError(str(exc)) from exc
    workspace = _coordination_workspace(ledger_path)
    if workspace is None:
        _append_json_records_uncoordinated(
            ledger_path,
            records,
            create=create,
            maximum_record_bytes=maximum_record_bytes,
            maximum_total_bytes=maximum_total_bytes,
        )
        return
    if __package__:
        from . import stream_coordination
    else:
        import stream_coordination  # type: ignore[no-redef]
    with stream_coordination.writer_guard_from_environment(workspace):
        _append_json_records_uncoordinated(
            ledger_path,
            records,
            create=create,
            maximum_record_bytes=maximum_record_bytes,
            maximum_total_bytes=maximum_total_bytes,
        )


def _append_json_records_uncoordinated(
    ledger_path: Path,
    records: list[dict[str, Any]],
    *,
    create: bool,
    maximum_record_bytes: int | None,
    maximum_total_bytes: int | None,
) -> None:
    chunks: list[bytes] = []
    try:
        for record in records:
            encoded = (
                json.dumps(
                    record,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            if maximum_record_bytes is not None and len(encoded) > maximum_record_bytes:
                raise LedgerIOError("record is too large")
            chunks.append(encoded)
    except (TypeError, ValueError) as exc:
        raise LedgerIOError("record is not serializable as strict JSON") from exc
    payload = b"".join(chunks)
    if maximum_total_bytes is not None and len(payload) > maximum_total_bytes:
        raise LedgerIOError("record batch is too large")
    _append_bytes_uncoordinated(ledger_path, payload, create=create)


def _append_json_record_uncoordinated(
    ledger_path: Path,
    record: dict[str, Any],
    *,
    create: bool,
    maximum_bytes: int | None = None,
) -> None:
    """Perform one append after the caller acquired every required guard."""
    try:
        encoded = (
            json.dumps(
                record,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LedgerIOError("record is not serializable as strict JSON") from exc
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise LedgerIOError("record is too large")
    _append_bytes_uncoordinated(ledger_path, encoded, create=create)


def _append_bytes_uncoordinated(
    ledger_path: Path, encoded: bytes, *, create: bool
) -> None:
    """Append one already serialized payload with bounded tail rollback."""
    if not encoded or not encoded.endswith(b"\n"):
        raise LedgerIOError("append payload must be non-empty and newline terminated")
    _ensure_ledger(ledger_path, create=create)

    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(ledger_path, flags)
    except OSError as exc:
        raise LedgerIOError(f"cannot open {ledger_path.name} for append") from exc
    try:
        opened = os.fstat(descriptor)
        try:
            current = ledger_path.lstat()
        except OSError as exc:
            raise LedgerIOError(f"cannot inspect {ledger_path.name}") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or not _same_identity(opened, current)
            or opened.st_nlink != 1
        ):
            raise LedgerIOError(f"{ledger_path.name} changed before append")

        initial_size = opened.st_size
        if initial_size:
            try:
                final_byte = os.pread(descriptor, 1, initial_size - 1)
            except OSError as exc:
                raise LedgerIOError(
                    f"cannot inspect the end of {ledger_path.name}"
                ) from exc
            if final_byte != b"\n":
                raise LedgerIOError(
                    f"{ledger_path.name} has an unterminated final record"
                )
        written = 0
        while written < len(encoded):
            try:
                count = os.write(descriptor, encoded[written:])
            except OSError as exc:
                if written and not _rollback_partial_append(
                    descriptor,
                    ledger_path,
                    opened,
                    initial_size,
                    written,
                ):
                    raise LedgerIOError(
                        f"failed to append {ledger_path.name}; "
                        "partial tail could not be rolled back"
                    ) from exc
                raise LedgerIOError(f"failed to append {ledger_path.name}") from exc
            if count <= 0:
                if written and not _rollback_partial_append(
                    descriptor,
                    ledger_path,
                    opened,
                    initial_size,
                    written,
                ):
                    raise LedgerIOError(
                        f"failed to append {ledger_path.name}; "
                        "partial tail could not be rolled back"
                    )
                raise LedgerIOError(f"failed to append {ledger_path.name}")
            written += count
        try:
            os.fsync(descriptor)
            final = ledger_path.lstat()
        except OSError as exc:
            raise LedgerIOError(f"failed to finalize {ledger_path.name}") from exc
        if stat.S_ISLNK(final.st_mode) or not _same_identity(opened, final):
            raise LedgerIOError(f"{ledger_path.name} changed during append")
    finally:
        os.close(descriptor)


def _rollback_partial_append(
    descriptor: int,
    ledger_path: Path,
    opened: os.stat_result,
    initial_size: int,
    written: int,
) -> bool:
    """Remove only this writer's verified incomplete tail after a short write."""
    try:
        current_fd = os.fstat(descriptor)
        current_path = ledger_path.lstat()
        if (
            not stat.S_ISREG(current_fd.st_mode)
            or stat.S_ISLNK(current_path.st_mode)
            or not _same_identity(opened, current_fd)
            or not _same_identity(opened, current_path)
            or current_fd.st_nlink != 1
            or current_fd.st_size != initial_size + written
        ):
            return False
        os.ftruncate(descriptor, initial_size)
        os.fsync(descriptor)
    except OSError:
        return False
    return True
