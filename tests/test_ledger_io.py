"""Focused integrity tests for shared append-only ledger I/O."""

import errno
from pathlib import Path

import pytest

from scripts import ledger_io


def test_partial_append_is_rolled_back_without_changing_prior_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "records.jsonl"
    original = b'{"existing":true}\n'
    ledger.write_bytes(original)
    real_write = ledger_io.os.write
    calls = 0

    def short_then_fail(descriptor: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:5])
        raise OSError(errno.ENOSPC, "synthetic full filesystem")

    monkeypatch.setattr(ledger_io.os, "write", short_then_fail)

    with (
        ledger_io.exclusive_ledger_lock(ledger),
        pytest.raises(ledger_io.LedgerIOError, match="failed to append"),
    ):
        ledger_io.append_json_record(
            ledger,
            {"new": True},
            create=False,
        )

    assert ledger.read_bytes() == original


def test_partial_batch_append_is_rolled_back_as_one_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "records.jsonl"
    original = b'{"existing":true}\n'
    ledger.write_bytes(original)
    real_write = ledger_io.os.write
    calls = 0

    def short_then_fail(descriptor: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:9])
        raise OSError(errno.ENOSPC, "synthetic full filesystem")

    monkeypatch.setattr(ledger_io.os, "write", short_then_fail)
    with pytest.raises(ledger_io.LedgerIOError, match="failed to append"):
        ledger_io.append_json_records(
            ledger,
            [{"first": True}, {"second": True}],
            create=False,
        )
    assert ledger.read_bytes() == original


def test_batch_is_serialized_before_any_append(tmp_path: Path) -> None:
    ledger = tmp_path / "records.jsonl"
    original = b'{"existing":true}\n'
    ledger.write_bytes(original)
    with pytest.raises(ledger_io.LedgerIOError, match="strict JSON"):
        ledger_io.append_json_records(
            ledger,
            [{"valid": True}, {"invalid": float("nan")}],
            create=False,
        )
    assert ledger.read_bytes() == original


def test_symlinked_lock_is_rejected_without_touching_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "records.jsonl"
    ledger.write_bytes(b"")
    outside = tmp_path / "outside.lock"
    outside.write_bytes(b"sentinel")
    (tmp_path / ".records.lock").symlink_to(outside)

    with (
        pytest.raises(ledger_io.LedgerIOError, match="cannot open lock"),
        ledger_io.exclusive_ledger_lock(ledger),
    ):
        raise AssertionError("unreachable")

    assert ledger.read_bytes() == b""
    assert outside.read_bytes() == b"sentinel"


def test_hard_linked_ledger_is_rejected_without_append(tmp_path: Path) -> None:
    ledger = tmp_path / "records.jsonl"
    ledger.write_bytes(b"")
    alias = tmp_path / "alias.jsonl"
    alias.hardlink_to(ledger)

    with (
        ledger_io.exclusive_ledger_lock(ledger),
        pytest.raises(ledger_io.LedgerIOError, match="dedicated"),
    ):
        ledger_io.append_json_record(
            ledger,
            {"new": True},
            create=False,
        )

    assert ledger.read_bytes() == b""
    assert alias.read_bytes() == b""


def test_unterminated_valid_json_record_is_rejected_without_append(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "records.jsonl"
    original = b'{"existing":true}'
    ledger.write_bytes(original)

    with (
        ledger_io.exclusive_ledger_lock(ledger),
        pytest.raises(ledger_io.LedgerIOError, match="unterminated final record"),
    ):
        ledger_io.append_json_record(
            ledger,
            {"new": True},
            create=False,
        )

    assert ledger.read_bytes() == original


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object()])
def test_non_strict_or_unserializable_json_is_rejected_before_mutation(
    tmp_path: Path,
    value: object,
) -> None:
    ledger = tmp_path / "records.jsonl"
    original = b'{"existing":true}\n'
    ledger.write_bytes(original)

    with (
        ledger_io.exclusive_ledger_lock(ledger),
        pytest.raises(ledger_io.LedgerIOError, match="strict JSON"),
    ):
        ledger_io.append_json_record(
            ledger,
            {"value": value},
            create=False,
        )

    assert ledger.read_bytes() == original


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e999}',
        b'{"value":-1e999}',
        b'{"value":1,"value":2}',
        b'{"nested":{"value":1,"value":2}}',
    ],
)
def test_loads_json_rejects_non_rfc_constants_and_duplicate_keys(
    payload: bytes,
) -> None:
    with pytest.raises(ledger_io.LedgerIOError, match="invalid strict JSON"):
        ledger_io.loads_json(payload)
