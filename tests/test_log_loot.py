"""Tests for scripts/log_loot.py."""

import hashlib
import io
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import ledger_io
from scripts import log_loot as log_loot_module
from scripts.log_loot import main

FIXED_NOW = datetime(2026, 7, 29, 12, 0, 0, 123456, tzinfo=UTC)
EXPECTED_LOOT_ID = "LOOT-20260729T120000123456Z"
EXPECTED_TIMESTAMP = "2026-07-29T12:00:00.123456Z"

EXPECTED_FIELDS = [
    "schema_version",
    "loot_id",
    "timestamp_utc",
    "host_id",
    "category",
    "label",
    "source",
    "username",
    "value_sha256",
    "value_text",
]


def run(
    capsys: pytest.CaptureFixture[str], *args: str, now: datetime | None = None
) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(tmp_path: Path, host_id: str = "H01") -> Path:
    """Create a minimal valid workspace for loot logging tests."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "hosts").mkdir()
    (workspace / "hosts" / f"{host_id}.md").write_text(
        f"# Host {host_id}\n", encoding="utf-8"
    )
    (workspace / "loot.jsonl").write_bytes(b"")
    return workspace


def read_records(workspace: Path) -> list[dict[str, object]]:
    """Return all JSON records in the loot ledger."""
    lines = (workspace / "loot.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_value_from_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A value supplied by file is logged correctly."""
    workspace = make_workspace(tmp_path)
    value_bytes = b"secret password\n"
    value_file = tmp_path / "loot-value.txt"
    value_file.write_bytes(value_bytes)

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "SSH password",
        "--source",
        "config.yml",
        "--username",
        "admin",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    records = read_records(workspace)
    assert len(records) == 1
    record = records[0]
    assert record["schema_version"] == "1.0"
    assert record["loot_id"] == EXPECTED_LOOT_ID
    assert record["timestamp_utc"] == EXPECTED_TIMESTAMP
    assert record["host_id"] == "H01"
    assert record["category"] == "credential"
    assert record["label"] == "SSH password"
    assert record["source"] == "config.yml"
    assert record["username"] == "admin"
    assert record["value_text"] == "secret password\n"
    assert record["value_sha256"] == hashlib.sha256(value_bytes).hexdigest()
    assert "secret password" not in stdout
    assert "path: loot.jsonl" in stdout


def test_value_from_stdin(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A value supplied on standard input is logged correctly."""
    workspace = make_workspace(tmp_path)
    value_bytes = b"from-stdin value"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(value_bytes)))

    code, _stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "stdin secret",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    records = read_records(workspace)
    assert len(records) == 1
    assert records[0]["value_text"] == "from-stdin value"
    assert records[0]["value_sha256"] == hashlib.sha256(value_bytes).hexdigest()


def test_validate_only_does_not_append(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"synthetic value")

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "Synthetic value",
        "--value-file",
        str(value_file),
        "--validate-only",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert "validation: valid" in stdout
    assert "prospective_loot_id:" in stdout
    assert (workspace / "loot.jsonl").read_bytes() == b""


def test_exact_json_fields(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The JSON record contains exactly the required fields in order."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    raw_line = (workspace / "loot.jsonl").read_text(encoding="utf-8").splitlines()[0]
    record = json.loads(raw_line)
    assert list(record.keys()) == EXPECTED_FIELDS
    # Compact JSON: no spaces after separators.
    assert raw_line == json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def test_fixed_datetime_and_deterministic_id(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Injecting a fixed datetime yields a deterministic loot ID."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, stdout, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code == 0
    assert f"loot_id: {EXPECTED_LOOT_ID}" in stdout
    records = read_records(workspace)
    assert records[0]["loot_id"] == EXPECTED_LOOT_ID
    assert records[0]["timestamp_utc"] == EXPECTED_TIMESTAMP


def test_sha256_and_whitespace_preservation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """SHA-256 is computed from raw bytes and whitespace is preserved."""
    workspace = make_workspace(tmp_path)
    value_bytes = b"  leading and trailing \n"
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(value_bytes)

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "whitespace test",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    record = read_records(workspace)[0]
    assert record["value_text"] == "  leading and trailing \n"
    assert record["value_sha256"] == hashlib.sha256(value_bytes).hexdigest()


def test_existing_ledger_content_unchanged_before_appended_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Earlier ledger lines remain byte-for-byte identical after appending."""
    workspace = make_workspace(tmp_path)
    existing = (
        b'{"loot_id":"LOOT-20260729T115958123456Z"}\n'
        b'{"loot_id":"LOOT-20260729T115959123456Z"}\n'
    )
    (workspace / "loot.jsonl").write_bytes(existing)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    data = (workspace / "loot.jsonl").read_bytes()
    assert data.startswith(existing)
    assert data.count(b"\n") == 3


@pytest.mark.parametrize("host_id", ["H00"])
def test_h00_rejected(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """H00 is rejected as a reserved host ID."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        host_id,
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "H00 is reserved" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before


@pytest.mark.parametrize("host_id", ["H1", "H001", "h01", "", "H100", "H 01", "ABC"])
def test_malformed_host_id_rejected(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Malformed host IDs are rejected."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        host_id,
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "host id" in stderr.lower()
    assert (workspace / "loot.jsonl").read_bytes() == before


def test_missing_host_record(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace without the requested host record is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / "hosts" / "H01.md").unlink()
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing host record" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before


def test_missing_workspace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A non-existent workspace is rejected."""
    workspace = tmp_path / "does-not-exist"
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "workspace does not exist" in stderr


def test_missing_loot_jsonl(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace missing loot.jsonl is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / "loot.jsonl").unlink()
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing loot.jsonl" in stderr


def test_loot_jsonl_not_regular_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A non-file loot.jsonl is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / "loot.jsonl").unlink()
    (workspace / "loot.jsonl").mkdir()
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "not a regular file" in stderr


@pytest.mark.parametrize("value_bytes", [b"", b"   ", b"\n\t "])
def test_empty_or_whitespace_value_rejected(
    value_bytes: bytes,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Empty and whitespace-only values are rejected."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(value_bytes)
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "empty" in stderr or "whitespace" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before


def test_invalid_utf8_value_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Invalid UTF-8 bytes are rejected."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"\xff\xfe")
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "valid UTF-8" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--category", "   "),
        ("--category", "cat\nname"),
        ("--category", "cat\x00name"),
        ("--category", "c" * 41),
        ("--label", "   "),
        ("--label", "la\rbe"),
        ("--label", "la\x01be"),
        ("--label", "l" * 161),
        ("--source", "so\nurce"),
        ("--source", "s" * 161),
        ("--username", "us\tname"),
        ("--username", "u" * 161),
    ],
)
def test_invalid_metadata_rejected(
    flag: str,
    value: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Malformed metadata fields are rejected without touching the ledger."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")
    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "valid label",
        flag,
        value,
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "error:" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before


def test_duplicate_loot_id_leaves_ledger_unchanged(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A duplicate loot ID is rejected and the ledger stays unchanged."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, _, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "first",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )
    assert code == 0

    before = (workspace / "loot.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "second",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "duplicate loot_id" in stderr
    assert (workspace / "loot.jsonl").read_bytes() == before
    records = read_records(workspace)
    assert len(records) == 1
    assert records[0]["label"] == "first"


def test_malformed_loot_ledger_fails_closed_without_append(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"synthetic value")
    malformed = b'{"loot_id":"LOOT-20260729T115959123456Z"}\n{"loot_id":\n'
    ledger = workspace / "loot.jsonl"
    ledger.write_bytes(malformed)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "synthetic",
        "--label",
        "Synthetic item",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "invalid JSON" in stderr
    assert ledger.read_bytes() == malformed


@pytest.mark.parametrize(
    ("existing", "error"),
    [
        (b"{}\n", "invalid loot_id"),
        (b'{"loot_id":"LOOT-OLD"}\n', "invalid loot_id"),
        (
            b'{"loot_id":"LOOT-20260729T120000123456Z"}',
            "not newline terminated",
        ),
        (
            b'{"loot_id":"LOOT-20260729T115959123456Z","value_text":NaN}\n',
            "invalid JSON",
        ),
        (
            (
                b'{"loot_id":"LOOT-20260729T115959123456Z",'
                b'"loot_id":"LOOT-20260729T115958123456Z"}\n'
            ),
            "invalid JSON",
        ),
        (
            (
                b'{"loot_id":"LOOT-20260729T115959123456Z"}\n'
                b'{"loot_id":"LOOT-20260729T115959123456Z"}\n'
            ),
            "duplicates loot_id",
        ),
    ],
)
def test_invalid_existing_loot_identity_fails_closed(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    existing: bytes,
    error: str,
) -> None:
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"synthetic value")
    ledger = workspace / "loot.jsonl"
    ledger.write_bytes(existing)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "synthetic",
        "--label",
        "Synthetic item",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert error in stderr
    assert ledger.read_bytes() == existing


def test_concurrent_same_loot_id_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")
    first_in_append = threading.Event()
    release_first = threading.Event()
    second_at_lock = threading.Event()
    outcomes: dict[str, str] = {}

    original_append = log_loot_module._append_record_unlocked
    original_flock = ledger_io.fcntl.flock

    def delayed_append(path: Path, record: dict[str, object]) -> None:
        if threading.current_thread().name == "loot-first":
            first_in_append.set()
            assert release_first.wait(timeout=5)
        original_append(path, record)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "loot-second"
            and operation == ledger_io.fcntl.LOCK_EX
        ):
            second_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(log_loot_module, "_append_record_unlocked", delayed_append)
    monkeypatch.setattr(ledger_io.fcntl, "flock", observed_flock)

    def invoke(label: str) -> None:
        try:
            log_loot_module.log_loot(
                workspace=str(workspace),
                host_id="H01",
                category="synthetic",
                label=label,
                source=None,
                username=None,
                value_file=str(value_file),
                now=FIXED_NOW,
            )
        except SystemExit:
            outcomes[label] = "rejected"
        else:
            outcomes[label] = "appended"

    first = threading.Thread(target=invoke, args=("first",), name="loot-first")
    second = threading.Thread(target=invoke, args=("second",), name="loot-second")
    first.start()
    assert first_in_append.wait(timeout=5)
    second.start()
    assert second_at_lock.wait(timeout=5)
    assert "second" not in outcomes
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == {"first": "appended", "second": "rejected"}
    records = read_records(workspace)
    assert len(records) == 1
    assert records[0]["label"] == "first"


def test_success_output_does_not_reveal_value(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Success output never contains the secret value."""
    workspace = make_workspace(tmp_path)
    secret = "super-secret-value-42"
    value_file = tmp_path / "value.txt"
    value_file.write_text(secret, encoding="utf-8")

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "credential",
        "--label",
        "SSH password",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code == 0
    combined = stdout + stderr
    assert secret not in combined
    assert "value_text" not in combined


def test_failures_do_not_modify_ledger(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Any validation failure leaves the existing ledger byte-for-byte unchanged."""
    workspace = make_workspace(tmp_path)
    existing = b'{"loot_id":"LOOT-EXISTING"}\n'
    (workspace / "loot.jsonl").write_bytes(existing)
    before = existing

    code, _, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H00",
        "--category",
        "c",
        "--label",
        "l",
        now=FIXED_NOW,
    )
    assert code != 0
    assert (workspace / "loot.jsonl").read_bytes() == before


def test_optional_defaults(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Omitted source and username default to 'unknown'."""
    workspace = make_workspace(tmp_path)
    value_file = tmp_path / "value.txt"
    value_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--category",
        "c",
        "--label",
        "l",
        "--value-file",
        str(value_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    record = read_records(workspace)[0]
    assert record["source"] == "unknown"
    assert record["username"] == "unknown"
