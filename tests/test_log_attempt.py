"""Tests for scripts/log_attempt.py."""

import hashlib
import io
import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import capture_evidence, ledger_io
from scripts import log_attempt as log_attempt_module
from scripts.log_attempt import main

FIXED_NOW = datetime(2026, 7, 29, 12, 0, 0, 123456, tzinfo=UTC)
EXPECTED_ATTEMPT_ID = "ATT-20260729T120000123456Z"
EXPECTED_TIMESTAMP = "2026-07-29T12:00:00.123456Z"

EXPECTED_FIELDS = [
    "schema_version",
    "attempt_id",
    "timestamp_utc",
    "host_id",
    "action",
    "status",
    "result_sha256",
    "result_text",
    "evidence_refs",
    "next_step",
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
    """Create a minimal valid workspace for attempt logging tests."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "hosts").mkdir()
    (workspace / "hosts" / f"{host_id}.md").write_text(
        f"# Host {host_id}\n", encoding="utf-8"
    )
    (workspace / "attempts.jsonl").write_bytes(b"")
    return workspace


def read_records(workspace: Path) -> list[dict[str, object]]:
    """Return all JSON records in the attempts ledger."""
    lines = (workspace / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def retained_evidence(workspace: Path, tmp_path: Path, offset: int = 0) -> str:
    (workspace / "evidence/H01").mkdir(parents=True, exist_ok=True)
    source = tmp_path / f"evidence-{offset}.txt"
    source.write_bytes(f"Synthetic result {offset}\n".encode())
    _, artifact, _ = capture_evidence.capture_evidence(
        str(workspace), "H01", "manual", "Synthetic evidence", "txt", str(source),
        now=FIXED_NOW + timedelta(microseconds=offset),
    )
    return artifact.relative_to(workspace).as_posix()


def write_probe_spec(
    tmp_path: Path,
    *,
    name: str = "probe.json",
    generation: str = "generation-1",
    variant: str | None = "arithmetic-marker",
) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "target_generation": generation,
                "service": "HTTP",
                "endpoint": "POST /render parameter=template",
                "technique": "SSTI-Jinja2",
                "variant": variant,
                "credential_id": None,
                "helper_sha256": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_result_from_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A result supplied by file is logged correctly."""
    workspace = make_workspace(tmp_path)
    evidence = retained_evidence(workspace, tmp_path)
    result_bytes = b"SSH login failed: permission denied\n"
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(result_bytes)

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Test default SSH credentials",
        "--status",
        "failed",
        "--evidence",
        evidence,
        "--next-step",
        "Enumerate application configuration",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    records = read_records(workspace)
    assert len(records) == 1
    record = records[0]
    assert record["schema_version"] == "1.0"
    assert record["attempt_id"] == EXPECTED_ATTEMPT_ID
    assert record["timestamp_utc"] == EXPECTED_TIMESTAMP
    assert record["host_id"] == "H01"
    assert record["action"] == "Test default SSH credentials"
    assert record["status"] == "failed"
    assert record["result_text"] == "SSH login failed: permission denied\n"
    assert record["result_sha256"] == hashlib.sha256(result_bytes).hexdigest()
    assert record["evidence_refs"] == [evidence]
    assert record["next_step"] == "Enumerate application configuration"
    assert "SSH login failed" not in stdout
    assert "path: attempts.jsonl" in stdout


def test_result_from_stdin(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A result supplied on standard input is logged correctly."""
    workspace = make_workspace(tmp_path)
    result_bytes = b"from-stdin result"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(result_bytes)))

    code, _stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "stdin action",
        "--status",
        "success",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    records = read_records(workspace)
    assert len(records) == 1
    assert records[0]["result_text"] == "from-stdin result"
    assert records[0]["result_sha256"] == hashlib.sha256(result_bytes).hexdigest()


def test_probe_outcome_records_stable_memory_fields(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"literal reflection; no evaluation\n")
    spec_path = write_probe_spec(tmp_path)

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Check an inert SSTI marker",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        "--probe-spec",
        str(spec_path),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    record = read_records(workspace)[0]
    assert record["schema_version"] == "1.1"
    assert record["work_kind"] == "probe"
    assert record["probe_spec"] == {
        "target_generation": "generation-1",
        "service": "http",
        "endpoint": "POST /render parameter=template",
        "technique": "ssti-jinja2",
        "variant": "arithmetic-marker",
        "credential_id": None,
        "helper_sha256": None,
    }
    assert record["probe_fingerprint"] == log_attempt_module.probe_fingerprint(
        "H01",
        record["probe_spec"],  # type: ignore[arg-type]
    )
    assert record["duplicate_of"] is None
    assert record["retry_of"] is None
    assert "probe_fingerprint:" in stdout


def test_probe_preflight_blocks_an_exact_duplicate_without_writing(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"synthetic result")
    spec_path = write_probe_spec(tmp_path)
    assert (
        run(
            capsys,
            "--workspace",
            str(workspace),
            "--host-id",
            "H01",
            "--action",
            "First probe",
            "--status",
            "failed",
            "--result-file",
            str(result_file),
            "--probe-spec",
            str(spec_path),
            now=FIXED_NOW,
        )[0]
        == 0
    )
    before = (workspace / "attempts.jsonl").read_bytes()

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--check-probe",
        str(spec_path),
    )

    assert code == 1, stderr
    assert "decision: blocked_duplicate" in stdout
    assert "matching_attempts: 1" in stdout
    assert f"match: {EXPECTED_ATTEMPT_ID} failed" in stdout
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_probe_preflight_allows_changed_generation_and_explicit_retry(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"synthetic result")
    spec_path = write_probe_spec(tmp_path)
    assert (
        run(
            capsys,
            "--workspace",
            str(workspace),
            "--host-id",
            "H01",
            "--action",
            "First probe",
            "--status",
            "failed",
            "--result-file",
            str(result_file),
            "--probe-spec",
            str(spec_path),
            now=FIXED_NOW,
        )[0]
        == 0
    )

    changed = write_probe_spec(tmp_path, name="changed.json", generation="generation-2")
    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--check-probe",
        str(changed),
    )
    assert code == 0, stderr
    assert "decision: proceed" in stdout

    retry_reason = "Helper implementation changed after review"
    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--check-probe",
        str(spec_path),
        "--retry-of",
        EXPECTED_ATTEMPT_ID,
        "--retry-reason",
        retry_reason,
    )
    assert code == 0, stderr
    assert "decision: proceed_retry" in stdout

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Reviewed retry",
        "--status",
        "success",
        "--result-file",
        str(result_file),
        "--probe-spec",
        str(spec_path),
        "--retry-of",
        EXPECTED_ATTEMPT_ID,
        "--retry-reason",
        retry_reason,
        now=FIXED_NOW + timedelta(microseconds=1),
    )
    assert code == 0, stderr
    retry = read_records(workspace)[1]
    assert retry["retry_of"] == EXPECTED_ATTEMPT_ID
    assert retry["retry_reason"] == retry_reason
    assert retry["duplicate_of"] is None


def test_unpreflighted_duplicate_outcome_is_preserved_and_marked(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"synthetic result")
    spec_path = write_probe_spec(tmp_path)
    common = (
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        "--probe-spec",
        str(spec_path),
    )
    assert run(capsys, *common, "--action", "First", now=FIXED_NOW)[0] == 0
    code, stdout, stderr = run(
        capsys,
        *common,
        "--action",
        "Unexpected duplicate",
        now=FIXED_NOW + timedelta(microseconds=1),
    )
    assert code == 0, stderr
    records = read_records(workspace)
    assert len(records) == 2
    assert records[1]["duplicate_of"] == EXPECTED_ATTEMPT_ID
    assert f"duplicate_of: {EXPECTED_ATTEMPT_ID}" in stdout


def test_exact_json_fields(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The JSON record contains exactly the required fields in order."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "success",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    raw_line = (
        (workspace / "attempts.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    record = json.loads(raw_line)
    assert list(record.keys()) == EXPECTED_FIELDS
    # Compact JSON: no spaces after separators.
    assert raw_line == json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def test_fixed_datetime_and_deterministic_id(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Injecting a fixed datetime yields a deterministic attempt ID."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, stdout, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "success",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code == 0
    assert f"attempt_id: {EXPECTED_ATTEMPT_ID}" in stdout
    records = read_records(workspace)
    assert records[0]["attempt_id"] == EXPECTED_ATTEMPT_ID
    assert records[0]["timestamp_utc"] == EXPECTED_TIMESTAMP


def test_sha256_and_whitespace_preservation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """SHA-256 is computed from raw bytes and whitespace is preserved."""
    workspace = make_workspace(tmp_path)
    result_bytes = b"  leading and trailing \n"
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(result_bytes)

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "whitespace action",
        "--status",
        "partial",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    record = read_records(workspace)[0]
    assert record["result_text"] == "  leading and trailing \n"
    assert record["result_sha256"] == hashlib.sha256(result_bytes).hexdigest()


@pytest.mark.parametrize("status", ["success", "failed", "partial", "blocked"])
def test_all_valid_statuses(
    status: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """All four allowed statuses are accepted."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        status,
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert read_records(workspace)[0]["status"] == status


def test_invalid_status_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An unknown status is rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "unknown",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "invalid status" in stderr
    assert (workspace / "attempts.jsonl").read_bytes() == before


@pytest.mark.parametrize("host_id", ["H00"])
def test_h00_rejected(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """H00 is rejected as a reserved host ID."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        host_id,
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "H00 is reserved" in stderr
    assert (workspace / "attempts.jsonl").read_bytes() == before


@pytest.mark.parametrize("host_id", ["H1", "H001", "h01", "", "H100", "H 01", "ABC"])
def test_malformed_host_id_rejected(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Malformed host IDs are rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        host_id,
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "host id" in stderr.lower()
    assert (workspace / "attempts.jsonl").read_bytes() == before


@pytest.mark.parametrize(
    "action,needle",
    [
        ("", "action must not be empty"),
        ("   ", "action must not contain only whitespace"),
        ("action\nsecond line", "action must be single-line text"),
        ("action\twith tab", "action must not contain control characters"),
        ("a" * 241, "action too long"),
    ],
)
def test_invalid_action_rejected(
    action: str,
    needle: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Invalid action strings are rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        action,
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert needle.lower() in stderr.lower()
    assert (workspace / "attempts.jsonl").read_bytes() == before


@pytest.mark.parametrize(
    "next_step,needle",
    [
        ("   ", "next-step must not contain only whitespace"),
        ("step\nsecond line", "next-step must be single-line text"),
        ("step\twith tab", "next-step must not contain control characters"),
        ("s" * 241, "next-step too long"),
    ],
)
def test_invalid_next_step_rejected(
    next_step: str,
    needle: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Invalid next-step strings are rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--next-step",
        next_step,
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert needle.lower() in stderr.lower()
    assert (workspace / "attempts.jsonl").read_bytes() == before


@pytest.mark.parametrize("validate_only", [False, True])
@pytest.mark.parametrize("damage", ["unknown-id", "missing", "tampered", "wrong-host", "arbitrary-file"])
def test_attempt_rejects_unretained_or_unrelated_evidence(
    tmp_path: Path, damage: str, validate_only: bool,
) -> None:
    workspace = make_workspace(tmp_path)
    reference = retained_evidence(workspace, tmp_path)
    artifact = workspace / reference
    if damage == "unknown-id":
        reference = "EVD-20260729T120000999999Z"
    elif damage == "missing":
        artifact.unlink()
    elif damage == "tampered":
        artifact.write_bytes(b"X" * artifact.stat().st_size)
    elif damage == "wrong-host":
        (workspace / "hosts/H02.md").write_text("# Host H02\n")
    else:
        reference = "evidence/H01/unregistered.txt"
        (workspace / reference).write_bytes(b"unregistered")
    result = tmp_path / "result.txt"
    result.write_text("Synthetic result")
    before = (workspace / "attempts.jsonl").read_bytes()
    with pytest.raises(SystemExit):
        log_attempt_module.log_attempt(
            str(workspace), "H02" if damage == "wrong-host" else "H01", "Synthetic",
            "failed", "review", [reference], str(result), now=FIXED_NOW,
            validate_only=validate_only,
        )
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_evidence_deduplication_and_order(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Duplicate evidence references are removed while preserving order."""
    workspace = make_workspace(tmp_path)
    evidence = [retained_evidence(workspace, tmp_path, offset) for offset in range(3)]
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--evidence",
        evidence[0],
        "--evidence",
        evidence[1],
        "--evidence",
        evidence[0],
        "--evidence",
        evidence[2],
        "--evidence",
        evidence[1],
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert read_records(workspace)[0]["evidence_refs"] == evidence


@pytest.mark.parametrize(
    "evidence,needle",
    [
        ("/absolute/path", "must be relative"),
        ("../escape", "must not contain '..'"),
        ("evidence//double", "must not contain empty components"),
        ("evidence/", "must not contain empty components"),
        ("/leading", "must be relative"),
        ("./relative", "must not contain '.' components"),
        ("evidence/.\u0001.txt", "must not contain control characters"),
    ],
)
def test_invalid_evidence_rejected(
    evidence: str,
    needle: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Invalid evidence references are rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--evidence",
        evidence,
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert needle.lower() in stderr.lower()
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_missing_workspace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A non-existent workspace is rejected."""
    workspace = tmp_path / "does-not-exist"
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "workspace does not exist" in stderr


def test_missing_host_record(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace without the requested host record is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / "hosts" / "H01.md").unlink()
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing host record" in stderr
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_missing_attempts_jsonl(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace without attempts.jsonl is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / "attempts.jsonl").unlink()
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing attempts.jsonl" in stderr


def test_attempts_jsonl_not_regular_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """attempts.jsonl must be a regular file."""
    workspace = make_workspace(tmp_path)
    (workspace / "attempts.jsonl").unlink()
    (workspace / "attempts.jsonl").mkdir()
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "not a regular file" in stderr


@pytest.mark.parametrize(
    "result_bytes,needle",
    [
        (b"", "result is empty"),
        (b"   \n\t", "result contains only whitespace"),
        (b"\xff\xfe", "result is not valid UTF-8"),
    ],
)
def test_invalid_result_rejected(
    result_bytes: bytes,
    needle: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Empty, whitespace-only, and invalid UTF-8 results are rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(result_bytes)
    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert needle.lower() in stderr.lower()
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_duplicate_attempt_id_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A duplicate attempt ID is rejected."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "first",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    before = (workspace / "attempts.jsonl").read_bytes()

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "second",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "duplicate attempt_id" in stderr
    assert (workspace / "attempts.jsonl").read_bytes() == before


def test_malformed_attempt_ledger_fails_closed_without_append(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"synthetic result")
    malformed = b'{"attempt_id":"ATT-20260729T115959123456Z"}\n{"attempt_id":\n'
    ledger = workspace / "attempts.jsonl"
    ledger.write_bytes(malformed)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Synthetic action",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "invalid JSON" in stderr
    assert ledger.read_bytes() == malformed


@pytest.mark.parametrize(
    ("existing", "error"),
    [
        (b"{}\n", "invalid attempt_id"),
        (b'{"attempt_id":"ATT-OLD"}\n', "invalid attempt_id"),
        (
            b'{"attempt_id":"ATT-20260729T120000123456Z"}',
            "not newline terminated",
        ),
        (
            b'{"attempt_id":"ATT-20260729T115959123456Z","result_text":NaN}\n',
            "invalid JSON",
        ),
        (
            (
                b'{"attempt_id":"ATT-20260729T115959123456Z",'
                b'"attempt_id":"ATT-20260729T115958123456Z"}\n'
            ),
            "invalid JSON",
        ),
        (
            (
                b'{"attempt_id":"ATT-20260729T115959123456Z"}\n'
                b'{"attempt_id":"ATT-20260729T115959123456Z"}\n'
            ),
            "duplicates attempt_id",
        ),
    ],
)
def test_invalid_existing_attempt_identity_fails_closed(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    existing: bytes,
    error: str,
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"synthetic result")
    ledger = workspace / "attempts.jsonl"
    ledger.write_bytes(existing)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Synthetic action",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert error in stderr
    assert ledger.read_bytes() == existing


def test_concurrent_same_attempt_id_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")
    first_in_append = threading.Event()
    release_first = threading.Event()
    second_at_lock = threading.Event()
    outcomes: dict[str, str] = {}

    original_append = log_attempt_module._append_record_unlocked
    original_flock = ledger_io.fcntl.flock

    def delayed_append(path: Path, record: dict[str, object]) -> None:
        if threading.current_thread().name == "attempt-first":
            first_in_append.set()
            assert release_first.wait(timeout=5)
        original_append(path, record)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "attempt-second"
            and operation == ledger_io.fcntl.LOCK_EX
        ):
            second_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(log_attempt_module, "_append_record_unlocked", delayed_append)
    monkeypatch.setattr(ledger_io.fcntl, "flock", observed_flock)

    def invoke(action: str) -> None:
        try:
            log_attempt_module.log_attempt(
                workspace=str(workspace),
                host_id="H01",
                action=action,
                status="failed",
                next_step=None,
                evidence_refs=[],
                result_file=str(result_file),
                now=FIXED_NOW,
            )
        except SystemExit:
            outcomes[action] = "rejected"
        else:
            outcomes[action] = "appended"

    first = threading.Thread(target=invoke, args=("first",), name="attempt-first")
    second = threading.Thread(target=invoke, args=("second",), name="attempt-second")
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
    assert records[0]["action"] == "first"


def test_existing_ledger_bytes_preserved(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Earlier ledger lines remain byte-for-byte identical after appending."""
    workspace = make_workspace(tmp_path)
    existing = (
        b'{"attempt_id":"ATT-20260729T115958123456Z"}\n'
        b'{"attempt_id":"ATT-20260729T115959123456Z"}\n'
    )
    (workspace / "attempts.jsonl").write_bytes(existing)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "a",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    data = (workspace / "attempts.jsonl").read_bytes()
    assert data.startswith(existing)
    assert data.count(b"\n") == 3


def test_failure_does_not_modify_ledger(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Validation failures leave the ledger byte-for-byte unchanged."""
    workspace = make_workspace(tmp_path)
    existing = b'{"attempt_id":"ATT-OLD1"}\n'
    (workspace / "attempts.jsonl").write_bytes(existing)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"x")

    code, _, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert (workspace / "attempts.jsonl").read_bytes() == existing


def test_success_output_does_not_reveal_result(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The success message does not include result text or SHA source data."""
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"super secret result\n")

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Secret attempt",
        "--status",
        "success",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert "super secret" not in stdout
    assert "result_text" not in stdout
    assert "attempt_id:" in stdout
    assert "host_id:" in stdout
    assert "status:" in stdout
    assert "action:" in stdout
    assert "path:" in stdout
    assert "result_sha256:" in stdout


def test_validate_only_checks_candidate_without_appending(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "result.txt"
    result_file.write_bytes(b"bounded synthetic summary")

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Validate synthetic attempt",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        "--validate-only",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert "validation: valid" in stdout
    assert "prospective_attempt_id:" in stdout
    assert (workspace / "attempts.jsonl").read_bytes() == b""


def test_oversized_result_requires_evidence_and_is_never_truncated(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    result_file = tmp_path / "full-output.txt"
    original = b"x" * (log_attempt_module.RESULT_TEXT_MAX_BYTES + 1)
    result_file.write_bytes(original)

    code, _stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--action",
        "Reject oversized summary",
        "--status",
        "failed",
        "--result-file",
        str(result_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "capture the full output as immutable evidence" in stderr
    assert result_file.read_bytes() == original
    assert (workspace / "attempts.jsonl").read_bytes() == b""
