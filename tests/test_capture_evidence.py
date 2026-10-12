"""Tests for scripts/capture_evidence.py."""

import hashlib
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.capture_evidence import main

FIXED_NOW = datetime(2026, 7, 29, 12, 0, 0, 123456, tzinfo=UTC)
EXPECTED_EVIDENCE_ID = "EVD-20260729T120000123456Z"
EXPECTED_TIMESTAMP = "2026-07-29T12:00:00.123456Z"

EXPECTED_FIELDS = [
    "schema_version",
    "evidence_id",
    "timestamp_utc",
    "host_id",
    "kind",
    "origin",
    "label",
    "artifact_path",
    "size_bytes",
    "sha256",
]


def run(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    now: datetime | None = None,
) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(tmp_path: Path, host_id: str = "H01") -> Path:
    """Create a minimal valid workspace for evidence capture tests."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "hosts").mkdir()
    (workspace / "hosts" / f"{host_id}.md").write_text(
        f"# Host {host_id}\n", encoding="utf-8"
    )
    (workspace / "evidence").mkdir()
    (workspace / "evidence" / host_id).mkdir()
    return workspace


def test_file_input(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A file-supplied artifact is captured with exact metadata."""
    workspace = make_workspace(tmp_path)
    data = b"scan output\n"
    input_file = tmp_path / "nmap.txt"
    input_file.write_bytes(data)

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Initial TCP scan",
        "--input-file", str(input_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr

    artifact = workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.txt"
    metadata = workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.json"
    assert artifact.read_bytes() == data

    record = json.loads(metadata.read_text(encoding="utf-8"))
    assert list(record.keys()) == EXPECTED_FIELDS
    assert record["schema_version"] == "1.1"
    assert record["origin"] == "target-file"
    assert record["evidence_id"] == EXPECTED_EVIDENCE_ID
    assert record["timestamp_utc"] == EXPECTED_TIMESTAMP
    assert record["host_id"] == "H01"
    assert record["kind"] == "nmap"
    assert record["label"] == "Initial TCP scan"
    assert record["artifact_path"] == f"evidence/H01/{EXPECTED_EVIDENCE_ID}.txt"
    assert record["size_bytes"] == len(data)
    assert record["sha256"] == hashlib.sha256(data).hexdigest()

    assert f"evidence_id: {EXPECTED_EVIDENCE_ID}" in stdout
    assert "host_id: H01" in stdout
    assert "kind: nmap" in stdout
    assert "label: Initial TCP scan" in stdout
    assert f"artifact_path: evidence/H01/{EXPECTED_EVIDENCE_ID}.txt" in stdout
    assert "size_bytes: 12" in stdout
    assert f"sha256: {record['sha256']}" in stdout
    assert "scan output" not in stdout
    assert "scan output" not in stderr


def test_stdin_input(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdin-supplied artifact is captured correctly."""
    workspace = make_workspace(tmp_path)
    data = b"stdin payload\n"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "gobuster",
        "--label", "Stdin test",
        now=FIXED_NOW,
    )

    assert code == 0, stderr

    artifact = workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.txt"
    assert artifact.read_bytes() == data

    record = json.loads(
        (workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.json")
        .read_text(encoding="utf-8")
    )
    assert record["size_bytes"] == len(data)
    assert record["sha256"] == hashlib.sha256(data).hexdigest()
    assert EXPECTED_EVIDENCE_ID in stdout


def test_binary_input(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Binary data is preserved byte-for-byte."""
    workspace = make_workspace(tmp_path)
    data = bytes(range(256))
    input_file = tmp_path / "binary.bin"
    input_file.write_bytes(data)

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Binary scan",
        "--input-file", str(input_file),
        "--extension", "bin",
        now=FIXED_NOW,
    )

    assert code == 0, stderr

    artifact = workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.bin"
    assert artifact.read_bytes() == data

    record = json.loads(
        (workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.json")
        .read_text(encoding="utf-8")
    )
    assert record["size_bytes"] == 256
    assert record["sha256"] == hashlib.sha256(data).hexdigest()
    assert data not in stdout.encode("utf-8")


def test_custom_extension(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A custom extension is applied to the artifact filename."""
    workspace = make_workspace(tmp_path)
    data = b"data"
    input_file = tmp_path / "data.xml"
    input_file.write_bytes(data)

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "XML output",
        "--input-file", str(input_file),
        "--extension", "xml",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert (
        workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.xml"
    ).is_file()
    assert (
        workspace / "evidence" / "H01" / f"{EXPECTED_EVIDENCE_ID}.json"
    ).is_file()


@pytest.mark.parametrize(
    "host_id",
    ["", "H00", "H001", "h01", "A01", "H1", "H01 ", "H 01"],
)
def test_invalid_host_id(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    host_id: str,
) -> None:
    """Invalid host IDs are rejected."""
    workspace = make_workspace(tmp_path)
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", host_id,
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(tmp_path / "placeholder.txt"),
    )
    assert code != 0
    assert "host id" in stderr.lower()


def test_h100_host_id_is_supported(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Evidence capture follows the canonical host scheme beyond H99."""
    workspace = make_workspace(tmp_path, host_id="H100")
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"synthetic evidence")
    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H100",
        "--kind",
        "test",
        "--label",
        "Synthetic H100 evidence",
        "--input-file",
        str(input_file),
        now=FIXED_NOW,
    )
    assert code == 0, stderr
    assert "host_id: H100" in stdout


@pytest.mark.parametrize(
    "kind",
    ["", "Nmap", "nmap scan", "nmap!", "a" * 41],
)
def test_invalid_kind(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    kind: str,
) -> None:
    """Invalid kinds are rejected."""
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "placeholder.txt"
    input_file.write_bytes(b"data")
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", kind,
        "--label", "Test",
        "--input-file", str(input_file),
    )
    assert code != 0
    assert "kind" in stderr.lower()


@pytest.mark.parametrize(
    "label",
    ["", "line1\nline2", "\x00hidden", " ", "a" * 161],
)
def test_invalid_label(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    label: str,
) -> None:
    """Invalid labels are rejected."""
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "placeholder.txt"
    input_file.write_bytes(b"data")
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", label,
        "--input-file", str(input_file),
    )
    assert code != 0
    assert "label" in stderr.lower()


@pytest.mark.parametrize(
    "extension",
    ["", "TXT", "t.t", "toolong1234", "tx!", ".txt", "txt/log", "json"],
)
def test_invalid_extension(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    extension: str,
) -> None:
    """Invalid extensions are rejected."""
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "placeholder.txt"
    input_file.write_bytes(b"data")
    args = [
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(input_file),
    ]
    args.extend(["--extension", extension])
    code, _, stderr = run(capsys, *args)
    assert code != 0
    assert "extension" in stderr.lower()


def test_missing_workspace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A non-existent workspace is rejected."""
    workspace = tmp_path / "does_not_exist"
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
    )
    assert code != 0
    assert "workspace does not exist" in stderr


def test_missing_host_record(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A workspace without the host record is rejected."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "hosts").mkdir()
    (workspace / "evidence").mkdir()
    (workspace / "evidence" / "H01").mkdir()

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
    )
    assert code != 0
    assert "missing host record" in stderr


def test_missing_evidence_directory(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A workspace without the host evidence directory is rejected."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "hosts").mkdir()
    (workspace / "hosts" / "H01.md").write_text("# Host H01\n", encoding="utf-8")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
    )
    assert code != 0
    assert "missing evidence directory" in stderr


def test_input_file_missing(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A missing input file is rejected."""
    workspace = make_workspace(tmp_path)
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(tmp_path / "missing.txt"),
    )
    assert code != 0
    assert "input file does not exist" in stderr


def test_input_file_is_directory(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A directory passed as input file is rejected."""
    workspace = make_workspace(tmp_path)
    dir_path = tmp_path / "directory_input"
    dir_path.mkdir()
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(dir_path),
    )
    assert code != 0
    assert "input file is not a regular file" in stderr


def test_empty_file_input(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """An empty input file is rejected."""
    workspace = make_workspace(tmp_path)
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(empty_file),
    )
    assert code != 0
    assert "input is empty" in stderr


def test_empty_stdin_input(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty standard input is rejected."""
    workspace = make_workspace(tmp_path)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"")))
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
    )
    assert code != 0
    assert "input is empty" in stderr


def test_conflict_without_overwrite(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Existing artifact or metadata files are never overwritten."""
    workspace = make_workspace(tmp_path)
    evidence_dir = workspace / "evidence" / "H01"
    existing_data = b"existing artifact\n"
    artifact = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.txt"
    metadata = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.json"
    artifact.write_bytes(existing_data)
    metadata.write_text("{}", encoding="utf-8")

    new_file = tmp_path / "new.txt"
    new_file.write_bytes(b"new data\n")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Test",
        "--input-file", str(new_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "already exists" in stderr
    assert artifact.read_bytes() == existing_data
    assert metadata.read_text(encoding="utf-8") == "{}"


def test_metadata_collision_after_preflight_preserves_other_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import capture_evidence, workspace_transaction

    workspace = make_workspace(tmp_path)
    source = tmp_path / "input.txt"
    source.write_bytes(b"our artifact")
    evidence_dir = workspace / "evidence/H01"
    metadata = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.json"

    def collide(_identifier, index):
        if index == 0:
            metadata.write_bytes(b"other writer metadata")

    monkeypatch.setattr(workspace_transaction, "_after_operation", collide)
    with pytest.raises(SystemExit):
        capture_evidence.capture_evidence(
            str(workspace), "H01", "manual", "Synthetic", "txt", str(source), now=FIXED_NOW,
        )
    assert metadata.read_bytes() == b"other writer metadata"
    assert (evidence_dir / f"{EXPECTED_EVIDENCE_ID}.txt").read_bytes() == b"our artifact"
    assert len(workspace_transaction.incomplete(workspace)) == 1
    # Collision recovery never deletes or overwrites another writer's bytes.
    with pytest.raises(workspace_transaction.TransactionError, match="conflicts"):
        workspace_transaction.replay(workspace, workspace_transaction.incomplete(workspace)[0])
    assert metadata.read_bytes() == b"other writer metadata"


def test_recovery_after_metadata_write_failure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import workspace_transaction

    workspace = make_workspace(tmp_path)
    data = b"partial data"
    input_file = tmp_path / "data.txt"
    input_file.write_bytes(data)

    def interrupt(_identifier, index):
        if index == 0:
            raise RuntimeError("forced interruption before metadata publication")

    monkeypatch.setattr(workspace_transaction, "_after_operation", interrupt)
    code, _, _ = run(
        capsys, "--workspace", str(workspace), "--host-id", "H01", "--kind", "nmap",
        "--label", "Test", "--input-file", str(input_file), now=FIXED_NOW,
    )
    assert code != 0
    evidence_dir = workspace / "evidence/H01"
    artifact = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.txt"
    metadata = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.json"
    assert artifact.read_bytes() == data
    assert not metadata.exists()
    transaction_id, = workspace_transaction.incomplete(workspace)
    monkeypatch.setattr(workspace_transaction, "_after_operation", lambda *_: None)
    workspace_transaction.replay(workspace, transaction_id)
    workspace_transaction.replay(workspace, transaction_id)
    assert artifact.read_bytes() == data
    assert json.loads(metadata.read_bytes())["size_bytes"] == len(data)
    assert workspace_transaction.incomplete(workspace) == []


def test_success_output_does_not_reveal_content(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Success output must not contain the artifact bytes."""
    workspace = make_workspace(tmp_path)
    data = b"SECRET_TOKEN_12345\n"
    input_file = tmp_path / "secret.txt"
    input_file.write_bytes(data)

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--kind", "nmap",
        "--label", "Secret scan",
        "--input-file", str(input_file),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert "SECRET_TOKEN_12345" not in stdout
    assert "SECRET_TOKEN_12345" not in stderr
