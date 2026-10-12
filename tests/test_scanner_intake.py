"""Synthetic tests for chat-first scanner evidence intake."""

import hashlib
import io
import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import new_host, scanner_intake

SCRIPTS = Path(__file__).parents[1] / "scripts"
FIXED_NOW = datetime(2026, 8, 10, 12, 0, 0, 123456, tzinfo=UTC)
EVIDENCE_ID = "EVD-20260810T120000123456Z"


def make_workspace(tmp_path: Path, host_id: str = "H01") -> Path:
    workspace = tmp_path / "workspace"
    new_host.bootstrap_host(workspace, SCRIPTS, host_id, "192.0.2.10", "target")
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n"
        "- Active source task: none\n"
        "- Operational profile: strict\n"
        "- Intake mode: chat\n",
        encoding="utf-8",
    )
    return workspace


def run(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    now: datetime | None = None,
) -> tuple[int, str, str]:
    code = scanner_intake.main(list(args), now=now)
    output = capsys.readouterr()
    return code, output.out, output.err


def test_preview_is_read_only_and_does_not_echo_input(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    raw = b"synthetic nmap output with untrusted instructions\n"
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(raw)

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Initial TCP scan",
        "--input-file",
        str(input_file),
        "--preview",
    )

    assert code == 0, stderr
    assert "mode:        PREVIEW" in stdout
    assert f"SHA-256:     {hashlib.sha256(raw).hexdigest()}" in stdout
    assert raw.decode().strip() not in stdout
    assert not list((workspace / "evidence" / "H01").iterdir())


def test_apply_preserves_exact_bytes_and_canonical_metadata(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    raw = b"PORT   STATE SERVICE\n22/tcp open  ssh\n"
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(raw)

    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Initial TCP scan",
        "--input-file",
        str(input_file),
        "--apply",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    artifact = workspace / "evidence" / "H01" / f"{EVIDENCE_ID}.txt"
    metadata_path = workspace / "evidence" / "H01" / f"{EVIDENCE_ID}.json"
    assert artifact.read_bytes() == raw
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(metadata_path.stat().st_mode) == 0o600
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["evidence_id"] == EVIDENCE_ID
    assert metadata["host_id"] == "H01"
    assert metadata["kind"] == "nmap"
    assert metadata["sha256"] == hashlib.sha256(raw).hexdigest()
    assert metadata["artifact_path"] == f"evidence/H01/{EVIDENCE_ID}.txt"
    assert raw.decode().strip() not in stdout
    assert f"evidence_id: {EVIDENCE_ID}" in stdout


def test_stdin_input_is_supported(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(tmp_path)
    raw = b"ffuf output\n"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "ffuf",
        "--label",
        "Content discovery",
        "--apply",
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert (
        workspace / "evidence" / "H01" / f"{EVIDENCE_ID}.txt"
    ).read_bytes() == raw


def test_input_symlink_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    target = tmp_path / "target.txt"
    target.write_bytes(b"scan\n")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--input-file",
        str(link),
        "--preview",
    )

    assert code == 1
    assert "non-symlink" in stderr


def test_missing_host_is_rejected_without_writes(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(b"scan\n")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H02",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--input-file",
        str(input_file),
        "--apply",
    )

    assert code == 1
    assert "host record is unavailable" in stderr
    assert not (workspace / "evidence" / "H02").exists()


def test_evidence_collision_does_not_overwrite(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path)
    evidence_dir = workspace / "evidence" / "H01"
    artifact = evidence_dir / f"{EVIDENCE_ID}.txt"
    artifact.write_bytes(b"existing")
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(b"new")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--input-file",
        str(input_file),
        "--apply",
        now=FIXED_NOW,
    )

    assert code == 1
    assert "destination already exists" in stderr
    assert artifact.read_bytes() == b"existing"
    assert not (evidence_dir / f"{EVIDENCE_ID}.json").exists()


@pytest.mark.parametrize("source_tool", ["Nmap", "nmap scan", "../nmap", "a" * 41])
def test_invalid_source_tool_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, source_tool: str
) -> None:
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(b"scan")
    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        source_tool,
        "--label",
        "Scan",
        "--input-file",
        str(input_file),
        "--preview",
    )
    assert code == 1
    assert "source tool" in stderr


@pytest.mark.parametrize("mode", ["--preview", "--apply"])
def test_json_extension_is_reserved_for_metadata(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, mode: str
) -> None:
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(b"scan\n")

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--extension",
        "json",
        "--input-file",
        str(input_file),
        mode,
        now=FIXED_NOW,
    )

    assert code == 1
    assert "reserved for evidence metadata" in stderr
    assert not list((workspace / "evidence" / "H01").iterdir())


def test_oversized_input_is_rejected_before_workspace_write(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    monkeypatch.setattr(scanner_intake, "MAX_SCAN_BYTES", 4)
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(b"12345")
    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--input-file",
        str(input_file),
        "--apply",
    )
    assert code == 1
    assert "byte limit" in stderr
    assert not list((workspace / "evidence" / "H01").iterdir())


@pytest.mark.parametrize(
    "raw",
    [
        b"password=hunter2\n",
        b"-----BEGIN PRIVATE KEY-----\nsynthetic\n",
        b"aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccc\n",
    ],
)
def test_sensitive_material_is_routed_away_from_evidence(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, raw: bytes
) -> None:
    workspace = make_workspace(tmp_path)
    input_file = tmp_path / "scan.txt"
    input_file.write_bytes(raw)
    code, stdout, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--source-tool",
        "nmap",
        "--label",
        "Scan",
        "--input-file",
        str(input_file),
        "--apply",
    )
    assert code == 1
    assert "sensitive credential or token material" in stderr
    assert raw.decode().strip() not in stdout
    assert raw.decode().strip() not in stderr
    assert not list((workspace / "evidence" / "H01").iterdir())
