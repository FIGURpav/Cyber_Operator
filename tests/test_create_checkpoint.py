"""Tests for scripts/create_checkpoint.py."""

import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import create_checkpoint
from scripts.create_checkpoint import main

FIXED_NOW = datetime(2026, 7, 30, 12, 0, 0, 123456, tzinfo=UTC)
EXPECTED_CHECKPOINT_ID = "CHK-20260730T120000123456Z"
EXPECTED_TIMESTAMP = "2026-07-30T12:00:00.123456Z"

EXPECTED_FIELDS = [
    "schema_version",
    "checkpoint_id",
    "timestamp_utc",
    "source_workspace",
    "operational_profile",
    "unresolved_session_token_count",
    "contains_ephemeral_session_secrets",
    "file_count",
    "total_bytes",
    "files",
    "directories",
]

REQUIRED_FILES = ["global.md", "loot.jsonl", "attempts.jsonl"]
REQUIRED_DIRS = ["hosts", "queries", "evidence", "report"]


def run(capsys: pytest.CaptureFixture[str], *args: str, now: datetime | None = None) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(
    tmp_path: Path,
    extra_files: dict[str, bytes] | None = None,
    parent_name: str = "assessment_workspace",
) -> Path:
    """Create a minimal valid workspace for checkpoint tests."""
    workspace = tmp_path / parent_name
    workspace.mkdir()

    (workspace / "global.md").write_text("# Global\n", encoding="utf-8")
    (workspace / "loot.jsonl").write_bytes(b"")
    (workspace / "attempts.jsonl").write_bytes(b"")

    for name in REQUIRED_DIRS:
        (workspace / name).mkdir()

    if extra_files:
        for rel_path, content in extra_files.items():
            target = workspace / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    return workspace


def file_hashes(root: Path) -> dict[str, str]:
    """Return relative-path-to-sha256 mapping for all regular files under root."""
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(root).as_posix()
            result[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def test_private_permissions_and_verification_without_live_source(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, extra_files={"private/secret.txt": b"Synthetic secret"})
    (workspace / "private").chmod(0o700)
    (workspace / "private/secret.txt").chmod(0o600)
    previous = os.umask(0o022)
    try:
        _, checkpoint, _, _ = create_checkpoint.create_checkpoint(
            workspace, tmp_path / "checkpoints", FIXED_NOW, profile="strict",
            unresolved_session_token_count=0, contains_ephemeral_session_secrets=False,
        )
    finally:
        os.umask(previous)
    shutil.rmtree(workspace)
    manifest = create_checkpoint.verify_checkpoint(checkpoint)
    assert manifest["file_count"] == 4
    assert create_checkpoint.main(["--verify", str(checkpoint)]) == 0
    for path in (checkpoint, *checkpoint.rglob("*")):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize("damage", ["changed", "missing", "extra", "symlink", "permissions", "empty-directory"])
def test_verification_detects_damaged_checkpoint(tmp_path: Path, damage: str) -> None:
    workspace = make_workspace(tmp_path, extra_files={"evidence/proof.txt": b"proof"})
    (workspace / "empty").mkdir()
    _, checkpoint, _, _ = create_checkpoint.create_checkpoint(
        workspace, tmp_path / "checkpoints", FIXED_NOW, profile="strict",
        unresolved_session_token_count=0, contains_ephemeral_session_secrets=False,
    )
    artifact = checkpoint / "workspace/evidence/proof.txt"
    if damage == "changed":
        artifact.write_bytes(b"other")
    elif damage == "missing":
        artifact.unlink()
    elif damage == "extra":
        (checkpoint / "workspace/extra").write_text("unexpected")
    elif damage == "symlink":
        artifact.unlink()
        artifact.symlink_to(workspace / "evidence/proof.txt")
    elif damage == "permissions":
        (checkpoint / "workspace/evidence").chmod(0o755)
    else:
        (checkpoint / "workspace/empty").rmdir()
    with pytest.raises(create_checkpoint.CheckpointError):
        create_checkpoint.verify_checkpoint(checkpoint)


@pytest.mark.parametrize("failure", ["source-drift", "corrupt-copy", "publication-collision"])
def test_checkpoint_failure_preserves_destination_and_removes_only_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    workspace = make_workspace(tmp_path)
    destination = tmp_path / "checkpoints"
    final = destination / EXPECTED_CHECKPOINT_ID
    original_copy = create_checkpoint._copy_file
    original_publish = create_checkpoint.artifact_io.publish_directory

    def copy(source: Path, target: Path) -> None:
        original_copy(source, target)
        if source.name == "global.md":
            if failure == "source-drift":
                source.write_bytes(b"changed after copying")
            elif failure == "corrupt-copy":
                target.write_bytes(b"corrupted during copying")

    def publish(source: Path, target: Path) -> None:
        target.mkdir()
        (target / "other-writer").write_text("keep")
        original_publish(source, target)

    monkeypatch.setattr(create_checkpoint, "_copy_file", copy)
    if failure == "publication-collision":
        monkeypatch.setattr(create_checkpoint.artifact_io, "publish_directory", publish)
    with pytest.raises((create_checkpoint.CheckpointError, FileExistsError)):
        create_checkpoint.create_checkpoint(
            workspace, destination, FIXED_NOW, profile="strict",
            unresolved_session_token_count=0, contains_ephemeral_session_secrets=False,
        )
    if failure == "publication-collision":
        assert (final / "other-writer").read_text() == "keep"
        assert list(destination.iterdir()) == [final]
    else:
        assert list(destination.iterdir()) == []


def test_successful_complete_copy(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A valid workspace is copied completely into a checkpoint."""
    workspace = make_workspace(tmp_path, extra_files={"hosts/H01.md": b"# H01\n"})
    destination = tmp_path / "backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    checkpoint_dir = destination / EXPECTED_CHECKPOINT_ID
    assert checkpoint_dir.is_dir()
    assert (checkpoint_dir / "workspace" / "global.md").is_file()
    assert (checkpoint_dir / "workspace" / "hosts" / "H01.md").read_bytes() == b"# H01\n"


def test_nested_files_and_empty_directories(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Nested files and empty directories are preserved."""
    workspace = make_workspace(
        tmp_path,
        extra_files={
            "evidence/H01/scan.txt": b"scan output",
            "evidence/H01/deep/nested.txt": b"deep data",
        },
    )
    (workspace / "evidence" / "empty_dir").mkdir()
    destination = tmp_path / "backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    checkpoint_dir = destination / EXPECTED_CHECKPOINT_ID
    assert (checkpoint_dir / "workspace" / "evidence" / "H01" / "scan.txt").read_bytes() == b"scan output"
    assert (checkpoint_dir / "workspace" / "evidence" / "H01" / "deep" / "nested.txt").read_bytes() == b"deep data"
    assert (checkpoint_dir / "workspace" / "evidence" / "empty_dir").is_dir()


def test_exact_checkpoint_json_fields(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """checkpoint.json contains exactly the required fields in order."""
    workspace = make_workspace(tmp_path, extra_files={"hosts/H01.md": b"x"})
    destination = tmp_path / "backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    manifest_path = destination / EXPECTED_CHECKPOINT_ID / "checkpoint.json"
    raw = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(raw)

    assert list(manifest.keys()) == EXPECTED_FIELDS
    assert manifest["schema_version"] == "1.2"
    assert manifest["checkpoint_id"] == EXPECTED_CHECKPOINT_ID
    assert manifest["timestamp_utc"] == EXPECTED_TIMESTAMP
    assert manifest["source_workspace"] == str(workspace.resolve())
    assert manifest["operational_profile"] == "strict"
    assert manifest["unresolved_session_token_count"] == 0
    assert manifest["contains_ephemeral_session_secrets"] is False
    assert manifest["file_count"] == 4  # global.md, loot.jsonl, attempts.jsonl, hosts/H01.md
    assert manifest["total_bytes"] == sum(
        (workspace / p).stat().st_size for p in ["global.md", "loot.jsonl", "attempts.jsonl", "hosts/H01.md"]
    )
    assert raw.endswith("\n")


def test_deterministic_id_with_fixed_datetime(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Injecting a fixed datetime yields a deterministic checkpoint ID."""
    workspace = make_workspace(tmp_path)
    destination = tmp_path / "backups"

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert EXPECTED_CHECKPOINT_ID in stdout
    assert (destination / EXPECTED_CHECKPOINT_ID).is_dir()


def test_source_remains_unchanged(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The source workspace is byte-for-byte unchanged after checkpointing."""
    workspace = make_workspace(
        tmp_path,
        extra_files={
            "hosts/H01.md": b"# H01\n",
            "queries/q1.md": b"question",
            "evidence/H01/proof.txt": b"proof",
            "report/H01.md": b"report",
        },
    )
    before = file_hashes(workspace)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert file_hashes(workspace) == before


@pytest.mark.parametrize("missing", ["global.md", "loot.jsonl", "attempts.jsonl"])
def test_missing_required_file_rejected(
    missing: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace missing a required file is rejected."""
    workspace = make_workspace(tmp_path)
    (workspace / missing).unlink()

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing" in stderr.lower()


@pytest.mark.parametrize("missing", ["hosts", "queries", "evidence", "report"])
def test_missing_required_directory_rejected(
    missing: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace missing a required directory is rejected."""
    workspace = make_workspace(tmp_path)
    shutil.rmtree(workspace / missing)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "missing" in stderr.lower()


def test_workspace_as_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace path that is a regular file is rejected."""
    workspace_file = tmp_path / "assessment_workspace"
    workspace_file.write_bytes(b"")

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace_file),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "not a directory" in stderr.lower()


def test_workspace_does_not_exist_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace that does not exist is rejected."""
    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(tmp_path / "missing"),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "does not exist" in stderr.lower()


def test_destination_created_when_absent(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The destination directory is created when it does not exist."""
    workspace = make_workspace(tmp_path)
    destination = tmp_path / "new_backups" / "nested"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert destination.is_dir()
    assert (destination / EXPECTED_CHECKPOINT_ID / "checkpoint.json").is_file()


def test_destination_as_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A destination path that is an existing file is rejected."""
    workspace = make_workspace(tmp_path)
    destination_file = tmp_path / "backups"
    destination_file.write_bytes(b"")

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination_file),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "not a directory" in stderr.lower()


@pytest.mark.parametrize(
    "dest_suffix",
    ["", "/nested"],
    ids=["equal", "inside"],
)
def test_destination_equal_to_or_inside_workspace_rejected(
    dest_suffix: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A destination equal to or inside the workspace is rejected."""
    workspace = make_workspace(tmp_path)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(workspace) + dest_suffix,
        now=FIXED_NOW,
    )

    assert code != 0
    assert "inside" in stderr.lower()


def test_source_inside_destination_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A source workspace inside the destination is rejected."""
    destination = tmp_path / "backups"
    destination.mkdir()
    workspace = destination / "assessment_workspace"
    workspace.mkdir()
    for name in REQUIRED_FILES:
        (workspace / name).write_bytes(b"")
    for name in REQUIRED_DIRS:
        (workspace / name).mkdir()

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "inside" in stderr.lower()


def test_workspace_directly_inside_checkpoint_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace directly inside a checkpoint directory is rejected."""
    checkpoint_root = tmp_path / "backups" / EXPECTED_CHECKPOINT_ID
    workspace = checkpoint_root / "workspace"
    workspace.mkdir(parents=True)
    for name in REQUIRED_FILES:
        (workspace / name).write_bytes(b"")
    for name in REQUIRED_DIRS:
        (workspace / name).mkdir()
    destination = tmp_path / "other_backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "checkpoint" in stderr.lower()
    assert not destination.exists()


def test_workspace_nested_inside_checkpoint_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A workspace nested deeper inside a checkpoint directory is rejected."""
    checkpoint_root = tmp_path / "backups" / EXPECTED_CHECKPOINT_ID
    workspace = checkpoint_root / "workspace" / "hosts" / "H01"
    workspace.mkdir(parents=True)
    for name in REQUIRED_FILES:
        (workspace / name).write_bytes(b"")
    for name in REQUIRED_DIRS:
        (workspace / name).mkdir()
    destination = tmp_path / "other_backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "checkpoint" in stderr.lower()
    assert not destination.exists()


def test_unrelated_chk_directory_allowed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An unrelated directory whose name is not a valid checkpoint ID is allowed."""
    workspace = make_workspace(tmp_path, parent_name="CHK-not-a-checkpoint")
    destination = tmp_path / "backups"

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    assert (destination / EXPECTED_CHECKPOINT_ID / "checkpoint.json").is_file()


@pytest.mark.parametrize(
    "destination",
    ["../backups", "foo/../bar", "backups/.."],
)
def test_traversal_destination_rejected(
    destination: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Destination paths containing '..' are rejected."""
    workspace = make_workspace(tmp_path)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", destination,
        now=FIXED_NOW,
    )

    assert code != 0
    assert ".." in stderr


def test_symbolic_link_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Symbolic links anywhere in the workspace are rejected."""
    workspace = make_workspace(tmp_path)
    real_file = tmp_path / "secret.txt"
    real_file.write_bytes(b"secret")
    (workspace / "hosts" / "link.md").symlink_to(real_file)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "symbolic link" in stderr.lower()


@pytest.mark.skipif(sys.platform != "linux", reason="FIFO special files require Linux")
def test_special_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Non-regular special files in the workspace are rejected."""
    workspace = make_workspace(tmp_path)
    fifo_path = workspace / "evidence" / "pipe"
    os.mkfifo(fifo_path)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "special file" in stderr.lower()


def test_existing_checkpoint_conflict(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """An existing checkpoint directory with the same ID is not overwritten."""
    workspace = make_workspace(tmp_path)
    destination = tmp_path / "backups"
    existing = destination / EXPECTED_CHECKPOINT_ID
    existing.mkdir(parents=True)
    existing.joinpath("placeholder.txt").write_bytes(b"do not delete")

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "already exists" in stderr.lower()
    assert existing.joinpath("placeholder.txt").read_bytes() == b"do not delete"


def test_partial_checkpoint_cleanup_after_copy_failure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A partially created checkpoint directory is removed on copy failure."""
    workspace = make_workspace(
        tmp_path,
        extra_files={
            "hosts/H01.md": b"first",
            "hosts/H02.md": b"second",
        },
    )
    destination = tmp_path / "backups"

    original_copy = create_checkpoint._copy_file
    call_count = 0

    def failing_copy(src: Path, dst: Path) -> None:
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise OSError("simulated copy failure")
        return original_copy(src, dst)

    monkeypatch.setattr(create_checkpoint, "_copy_file", failing_copy)

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code != 0
    assert "simulated copy failure" in stderr.lower() or "unexpected error" in stderr.lower()
    assert not (destination / EXPECTED_CHECKPOINT_ID).exists()


def test_success_output(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Success output contains checkpoint ID, path, file count, and total bytes."""
    workspace = make_workspace(tmp_path, extra_files={"hosts/H01.md": b"x"})
    destination = tmp_path / "backups"

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--destination", str(destination),
        now=FIXED_NOW,
    )

    assert code == 0, stderr
    lines = stdout.strip().splitlines()
    assert lines[0] == EXPECTED_CHECKPOINT_ID
    assert lines[1] == str(destination / EXPECTED_CHECKPOINT_ID)
    assert lines[2] == "files: 4"
    assert lines[3] == "bytes: 10"


def test_normal_errors_without_traceback(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Errors produce a concise stderr message without a traceback."""
    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(tmp_path / "missing"),
        "--destination", str(tmp_path / "backups"),
        now=FIXED_NOW,
    )

    assert code != 0
    assert stderr.startswith("error:")
    assert "Traceback" not in stderr
    assert "Traceback" not in capsys.readouterr().err
