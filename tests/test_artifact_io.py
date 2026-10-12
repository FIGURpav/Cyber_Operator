"""Immutable publication survives collisions, concurrency and failed commits."""

import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from scripts import artifact_io


def test_concurrent_publication_has_exactly_one_winner(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.txt"
    barrier = threading.Barrier(6)

    def publish(index: int) -> bytes | None:
        payload = f"writer-{index}".encode()
        barrier.wait(timeout=10)
        try:
            artifact_io.publish_file(destination, payload)
            return payload
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(publish, range(6)))
    winners = [result for result in results if result is not None]
    assert winners == [destination.read_bytes()]
    assert list(tmp_path.iterdir()) == [destination]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_dangling_symlink_is_a_collision(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.txt"
    outside = tmp_path / "missing.txt"
    destination.symlink_to(outside)
    with pytest.raises(FileExistsError):
        artifact_io.publish_file(destination, b"new evidence")
    assert destination.is_symlink()
    assert not outside.exists()


def test_rollback_preserves_replacement_file(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.txt"
    receipt = artifact_io.publish_file(destination, b"ours")
    # Keep the old inode alive so a filesystem cannot immediately reuse it.
    os.link(destination, tmp_path / "old-inode")
    destination.unlink()
    destination.write_bytes(b"other writer")
    artifact_io.remove_published(receipt)
    assert destination.read_bytes() == b"other writer"


def test_failed_directory_fsync_rolls_back_own_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = os.fsync

    def fail_directory(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("synthetic directory fsync failure")
        original(descriptor)

    monkeypatch.setattr(artifact_io.os, "fsync", fail_directory)
    with pytest.raises(OSError, match="fsync failure"):
        artifact_io.publish_file(tmp_path / "evidence.txt", b"private bytes")
    assert list(tmp_path.iterdir()) == []


def test_directory_publication_preserves_existing_empty_directory(tmp_path: Path) -> None:
    source, destination = tmp_path / "staging", tmp_path / "checkpoint"
    source.mkdir()
    (source / "manifest.json").write_text("synthetic")
    destination.mkdir()
    with pytest.raises(FileExistsError):
        artifact_io.publish_directory(source, destination)
    assert list(destination.iterdir()) == []
    assert (source / "manifest.json").read_text() == "synthetic"
