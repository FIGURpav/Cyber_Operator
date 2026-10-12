"""Publish immutable local files without replacing another writer's output."""

from __future__ import annotations

import ctypes
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def publish_directory(source: Path, destination: Path) -> None:
    """Atomically publish a completed directory on Linux, never replace a name."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError("atomic directory publication requires renameat2")
    result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class PublishedFile:
    path: Path
    device: int
    inode: int


def remove_published(receipt: PublishedFile) -> None:
    """Roll back only the file published by this operation, if still present."""
    try:
        current = receipt.path.lstat()
        if (current.st_dev, current.st_ino) == (receipt.device, receipt.inode):
            receipt.path.unlink()
    except FileNotFoundError:
        pass


def publish_file(path: Path, data: bytes | str) -> PublishedFile:
    """Fsync owner-only bytes, then link them into place with no replacement.

    The caller supplies a validated directory. Atomic publication also rejects
    dangling destination symlinks. A failed write never owns an existing file.
    """
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f".{path.name}.{secrets.token_hex(16)}.tmp"
    created = False
    published = False
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory,
        )
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            identity = os.fstat(handle.fileno())
        os.link(
            temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
            follow_symlinks=False,
        )
        published = True
        os.fsync(directory)
        return PublishedFile(path, identity.st_dev, identity.st_ino)
    except BaseException:
        if published:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.unlink(path.name, dir_fd=directory)
        raise
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=directory)
        finally:
            os.close(directory)
