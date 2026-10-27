#!/usr/bin/env python3
"""Preview or preserve one bounded scanner output as immutable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from . import host_identity, new_host, workspace_transaction
else:
    import host_identity
    import new_host
    import workspace_transaction

MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_LABEL_LENGTH = 160
HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
SOURCE_TOOL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$")
SECRET_ASSIGNMENT_RE = re.compile(
    rb"(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"
)
JWT_RE = re.compile(
    rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\."
    rb"[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"
)
SENSITIVE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)


class ScannerIntakeError(RuntimeError):
    """A bounded, non-secret scanner intake failure."""


@dataclass(frozen=True)
class ScanPlan:
    """A fully validated scanner evidence plan."""

    workspace: Path
    host_id: str
    source_tool: str
    label: str
    extension: str
    input_bytes: bytes
    sha256: str


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _validate_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ScannerIntakeError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ScannerIntakeError(f"{label} must be a real regular file")
    return metadata


def _validate_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ScannerIntakeError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ScannerIntakeError(f"{label} must be a real directory")
    return metadata


def validate_workspace(path_text: str, host_id: str) -> Path:
    """Validate the canonical workspace and selected host without mutation."""
    supplied = Path(path_text)
    if ".." in supplied.parts:
        raise ScannerIntakeError("workspace path must not contain parent traversal")
    workspace = supplied if supplied.is_absolute() else Path.cwd() / supplied
    workspace = workspace.absolute()
    try:
        new_host.validate_workspace_layout(workspace)
    except new_host.WorkspaceLayoutError as exc:
        raise ScannerIntakeError(str(exc)) from exc
    _validate_directory(workspace, "workspace")
    _validate_regular(workspace / "TASK_CONTEXT.md", "TASK_CONTEXT.md")
    _validate_regular(workspace / "global.md", "global.md")
    _validate_directory(workspace / "hosts", "hosts directory")
    _validate_directory(workspace / "evidence", "evidence directory")
    try:
        paths = host_identity.host_paths(workspace, host_id)
    except host_identity.HostIdentityError as exc:
        raise ScannerIntakeError("host record is unavailable") from exc
    _validate_regular(paths.state, "host record")
    host_evidence = paths.evidence
    _validate_directory(host_evidence, "host evidence directory")
    try:
        host_evidence.relative_to(workspace)
    except ValueError as exc:
        raise ScannerIntakeError("host evidence directory escapes workspace") from exc
    return workspace


def _validate_host_id(host_id: str) -> str:
    if HOST_ID_RE.fullmatch(host_id) is None:
        raise ScannerIntakeError(
            "invalid host ID; expected canonical Hxx form, e.g. H01 or H100"
        )
    return host_id


def _validate_source_tool(source_tool: str) -> str:
    if SOURCE_TOOL_RE.fullmatch(source_tool) is None:
        raise ScannerIntakeError(
            "source tool must use 1-40 lowercase letters, digits, '-' or '_'"
        )
    return source_tool


def _validate_label(label: str) -> str:
    if not label or not label.strip():
        raise ScannerIntakeError("label must not be empty")
    if len(label) > MAX_LABEL_LENGTH:
        raise ScannerIntakeError(
            f"label exceeds the {MAX_LABEL_LENGTH}-character limit"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise ScannerIntakeError("label must be printable single-line text")
    return label


def _validate_extension(extension: str) -> str:
    if EXTENSION_RE.fullmatch(extension) is None:
        raise ScannerIntakeError(
            "extension must use 1-10 lowercase ASCII letters or digits"
        )
    if extension == "json":
        raise ScannerIntakeError(
            "extension 'json' is reserved for evidence metadata"
        )
    return extension


def _reject_sensitive_material(input_bytes: bytes) -> None:
    """Keep credential and ephemeral-token values out of evidence storage."""
    if (
        any(marker in input_bytes for marker in SENSITIVE_MARKERS)
        or SECRET_ASSIGNMENT_RE.search(input_bytes)
        or JWT_RE.search(input_bytes)
    ):
        raise ScannerIntakeError(
            "scanner input appears to contain sensitive credential or token material; "
            "route the value through private credential or session-token intake"
        )


def _read_descriptor(descriptor: int, initial: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, MAX_SCAN_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_SCAN_BYTES:
            raise ScannerIntakeError(
                f"scanner input exceeds the {MAX_SCAN_BYTES}-byte limit"
            )
    final = os.fstat(descriptor)
    if (
        final.st_dev != initial.st_dev
        or final.st_ino != initial.st_ino
        or final.st_size != initial.st_size
        or final.st_mtime_ns != initial.st_mtime_ns
    ):
        raise ScannerIntakeError("scanner input changed while it was read")
    return b"".join(chunks)


def read_input(input_file: str | None) -> bytes:
    """Read exact bounded bytes from a verified file or stdin."""
    if input_file is None:
        try:
            data = sys.stdin.buffer.read(MAX_SCAN_BYTES + 1)
        except OSError as exc:
            raise ScannerIntakeError("scanner input could not be read from stdin") from exc
        if len(data) > MAX_SCAN_BYTES:
            raise ScannerIntakeError(
                f"scanner input exceeds the {MAX_SCAN_BYTES}-byte limit"
            )
    else:
        path = Path(input_file)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ScannerIntakeError(
                "scanner input must be an available regular non-symlink file"
            ) from exc
        try:
            initial = os.fstat(descriptor)
            if not stat.S_ISREG(initial.st_mode):
                raise ScannerIntakeError("scanner input must be a regular file")
            if initial.st_size > MAX_SCAN_BYTES:
                raise ScannerIntakeError(
                    f"scanner input exceeds the {MAX_SCAN_BYTES}-byte limit"
                )
            data = _read_descriptor(descriptor, initial)
        finally:
            os.close(descriptor)
    if not data:
        raise ScannerIntakeError("scanner input is empty")
    return data


def build_plan(
    *,
    workspace: str,
    host_id: str,
    source_tool: str,
    label: str,
    extension: str,
    input_bytes: bytes,
) -> ScanPlan:
    """Validate all scanner intake fields and build a read-only plan."""
    host_id = _validate_host_id(host_id)
    source_tool = _validate_source_tool(source_tool)
    label = _validate_label(label)
    extension = _validate_extension(extension)
    if not input_bytes:
        raise ScannerIntakeError("scanner input is empty")
    if len(input_bytes) > MAX_SCAN_BYTES:
        raise ScannerIntakeError(
            f"scanner input exceeds the {MAX_SCAN_BYTES}-byte limit"
        )
    _reject_sensitive_material(input_bytes)
    validated_workspace = validate_workspace(workspace, host_id)
    return ScanPlan(
        workspace=validated_workspace,
        host_id=host_id,
        source_tool=source_tool,
        label=label,
        extension=extension,
        input_bytes=input_bytes,
        sha256=hashlib.sha256(input_bytes).hexdigest(),
    )


def apply_plan(plan: ScanPlan, *, now: datetime | None = None) -> tuple[dict[str, object], Path]:
    try:
        with workspace_transaction.write_guard(plan.workspace):
            return _apply_plan_guarded(plan, now=now)
    except (OSError, RuntimeError) as exc:
        raise ScannerIntakeError(f"scanner evidence interrupted; inspect recovery journal: {exc}") from exc


def _apply_plan_guarded(
    plan: ScanPlan,
    *,
    now: datetime | None = None,
) -> tuple[dict[str, object], Path]:
    """Create one immutable evidence artifact and matching metadata."""
    current = now or datetime.now(UTC)
    evidence_id = current.strftime("EVD-%Y%m%dT%H%M%S%fZ")
    try:
        paths = host_identity.host_paths(plan.workspace, plan.host_id)
        basename = host_identity.evidence_basename(paths.record, evidence_id)
    except host_identity.HostIdentityError as exc:
        raise ScannerIntakeError(str(exc)) from exc
    evidence_dir = paths.evidence
    artifact = evidence_dir / f"{basename}.{plan.extension}"
    metadata_path = evidence_dir / f"{basename}.json"
    if _lexists(artifact) or _lexists(metadata_path):
        raise ScannerIntakeError("evidence destination already exists")
    relative_artifact = artifact.relative_to(plan.workspace).as_posix()
    record: dict[str, object] = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "timestamp_utc": current.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": paths.record.host_id,
        "kind": plan.source_tool,
        "label": plan.label,
        "artifact_path": relative_artifact,
        "size_bytes": len(plan.input_bytes),
        "sha256": plan.sha256,
    }
    metadata = json.dumps(
        record,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    transaction = workspace_transaction.Transaction(
        plan.workspace, "evidence", references={"host_id": paths.record.host_id, "evidence_id": evidence_id},
    )
    transaction.add("create", artifact, plan.input_bytes)
    transaction.add("create", metadata_path, metadata)
    transaction.commit()
    return record, artifact


def print_plan(mode: str, plan: ScanPlan) -> None:
    """Print bounded metadata without echoing scanner content."""
    print("Cyber-Operator scanner intake")
    print(f"  mode:        {mode.upper()}")
    print(f"  host:        {plan.host_id}")
    print(f"  source tool: {plan.source_tool}")
    print(f"  label:       {plan.label}")
    print(f"  extension:   {plan.extension}")
    print(f"  bytes:       {len(plan.input_bytes)}")
    print(f"  SHA-256:     {plan.sha256}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="cyber-scan",
        description="Preview or preserve scanner output as immutable evidence.",
    )
    root.add_argument("--workspace", required=True)
    root.add_argument("--host-id", required=True)
    root.add_argument("--source-tool", required=True)
    root.add_argument("--label", required=True)
    root.add_argument("--extension", default="txt")
    root.add_argument(
        "--input-file",
        help="regular input file; omit to read exact bytes from stdin",
    )
    modes = root.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preview", action="store_true")
    modes.add_argument("--apply", action="store_true")
    return root


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        input_bytes = read_input(args.input_file)
        plan = build_plan(
            workspace=args.workspace,
            host_id=args.host_id,
            source_tool=args.source_tool,
            label=args.label,
            extension=args.extension,
            input_bytes=input_bytes,
        )
        print_plan("apply" if args.apply else "preview", plan)
        if args.preview:
            print("Preview only. Re-run with --apply using the same scanner bytes.")
            return 0
        record, artifact = apply_plan(plan, now=now)
        print(f"evidence_id: {record['evidence_id']}")
        print(f"artifact_path: {artifact.relative_to(plan.workspace).as_posix()}")
        print("Scanner output preserved as immutable evidence.")
        return 0
    except ScannerIntakeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("error: scanner intake filesystem operation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
