"""Capture one immutable evidence artifact and its metadata."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import artifact_handling, host_identity, workspace_transaction
else:
    import artifact_handling
    import host_identity  # type: ignore[no-redef]
    import workspace_transaction  # type: ignore[no-redef]

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")

KIND_MAX_LEN = 40
LABEL_MAX_LEN = 160
EXTENSION_MAX_LEN = 10

VALID_KIND_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
VALID_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$")

FIELD_ORDER = (
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
)


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _has_control_characters(value: str) -> bool:
    """Return True if value contains ASCII control characters."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_host_id(host_id: str) -> None:
    """Validate a canonical Hxx host ID, allowing growth beyond H99."""
    if not host_id:
        fatal("host ID must not be empty")
    if not host_id.isascii():
        fatal(f"host ID must be ASCII: {host_id!r}")
    if host_id != host_id.strip():
        fatal(f"host ID must not contain whitespace: {host_id!r}")
    if HOST_ID_RE.fullmatch(host_id) is None:
        fatal(
            "invalid host ID; expected canonical Hxx form, e.g. H01 or H100, "
            f"got {host_id!r}"
        )


def validate_kind(kind: str) -> str:
    """Validate that kind contains only allowed characters."""
    if not kind:
        fatal("kind must not be empty")
    if not kind.isascii():
        fatal(f"kind must be ASCII: {kind!r}")
    if not VALID_KIND_RE.fullmatch(kind):
        fatal(
            f"invalid kind; expected 1-{KIND_MAX_LEN} lowercase ASCII letters, "
            f"digits, hyphen, or underscore, got {kind!r}"
        )
    return kind


def validate_label(label: str) -> str:
    """Validate a single-line printable label and return it."""
    if not label:
        fatal("label must not be empty")
    if "\n" in label or "\r" in label:
        fatal("label must be single-line text")
    if _has_control_characters(label):
        fatal("label must not contain control characters")
    if not label.strip():
        fatal("label must not contain only whitespace")
    if not label.isprintable():
        fatal("label must be printable text")
    if len(label) > LABEL_MAX_LEN:
        fatal(f"label too long: {len(label)} characters (max {LABEL_MAX_LEN})")
    return label


def validate_extension(extension: str) -> str:
    """Validate an artifact extension."""
    if not extension:
        fatal("extension must not be empty")
    if not extension.isascii():
        fatal(f"extension must be ASCII: {extension!r}")
    if "." in extension:
        fatal(f"extension must not contain a dot: {extension!r}")
    if not VALID_EXTENSION_RE.fullmatch(extension):
        fatal(
            f"invalid extension; expected 1-{EXTENSION_MAX_LEN} lowercase ASCII "
            f"letters or digits, got {extension!r}"
        )
    if extension == "json":
        fatal("extension 'json' is reserved for evidence metadata")
    return extension


def validate_workspace(workspace: str, host_id: str) -> Path:
    """Return a safe workspace path or exit if the workspace is unusable."""
    path = Path(workspace)

    for part in path.parts:
        if part == "..":
            fatal(f"workspace path must not contain '..': {workspace!r}")

    resolved = path.resolve(strict=False)

    if not resolved.exists():
        fatal(f"workspace does not exist: {workspace!r}")
    if not resolved.is_dir():
        fatal(f"workspace is not a directory: {workspace!r}")

    global_md = resolved / "global.md"
    if not global_md.is_file():
        fatal(f"workspace is missing global.md: {workspace!r}")

    try:
        paths = host_identity.host_paths(resolved, host_id)
    except host_identity.HostIdentityError as exc:
        fatal(f"workspace is missing host record: {exc}")
    if not paths.state.is_file():
        fatal("workspace is missing host record")
    if not paths.evidence.is_dir():
        fatal("workspace is missing evidence directory")

    return resolved


def read_input(input_file: str | None) -> bytes:
    """Read raw bytes from a file or standard input and validate them."""
    if input_file is not None:
        path = Path(input_file)
        if not path.exists():
            fatal(f"input file does not exist: {input_file!r}")
        if not path.is_file():
            fatal(f"input file is not a regular file: {input_file!r}")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            fatal(f"cannot read input file: {exc}")
    else:
        try:
            raw = sys.stdin.buffer.read()
        except OSError as exc:
            fatal(f"cannot read standard input: {exc}")

    if len(raw) == 0:
        fatal("input is empty")

    return raw


def build_evidence_id(now: datetime) -> str:
    """Generate an evidence ID from a UTC datetime with microsecond precision."""
    return now.strftime("EVD-%Y%m%dT%H%M%S%fZ")


def build_record(
    evidence_id: str,
    now: datetime,
    host_id: str,
    kind: str,
    label: str,
    artifact_path: str,
    size_bytes: int,
    sha256: str,
    origin: str = "target-file",
) -> dict[str, Any]:
    """Build the canonical evidence metadata dictionary in the required order."""
    record: dict[str, Any] = {}
    record["schema_version"] = "1.1"
    record["evidence_id"] = evidence_id
    record["timestamp_utc"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    record["host_id"] = host_id
    record["kind"] = kind
    record["origin"] = origin
    record["label"] = label
    record["artifact_path"] = artifact_path
    record["size_bytes"] = size_bytes
    record["sha256"] = sha256

    # Defensive: ensure the public field order never drifts.
    return {key: record[key] for key in FIELD_ORDER}


def capture_evidence(
    workspace: str,
    host_id: str,
    kind: str,
    label: str,
    extension: str,
    input_file: str | None,
    now: datetime | None = None,
    origin: str = "target-file",
) -> tuple[Path, Path, dict[str, Any]]:
    validate_host_id(host_id)
    root = validate_workspace(workspace, host_id)
    try:
        with workspace_transaction.write_guard(root):
            artifact_handling.require_local_persistence(root, origin)
            return _capture_guarded(workspace, host_id, kind, label, extension, input_file, now, origin)
    except (OSError, RuntimeError) as exc:
        fatal(str(exc))


def _capture_guarded(
    workspace: str, host_id: str, kind: str, label: str, extension: str,
    input_file: str | None, now: datetime | None = None, origin: str = "target-file",
) -> tuple[Path, Path, dict[str, Any]]:
    """Validate inputs and capture one immutable evidence artifact."""
    validate_host_id(host_id)
    kind = validate_kind(kind)
    label = validate_label(label)
    extension = validate_extension(extension)

    validated_workspace = validate_workspace(workspace, host_id)
    raw = read_input(input_file)

    if now is None:
        now = datetime.now(UTC)

    evidence_id = build_evidence_id(now)
    try:
        paths = host_identity.host_paths(validated_workspace, host_id)
        basename = host_identity.evidence_basename(paths.record, evidence_id)
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))
    evidence_dir = paths.evidence
    artifact_path = evidence_dir / f"{basename}.{extension}"
    metadata_path = evidence_dir / f"{basename}.json"

    if artifact_path.exists():
        fatal(f"artifact already exists: {artifact_path!r}")
    if metadata_path.exists():
        fatal(f"metadata already exists: {metadata_path!r}")

    sha256 = hashlib.sha256(raw).hexdigest()
    size_bytes = len(raw)
    relative_artifact = artifact_path.relative_to(validated_workspace).as_posix()

    record = build_record(
        evidence_id=evidence_id,
        now=now,
        host_id=paths.record.host_id,
        kind=kind,
        label=label,
        artifact_path=relative_artifact,
        size_bytes=size_bytes,
        sha256=sha256,
        origin=origin,
    )
    metadata_json = json.dumps(record, ensure_ascii=False, separators=(",", ":"))

    transaction = workspace_transaction.Transaction(
        validated_workspace, "evidence", references={"evidence_id": evidence_id, "host_id": paths.record.host_id},
    )
    transaction.add("create", artifact_path, raw)
    transaction.add("create", metadata_path, metadata_json.encode("utf-8"))
    transaction.commit()

    return validated_workspace, artifact_path, record


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Capture one immutable evidence artifact and its metadata."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="explicit private workspace directory",
    )
    parser.add_argument(
        "--host-id",
        required=True,
        help="host identifier, e.g. H01",
    )
    parser.add_argument(
        "--kind",
        required=True,
        help="evidence kind, e.g. nmap",
    )
    parser.add_argument(
        "--label",
        required=True,
        help="short human-readable label",
    )
    parser.add_argument(
        "--input-file",
        default=None,
        help="path to a file containing the input (default: read stdin)",
    )
    parser.add_argument(
        "--extension",
        default="txt",
        help="artifact file extension (default: txt)",
    )
    parser.add_argument("--origin", choices=("target-file", "operator-generated"), default="target-file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    workspace_path, artifact_path, record = capture_evidence(
        origin=args.origin,
        workspace=args.workspace,
        host_id=args.host_id,
        kind=args.kind,
        label=args.label,
        extension=args.extension,
        input_file=args.input_file,
        now=now,
    )

    relative_path = artifact_path.relative_to(workspace_path).as_posix()

    print(f"evidence_id: {record['evidence_id']}")
    print(f"host_id: {record['host_id']}")
    print(f"kind: {record['kind']}")
    print(f"label: {record['label']}")
    print(f"artifact_path: {relative_path}")
    print(f"size_bytes: {record['size_bytes']}")
    print(f"sha256: {record['sha256']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
