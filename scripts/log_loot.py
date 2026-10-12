"""Append one immutable JSON record to the operator loot ledger."""

import argparse
import hashlib
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import host_identity, ledger_io
else:
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]

HOST_ID_PATTERN = "H{:02d}"
VALID_HOST_IDS = {HOST_ID_PATTERN.format(i) for i in range(1, 100)}

CATEGORY_MAX_LEN = 40
LABEL_MAX_LEN = 160
SOURCE_MAX_LEN = 160
USERNAME_MAX_LEN = 160
LOOT_ID_RE = re.compile(r"^LOOT-\d{8}T\d{12}Z$")

FIELD_ORDER = (
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
)


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _has_control_characters(value: str) -> bool:
    """Return True if value contains ASCII control characters."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_host_id(host_id: str) -> None:
    """Validate that a host ID is in the H01..H99 range."""
    if not host_id:
        fatal("host ID must not be empty")
    if not host_id.isascii():
        fatal(f"host ID must be ASCII: {host_id!r}")
    if host_id != host_id.strip():
        fatal(f"host ID must not contain whitespace: {host_id!r}")
    if host_id == "H00":
        fatal("host ID H00 is reserved; expected H01 through H99")
    if host_id not in VALID_HOST_IDS:
        fatal(
            "invalid host ID; expected 'H' followed by exactly two decimal "
            f"digits from 01 to 99, e.g. H01, got {host_id!r}"
        )


def validate_metadata(value: str, name: str, max_len: int) -> str:
    """Validate a single-line printable metadata field and return it."""
    if not value:
        fatal(f"{name} must not be empty")
    if _has_control_characters(value):
        fatal(f"{name} must not contain control characters")
    if "\n" in value or "\r" in value:
        fatal(f"{name} must be single-line text")
    if not value.strip():
        fatal(f"{name} must not contain only whitespace")
    if not value.isprintable():
        fatal(f"{name} must be printable text")
    if len(value) > max_len:
        fatal(f"{name} too long: {len(value)} characters (max {max_len})")
    return value


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
        host_md = host_identity.host_paths(resolved, host_id).state
    except host_identity.HostIdentityError as exc:
        fatal(f"workspace is missing host record: {exc}")
    if not host_md.is_file():
        fatal("workspace is missing host record")

    loot_path = resolved / "loot.jsonl"
    if not loot_path.exists() and not loot_path.is_symlink():
        fatal(f"workspace is missing loot.jsonl: {loot_path!r}")
    if loot_path.is_symlink() or not loot_path.is_file():
        fatal(
            "loot.jsonl is not a regular file or is a symbolic link: "
            f"{loot_path!r}"
        )

    return resolved


def read_value(value_file: str | None) -> tuple[bytes, str]:
    """Read value bytes from a file or standard input and validate them."""
    if value_file is not None:
        path = Path(value_file)
        if not path.exists():
            fatal(f"value file does not exist: {value_file!r}")
        if not path.is_file():
            fatal(f"value file is not a regular file: {value_file!r}")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            fatal(f"cannot read value file: {exc}")
    else:
        try:
            raw = sys.stdin.buffer.read()
        except OSError as exc:
            fatal(f"cannot read standard input: {exc}")

    if len(raw) == 0:
        fatal("value is empty")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fatal(f"value is not valid UTF-8: {exc}")

    if not text.strip():
        fatal("value contains only whitespace")

    return raw, text


def build_loot_id(now: datetime) -> str:
    """Generate a loot ID from a UTC datetime with microsecond precision."""
    return now.strftime("LOOT-%Y%m%dT%H%M%S%fZ")


def build_record(
    loot_id: str,
    now: datetime,
    host_id: str,
    category: str,
    label: str,
    source: str,
    username: str,
    value_bytes: bytes,
    value_text: str,
) -> dict[str, Any]:
    """Build the canonical loot record dictionary in the required order."""
    sha256 = hashlib.sha256(value_bytes).hexdigest()
    record: dict[str, Any] = {}
    record["schema_version"] = "1.0"
    record["loot_id"] = loot_id
    record["timestamp_utc"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    record["host_id"] = host_id
    record["category"] = category
    record["label"] = label
    record["source"] = source
    record["username"] = username
    record["value_sha256"] = sha256
    record["value_text"] = value_text

    # Defensive: ensure the public field order never drifts.
    return {key: record[key] for key in FIELD_ORDER}


def _loot_id_exists(loot_path: Path, loot_id: str) -> bool:
    """Validate the complete ledger and report whether loot_id already exists."""
    exists = False
    identifiers: set[str] = set()
    try:
        with loot_path.open("rb") as handle:
            for number, line in enumerate(handle, 1):
                if not line.endswith(b"\n"):
                    fatal(f"loot ledger line {number} is not newline terminated")
                if not line.strip():
                    fatal(f"loot ledger line {number} is empty")
                try:
                    record = ledger_io.loads_json(line)
                except ledger_io.LedgerIOError:
                    fatal(f"loot ledger line {number} is invalid JSON")
                if not isinstance(record, dict):
                    fatal(f"loot ledger line {number} must be a JSON object")
                identifier = record.get("loot_id")
                if (
                    not isinstance(identifier, str)
                    or LOOT_ID_RE.fullmatch(identifier) is None
                ):
                    fatal(f"loot ledger line {number} has invalid loot_id")
                if identifier in identifiers:
                    fatal(f"loot ledger line {number} duplicates loot_id")
                identifiers.add(identifier)
                if identifier == loot_id:
                    exists = True
    except OSError as exc:
        fatal(f"cannot read loot ledger: {exc}")
    return exists


def _append_record_unlocked(loot_path: Path, record: dict[str, Any]) -> None:
    """Append one compact JSON line while the caller holds the ledger lock."""
    try:
        ledger_io.append_json_record(loot_path, record, create=False)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to append loot record: {exc}")


def append_record(loot_path: Path, record: dict[str, Any]) -> None:
    """Append one compact JSON line under the per-ledger writer lock."""
    try:
        with ledger_io.exclusive_ledger_lock(loot_path):
            _append_record_unlocked(loot_path, record)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to append loot record: {exc}")


def log_loot(
    workspace: str,
    host_id: str,
    category: str,
    label: str,
    source: str | None,
    username: str | None,
    value_file: str | None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, Path, dict[str, Any]]:
    """Validate inputs and optionally append one loot-ledger record."""
    validate_host_id(host_id)
    category = validate_metadata(category, "category", CATEGORY_MAX_LEN)
    label = validate_metadata(label, "label", LABEL_MAX_LEN)
    source = validate_metadata(source or "unknown", "source", SOURCE_MAX_LEN)
    username = validate_metadata(username or "unknown", "username", USERNAME_MAX_LEN)

    validated_workspace = validate_workspace(workspace, host_id)
    value_bytes, value_text = read_value(value_file)

    if now is None:
        now = datetime.now(UTC)

    loot_id = build_loot_id(now)
    loot_path = validated_workspace / "loot.jsonl"

    record = build_record(
        loot_id=loot_id,
        now=now,
        host_id=host_id,
        category=category,
        label=label,
        source=source,
        username=username,
        value_bytes=value_bytes,
        value_text=value_text,
    )
    try:
        with ledger_io.exclusive_ledger_lock(loot_path):
            revalidated_workspace = validate_workspace(workspace, host_id)
            revalidated_path = revalidated_workspace / "loot.jsonl"
            if revalidated_path != loot_path:
                fatal("loot ledger changed while waiting for its writer lock")
            if _loot_id_exists(loot_path, loot_id):
                fatal(f"duplicate loot_id: {loot_id}")
            if not validate_only:
                _append_record_unlocked(loot_path, record)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to update loot ledger: {exc}")

    if not validate_only:
        try:
            if __package__:
                from . import host_state
            else:
                import host_state
            host_state.best_effort_refresh(validated_workspace, [host_id])
        except Exception:  # noqa: BLE001 - the immutable loot record is authoritative
            return validated_workspace, loot_path, record

    return validated_workspace, loot_path, record


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Append one immutable JSON record to the operator loot ledger."
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
        "--category",
        required=True,
        help="loot category",
    )
    parser.add_argument(
        "--label",
        required=True,
        help="short human-readable label",
    )
    parser.add_argument(
        "--source",
        default="unknown",
        help="where the loot was found (default: unknown)",
    )
    parser.add_argument(
        "--username",
        default="unknown",
        help="username associated with the loot (default: unknown)",
    )
    parser.add_argument(
        "--value-file",
        default=None,
        help="path to a file containing the value (default: read stdin)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="run the complete append validation without changing loot.jsonl",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    workspace_path, loot_path, record = log_loot(
        workspace=args.workspace,
        host_id=args.host_id,
        category=args.category,
        label=args.label,
        source=args.source,
        username=args.username,
        value_file=args.value_file,
        now=now,
        validate_only=args.validate_only,
    )

    relative_path = loot_path.relative_to(workspace_path).as_posix()

    if args.validate_only:
        print("validation: valid")
        print(f"prospective_loot_id: {record['loot_id']}")
    else:
        print(f"loot_id: {record['loot_id']}")
    print(f"host_id: {record['host_id']}")
    print(f"category: {record['category']}")
    print(f"label: {record['label']}")
    print(f"path: {relative_path}")
    print(f"value_sha256: {record['value_sha256']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
