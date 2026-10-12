"""Append one immutable JSON record to the operator attempts ledger."""

import argparse
import hashlib
import json
import re
import stat
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

VALID_STATUSES = {"success", "failed", "partial", "blocked"}
ATTEMPT_ID_RE = re.compile(r"^ATT-\d{8}T\d{12}Z$")

METADATA_MAX_LEN = 240
PROBE_SPEC_MAX_BYTES = 64 * 1024
PROBE_TEXT_MAX_LEN = 2048
RESULT_TEXT_MAX_BYTES = 8 * 1024
CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

PROBE_SPEC_FIELDS = (
    "target_generation",
    "service",
    "endpoint",
    "technique",
    "variant",
    "credential_id",
    "helper_sha256",
)

FIELD_ORDER = (
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
)

PROBE_FIELD_ORDER = FIELD_ORDER + (
    "work_kind",
    "probe_fingerprint",
    "probe_spec",
    "duplicate_of",
    "retry_of",
    "retry_reason",
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


def validate_metadata(value: str, name: str, max_len: int = METADATA_MAX_LEN) -> str:
    """Validate a single-line printable metadata field and return it."""
    if not value:
        fatal(f"{name} must not be empty")
    if "\n" in value or "\r" in value:
        fatal(f"{name} must be single-line text")
    if _has_control_characters(value):
        fatal(f"{name} must not contain control characters")
    if not value.strip():
        fatal(f"{name} must not contain only whitespace")
    if not value.isprintable():
        fatal(f"{name} must be printable text")
    if len(value) > max_len:
        fatal(f"{name} too long: {len(value)} characters (max {max_len})")
    return value


def validate_status(status: str) -> str:
    """Validate that status is one of the allowed values."""
    if not status:
        fatal("status must not be empty")
    status_lower = status.lower()
    if status_lower not in VALID_STATUSES:
        fatal(
            f"invalid status; expected one of {', '.join(sorted(VALID_STATUSES))}, "
            f"got {status!r}"
        )
    return status_lower


def validate_evidence_refs(refs: list[str]) -> list[str]:
    """Validate evidence references and deduplicate while preserving order."""
    seen: set[str] = set()
    validated: list[str] = []

    for ref in refs:
        if not ref:
            fatal("evidence reference must not be empty")
        if not ref.isascii():
            fatal(f"evidence reference must be ASCII: {ref!r}")
        if _has_control_characters(ref):
            fatal(f"evidence reference must not contain control characters: {ref!r}")
        if not ref.isprintable():
            fatal(f"evidence reference must be printable text: {ref!r}")
        if ref.startswith("/"):
            fatal(f"evidence reference must be relative: {ref!r}")
        if ".." in ref:
            fatal(f"evidence reference must not contain '..': {ref!r}")
        if "//" in ref:
            fatal(f"evidence reference must not contain empty components: {ref!r}")
        if ref.startswith("/") or ref.endswith("/"):
            fatal(f"evidence reference must not contain empty components: {ref!r}")
        if "/./" in ref or ref.startswith("./") or ref.endswith("/."):
            fatal(f"evidence reference must not contain '.' components: {ref!r}")

        path = Path(ref)
        if path.is_absolute():
            fatal(f"evidence reference must be relative: {ref!r}")

        if ref not in seen:
            seen.add(ref)
            validated.append(ref)

    return validated


def _probe_text(
    value: Any,
    name: str,
    *,
    nullable: bool = False,
    lower: bool = False,
) -> str | None:
    """Validate one normalized, secret-free probe identity field."""
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        fatal(f"probe {name} must be text")
    if value != value.strip():
        fatal(f"probe {name} must not contain surrounding whitespace")
    validated = validate_metadata(value, f"probe {name}", PROBE_TEXT_MAX_LEN)
    return validated.lower() if lower else validated


def validate_probe_spec(value: Any) -> dict[str, str | None]:
    """Return one canonical probe identity suitable for stable hashing."""
    if not isinstance(value, dict) or set(value) != set(PROBE_SPEC_FIELDS):
        fatal("probe spec must contain exactly the documented fields")
    credential_id = value["credential_id"]
    if credential_id is not None and (
        not isinstance(credential_id, str)
        or CREDENTIAL_ID_RE.fullmatch(credential_id) is None
    ):
        fatal("probe credential_id must be null or a canonical CRED-ID")
    helper_sha256 = value["helper_sha256"]
    if helper_sha256 is not None and (
        not isinstance(helper_sha256, str)
        or SHA256_RE.fullmatch(helper_sha256) is None
    ):
        fatal("probe helper_sha256 must be null or a lowercase SHA-256")
    result: dict[str, str | None] = {
        "target_generation": _probe_text(
            value["target_generation"], "target_generation"
        ),
        "service": _probe_text(
            value["service"], "service", nullable=True, lower=True
        ),
        "endpoint": _probe_text(value["endpoint"], "endpoint", nullable=True),
        "technique": _probe_text(value["technique"], "technique", lower=True),
        "variant": _probe_text(
            value["variant"], "variant", nullable=True, lower=True
        ),
        "credential_id": credential_id,
        "helper_sha256": helper_sha256,
    }
    return {field: result[field] for field in PROBE_SPEC_FIELDS}


def read_probe_spec(probe_spec_file: str) -> dict[str, str | None]:
    """Read one bounded strict-JSON probe specification."""
    path = Path(probe_spec_file)
    if ".." in path.parts:
        fatal("probe spec path must not contain '..'")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fatal(f"probe spec file does not exist: {probe_spec_file!r}")
    except OSError as exc:
        fatal(f"cannot inspect probe spec file: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fatal("probe spec must be a real regular file")
    if metadata.st_size > PROBE_SPEC_MAX_BYTES:
        fatal("probe spec exceeds its size limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fatal(f"cannot read probe spec file: {exc}")
    try:
        value = ledger_io.loads_json(raw)
    except ledger_io.LedgerIOError:
        fatal("probe spec is invalid JSON")
    return validate_probe_spec(value)


def probe_fingerprint(host_id: str, spec: dict[str, str | None]) -> str:
    """Hash the canonical host-bound probe identity."""
    payload = {"host_id": host_id, **spec}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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

    attempts_path = resolved / "attempts.jsonl"
    if not attempts_path.exists() and not attempts_path.is_symlink():
        fatal(f"workspace is missing attempts.jsonl: {attempts_path!r}")
    if attempts_path.is_symlink() or not attempts_path.is_file():
        fatal(
            "attempts.jsonl is not a regular file or is a symbolic link: "
            f"{attempts_path!r}"
        )

    return resolved


def read_result(result_file: str | None) -> tuple[bytes, str]:
    """Read one bounded summary; full command output belongs in evidence."""
    if result_file is not None:
        path = Path(result_file)
        if not path.exists():
            fatal(f"result file does not exist: {result_file!r}")
        if not path.is_file():
            fatal(f"result file is not a regular file: {result_file!r}")
        try:
            with path.open("rb") as handle:
                raw = handle.read(RESULT_TEXT_MAX_BYTES + 1)
        except OSError as exc:
            fatal(f"cannot read result file: {exc}")
    else:
        try:
            raw = sys.stdin.buffer.read(RESULT_TEXT_MAX_BYTES + 1)
        except OSError as exc:
            fatal(f"cannot read standard input: {exc}")

    if len(raw) == 0:
        fatal("result is empty")
    if len(raw) > RESULT_TEXT_MAX_BYTES:
        fatal(
            f"result summary exceeds {RESULT_TEXT_MAX_BYTES} bytes; capture the full "
            "output as immutable evidence and pass a bounded summary as --result-file"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fatal(f"result is not valid UTF-8: {exc}")

    if not text.strip():
        fatal("result contains only whitespace")

    return raw, text


def build_attempt_id(now: datetime) -> str:
    """Generate an attempt ID from a UTC datetime with microsecond precision."""
    return now.strftime("ATT-%Y%m%dT%H%M%S%fZ")


def build_record(
    attempt_id: str,
    now: datetime,
    host_id: str,
    action: str,
    status: str,
    result_bytes: bytes,
    evidence_refs: list[str],
    next_step: str,
    probe_spec: dict[str, str | None] | None = None,
    duplicate_of: str | None = None,
    retry_of: str | None = None,
    retry_reason: str | None = None,
) -> dict[str, Any]:
    """Build the canonical attempt record dictionary in the required order."""
    sha256 = hashlib.sha256(result_bytes).hexdigest()
    result_text = result_bytes.decode("utf-8")
    record: dict[str, Any] = {}
    record["schema_version"] = "1.1" if probe_spec is not None else "1.0"
    record["attempt_id"] = attempt_id
    record["timestamp_utc"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    record["host_id"] = host_id
    record["action"] = action
    record["status"] = status
    record["result_sha256"] = sha256
    record["result_text"] = result_text
    record["evidence_refs"] = evidence_refs
    record["next_step"] = next_step

    if probe_spec is not None:
        record["work_kind"] = "probe"
        record["probe_fingerprint"] = probe_fingerprint(host_id, probe_spec)
        record["probe_spec"] = probe_spec
        record["duplicate_of"] = duplicate_of
        record["retry_of"] = retry_of
        record["retry_reason"] = retry_reason

    # Defensive: ensure the public field order never drifts.
    order = PROBE_FIELD_ORDER if probe_spec is not None else FIELD_ORDER
    return {key: record[key] for key in order}


def _validate_stored_probe(record: dict[str, Any], line_number: int) -> None:
    """Validate the fingerprint-bearing extension of one stored attempt."""
    probe_fields = set(PROBE_FIELD_ORDER) - set(FIELD_ORDER)
    present = probe_fields.intersection(record)
    if not present:
        return
    if (
        record.get("schema_version") != "1.1"
        or set(record) != set(PROBE_FIELD_ORDER)
        or record.get("work_kind") != "probe"
    ):
        fatal(f"attempts ledger line {line_number} has malformed probe metadata")
    spec = validate_probe_spec(record.get("probe_spec"))
    expected = probe_fingerprint(str(record.get("host_id")), spec)
    if record.get("probe_fingerprint") != expected:
        fatal(f"attempts ledger line {line_number} has invalid probe fingerprint")
    for field in ("duplicate_of", "retry_of"):
        value = record.get(field)
        if value is not None and (
            not isinstance(value, str) or ATTEMPT_ID_RE.fullmatch(value) is None
        ):
            fatal(f"attempts ledger line {line_number} has invalid {field}")
    retry_reason = record.get("retry_reason")
    if retry_reason is not None:
        if not isinstance(retry_reason, str):
            fatal(f"attempts ledger line {line_number} has invalid retry_reason")
        validate_metadata(retry_reason, "retry_reason")
    if (record.get("retry_of") is None) != (retry_reason is None):
        fatal(
            f"attempts ledger line {line_number} has incomplete retry provenance"
        )
    if record.get("duplicate_of") is not None and record.get("retry_of") is not None:
        fatal(
            f"attempts ledger line {line_number} cannot be both duplicate and retry"
        )


def _load_attempt_records(attempts_path: Path) -> list[dict[str, Any]]:
    """Load identity-valid attempts while preserving legacy record compatibility."""
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    try:
        with attempts_path.open("rb") as handle:
            for number, line in enumerate(handle, 1):
                if not line.endswith(b"\n"):
                    fatal(f"attempts ledger line {number} is not newline terminated")
                if not line.strip():
                    fatal(f"attempts ledger line {number} is empty")
                try:
                    record = ledger_io.loads_json(line)
                except ledger_io.LedgerIOError:
                    fatal(f"attempts ledger line {number} is invalid JSON")
                if not isinstance(record, dict):
                    fatal(f"attempts ledger line {number} must be a JSON object")
                identifier = record.get("attempt_id")
                if (
                    not isinstance(identifier, str)
                    or ATTEMPT_ID_RE.fullmatch(identifier) is None
                ):
                    fatal(f"attempts ledger line {number} has invalid attempt_id")
                if identifier in identifiers:
                    fatal(f"attempts ledger line {number} duplicates attempt_id")
                identifiers.add(identifier)
                _validate_stored_probe(record, number)
                records.append(record)
    except OSError as exc:
        fatal(f"cannot read attempts ledger: {exc}")
    earlier: dict[str, dict[str, Any]] = {}
    for number, record in enumerate(records, 1):
        for field in ("duplicate_of", "retry_of"):
            reference = record.get(field)
            if reference is None:
                continue
            referenced = earlier.get(str(reference))
            if referenced is None or referenced.get("probe_fingerprint") != record.get(
                "probe_fingerprint"
            ):
                fatal(
                    f"attempts ledger line {number} has invalid {field} provenance"
                )
        earlier[str(record["attempt_id"])] = record
    return records


def _matching_probes(
    records: list[dict[str, Any]], fingerprint: str
) -> list[dict[str, Any]]:
    """Return prior attempts with exactly the supplied probe fingerprint."""
    return [
        record
        for record in records
        if record.get("probe_fingerprint") == fingerprint
    ]


def _validate_retry(
    matches: list[dict[str, Any]],
    retry_of: str | None,
    retry_reason: str | None,
) -> tuple[str | None, str | None]:
    """Validate explicit retry provenance against exact matching attempts."""
    if retry_of is None and retry_reason is None:
        return None, None
    if retry_of is None or retry_reason is None:
        fatal("retry requires both --retry-of and --retry-reason")
    if ATTEMPT_ID_RE.fullmatch(retry_of) is None:
        fatal("retry-of must be a canonical ATT-ID")
    normalized_reason = validate_metadata(retry_reason, "retry-reason")
    matching_ids = {str(record["attempt_id"]) for record in matches}
    if retry_of not in matching_ids:
        fatal("retry-of does not reference an exact matching probe")
    return retry_of, normalized_reason


def preflight_probe(
    workspace: str,
    host_id: str,
    probe_spec_file: str,
    retry_of: str | None,
    retry_reason: str | None,
) -> tuple[Path, dict[str, Any]]:
    """Check the complete attempt memory before an exploratory probe executes."""
    validate_host_id(host_id)
    validated_workspace = validate_workspace(workspace, host_id)
    spec = read_probe_spec(probe_spec_file)
    fingerprint = probe_fingerprint(host_id, spec)
    attempts_path = validated_workspace / "attempts.jsonl"
    try:
        with ledger_io.exclusive_ledger_lock(attempts_path):
            revalidated_workspace = validate_workspace(workspace, host_id)
            if revalidated_workspace / "attempts.jsonl" != attempts_path:
                fatal("attempts ledger changed while waiting for its writer lock")
            records = _load_attempt_records(attempts_path)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to inspect attempts ledger: {exc}")
    matches = _matching_probes(records, fingerprint)
    normalized_retry_of, normalized_retry_reason = _validate_retry(
        matches, retry_of, retry_reason
    )
    unindexed = sum(1 for record in records if "probe_fingerprint" not in record)
    decision = (
        "proceed_retry"
        if normalized_retry_of is not None
        else ("blocked_duplicate" if matches else "proceed")
    )
    return validated_workspace, {
        "decision": decision,
        "probe_fingerprint": fingerprint,
        "matching_attempts": matches,
        "legacy_unindexed_attempts": unindexed,
        "retry_of": normalized_retry_of,
        "retry_reason": normalized_retry_reason,
    }


def _append_record_unlocked(attempts_path: Path, record: dict[str, Any]) -> None:
    """Append one compact JSON line while the caller holds the ledger lock."""
    try:
        ledger_io.append_json_record(attempts_path, record, create=False)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to append attempt record: {exc}")


def append_record(attempts_path: Path, record: dict[str, Any]) -> None:
    """Append one compact JSON line under the per-ledger writer lock."""
    try:
        with ledger_io.exclusive_ledger_lock(attempts_path):
            _append_record_unlocked(attempts_path, record)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to append attempt record: {exc}")


def log_attempt(
    workspace: str,
    host_id: str,
    action: str,
    status: str,
    next_step: str | None,
    evidence_refs: list[str],
    result_file: str | None,
    now: datetime | None = None,
    probe_spec_file: str | None = None,
    retry_of: str | None = None,
    retry_reason: str | None = None,
    validate_only: bool = False,
) -> tuple[Path, Path, dict[str, Any]]:
    """Validate inputs and optionally append one attempts-ledger record."""
    validate_host_id(host_id)
    action = validate_metadata(action, "action")
    status = validate_status(status)
    next_step = validate_metadata(next_step or "unknown", "next-step")
    evidence_refs = validate_evidence_refs(evidence_refs)

    validated_workspace = validate_workspace(workspace, host_id)
    result_bytes, _ = read_result(result_file)
    probe_spec = (
        read_probe_spec(probe_spec_file) if probe_spec_file is not None else None
    )
    if probe_spec is None and (retry_of is not None or retry_reason is not None):
        fatal("retry provenance requires --probe-spec")

    if now is None:
        now = datetime.now(UTC)

    attempt_id = build_attempt_id(now)
    attempts_path = validated_workspace / "attempts.jsonl"

    try:
        with ledger_io.exclusive_ledger_lock(attempts_path):
            revalidated_workspace = validate_workspace(workspace, host_id)
            revalidated_path = revalidated_workspace / "attempts.jsonl"
            if revalidated_path != attempts_path:
                fatal("attempts ledger changed while waiting for its writer lock")
            try:
                for reference in evidence_refs:
                    host_identity.validate_evidence_reference(
                        revalidated_workspace, host_id, reference
                    )
            except host_identity.HostIdentityError as exc:
                fatal(str(exc))
            records = _load_attempt_records(attempts_path)
            if any(record["attempt_id"] == attempt_id for record in records):
                fatal(f"duplicate attempt_id: {attempt_id}")
            duplicate_of: str | None = None
            normalized_retry_of: str | None = None
            normalized_retry_reason: str | None = None
            if probe_spec is not None:
                fingerprint = probe_fingerprint(host_id, probe_spec)
                matches = _matching_probes(records, fingerprint)
                normalized_retry_of, normalized_retry_reason = _validate_retry(
                    matches, retry_of, retry_reason
                )
                if matches and normalized_retry_of is None:
                    duplicate_of = str(matches[-1]["attempt_id"])
            record = build_record(
                attempt_id=attempt_id,
                now=now,
                host_id=host_id,
                action=action,
                status=status,
                result_bytes=result_bytes,
                evidence_refs=evidence_refs,
                next_step=next_step,
                probe_spec=probe_spec,
                duplicate_of=duplicate_of,
                retry_of=normalized_retry_of,
                retry_reason=normalized_retry_reason,
            )
            if not validate_only:
                _append_record_unlocked(attempts_path, record)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to update attempts ledger: {exc}")

    return validated_workspace, attempts_path, record


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Append one immutable JSON record to the operator attempts ledger."
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
        "--action",
        help="action description",
    )
    parser.add_argument(
        "--status",
        help="attempt status: success, failed, partial, or blocked",
    )
    parser.add_argument(
        "--next-step",
        default="unknown",
        help="next recommended step (default: unknown)",
    )
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="evidence reference (may be repeated)",
    )
    parser.add_argument(
        "--result-file",
        default=None,
        help="path to a file containing the result (default: read stdin)",
    )
    probe_mode = parser.add_mutually_exclusive_group()
    probe_mode.add_argument(
        "--probe-spec",
        help="strict JSON identity for a probe outcome",
    )
    probe_mode.add_argument(
        "--check-probe",
        help="preflight one strict JSON probe identity without executing it",
    )
    parser.add_argument(
        "--retry-of",
        help="matching ATT-ID intentionally retried after a material change",
    )
    parser.add_argument(
        "--retry-reason",
        help="bounded reason the exact probe is now worth retrying",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="run the complete append validation without changing attempts.jsonl",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    if args.check_probe is not None:
        if any(
            value
            for value in (
                args.action,
                args.status,
                args.result_file,
                args.evidence,
            )
        ) or args.next_step != "unknown":
            fatal("--check-probe cannot be combined with attempt outcome fields")
        _workspace_path, result = preflight_probe(
            workspace=args.workspace,
            host_id=args.host_id,
            probe_spec_file=args.check_probe,
            retry_of=args.retry_of,
            retry_reason=args.retry_reason,
        )
        print(f"decision: {result['decision']}")
        print(f"probe_fingerprint: {result['probe_fingerprint']}")
        print(f"matching_attempts: {len(result['matching_attempts'])}")
        for record in result["matching_attempts"][-10:]:
            print(f"match: {record['attempt_id']} {record.get('status', 'unknown')}")
        print(f"legacy_unindexed_attempts: {result['legacy_unindexed_attempts']}")
        if result["retry_of"] is not None:
            print(f"retry_of: {result['retry_of']}")
        return 1 if result["decision"] == "blocked_duplicate" else 0

    if args.action is None:
        fatal("--action is required when recording an attempt")
    if args.status is None:
        fatal("--status is required when recording an attempt")

    workspace_path, attempts_path, record = log_attempt(
        workspace=args.workspace,
        host_id=args.host_id,
        action=args.action,
        status=args.status,
        next_step=args.next_step,
        evidence_refs=args.evidence,
        result_file=args.result_file,
        now=now,
        probe_spec_file=args.probe_spec,
        retry_of=args.retry_of,
        retry_reason=args.retry_reason,
        validate_only=args.validate_only,
    )

    relative_path = attempts_path.relative_to(workspace_path).as_posix()

    if args.validate_only:
        print("validation: valid")
        print(f"prospective_attempt_id: {record['attempt_id']}")
    else:
        print(f"attempt_id: {record['attempt_id']}")
    print(f"host_id: {record['host_id']}")
    print(f"status: {record['status']}")
    print(f"action: {record['action']}")
    print(f"path: {relative_path}")
    print(f"result_sha256: {record['result_sha256']}")
    if record.get("probe_fingerprint") is not None:
        print(f"probe_fingerprint: {record['probe_fingerprint']}")
    if record.get("duplicate_of") is not None:
        print(f"duplicate_of: {record['duplicate_of']}")
    if record.get("retry_of") is not None:
        print(f"retry_of: {record['retry_of']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
