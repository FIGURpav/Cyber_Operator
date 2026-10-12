"""Append one structured observation to an Cyber-Operator workspace ledger."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

if __package__:
    from . import host_identity, ledger_io
else:
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
OBSERVATION_ID_RE = re.compile(r"^OBS-\d{8}T\d{12}Z$")
OBSERVATION_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

VALID_KINDS = {"service", "endpoint", "http", "note"}
VALID_STATES = {"observed", "inferred", "confirmed"}
VALID_TRANSPORTS = {"tcp", "udp"}

SOURCE_TOOL_MAX_LEN = 128
SERVICE_MAX_LEN = 128
URL_MAX_LEN = 2048
ENDPOINT_MAX_LEN = 1024
NOTE_MAX_LEN = 2048

KEY_FIELD_ORDER = (
    "host_id",
    "kind",
    "state",
    "source_tool",
    "evidence_ids",
    "transport",
    "port",
    "service",
    "url",
    "endpoint",
    "http_status",
    "note",
)

FIELD_ORDER = (
    "observation_id",
    "created_at_utc",
    *KEY_FIELD_ORDER,
    "observation_key",
)


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _has_ascii_control(value: str) -> bool:
    """Return True when value contains an ASCII control character."""
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def normalize_text(
    value: str | None,
    name: str,
    max_length: int,
    *,
    required: bool,
) -> str | None:
    """Normalize and validate one inert, single-line text field."""
    if value is None:
        if required:
            fatal(f"{name} is required")
        return None
    if _has_ascii_control(value):
        fatal(f"{name} must not contain ASCII control characters")
    normalized = value.strip()
    if not normalized:
        fatal(f"{name} must not be empty")
    if len(normalized) > max_length:
        fatal(f"{name} too long: {len(normalized)} characters (max {max_length})")
    return normalized


def normalize_choice(value: str, name: str, allowed: set[str]) -> str:
    """Normalize an enumerated value and require an allowed choice."""
    normalized = normalize_text(value, name, 32, required=True)
    assert normalized is not None
    normalized = normalized.lower()
    if normalized not in allowed:
        fatal(
            f"invalid {name}; expected one of {', '.join(sorted(allowed))}, "
            f"got {value!r}"
        )
    return normalized


def normalize_host_id(host_id: str) -> str:
    """Normalize and validate an H01 through H99 host ID."""
    normalized = normalize_text(host_id, "host-id", 3, required=True)
    assert normalized is not None
    if HOST_ID_RE.fullmatch(normalized) is None:
        fatal(
            "invalid host ID; expected 'H' followed by exactly two decimal "
            f"digits from 01 to 99, e.g. H01, got {host_id!r}"
        )
    return normalized


def normalize_integer(
    value: str | int | None,
    name: str,
    minimum: int,
    maximum: int,
    *,
    required: bool,
) -> int | None:
    """Normalize a decimal integer constrained to an inclusive range."""
    if value is None:
        if required:
            fatal(f"{name} is required")
        return None
    text = normalize_text(str(value), name, 10, required=True)
    assert text is not None
    if not text.isascii() or not text.isdecimal():
        fatal(f"{name} must be an integer from {minimum} through {maximum}")
    number = int(text, 10)
    if not minimum <= number <= maximum:
        fatal(f"{name} must be an integer from {minimum} through {maximum}")
    return number


def _reject_traversal_segments(value: str, name: str) -> None:
    """Reject path traversal syntax without opening the supplied value."""
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if "\\" in decoded:
        fatal(f"{name} must not contain backslashes")
    path = urlsplit(decoded).path
    if any(segment in {".", ".."} for segment in path.split("/")):
        fatal(f"{name} must not contain traversal segments")


def normalize_endpoint(endpoint: str | None, *, required: bool) -> str | None:
    """Normalize a local endpoint path and reject traversal syntax."""
    normalized = normalize_text(
        endpoint,
        "endpoint",
        ENDPOINT_MAX_LEN,
        required=required,
    )
    if normalized is None:
        return None
    if not normalized.startswith("/") or normalized.startswith("//"):
        fatal("endpoint must begin with a single '/'")
    if any(character.isspace() for character in normalized):
        fatal("endpoint must not contain whitespace")
    _reject_traversal_segments(normalized, "endpoint")
    return normalized


def normalize_url(url: str | None, *, required: bool) -> str | None:
    """Normalize and validate an HTTP(S) URL without opening it."""
    normalized = normalize_text(url, "url", URL_MAX_LEN, required=required)
    if normalized is None:
        return None
    if any(character.isspace() for character in normalized):
        fatal("URL must not contain whitespace")
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed_port = parsed.port
    except ValueError as exc:
        fatal(f"invalid URL: {exc}")
    if parsed.scheme.lower() not in {"http", "https"}:
        fatal("URL scheme must be http or https")
    if not hostname:
        fatal("URL must contain a hostname")
    if username is not None or password is not None or "@" in parsed.netloc:
        fatal("URL must not contain embedded credentials")
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        fatal("URL port must be from 1 through 65535")
    _reject_traversal_segments(normalized, "URL")
    return normalized


def validate_workspace(workspace: str, host_id: str) -> tuple[Path, Path]:
    """Validate an existing workspace before any ledger is created or changed."""
    supplied = Path(workspace)
    if any(part == ".." for part in supplied.parts):
        fatal(f"workspace path must not contain '..': {workspace!r}")
    resolved = supplied.resolve(strict=False)
    if not resolved.is_dir():
        fatal(f"workspace does not exist or is not a directory: {workspace!r}")

    required_files = ("global.md", "loot.jsonl", "attempts.jsonl")
    for filename in required_files:
        if not (resolved / filename).is_file():
            fatal(f"workspace is missing {filename}: {workspace!r}")
    for dirname in ("hosts", "evidence", "queries", "report"):
        directory = resolved / dirname
        if dirname == "evidence" and directory.is_symlink():
            fatal(f"workspace evidence directory must not be a symbolic link: {directory!r}")
        if not directory.is_dir():
            fatal(f"workspace is missing {dirname}/: {workspace!r}")
    try:
        paths = host_identity.host_paths(resolved, host_id)
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))
    if not paths.state.is_file():
        fatal("workspace is missing host record")

    observations_path = resolved / "observations.jsonl"
    if (observations_path.exists() or observations_path.is_symlink()) and (
        observations_path.is_symlink() or not observations_path.is_file()
    ):
        fatal(
            "observations.jsonl is not a real regular file: "
            f"{observations_path!r}"
        )
    return resolved, observations_path


def normalize_evidence_ids(workspace: Path, evidence_ids: list[str]) -> list[str]:
    """Validate canonical evidence relationships and remove repeated arguments."""
    seen: set[str] = set()
    normalized_ids: list[str] = []
    for supplied in evidence_ids:
        normalized = normalize_text(supplied, "evidence ID", 40, required=True)
        assert normalized is not None
        if EVIDENCE_ID_RE.fullmatch(normalized) is None:
            fatal(f"malformed evidence ID: {supplied!r}")
        try:
            datetime.strptime(normalized, "EVD-%Y%m%dT%H%M%S%fZ").replace(
                tzinfo=UTC
            )
        except ValueError:
            fatal(f"malformed evidence ID: {supplied!r}")
        if normalized in seen:
            continue
        candidates: list[tuple[str, Path]] = []
        try:
            for owner_host_id, host_directory in host_identity.evidence_roots(workspace):
                if host_directory.is_symlink():
                    fatal("evidence host directory must not be a symbolic link")
                if not host_directory.is_dir():
                    continue
                for path in host_directory.iterdir():
                    if path.name == f"{normalized}.json" or path.name.endswith(
                        f"-{normalized}.json"
                    ):
                        candidates.append((owner_host_id, path))
        except (OSError, host_identity.HostIdentityError) as exc:
            fatal(f"cannot inspect evidence metadata: {exc}")
        if not candidates:
            fatal(f"evidence ID does not exist in workspace: {normalized}")
        if len(candidates) != 1:
            fatal(f"evidence ID does not resolve uniquely in workspace: {normalized}")
        owner_host_id, metadata_path = candidates[0]
        if metadata_path.is_symlink():
            fatal("evidence metadata must not be a symbolic link")
        if not metadata_path.is_file():
            fatal("evidence metadata is not a regular file")
        try:
            metadata_text = metadata_path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            fatal(f"evidence metadata is not valid UTF-8: {exc}")
        try:
            metadata = json.loads(metadata_text)
        except json.JSONDecodeError as exc:
            fatal(f"evidence metadata is not valid JSON: {exc}")
        if not isinstance(metadata, dict):
            fatal("evidence metadata must contain a JSON object")
        if metadata.get("evidence_id") != normalized:
            fatal("evidence metadata ID does not match the requested evidence ID")
        if metadata.get("host_id") != owner_host_id:
            fatal("evidence metadata host does not match its owning directory")
        artifact_value = metadata.get("artifact_path")
        if not isinstance(artifact_value, str) or "\\" in artifact_value:
            fatal("evidence metadata artifact_path must be a workspace-relative string")
        artifact_relative = Path(artifact_value)
        parts = artifact_relative.parts
        extension = Path(parts[2]).suffix if len(parts) == 3 else ""
        if (
            artifact_relative.is_absolute()
            or ".." in parts
            or len(parts) != 3
            or parts[0] != "evidence"
            or parts[1] not in {owner_host_id, metadata_path.parent.name}
            or not Path(parts[2]).stem.endswith(normalized)
            or not extension
        ):
            fatal("evidence metadata artifact_path is not canonical")
        if extension != ".json" and re.fullmatch(r"\.[a-z0-9]{1,10}", extension) is None:
            fatal("evidence metadata artifact_path extension is not canonical")
        if extension == ".json":
            try:
                host_identity.locate_evidence_artifact(metadata_path, metadata)
            except host_identity.HostIdentityError as exc:
                fatal(str(exc))
        else:
            artifact = metadata_path.with_suffix(extension)
            if artifact.is_symlink():
                fatal("evidence artifact must not be a symbolic link")
            if not artifact.exists():
                fatal("evidence artifact does not exist")
            if not artifact.is_file():
                fatal("evidence artifact is not a regular file")
        seen.add(normalized)
        normalized_ids.append(normalized)
    return normalized_ids


def normalize_observation(
    *,
    workspace: str,
    host_id: str,
    kind: str,
    state: str,
    source_tool: str,
    evidence_ids: list[str],
    transport: str | None,
    port: str | int | None,
    service: str | None,
    url: str | None,
    endpoint: str | None,
    http_status: str | int | None,
    note: str,
) -> tuple[Path, Path, dict[str, Any]]:
    """Validate and normalize all operator-supplied observation data."""
    normalized_host = normalize_host_id(host_id)
    normalized_kind = normalize_choice(kind, "kind", VALID_KINDS)
    normalized_state = normalize_choice(state, "state", VALID_STATES)
    normalized_source = normalize_text(
        source_tool,
        "source-tool",
        SOURCE_TOOL_MAX_LEN,
        required=True,
    )
    normalized_note = normalize_text(note, "note", NOTE_MAX_LEN, required=True)
    assert normalized_source is not None
    assert normalized_note is not None

    normalized_transport = None
    if transport is not None:
        normalized_transport = normalize_choice(
            transport,
            "transport",
            VALID_TRANSPORTS,
        )
    normalized_port = normalize_integer(
        port,
        "port",
        1,
        65535,
        required=normalized_kind == "service",
    )
    normalized_service = normalize_text(
        service,
        "service",
        SERVICE_MAX_LEN,
        required=False,
    )
    normalized_endpoint = normalize_endpoint(
        endpoint,
        required=normalized_kind == "endpoint",
    )
    normalized_url = normalize_url(url, required=normalized_kind == "http")
    normalized_http_status = normalize_integer(
        http_status,
        "http-status",
        100,
        599,
        required=False,
    )

    if normalized_kind == "service":
        if normalized_transport is None:
            fatal("transport is required for service observations")
        if normalized_url is not None or normalized_endpoint is not None:
            fatal("service observations must not include URL or endpoint")
        if normalized_http_status is not None:
            fatal("service observations must not include HTTP status")
    elif normalized_kind == "endpoint":
        if normalized_url is not None:
            fatal("endpoint observations must not include URL")
        if normalized_http_status is not None:
            fatal("endpoint observations must not include HTTP status")
    elif normalized_kind == "note":
        structured = (
            normalized_transport,
            normalized_port,
            normalized_service,
            normalized_url,
            normalized_endpoint,
            normalized_http_status,
        )
        if any(value is not None for value in structured):
            fatal("note observations must not include structured fields")

    validated_workspace, observations_path = validate_workspace(
        workspace,
        normalized_host,
    )
    normalized_evidence = normalize_evidence_ids(
        validated_workspace,
        evidence_ids,
    )

    normalized_data: dict[str, Any] = {
        "host_id": normalized_host,
        "kind": normalized_kind,
        "state": normalized_state,
        "source_tool": normalized_source,
        "evidence_ids": normalized_evidence,
        "transport": normalized_transport,
        "port": normalized_port,
        "service": normalized_service,
        "url": normalized_url,
        "endpoint": normalized_endpoint,
        "http_status": normalized_http_status,
        "note": normalized_note,
    }
    return validated_workspace, observations_path, normalized_data


def build_observation_key(normalized_data: dict[str, Any]) -> str:
    """Hash the canonical normalized operator-supplied observation fields."""
    canonical = {field: normalized_data[field] for field in KEY_FIELD_ORDER}
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_existing_records(observations_path: Path) -> list[dict[str, Any]]:
    """Read the observation ledger only, failing closed on malformed records."""
    if not observations_path.exists():
        return []
    records: list[dict[str, Any]] = []
    observation_ids: set[str] = set()
    key_states: dict[str, dict[str, Any]] = {}
    try:
        with observations_path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n"):
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: not newline terminated"
                    )
                if not line.strip():
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: empty physical line"
                    )
                try:
                    record = ledger_io.loads_json(line)
                except ledger_io.LedgerIOError as exc:
                    fatal(
                        "malformed JSON in observations.jsonl at line "
                        f"{line_number}: {exc}"
                    )
                if not isinstance(record, dict):
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: expected object"
                    )
                observation_id = record.get("observation_id")
                observation_key = record.get("observation_key")
                if (
                    not isinstance(observation_id, str)
                    or OBSERVATION_ID_RE.fullmatch(observation_id) is None
                    or not isinstance(observation_key, str)
                    or OBSERVATION_KEY_RE.fullmatch(observation_key) is None
                ):
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: missing observation identity"
                    )
                if observation_id in observation_ids:
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: duplicate observation_id"
                    )
                observation_ids.add(observation_id)
                missing_state = [
                    field for field in KEY_FIELD_ORDER if field not in record
                ]
                if missing_state:
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: missing observation key state"
                    )
                key_state = {field: record[field] for field in KEY_FIELD_ORDER}
                if (
                    observation_key in key_states
                    and key_states[observation_key] != key_state
                ):
                    fatal(
                        "invalid record in observations.jsonl at line "
                        f"{line_number}: conflicting duplicate observation_key state"
                    )
                key_states.setdefault(observation_key, key_state)
                records.append(record)
    except (OSError, UnicodeError) as exc:
        fatal(f"cannot read observations ledger: {exc}")
    return records


def build_observation_id(now: datetime) -> str:
    """Build an immutable UTC observation ID with microsecond precision."""
    return now.strftime("OBS-%Y%m%dT%H%M%S%fZ")


def _append_record(observations_path: Path, record: dict[str, Any]) -> None:
    """Append one compact JSON line while the caller holds the ledger lock."""
    try:
        ledger_io.append_json_record(observations_path, record, create=True)
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to append observation record: {exc}")


def log_observation(
    *,
    workspace: str,
    host_id: str,
    kind: str,
    state: str,
    source_tool: str,
    note: str,
    evidence_ids: list[str],
    transport: str | None = None,
    port: str | int | None = None,
    service: str | None = None,
    url: str | None = None,
    endpoint: str | None = None,
    http_status: str | int | None = None,
    now: datetime | None = None,
    validate_only: bool = False,
) -> tuple[Path, Path, dict[str, Any], str, str | None]:
    """Validate, deduplicate, and optionally append one observation."""
    validated_workspace, observations_path, normalized_data = normalize_observation(
        workspace=workspace,
        host_id=host_id,
        kind=kind,
        state=state,
        source_tool=source_tool,
        evidence_ids=evidence_ids,
        transport=transport,
        port=port,
        service=service,
        url=url,
        endpoint=endpoint,
        http_status=http_status,
        note=note,
    )
    try:
        with ledger_io.exclusive_ledger_lock(observations_path):
            (
                revalidated_workspace,
                revalidated_path,
                normalized_data,
            ) = normalize_observation(
                workspace=workspace,
                host_id=host_id,
                kind=kind,
                state=state,
                source_tool=source_tool,
                evidence_ids=evidence_ids,
                transport=transport,
                port=port,
                service=service,
                url=url,
                endpoint=endpoint,
                http_status=http_status,
                note=note,
            )
            if (
                revalidated_workspace != validated_workspace
                or revalidated_path != observations_path
            ):
                fatal("observations ledger changed while waiting for its writer lock")
            observation_key = build_observation_key(normalized_data)
            existing_records = _read_existing_records(observations_path)
            for existing in existing_records:
                if existing["observation_key"] == observation_key:
                    return (
                        validated_workspace,
                        observations_path,
                        existing,
                        "duplicate",
                        existing["observation_id"],
                    )

            moment = now or datetime.now(UTC)
            observation_id = build_observation_id(moment)
            if any(
                record["observation_id"] == observation_id
                for record in existing_records
            ):
                fatal(f"duplicate observation_id: {observation_id}")

            record: dict[str, Any] = {
                "observation_id": observation_id,
                "created_at_utc": moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                **normalized_data,
                "observation_key": observation_key,
            }
            record = {field: record[field] for field in FIELD_ORDER}
            if validate_only:
                return (
                    validated_workspace,
                    observations_path,
                    record,
                    "validated",
                    None,
                )
            _append_record(observations_path, record)
            return validated_workspace, observations_path, record, "appended", None
    except ledger_io.LedgerIOError as exc:
        fatal(f"failed to update observations ledger: {exc}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Append one structured observation to an operator workspace."
    )
    parser.add_argument("--workspace", required=True, help="existing workspace")
    parser.add_argument("--host-id", required=True, help="host identifier, e.g. H01")
    parser.add_argument("--kind", required=True, help="service, endpoint, http, or note")
    parser.add_argument("--state", required=True, help="observed, inferred, or confirmed")
    parser.add_argument("--source-tool", required=True, help="source tool or manual source label")
    parser.add_argument("--note", required=True, help="short inert observation note")
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="existing evidence ID (may be repeated)",
    )
    parser.add_argument("--transport")
    parser.add_argument("--port")
    parser.add_argument("--service")
    parser.add_argument("--url")
    parser.add_argument("--endpoint")
    parser.add_argument("--http-status")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="run the complete append validation without changing observations.jsonl",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)
    workspace, observations_path, record, status, existing_id = log_observation(
        workspace=args.workspace,
        host_id=args.host_id,
        kind=args.kind,
        state=args.state,
        source_tool=args.source_tool,
        note=args.note,
        evidence_ids=args.evidence,
        transport=args.transport,
        port=args.port,
        service=args.service,
        url=args.url,
        endpoint=args.endpoint,
        http_status=args.http_status,
        now=now,
        validate_only=args.validate_only,
    )
    relative_path = observations_path.relative_to(workspace).as_posix()
    if status == "duplicate":
        print("status: duplicate")
        print(f"existing_observation_id: {existing_id}")
        print(f"observation_key: {record['observation_key']}")
        print(f"path: {relative_path}")
        return 0
    if status == "validated":
        print("validation: valid")
        print(f"prospective_observation_id: {record['observation_id']}")
        print(f"observation_key: {record['observation_key']}")
        print(f"path: {relative_path}")
        return 0

    print(f"observation_id: {record['observation_id']}")
    print(f"host_id: {record['host_id']}")
    print(f"kind: {record['kind']}")
    print(f"state: {record['state']}")
    print(f"path: {relative_path}")
    print(f"observation_key: {record['observation_key']}")
    print("status: appended")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
