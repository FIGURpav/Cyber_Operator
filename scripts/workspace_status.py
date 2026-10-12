"""Read-only workspace status summary for the Cyber-Operator."""

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
    from . import artifact_handling, host_identity, workspace_health
    from .operational_trace import (
        TraceError,
        change_histories,
        change_is_active,
        load_attack_paths,
        load_authorizations,
        load_changes,
    )
else:
    import artifact_handling  # type: ignore[no-redef]
    import host_identity  # type: ignore[no-redef]
    import workspace_health
    from operational_trace import (
        TraceError,
        change_histories,
        change_is_active,
        load_attack_paths,
        load_authorizations,
        load_changes,
    )

QUERY_FILE_RE = re.compile(r"^QRY-.*\.json$")
EVIDENCE_FILE_RE = re.compile(r"^(?:[A-Za-z0-9._-]+-)?EVD-.*\.json$")
HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
OBSERVATION_ID_RE = re.compile(r"^OBS-\d{8}T\d{12}Z$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
CREATED_AT_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

VALID_STATUSES = {"success", "failed", "partial", "blocked"}
OBSERVATION_STATES = {"observed", "inferred", "confirmed"}
OBSERVATION_KINDS = {"service", "endpoint", "http", "note"}
OBSERVATION_TRANSPORTS = {"tcp", "udp"}

SOURCE_TOOL_MAX_LEN = 128
SERVICE_MAX_LEN = 128
URL_MAX_LEN = 2048
ENDPOINT_MAX_LEN = 1024
NOTE_MAX_LEN = 2048

REQUIRED_ATTEMPT_FIELDS = ("attempt_id", "host_id", "action", "status", "next_step")
REQUIRED_LOOT_FIELDS = ("loot_id", "host_id", "category", "label")
REQUIRED_QUERY_FIELDS = ("query_id", "host_ids", "purpose", "model")
OBSERVATION_FIELDS = (
    "observation_id",
    "created_at_utc",
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
    "observation_key",
)

OBSERVATION_KEY_FIELDS = (
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


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _validate_path_does_not_escape(path: Path, label: str) -> None:
    """Reject paths that contain '..' components."""
    for part in path.parts:
        if part == "..":
            fatal(f"{label} path must not contain '..': {path}")


def validate_workspace(workspace: Path) -> Path:
    """Return the resolved workspace path or exit if it is unusable."""
    _validate_path_does_not_escape(workspace, "workspace")

    if not workspace.exists():
        fatal(f"workspace does not exist: {workspace}")
    if not workspace.is_dir():
        fatal(f"workspace is not a directory: {workspace}")

    resolved = workspace.resolve(strict=True)

    required_files = ["global.md", "loot.jsonl", "attempts.jsonl"]
    for name in required_files:
        path = resolved / name
        if not path.is_file():
            fatal(f"workspace is missing {name}: {resolved}")

    required_dirs = ["hosts", "queries", "evidence", "report"]
    for name in required_dirs:
        path = resolved / name
        if not path.is_dir():
            fatal(f"workspace is missing {name}/ directory: {resolved}")

    return resolved


def discover_hosts(workspace: Path) -> list[str]:
    """Return sorted canonical IDs from legacy or friendly host filenames."""
    try:
        return [record.host_id for record in host_identity.discover_hosts(workspace)]
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read non-empty lines from a JSONL file, erroring on invalid data."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fatal(f"cannot read {path.name}: {exc}")

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(keepends=False), start=1):
        if not line.strip():
            continue
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            fatal(f"invalid UTF-8 in {path.name} line {line_number}: {exc}")
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            fatal(f"invalid JSON in {path.name} line {line_number}: {exc}")
        if not isinstance(record, dict):
            fatal(f"invalid record in {path.name} line {line_number}: expected object")
        records.append(record)
    return records


def parse_attempts(
    workspace: Path, host_ids: set[str], *, host_history: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Parse attempts.jsonl and group matching records by host."""
    path = workspace / "attempts.jsonl"
    by_host: dict[str, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}

    for record in _read_jsonl(path):
        for field in REQUIRED_ATTEMPT_FIELDS:
            if field not in record:
                fatal(f"missing field {field!r} in {path.name}")
        status = record["status"]
        if status not in VALID_STATUSES:
            fatal(f"unknown attempt status {status!r} in {path.name}")
        host_id = (host_history or {}).get(record["host_id"], record["host_id"])
        if host_id in by_host:
            by_host[host_id].append(record)

    return by_host


def parse_loot(
    workspace: Path, host_ids: set[str], *, host_history: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Parse loot.jsonl and group matching records by host."""
    path = workspace / "loot.jsonl"
    by_host: dict[str, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}

    for record in _read_jsonl(path):
        for field in REQUIRED_LOOT_FIELDS:
            if field not in record:
                fatal(f"missing field {field!r} in {path.name}")
        host_id = (host_history or {}).get(record["host_id"], record["host_id"])
        if host_id in by_host:
            by_host[host_id].append(record)

    return by_host


def parse_queries(
    workspace: Path, host_ids: set[str], *, host_history: dict[str, str] | None = None,
) -> tuple[int, dict[str, list[dict[str, Any]]]]:
    """Parse queries/QRY-*.json files and group matching records by host."""
    queries_dir = workspace / "queries"
    global_count = 0
    by_host: dict[str, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}

    for path in sorted(queries_dir.iterdir()):
        if not path.is_file():
            continue
        if not QUERY_FILE_RE.match(path.name):
            continue

        try:
            raw = path.read_bytes()
        except OSError as exc:
            fatal(f"cannot read {path.name}: {exc}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            fatal(f"invalid UTF-8 in {path.name}: {exc}")
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            fatal(f"invalid JSON in {path.name}: {exc}")
        if not isinstance(record, dict):
            fatal(f"invalid record in {path.name}: expected object")

        for field in REQUIRED_QUERY_FIELDS:
            if field not in record:
                fatal(f"missing field {field!r} in {path.name}")

        record["_filename"] = path.name
        query_host_ids = record["host_ids"]
        if not query_host_ids:
            global_count += 1
        else:
            for host_id in {(host_history or {}).get(item, item) for item in query_host_ids}:
                if host_id in by_host:
                    by_host[host_id].append(record)

    return global_count, by_host


def parse_evidence(
    workspace: Path, host_ids: set[str], *, host_history: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """Count canonical evidence metadata filenames without opening their contents."""
    by_host: dict[str, list[str]] = {host_id: [] for host_id in host_ids}

    try:
        roots = host_identity.evidence_roots(workspace)
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))
    for host_id, host_evidence_dir in roots:
        host_id = (host_history or {}).get(host_id, host_id)
        if host_id not in host_ids:
            continue
        if not host_evidence_dir.is_dir():
            continue

        for path in sorted(host_evidence_dir.iterdir()):
            if not path.is_file():
                continue
            if not EVIDENCE_FILE_RE.match(path.name):
                continue
            by_host[host_id].append(path.name)

    return by_host


def _validate_observation_record(
    record: dict[str, Any],
    line_number: int,
) -> None:
    """Validate one record against the stable Batch 1A observation schema."""
    source = f"observations.jsonl line {line_number}"
    missing = [field for field in OBSERVATION_FIELDS if field not in record]
    if missing:
        fatal(f"invalid {source}: missing required fields: {', '.join(missing)}")
    unexpected = [field for field in record if field not in OBSERVATION_FIELDS]
    if unexpected:
        fatal(f"invalid {source}: unexpected fields: {', '.join(unexpected)}")

    identity_strings = (
        "observation_id",
        "created_at_utc",
        "host_id",
        "kind",
        "state",
        "observation_key",
    )
    for field in identity_strings:
        if not isinstance(record[field], str):
            fatal(f"invalid {source}: {field} must be a string")

    if OBSERVATION_ID_RE.fullmatch(record["observation_id"]) is None:
        fatal(f"invalid {source}: malformed observation_id")
    try:
        observation_time = datetime.strptime(
            record["observation_id"], "OBS-%Y%m%dT%H%M%S%fZ"
        ).replace(tzinfo=UTC)
    except ValueError:
        fatal(f"invalid {source}: malformed observation_id")
    if CREATED_AT_UTC_RE.fullmatch(record["created_at_utc"]) is None:
        fatal(f"invalid {source}: malformed created_at_utc")
    try:
        created_time = datetime.strptime(
            record["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC)
    except ValueError:
        fatal(f"invalid {source}: malformed created_at_utc")
    if observation_time != created_time:
        fatal(f"invalid {source}: observation_id and created_at_utc do not match")
    host_match = HOST_ID_RE.fullmatch(record["host_id"])
    if host_match is None:
        fatal(f"invalid {source}: invalid host_id")
    if record["kind"] not in OBSERVATION_KINDS:
        fatal(f"invalid {source}: unsupported kind")
    if record["state"] not in OBSERVATION_STATES:
        fatal(f"invalid {source}: unsupported state")

    _validate_canonical_text(
        record["source_tool"], "source_tool", SOURCE_TOOL_MAX_LEN, source, required=True
    )
    _validate_canonical_text(
        record["note"], "note", NOTE_MAX_LEN, source, required=True
    )

    evidence_ids = record["evidence_ids"]
    if not isinstance(evidence_ids, list):
        fatal(f"invalid {source}: evidence_ids must be a list of evidence IDs")
    seen_evidence_ids: set[str] = set()
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
            fatal(f"invalid {source}: evidence_ids must be a list of evidence IDs")
        try:
            datetime.strptime(evidence_id, "EVD-%Y%m%dT%H%M%S%fZ").replace(
                tzinfo=UTC
            )
        except ValueError:
            fatal(f"invalid {source}: evidence_ids must contain valid UTC evidence IDs")
        if evidence_id in seen_evidence_ids:
            fatal(f"invalid {source}: evidence_ids must not contain duplicates")
        seen_evidence_ids.add(evidence_id)
    transport = record["transport"]
    if transport is not None and (
        not isinstance(transport, str) or transport not in OBSERVATION_TRANSPORTS
    ):
        fatal(f"invalid {source}: transport must be tcp, udp, or null")
    _validate_canonical_text(
        record["service"], "service", SERVICE_MAX_LEN, source, required=False
    )
    _validate_url(record["url"], source)
    _validate_endpoint(record["endpoint"], source)
    port = record["port"]
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        fatal(f"invalid {source}: port must be an integer from 1 through 65535 or null")
    status = record["http_status"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        fatal(
            f"invalid {source}: http_status must be an integer from 100 through 599 or null"
        )

    kind = record["kind"]
    if kind == "service":
        if transport is None:
            fatal(f"invalid {source}: service observations require transport")
        if port is None:
            fatal(f"invalid {source}: service observations require port")
        if record["url"] is not None or record["endpoint"] is not None:
            fatal(f"invalid {source}: service observations must not include URL or endpoint")
        if status is not None:
            fatal(f"invalid {source}: service observations must not include HTTP status")
    elif kind == "endpoint":
        if record["endpoint"] is None:
            fatal(f"invalid {source}: endpoint observations require endpoint")
        if record["url"] is not None:
            fatal(f"invalid {source}: endpoint observations must not include URL")
        if status is not None:
            fatal(f"invalid {source}: endpoint observations must not include HTTP status")
    elif kind == "http" and record["url"] is None:
        fatal(f"invalid {source}: http observations require URL")
    elif kind == "note" and any(
        record[field] is not None
        for field in ("transport", "port", "service", "url", "endpoint", "http_status")
    ):
        fatal(f"invalid {source}: note observations must not include structured fields")

    if re.fullmatch(r"[0-9a-f]{64}", record["observation_key"]) is None:
        fatal(f"invalid {source}: malformed observation_key")
    canonical = {field: record[field] for field in OBSERVATION_KEY_FIELDS}
    expected_key = hashlib.sha256(
        json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if record["observation_key"] != expected_key:
        fatal(f"invalid {source}: observation_key does not match record content")


def _has_ascii_control(value: str) -> bool:
    """Return whether a stored text value contains an ASCII control character."""
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_canonical_text(
    value: Any,
    name: str,
    max_length: int,
    source: str,
    *,
    required: bool,
) -> str | None:
    """Require a stored text value to already match Batch 1A normalization."""
    if value is None:
        if required:
            fatal(f"invalid {source}: {name} must be a string")
        return None
    if not isinstance(value, str):
        fatal(f"invalid {source}: {name} must be a string or null")
    if _has_ascii_control(value):
        fatal(f"invalid {source}: {name} must not contain ASCII control characters")
    if not value or value != value.strip():
        fatal(f"invalid {source}: {name} is not canonical nonempty text")
    if len(value) > max_length:
        fatal(f"invalid {source}: {name} exceeds {max_length} characters")
    return value


def _reject_traversal_segments(value: str, name: str, source: str) -> None:
    """Reject Batch 1A traversal syntax without following the stored value."""
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if "\\" in decoded:
        fatal(f"invalid {source}: {name} must not contain backslashes")
    if any(segment in {".", ".."} for segment in urlsplit(decoded).path.split("/")):
        fatal(f"invalid {source}: {name} must not contain traversal segments")


def _validate_endpoint(value: Any, source: str) -> None:
    """Validate a stored optional endpoint as canonical Batch 1A data."""
    endpoint = _validate_canonical_text(
        value, "endpoint", ENDPOINT_MAX_LEN, source, required=False
    )
    if endpoint is None:
        return
    if not endpoint.startswith("/") or endpoint.startswith("//"):
        fatal(f"invalid {source}: endpoint must begin with a single '/'")
    if any(character.isspace() for character in endpoint):
        fatal(f"invalid {source}: endpoint must not contain whitespace")
    _reject_traversal_segments(endpoint, "endpoint", source)


def _validate_url(value: Any, source: str) -> None:
    """Validate a stored optional URL without opening or normalizing it."""
    url = _validate_canonical_text(value, "url", URL_MAX_LEN, source, required=False)
    if url is None:
        return
    if any(character.isspace() for character in url):
        fatal(f"invalid {source}: URL must not contain whitespace")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed_port = parsed.port
    except ValueError as exc:
        fatal(f"invalid {source}: invalid URL: {exc}")
    if parsed.scheme.lower() not in {"http", "https"}:
        fatal(f"invalid {source}: URL scheme must be http or https")
    if not hostname:
        fatal(f"invalid {source}: URL must contain a hostname")
    if username is not None or password is not None or "@" in parsed.netloc:
        fatal(f"invalid {source}: URL must not contain embedded credentials")
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        fatal(f"invalid {source}: URL port must be from 1 through 65535")
    _reject_traversal_segments(url, "URL", source)


def parse_observations(
    workspace: Path,
    host_ids: set[str],
    *, host_history: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Parse observations read-only, treating a missing legacy ledger as empty."""
    path = workspace / "observations.jsonl"
    by_host: dict[str, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}
    if not path.exists():
        return by_host
    if not path.is_file():
        fatal(f"observations.jsonl is not a regular file: {path}")

    seen_observation_ids: set[str] = set()
    seen_observation_keys: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n"):
                    fatal(
                        "invalid observations.jsonl at line "
                        f"{line_number}: incomplete newline-terminated record"
                    )
                serialized = line[:-1]
                if not serialized.strip():
                    fatal(f"invalid observations.jsonl at line {line_number}: blank line")
                try:
                    record = json.loads(serialized)
                except json.JSONDecodeError as exc:
                    fatal(
                        "invalid JSON in observations.jsonl line "
                        f"{line_number}: {exc}"
                    )
                if not isinstance(record, dict):
                    fatal(
                        "invalid record in observations.jsonl line "
                        f"{line_number}: expected object"
                    )
                _validate_observation_record(record, line_number)
                if record["observation_id"] in seen_observation_ids:
                    fatal(
                        "invalid observations.jsonl at line "
                        f"{line_number}: duplicate observation_id"
                    )
                if record["observation_key"] in seen_observation_keys:
                    fatal(
                        "invalid observations.jsonl at line "
                        f"{line_number}: duplicate observation_key"
                    )
                seen_observation_ids.add(record["observation_id"])
                seen_observation_keys.add(record["observation_key"])
                host_id = (host_history or {}).get(record["host_id"], record["host_id"])
                if host_id in by_host:
                    by_host[host_id].append(record)
    except UnicodeError as exc:
        fatal(f"invalid UTF-8 in observations.jsonl: {exc}")
    except OSError as exc:
        fatal(f"cannot read observations.jsonl: {exc}")
    return by_host


def _latest_attempt_line(records: list[dict[str, Any]]) -> str:
    """Format the latest attempt record, or 'none'."""
    if not records:
        return "none"
    rec = records[-1]
    return f"{rec['attempt_id']} | {rec['status']} | {rec['action']}"


def _latest_loot_line(records: list[dict[str, Any]]) -> str:
    """Format the latest loot record, or 'none'."""
    if not records:
        return "none"
    rec = records[-1]
    return f"{rec['loot_id']} | {rec['category']} | {rec['label']}"


def _latest_query_line(records: list[dict[str, Any]]) -> str:
    """Format the lexicographically latest query record, or 'none'."""
    if not records:
        return "none"
    rec = max(records, key=lambda record: record["_filename"])
    return f"{rec['query_id']} | {rec['purpose']} | {rec['model']}"


def _latest_observation_line(records: list[dict[str, Any]]) -> str:
    """Format bounded metadata for the latest observation, or 'none'."""
    if not records:
        return "none"
    record = records[-1]
    return f"{record['observation_id']} | {record['state']} | {record['kind']}"


def _latest_path_line(records: list[dict[str, Any]]) -> str:
    """Format bounded metadata for the latest attack-path transition."""
    if not records:
        return "none"
    record = records[-1]
    source = f"{record['source_host_id']}:{record['source_identity']}"
    destination = (
        f"{record['destination_host_id']}:{record['destination_identity']}"
    )
    return (
        f"{record['path_event_id']} | {record['transition']} | "
        f"{source} -> {destination}"
    )


def _report_notes_status(workspace: Path, host_id: str) -> str:
    """Return 'present' or 'missing' for report/<host-id>.md."""
    try:
        report_path = host_identity.host_paths(workspace, host_id).report
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))
    if report_path.exists() and not report_path.is_file():
        fatal(f"report path is not a regular file: {report_path}")
    return "present" if report_path.is_file() else "missing"


def _format_host_section(
    host_id: str,
    attempts: list[dict[str, Any]],
    loot: list[dict[str, Any]],
    queries: list[dict[str, Any]],
    evidence: list[str],
    observations: list[dict[str, Any]],
    change_records: list[dict[str, Any]],
    path_records: list[dict[str, Any]],
    workspace: Path,
) -> list[str]:
    """Return the status lines for a single host."""
    counts = {status: 0 for status in VALID_STATUSES}
    for rec in attempts:
        counts[rec["status"]] += 1

    total_attempts = len(attempts)
    next_step = attempts[-1]["next_step"] if attempts else "none"
    report_notes = _report_notes_status(workspace, host_id)
    observation_counts = {state: 0 for state in OBSERVATION_STATES}
    for record in observations:
        observation_counts[record["state"]] += 1

    histories = change_histories(change_records)
    active_histories = [
        history for history in histories.values() if change_is_active(history)
    ]
    retained_changes = sum(
        history[-1]["event"] == "retained" for history in active_histories
    )
    pending_rollbacks = len(active_histories) - retained_changes

    try:
        display = host_identity.resolve_host(workspace, host_id).display_name
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))
    return [
        f"Host {display} (canonical: {host_id})" if display != host_id else f"Host {host_id}",
        (
            f"Attempts: {total_attempts} "
            f"(success={counts['success']}, failed={counts['failed']}, "
            f"partial={counts['partial']}, blocked={counts['blocked']})"
        ),
        f"Latest attempt: {_latest_attempt_line(attempts)}",
        f"Next step: {next_step}",
        f"Loot: {len(loot)}",
        f"Latest loot: {_latest_loot_line(loot)}",
        f"AI queries: {len(queries)}",
        f"Latest AI query: {_latest_query_line(queries)}",
        f"Evidence: {len(evidence)}",
        (
            f"Observations: {len(observations)} "
            f"(observed={observation_counts['observed']}, "
            f"inferred={observation_counts['inferred']}, "
            f"confirmed={observation_counts['confirmed']})"
        ),
        f"Latest observation: {_latest_observation_line(observations)}",
        (
            f"Changes: {len(histories)} "
            f"(active={len(active_histories)}, "
            f"pending_rollback={pending_rollbacks}, retained={retained_changes})"
        ),
        f"Attack-path events: {len(path_records)}",
        f"Latest attack path: {_latest_path_line(path_records)}",
        f"Report notes: {report_notes}",
    ]


def generate_status(
    workspace: Path,
    selected_host_id: str | None,
    now: datetime,
    health: dict[str, Any] | None = None,
) -> list[str]:
    """Generate all status lines for the workspace."""
    resolved_workspace = validate_workspace(workspace)
    health = workspace_health.snapshot(workspace, now=now) if health is None else health
    if not health["history_readable"]:
        return ["Cyber-Operator Workspace Status", *workspace_health.render(health),
                "Host history summary unavailable until local state is stable."]
    try:
        artifact_mode = artifact_handling.workspace_mode(resolved_workspace)
    except artifact_handling.ArtifactHandlingError as exc:
        fatal(str(exc))
    all_host_ids = discover_hosts(resolved_workspace)
    try:
        if __package__:
            from . import host_state, workspace_lifecycle
        else:
            import host_state
            import workspace_lifecycle
        lifecycle_state = (
            "closed" if workspace_lifecycle.is_closed(resolved_workspace) else "open"
        )
        host_views = host_state.view_status(resolved_workspace)
    except (ValueError, OSError, RuntimeError):
        lifecycle_state = "unavailable"
        host_views = {host_id: "unavailable" for host_id in all_host_ids}
        host_views["global"] = "unavailable"
    try:
        history = host_identity.historical_host_map(resolved_workspace)
    except host_identity.HostIdentityError as exc:
        fatal(str(exc))

    if selected_host_id is not None:
        selected_host_id = history.get(selected_host_id, selected_host_id)
        if selected_host_id not in all_host_ids:
            fatal(f"host not found: {selected_host_id}")
        host_ids = [selected_host_id]
    else:
        host_ids = all_host_ids

    host_id_set = set(host_ids)
    attempts_by_host = parse_attempts(
        resolved_workspace, host_id_set, host_history=history,
    )
    loot_by_host = parse_loot(
        resolved_workspace, host_id_set, host_history=history,
    )
    global_query_count, queries_by_host = parse_queries(
        resolved_workspace, host_id_set, host_history=history,
    )
    evidence_by_host = parse_evidence(
        resolved_workspace, host_id_set, host_history=history,
    )
    observations_by_host = parse_observations(
        resolved_workspace, host_id_set, host_history=history,
    )
    try:
        authorization_records = load_authorizations(resolved_workspace)
        change_records = load_changes(resolved_workspace)
        attack_path_records = load_attack_paths(resolved_workspace)
    except TraceError as exc:
        fatal(str(exc))
    changes_by_host: dict[str, list[dict[str, Any]]] = {
        host_id: [] for host_id in host_ids
    }
    paths_by_host: dict[str, list[dict[str, Any]]] = {
        host_id: [] for host_id in host_ids
    }
    for record in change_records:
        host = history.get(record["host_id"])
        if host in changes_by_host:
            changes_by_host[host].append(record)
    for record in attack_path_records:
        related = {
            history.get(record["destination_host_id"]),
            history.get(record["source_host_id"]),
        }
        for host_id in related & host_id_set:
            paths_by_host[host_id].append(record)

    lines = [
        "Cyber-Operator Workspace Status",
        f"Generated UTC: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Workspace: {resolved_workspace}",
        f"Artifact handling: {artifact_mode}",
        f"Workspace target actions: {lifecycle_state}",
        f"Global managed view: {host_views.get('global', 'unavailable')}",
        f"Hosts: {len(all_host_ids)}",
        f"Global AI queries: {global_query_count}",
        f"Impact authorizations: {len(authorization_records)}",
        *workspace_health.render(health),
        "",
    ]
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    try:
        configuration = engagement_config.status(resolved_workspace, now=now)
        if configuration["status"] != "legacy-unmanaged":
            lines.extend([
                f"Assessment configuration: {configuration['status']}",
                f"Configuration revision: {configuration['revision']}; latest event: {configuration['event_sequence']}",
                f"Configuration reason: {configuration['reason']}",
                f"Pending configuration proposals: {configuration['pending_proposals']}", "",
            ])
    except (ValueError, RuntimeError, OSError) as exc:
        fatal(str(exc))

    for host_id in host_ids:
        lines.extend(
            _format_host_section(
                host_id,
                attempts_by_host[host_id],
                loot_by_host[host_id],
                queries_by_host[host_id],
                evidence_by_host[host_id],
                observations_by_host[host_id],
                changes_by_host[host_id],
                paths_by_host[host_id],
                resolved_workspace,
            )
        )
        lines.append(f"Managed host view: {host_views.get(host_id, 'unavailable')}")
        lines.append("")

    return lines


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Read-only workspace status summary for the Cyber-Operator."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="explicit private workspace directory",
    )
    parser.add_argument(
        "--host-id",
        default=None,
        help="optional single host identifier, e.g. H01",
    )
    return parser.parse_args(argv)


def validate_host_id(host_id: str) -> None:
    """Validate a --host-id argument."""
    if HOST_ID_RE.fullmatch(host_id) is None:
        fatal("invalid host-id; expected canonical Hxx form")


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    workspace = Path(args.workspace)
    validate_workspace(workspace)
    if now is None:
        now = datetime.now(UTC)
    health = workspace_health.snapshot(workspace, now=now)
    if not health["history_readable"]:
        print("\n".join(generate_status(workspace, None, now, health=health)))
        return 2

    selected_host_id = args.host_id
    if selected_host_id is not None:
        if selected_host_id.startswith("H") and HOST_ID_RE.fullmatch(selected_host_id) is None:
            fatal("invalid host-id; expected canonical Hxx form or a friendly host selector")
        try:
            selected_host_id = host_identity.resolve_host(
                workspace, selected_host_id
            ).host_id
        except host_identity.HostIdentityError as exc:
            if HOST_ID_RE.fullmatch(selected_host_id):
                fatal(f"host not found: {selected_host_id}")
            fatal(str(exc))

    if now is None:
        now = datetime.now(UTC)

    lines = generate_status(workspace, selected_host_id, now, health=health)
    print("\n".join(lines).rstrip("\n"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
