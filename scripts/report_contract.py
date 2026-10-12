"""Canonical Cyber-Operator engagement manifest, report steps, and readiness derivation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

if __package__:
    from . import host_identity, ledger_io
else:
    import host_identity  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]

MANIFEST_NAME = "engagement_manifest.json"
STEP_LEDGER_NAME = "report_steps.jsonl"
SECRET_ADJUDICATION_LEDGER = Path("private/report_secret_false_positives.jsonl")
MANIFEST_HISTORY = Path("report/manifest_history")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_TEXT = 4096
MAX_INPUT_TEXT = 256 * 1024

HOST_ID_RE = re.compile(r"^H(?:0[1-9]|[1-9]\d+)$")
REPORT_ID_RE = re.compile(r"^RPT-\d{8}T\d{12}Z$")
STEP_ID_RE = re.compile(r"^(H(?:0[1-9]|[1-9]\d+))-ST-(?=\d{2,}$)(0*[1-9]\d*)$")
STEP_EVENT_ID_RE = re.compile(r"^RSE-\d{8}T\d{12}Z$")
SECRET_ADJUDICATION_ID_RE = re.compile(r"^RSF-\d{8}T\d{12}Z$")
ATTEMPT_ID_RE = re.compile(r"^ATT-\d{8}T\d{12}Z$")
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{8}T\d{12}Z$")
QUERY_ID_RE = re.compile(r"^QRY-\d{8}T\d{12}Z$")
PATH_ID_RE = re.compile(r"^PTH-\d{8}T\d{12}Z$")
CREDENTIAL_ID_RE = re.compile(r"^CRED-\d{8}T\d{12}Z$")
LOOT_ID_RE = re.compile(r"^LOOT-\d{8}T\d{12}Z$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

MANIFEST_FIELDS = {
    "schema_version",
    "report_id",
    "assessment_team",
    "engagement",
    "chains",
    "assessment_objectives",
}
LEGACY_PLAN_FIELDS = {
    "objective",
    "starting_context",
    "operation_kind",
    "operation_origin",
    "input_text",
    "query_ids",
    "credential_ids",
    "expected_state",
    "checkpoint_class",
    "screenshot",
}
PLAN_FIELDS = LEGACY_PLAN_FIELDS | {"report_purpose"}
STARTING_CONTEXT_FIELDS = {"principal", "session", "route", "working_directory"}
SCREENSHOT_FIELDS = {
    "stage",
    "interface",
    "protocol",
    "port",
    "endpoint",
    "safe_url",
    "service",
    "reproducibility",
    "must_include",
    "must_exclude",
}
OUTCOME_FIELDS = {
    "attempt_id",
    "evidence_ids",
    "path_event_ids",
    "query_ids",
    "credential_ids",
    "resulting_access",
    "resulting_route",
    "resulting_objective_loot_id",
    "note",
}
STEP_EVENTS = {"planned", "completed", "failed", "partial", "legacy_missing", "superseded"}
TERMINAL_EVENTS = STEP_EVENTS - {"planned"}
OPERATION_KINDS = {"command", "request", "query", "prompt", "code", "manual"}
OPERATION_ORIGINS = {"observed", "reconstructed", "planned", "missing"}
CHECKPOINT_CLASSES = {
    "ai_exploitation",
    "objective",
    "credential_discovery",
    "admin_proof",
    "other",
}
REPORT_PURPOSES = {
    "confirmed_reproduction",
    "assessment_objective",
    "material_negative",
    "historical_reconstruction",
}
VALIDATION_BARRIERS = ("milestone", "checkpoint", "closure", "manual")
STAGES = {
    "discovery",
    "access",
    "exploitation",
    "objective",
    "identity",
    "transition",
    "troubleshooting",
    "closure",
}
INTERFACES = {"url", "terminal", "rdp", "ssh", "application", "api"}
OBJECTIVE_CATEGORIES = {"application", "infrastructure", "identity"}
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|token|secret|api[_-]?key|passphrase)\s*[:=]\s*\S+"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE
)
JWT_RE = re.compile(
    r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"
)
QUERY_FIELDS = {
    "schema_version",
    "query_id",
    "timestamp_utc",
    "scope",
    "host_ids",
    "purpose",
    "model",
    "context_refs",
    "prompt_sha256",
    "prompt_text",
}
SECRET_ADJUDICATION_FIELDS = {
    "schema_version",
    "adjudication_id",
    "created_at_utc",
    "credential_id",
    "step_event_id",
    "field_path",
    "field_sha256",
    "reason",
}
SECRET_ADJUDICATION_REASON = "operator-reviewed retroactive substring collision"


class ReportContractError(ValueError):
    """A bounded report-contract validation failure."""


@dataclass(frozen=True)
class ScreenshotRequirement:
    """One deterministic screenshot checkpoint derived from canonical state."""

    coverage_key: str
    host_id: str
    priority: str
    stage: str
    reason: str
    interface: str
    protocol: str
    port: int | None
    endpoint: str
    safe_url: str | None
    service: str | None
    steps: tuple[str, ...]
    must_include: tuple[str, ...]
    must_exclude: tuple[str, ...]
    reproducibility: str
    attempt_id: str | None
    evidence_ids: tuple[str, ...]
    query_ids: tuple[str, ...]
    path_event_id: str | None
    report_step_id: str | None
    legacy_missing: bool = False


@dataclass(frozen=True)
class ContractReadiness:
    """Metadata-only documentation readiness dimensions."""

    content_ready: bool
    credential_ready: bool
    query_appendix_ready: bool
    blockers: tuple[str, ...]
    manifest_targets: int
    active_steps: int


class ValidationContext:
    """One command-local, lazily populated snapshot of validation indexes."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self._known_hosts: set[str] | None = None
        self._host_history: dict[str, str] | None = None
        self._queries: dict[str, dict[str, Any]] | None = None
        self._query_hashes_verified = False
        self._evidence: dict[str, dict[str, Any]] | None = None
        self._credentials: dict[str, dict[str, Any]] | None = None
        self._attempts: dict[str, dict[str, Any]] | None = None
        self._paths: dict[str, dict[str, Any]] | None = None
        self._loot: dict[str, dict[str, Any]] | None = None

    @property
    def known_hosts(self) -> set[str]:
        if self._known_hosts is None:
            self._known_hosts = _known_hosts(self.workspace)
        return self._known_hosts

    def same_host(self, left: object, right: object) -> bool:
        """Compare evidence ownership through confirmed merges, never authorization."""
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        if self._host_history is None:
            try:
                self._host_history = host_identity.historical_host_map(self.workspace)
            except host_identity.HostIdentityError as exc:
                raise ReportContractError(str(exc)) from exc
        return left in self._host_history and (
            self._host_history[left] == self._host_history.get(right)
        )

    def query_index(
        self, *, verify_hashes: bool = False
    ) -> dict[str, dict[str, Any]]:
        if self._queries is None:
            self._queries = _query_index(
                self.workspace,
                verify_hashes=verify_hashes,
                known_hosts=self.known_hosts,
            )
            self._query_hashes_verified = verify_hashes
        elif verify_hashes and not self._query_hashes_verified:
            for record in self._queries.values():
                prompt = record["prompt_text"]
                if record["prompt_sha256"] != hashlib.sha256(prompt.encode()).hexdigest():
                    raise ReportContractError("query record hash validation failed")
            self._query_hashes_verified = True
        return self._queries

    @property
    def evidence(self) -> dict[str, dict[str, Any]]:
        if self._evidence is None:
            self._evidence = _evidence_index(self.workspace)
        return self._evidence

    @property
    def credentials(self) -> dict[str, dict[str, Any]]:
        if self._credentials is None:
            self._credentials = _credential_index(self.workspace)
        return self._credentials

    @property
    def attempts(self) -> dict[str, dict[str, Any]]:
        if self._attempts is None:
            self._attempts = _attempt_index(self.workspace)
        return self._attempts

    @property
    def paths(self) -> dict[str, dict[str, Any]]:
        if self._paths is None:
            self._paths = _path_index(self.workspace)
        return self._paths

    @property
    def loot(self) -> dict[str, dict[str, Any]]:
        if self._loot is None:
            self._loot = _loot_index(self.workspace)
        return self._loot


def _validation_context(
    workspace: Path, context: ValidationContext | None
) -> ValidationContext:
    if context is None:
        return ValidationContext(workspace)
    if context.workspace != workspace:
        raise ReportContractError("validation context belongs to another workspace")
    return context


# Cooperating cross-ledger mutations acquire locks only in this order:
# report steps -> execution runs -> claims. Readers used for readiness remain
# lock-free snapshots; writers hold every acquired lock through publication.
def _acquire_ledger_lock(workspace: Path, name: str, operation: int) -> int:
    path = workspace / name
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        fcntl.flock(descriptor, operation)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def identifier(prefix: str, moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(f"{prefix}-%Y%m%dT%H%M%S%fZ")


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReportContractError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReportContractError(f"{label} must be a real non-symlink directory")


def _real_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReportContractError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReportContractError(f"{label} must be a real non-symlink regular file")
    if metadata.st_size > maximum:
        raise ReportContractError(f"{label} exceeds its size limit")
    return metadata


def _text(value: Any, label: str, maximum: int = MAX_TEXT, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ReportContractError(f"{label} must be text")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise ReportContractError(f"{label} contains control characters")
    normalized = value.strip()
    if not normalized:
        raise ReportContractError(f"{label} must not be empty")
    if len(normalized) > maximum:
        raise ReportContractError(f"{label} is too long")
    return normalized


def _string_list(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReportContractError(f"{label} must be a string list")
    result: list[str] = []
    for item in value:
        normalized = _text(item, label)
        assert normalized is not None
        if pattern is not None and pattern.fullmatch(normalized) is None:
            raise ReportContractError(f"{label} contains a malformed identifier")
        if normalized not in result:
            result.append(normalized)
    return result


def _json_file(path: Path, label: str, maximum: int) -> dict[str, Any]:
    _real_file(path, label, maximum)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportContractError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReportContractError(f"{label} must contain one JSON object")
    return value


def _jsonl(path: Path, label: str, *, missing_ok: bool = False) -> list[dict[str, Any]]:
    if not _lexists(path):
        if missing_ok:
            return []
        raise ReportContractError(f"{label} does not exist")
    _real_file(path, label, MAX_LEDGER_BYTES)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReportContractError(f"{label} is not valid UTF-8") from exc
    if raw and not raw.endswith("\n"):
        raise ReportContractError(f"{label} is missing its final newline")
    lines = raw.splitlines()
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise ReportContractError(f"{label} line {line_number} is empty")
        try:
            record = ledger_io.loads_json(line)
        except ledger_io.LedgerIOError as exc:
            raise ReportContractError(f"{label} line {line_number} is invalid JSON") from exc
        if not isinstance(record, dict):
            raise ReportContractError(f"{label} line {line_number} must be an object")
        records.append(record)
    return records


def _known_hosts(workspace: Path) -> set[str]:
    try:
        return host_identity.known_host_ids(workspace)
    except host_identity.HostIdentityError as exc:
        raise ReportContractError(str(exc)) from exc


def _host_endpoint(workspace: Path, host_id: str) -> str:
    try:
        path = host_identity.host_paths(workspace, host_id).state
    except host_identity.HostIdentityError as exc:
        raise ReportContractError(str(exc)) from exc
    _real_file(path, "canonical host record", 1024 * 1024)
    text = path.read_text(encoding="utf-8")
    matches = re.findall(r"^- IP address: `([^`\r\n]+)`$", text, re.MULTILINE)
    return matches[0] if len(matches) == 1 else host_id


def _ids_from_jsonl(workspace: Path, name: str, field: str) -> set[str]:
    return {
        str(record.get(field))
        for record in _jsonl(workspace / name, name, missing_ok=True)
        if isinstance(record.get(field), str)
    }


def _query_index(
    workspace: Path,
    *,
    verify_hashes: bool = False,
    known_hosts: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
    directory = workspace / "queries"
    _real_directory(directory, "workspace queries directory")
    active_known_hosts = known_hosts if known_hosts is not None else _known_hosts(workspace)
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("QRY-*.json")):
        record = _json_file(path, "query record", 4 * 1024 * 1024)
        query_id = record.get("query_id")
        if set(record) != QUERY_FIELDS or record.get("schema_version") != "1.0":
            raise ReportContractError("query record has unsupported schema")
        if (
            not isinstance(query_id, str)
            or QUERY_ID_RE.fullmatch(query_id) is None
            or query_id != path.stem
            or query_id in result
        ):
            raise ReportContractError("query record has malformed identity")
        host_ids = _string_list(record.get("host_ids"), "query host_ids", HOST_ID_RE)
        if any(host_id not in active_known_hosts for host_id in host_ids):
            raise ReportContractError("query record references an unknown host")
        if record.get("scope") not in {"global", "host"} or (
            (record["scope"] == "global" and host_ids)
            or (record["scope"] == "host" and not host_ids)
        ):
            raise ReportContractError("query record has inconsistent scope")
        if (
            not isinstance(record.get("timestamp_utc"), str)
            or TIMESTAMP_RE.fullmatch(record["timestamp_utc"]) is None
        ):
            raise ReportContractError("query record has malformed timestamp")
        _text(record.get("purpose"), "query purpose")
        _text(record.get("model"), "query model")
        _string_list(record.get("context_refs"), "query context_refs")
        prompt = record.get("prompt_text")
        digest = record.get("prompt_sha256")
        if (
            not isinstance(prompt, str)
            or not prompt.strip()
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ReportContractError("query record has invalid prompt metadata")
        if verify_hashes and digest != hashlib.sha256(prompt.encode()).hexdigest():
            raise ReportContractError("query record hash validation failed")
        result[query_id] = record
    return result


def _query_ids(workspace: Path, *, verify_hashes: bool = False) -> set[str]:
    return set(_query_index(workspace, verify_hashes=verify_hashes))


def _evidence_index(workspace: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    evidence = workspace / "evidence"
    _real_directory(evidence, "workspace evidence directory")
    try:
        roots = host_identity.evidence_roots(workspace)
    except host_identity.HostIdentityError as exc:
        raise ReportContractError(str(exc)) from exc
    for owner_host_id, directory in roots:
        for path in directory.glob("*EVD-*.json"):
            _real_directory(path.parent, "evidence host directory")
            record = _json_file(path, "evidence metadata", 1024 * 1024)
            evidence_id = record.get("evidence_id")
            if (
                not isinstance(evidence_id, str)
                or not path.stem.endswith(evidence_id)
                or EVIDENCE_ID_RE.fullmatch(evidence_id) is None
                or evidence_id in result
                or record.get("host_id") != owner_host_id
            ):
                raise ReportContractError("evidence metadata has malformed scope or identity")
            try:
                host_identity.verify_evidence_artifact(path, record)
            except host_identity.HostIdentityError as exc:
                raise ReportContractError(f"{evidence_id}: {exc}") from exc
            result[evidence_id] = record
    return result


def _evidence_ids(workspace: Path) -> set[str]:
    return set(_evidence_index(workspace))


def _credential_records(workspace: Path) -> list[dict[str, Any]]:
    ledger = workspace / "private/credentials/credentials.jsonl"
    if not _lexists(ledger):
        return []
    return _jsonl(ledger, "credential ledger")


def _credential_index(workspace: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in _credential_records(workspace):
        credential_id = record.get("credential_id")
        if not isinstance(credential_id, str) or CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
            raise ReportContractError("credential ledger has malformed identity")
        if credential_id in result:
            raise ReportContractError("credential ledger contains duplicate IDs")
        result[credential_id] = record
    return result


def _loot_ids(workspace: Path) -> set[str]:
    return set(_loot_index(workspace))


def _record_index(
    workspace: Path,
    name: str,
    field: str,
    pattern: re.Pattern[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in _jsonl(workspace / name, name, missing_ok=True):
        identifier_value = record.get(field)
        if (
            not isinstance(identifier_value, str)
            or pattern.fullmatch(identifier_value) is None
            or identifier_value in result
        ):
            raise ReportContractError(f"{name} has malformed or duplicate identity")
        result[identifier_value] = record
    return result


def _attempt_index(workspace: Path) -> dict[str, dict[str, Any]]:
    return _record_index(workspace, "attempts.jsonl", "attempt_id", ATTEMPT_ID_RE)


def _path_index(workspace: Path) -> dict[str, dict[str, Any]]:
    return _record_index(workspace, "attack_paths.jsonl", "path_event_id", PATH_ID_RE)


def _loot_index(workspace: Path) -> dict[str, dict[str, Any]]:
    return _record_index(workspace, "loot.jsonl", "loot_id", LOOT_ID_RE)


def _query_matches_host(
    record: dict[str, Any], host_id: str, context: ValidationContext
) -> bool:
    host_ids = record["host_ids"]
    return not host_ids or any(context.same_host(item, host_id) for item in host_ids)


def _max_backtick_run(text: str) -> int:
    longest = 0
    current = 0
    for character in text:
        if character == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _query_appendix_entries(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in sorted(records, key=lambda item: item["query_id"]):
        host_ids = ", ".join(record["host_ids"]) if record["host_ids"] else "global"
        context_refs = (
            ", ".join(record["context_refs"])
            if record["context_refs"]
            else "none"
        )
        fence = "`" * max(_max_backtick_run(record["prompt_text"]) + 1, 3)
        lines.extend(
            [
                f"## {record['query_id']}",
                "",
                f"- **Timestamp**: {record['timestamp_utc']}",
                f"- **Scope**: {record['scope']}",
                f"- **Host IDs**: {host_ids}",
                f"- **Purpose**: {record['purpose']}",
                f"- **Model**: {record['model']}",
                f"- **Context References**: {context_refs}",
                f"- **Prompt SHA-256**: {record['prompt_sha256']}",
                "",
                "### Prompt",
                "",
                fence,
                record["prompt_text"],
                fence,
                "",
            ]
        )
    return "\n".join(lines)


def _query_appendix_matches(
    workspace: Path, records: list[dict[str, Any]], appendix_text: str
) -> bool:
    if not appendix_text.startswith("# AI Query Appendix\n"):
        return False
    if f"- **Source Workspace**: {workspace}\n" not in appendix_text:
        return False
    if f"- **Total Queries**: {len(records)}\n" not in appendix_text:
        return False
    first_entry = appendix_text.find("## QRY-")
    if first_entry < 0:
        return False
    return appendix_text[first_entry:] == _query_appendix_entries(records)


def _pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _text_fields(value: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, list):
        return [
            pair
            for index, item in enumerate(value)
            for pair in _text_fields(item, f"{path}/{index}")
        ]
    if isinstance(value, dict):
        return [
            pair
            for key, item in value.items()
            for pair in _text_fields(item, f"{path}/{_pointer_part(str(key))}")
        ]
    return []


def _all_text(value: Any) -> list[str]:
    return [text for _, text in _text_fields(value)]


def reject_secrets(
    workspace: Path,
    value: Any,
    *,
    allowed_credential_ids_by_path: dict[str, set[str]] | None = None,
    context: ValidationContext | None = None,
) -> None:
    """Reject secret material, with exact reviewed exemptions for old records only."""
    active_context = _validation_context(workspace, context)
    credentials = [
        (record.get("credential_id"), record.get("secret"))
        for record in active_context.credentials.values()
    ]
    allowed = allowed_credential_ids_by_path or {}
    for path, text in _text_fields(value):
        reject_secret_shapes(text)
        for credential_id, secret in credentials:
            if not isinstance(secret, str) or not secret or secret not in text:
                continue
            if (
                isinstance(credential_id, str)
                and credential_id in allowed.get(path, set())
            ):
                continue
            raise ReportContractError("report metadata contains a stored credential value")


def reject_secret_shapes(value: Any) -> None:
    """Reject intrinsically secret-shaped text without consulting credential state."""
    for text in _all_text(value):
        if PRIVATE_KEY_RE.search(text):
            raise ReportContractError("report metadata resembles private-key material")
        if SECRET_ASSIGNMENT_RE.search(text) or JWT_RE.search(text):
            raise ReportContractError("report metadata resembles a secret assignment")


def _parsed_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise ReportContractError(f"{label} is malformed")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReportContractError(f"{label} is malformed") from exc


def _step_secret_payload(record: dict[str, Any]) -> dict[str, Any]:
    event = record.get("event")
    if event == "planned":
        fields = (
            LEGACY_PLAN_FIELDS
            if record.get("schema_version") == "1.0"
            else PLAN_FIELDS
        )
    elif event in {"completed", "failed", "partial", "legacy_missing"}:
        fields = OUTCOME_FIELDS
    elif event == "superseded":
        fields = {"reason"}
    else:
        raise ReportContractError("report step has an unsupported adjudication target")
    if not fields.issubset(record):
        raise ReportContractError("report step adjudication target is malformed")
    return {field: record[field] for field in fields}


def _secret_adjudication_exemptions(
    workspace: Path,
    step_records: list[dict[str, Any]],
    *,
    extra_records: list[dict[str, Any]] | None = None,
    context: ValidationContext | None = None,
) -> dict[str, dict[str, set[str]]]:
    records = _jsonl(
        workspace / SECRET_ADJUDICATION_LEDGER,
        "report secret false-positive ledger",
        missing_ok=True,
    )
    if extra_records:
        records.extend(extra_records)
    active_context = _validation_context(workspace, context)
    credentials = active_context.credentials
    steps = {
        record.get("step_event_id"): record
        for record in step_records
        if isinstance(record.get("step_event_id"), str)
    }
    result: dict[str, dict[str, set[str]]] = {}
    adjudication_ids: set[str] = set()
    keys: set[tuple[str, str, str]] = set()
    for line_number, record in enumerate(records, 1):
        if (
            set(record) != SECRET_ADJUDICATION_FIELDS
            or record.get("schema_version") != "1.0"
        ):
            raise ReportContractError(
                f"report secret false-positive line {line_number} has invalid metadata"
            )
        adjudication_id = record.get("adjudication_id")
        credential_id = record.get("credential_id")
        step_event_id = record.get("step_event_id")
        field_path = record.get("field_path")
        field_sha256 = record.get("field_sha256")
        if (
            not isinstance(adjudication_id, str)
            or SECRET_ADJUDICATION_ID_RE.fullmatch(adjudication_id) is None
            or adjudication_id in adjudication_ids
            or not isinstance(credential_id, str)
            or CREDENTIAL_ID_RE.fullmatch(credential_id) is None
            or credential_id not in credentials
            or not isinstance(step_event_id, str)
            or STEP_EVENT_ID_RE.fullmatch(step_event_id) is None
            or step_event_id not in steps
            or not isinstance(field_path, str)
            or not field_path.startswith("/")
            or not isinstance(field_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", field_sha256) is None
            or record.get("reason") != SECRET_ADJUDICATION_REASON
        ):
            raise ReportContractError(
                f"report secret false-positive line {line_number} is malformed"
            )
        adjudication_ids.add(adjudication_id)
        key = (credential_id, step_event_id, field_path)
        if key in keys:
            raise ReportContractError(
                "report secret false-positive ledger contains a duplicate target"
            )
        keys.add(key)
        step = steps[step_event_id]
        fields = dict(_text_fields(_step_secret_payload(step)))
        text = fields.get(field_path)
        secret = credentials[credential_id].get("secret")
        if (
            text is None
            or not isinstance(secret, str)
            or not secret
            or secret not in text
            or hashlib.sha256(text.encode()).hexdigest() != field_sha256
        ):
            raise ReportContractError(
                "report secret false-positive adjudication no longer matches its target"
            )
        step_time = _parsed_timestamp(
            step.get("created_at_utc"), "report step adjudication timestamp"
        )
        credential_time = _parsed_timestamp(
            credentials[credential_id].get("created_at_utc"),
            "credential adjudication timestamp",
        )
        adjudication_time = _parsed_timestamp(
            record.get("created_at_utc"), "report secret false-positive timestamp"
        )
        if step_time >= credential_time or adjudication_time < credential_time:
            raise ReportContractError(
                "report secret false-positive is not a retroactive match"
            )
        result.setdefault(step_event_id, {}).setdefault(field_path, set()).add(
            credential_id
        )
    return result


def _ensure_secret_adjudication_ledger(workspace: Path) -> Path:
    private = workspace / "private"
    _real_directory(private, "workspace private directory")
    path = workspace / SECRET_ADJUDICATION_LEDGER
    if _lexists(path):
        _real_file(path, "report secret false-positive ledger", MAX_LEDGER_BYTES)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    return path


def adjudicate_retroactive_step_secret_matches(
    workspace: Path,
    credential_id: str,
    *,
    apply: bool,
    acknowledged: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind reviewed retroactive substring collisions to exact immutable fields."""
    if CREDENTIAL_ID_RE.fullmatch(credential_id) is None:
        raise ReportContractError("credential_id is malformed")
    lock = workspace / ".report_steps.lock"
    descriptor = os.open(
        lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        context = ValidationContext(workspace)
        step_records = _jsonl(
            workspace / STEP_LEDGER_NAME, "report step ledger", missing_ok=True
        )
        credentials = context.credentials
        credential = credentials.get(credential_id)
        if credential is None:
            raise ReportContractError("credential_id does not exist")
        secret = credential.get("secret")
        if not isinstance(secret, str) or not secret:
            raise ReportContractError("credential record has no usable secret value")
        credential_time = _parsed_timestamp(
            credential.get("created_at_utc"), "credential adjudication timestamp"
        )
        existing = _secret_adjudication_exemptions(
            workspace, step_records, context=context
        )
        existing_keys = {
            (event_id, field_path, known_credential_id)
            for event_id, fields in existing.items()
            for field_path, credential_ids in fields.items()
            for known_credential_id in credential_ids
        }
        matches: list[tuple[str, str, str]] = []
        existing_match_count = 0
        for step in step_records:
            step_event_id = step.get("step_event_id")
            if (
                not isinstance(step_event_id, str)
                or STEP_EVENT_ID_RE.fullmatch(step_event_id) is None
            ):
                raise ReportContractError("report step has malformed adjudication identity")
            if _parsed_timestamp(
                step.get("created_at_utc"), "report step adjudication timestamp"
            ) >= credential_time:
                continue
            for field_path, text_value in _text_fields(_step_secret_payload(step)):
                if secret not in text_value:
                    continue
                digest = hashlib.sha256(text_value.encode()).hexdigest()
                key = (step_event_id, field_path, credential_id)
                if key in existing_keys:
                    existing_match_count += 1
                else:
                    matches.append((step_event_id, field_path, digest))
        if apply and matches and not acknowledged:
            raise ReportContractError(
                "apply requires --ack-reviewed-false-positives"
            )
        moment = now or datetime.now(UTC)
        new_records = [
            {
                "schema_version": "1.0",
                "adjudication_id": identifier(
                    "RSF", moment + timedelta(microseconds=index)
                ),
                "created_at_utc": timestamp(moment + timedelta(microseconds=index)),
                "credential_id": credential_id,
                "step_event_id": step_event_id,
                "field_path": field_path,
                "field_sha256": digest,
                "reason": SECRET_ADJUDICATION_REASON,
            }
            for index, (step_event_id, field_path, digest) in enumerate(matches)
        ]
        _validate_step_sequence(
            workspace,
            step_records,
            extra_secret_adjudications=new_records,
            context=context,
        )
        if apply and new_records:
            ledger = _ensure_secret_adjudication_ledger(workspace)
            encoded = b"".join(
                (
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                ).encode()
                for record in new_records
            )
            if ledger.stat().st_size + len(encoded) > MAX_LEDGER_BYTES:
                raise ReportContractError(
                    "report secret false-positive ledger exceeds its size limit"
                )
            with ledger.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            _validate_step_sequence(workspace, step_records, context=context)
        return {
            "credential_id": credential_id,
            "candidate_count": len(new_records),
            "existing_count": existing_match_count,
            "matches": [
                {
                    "step_event_id": record["step_event_id"],
                    "field_path": record["field_path"],
                    "field_sha256": record["field_sha256"],
                }
                for record in new_records
            ],
        }
    finally:
        os.close(descriptor)


def validate_manifest(
    workspace: Path,
    manifest: dict[str, Any],
    *,
    context: ValidationContext | None = None,
) -> dict[str, Any]:
    active_context = _validation_context(workspace, context)
    bound = manifest.get("schema_version") == "2.1"
    if set(manifest) != (MANIFEST_FIELDS | {"configuration"} if bound else MANIFEST_FIELDS) or manifest.get("schema_version") not in {"2.0", "2.1"}:
        raise ReportContractError("engagement manifest has an unsupported schema")
    report_id = manifest.get("report_id")
    if not isinstance(report_id, str) or REPORT_ID_RE.fullmatch(report_id) is None:
        raise ReportContractError("engagement manifest has a malformed report_id")
    candidate = manifest.get("assessment_team")
    if not isinstance(candidate, dict) or set(candidate) != {"team_id", "name"}:
        raise ReportContractError("engagement manifest assessment team metadata is malformed")
    _text(candidate["team_id"], "assessment team ID", 64)
    _text(candidate["name"], "assessment team name", 256)
    engagement = manifest.get("engagement")
    if not isinstance(engagement, dict) or set(engagement) != {
        "engagement_date",
        "scope_version",
        "scope_url",
        "approved_at_utc",
    }:
        raise ReportContractError("engagement manifest engagement metadata is malformed")
    if not isinstance(engagement["engagement_date"], str) or DATE_RE.fullmatch(engagement["engagement_date"]) is None:
        raise ReportContractError("engagement manifest engagement_date is malformed")
    _text(engagement["scope_version"], "engagement guide version", 128)
    if bound:
        _text(engagement["scope_url"], "external scope reference", 2048, nullable=True)
    else:
        scope_url = _text(engagement["scope_url"], "engagement guide URL", 2048)
        assert scope_url is not None
        parsed = urlsplit(scope_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ReportContractError("engagement guide URL must be a credential-free HTTPS URL")
    if not isinstance(engagement["approved_at_utc"], str) or TIMESTAMP_RE.fullmatch(engagement["approved_at_utc"]) is None:
        raise ReportContractError("engagement manifest approved_at_utc is malformed")
    hosts = active_context.known_hosts
    chains = manifest.get("chains")
    if not isinstance(chains, list):
        raise ReportContractError("engagement manifest chains must be a list")
    chain_ids: set[str] = set()
    chain_hosts: dict[str, set[str]] = {}
    for chain in chains:
        if not isinstance(chain, dict) or set(chain) != {"chain_id", "entry_host_id", "host_ids"}:
            raise ReportContractError("engagement manifest chain is malformed")
        chain_id = chain["chain_id"]
        if not isinstance(chain_id, str) or CHAIN_ID_RE.fullmatch(chain_id) is None or chain_id in chain_ids:
            raise ReportContractError("engagement manifest chain_id is invalid or duplicated")
        chain_ids.add(chain_id)
        host_ids = _string_list(chain["host_ids"], "chain host_ids", HOST_ID_RE)
        if not host_ids or any(host_id not in hosts for host_id in host_ids):
            raise ReportContractError("engagement manifest chain references an unknown host")
        if chain["entry_host_id"] not in host_ids:
            raise ReportContractError("engagement manifest entry host must belong to its chain")
        chain_hosts[chain_id] = set(host_ids)
    targets = manifest.get("assessment_objectives")
    if not isinstance(targets, list) or not targets:
        raise ReportContractError(
            "engagement manifest assessment_objectives must be a non-empty list"
        )
    target_hosts: set[str] = set()
    target_pairs: set[tuple[str, str]] = set()
    loot = active_context.loot
    for target in targets:
        if not isinstance(target, dict) or set(target) != {
            "host_id",
            "chain_id",
            "category",
            "objective_name",
            "objective_loot_id",
        }:
            raise ReportContractError("engagement manifest assessment objective is malformed")
        host_id = target["host_id"]
        if host_id not in hosts or (not bound and host_id in target_hosts):
            raise ReportContractError("engagement manifest target host is unknown or duplicated")
        target_hosts.add(host_id)
        chain_id = target["chain_id"]
        if chain_id is not None and chain_id not in chain_ids:
            raise ReportContractError("engagement manifest target references an unknown chain")
        if chain_id is not None and host_id not in chain_hosts[chain_id]:
            raise ReportContractError(
                "engagement manifest target host does not belong to its chain"
            )
        category = target["category"]
        if category not in OBJECTIVE_CATEGORIES:
            raise ReportContractError("engagement manifest objective category is unsupported")
        _text(target["objective_name"], "target objective_name", 128)
        pair = (host_id, target["objective_name"])
        if pair in target_pairs:
            raise ReportContractError("engagement manifest duplicates an objective on the same host")
        target_pairs.add(pair)
        loot_id = target["objective_loot_id"]
        if loot_id is not None and (
            not isinstance(loot_id, str)
            or LOOT_ID_RE.fullmatch(loot_id) is None
            or loot_id not in loot
        ):
            raise ReportContractError("engagement manifest target objective_loot_id does not exist")
        if loot_id is not None:
            loot_record = loot[loot_id]
            if (
                not active_context.same_host(loot_record.get("host_id"), host_id)
                or loot_record.get("label") != target["objective_name"]
            ):
                raise ReportContractError(
                    "engagement manifest objective proof does not match target host and name"
                )
    if bound:
        if __package__:
            from . import configuration_report
        else:
            import configuration_report
        try:
            configuration_report.validate_binding(workspace, manifest)
        except (ValueError, KeyError, TypeError) as exc:
            raise ReportContractError(str(exc)) from exc
    reject_secrets(workspace, manifest, context=active_context)
    return manifest


def load_manifest(
    workspace: Path,
    *,
    required: bool = False,
    context: ValidationContext | None = None,
) -> dict[str, Any] | None:
    path = workspace / MANIFEST_NAME
    if not _lexists(path):
        if required:
            raise ReportContractError("engagement manifest is missing")
        return None
    return validate_manifest(
        workspace,
        _json_file(path, "engagement manifest", MAX_MANIFEST_BYTES),
        context=context,
    )


def _atomic_replace(path: Path, raw: bytes) -> None:
    if __package__:
        from . import restore_checkpoint
    else:
        import restore_checkpoint
    restore_checkpoint.require_path_instance(path)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def apply_manifest(
    workspace: Path,
    input_path: Path,
    *,
    apply: bool,
    replace: bool,
    now: datetime | None = None,
) -> str:
    source_metadata = _real_file(input_path, "manifest input", MAX_MANIFEST_BYTES)
    raw = input_path.read_bytes()
    current_metadata = input_path.lstat()
    # Reading may update atime; only identity, content and protection changes are drift.
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_gid")
    if any(getattr(current_metadata, field) != getattr(source_metadata, field) for field in stable_fields):
        raise ReportContractError("manifest input changed during validation")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReportContractError("manifest input is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ReportContractError("manifest input must contain one JSON object")
    validate_manifest(workspace, parsed)
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    if engagement_config.is_managed(workspace) and parsed['schema_version'] == '2.0':
        raise ReportContractError('new managed report writes require configuration-bound schema 2.1; schema 2.0 remains readable')
    normalized = (json.dumps(parsed, indent=2, ensure_ascii=False) + "\n").encode()
    destination = workspace / MANIFEST_NAME
    existed = _lexists(destination)
    before = b""
    if existed:
        _real_file(destination, "existing engagement manifest", MAX_MANIFEST_BYTES)
        before = destination.read_bytes()
        if before == normalized:
            return "noop"
        if not replace:
            raise ReportContractError("engagement manifest differs; use --replace after preview")
    action = "replace" if existed else "create"
    if not apply:
        return action
    lock = workspace / ".engagement_manifest.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if _lexists(destination):
            _real_file(destination, "existing engagement manifest", MAX_MANIFEST_BYTES)
            current = destination.read_bytes()
            if current == normalized:
                return "noop"
            if not replace:
                raise ReportContractError("engagement manifest changed before apply")
            history = workspace / MANIFEST_HISTORY
            if _lexists(history):
                _real_directory(history, "manifest history directory")
            else:
                history.mkdir(mode=0o700)
            moment = now or datetime.now(UTC)
            digest = hashlib.sha256(current).hexdigest()
            archive = history / f"{moment.strftime('%Y%m%dT%H%M%S%fZ')}-{digest}.json"
            archive_descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(archive_descriptor, current)
                os.fsync(archive_descriptor)
            finally:
                os.close(archive_descriptor)
        else:
            if existed:
                raise ReportContractError("engagement manifest disappeared before apply")
        _atomic_replace(destination, normalized)
    finally:
        os.close(descriptor)
    return action


def _validate_starting_context(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != STARTING_CONTEXT_FIELDS:
        raise ReportContractError("starting_context is malformed")
    result: dict[str, str] = {}
    for field in sorted(STARTING_CONTEXT_FIELDS):
        normalized = _text(value[field], f"starting_context.{field}")
        assert normalized is not None
        result[field] = normalized
    return result


def _validate_screenshot_contract(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != SCREENSHOT_FIELDS:
        raise ReportContractError("screenshot contract is malformed")
    if value["stage"] not in STAGES or value["interface"] not in INTERFACES:
        raise ReportContractError("screenshot stage or interface is invalid")
    if value["reproducibility"] not in {"repeatable", "time-sensitive"}:
        raise ReportContractError("screenshot reproducibility is invalid")
    port = value["port"]
    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
        raise ReportContractError("screenshot port is invalid")
    for field in ("protocol", "endpoint"):
        _text(value[field], f"screenshot.{field}", 2048)
    for field in ("safe_url", "service"):
        _text(value[field], f"screenshot.{field}", 2048, nullable=True)
    _string_list(value["must_include"], "screenshot.must_include")
    _string_list(value["must_exclude"], "screenshot.must_exclude")
    return value


def validate_plan_payload(
    workspace: Path,
    host_id: str,
    value: dict[str, Any],
    *,
    secret_exemptions: dict[str, set[str]] | None = None,
    context: ValidationContext | None = None,
    schema_version: str = "1.1",
) -> dict[str, Any]:
    active_context = _validation_context(workspace, context)
    expected_fields = LEGACY_PLAN_FIELDS if schema_version == "1.0" else PLAN_FIELDS
    if schema_version not in {"1.0", "1.1"} or set(value) != expected_fields:
        raise ReportContractError("step plan payload has unexpected fields")
    if host_id not in active_context.known_hosts:
        raise ReportContractError("step plan references an unknown host")
    _text(value["objective"], "objective")
    _validate_starting_context(value["starting_context"])
    if value["operation_kind"] not in OPERATION_KINDS:
        raise ReportContractError("operation_kind is invalid")
    if value["operation_origin"] not in OPERATION_ORIGINS:
        raise ReportContractError("operation_origin is invalid")
    input_text = value["input_text"]
    if input_text is not None:
        _text(input_text, "input_text", MAX_INPUT_TEXT)
    query_ids = _string_list(value["query_ids"], "query_ids", QUERY_ID_RE)
    credential_ids = _string_list(value["credential_ids"], "credential_ids", CREDENTIAL_ID_RE)
    queries = active_context.query_index()
    if any(item not in queries for item in query_ids):
        raise ReportContractError("step plan references an unknown query")
    if any(not _query_matches_host(queries[item], host_id, active_context) for item in query_ids):
        raise ReportContractError("step plan query belongs to an unrelated host")
    credentials = active_context.credentials
    if any(item not in credentials for item in credential_ids):
        raise ReportContractError("step plan references an unknown credential")
    if any(not active_context.same_host(credentials[item].get("host_id"), host_id) for item in credential_ids):
        raise ReportContractError("step plan credential belongs to an unrelated host")
    if value["operation_origin"] == "missing":
        if input_text is not None or query_ids:
            raise ReportContractError("missing operation must not claim input content")
    elif value["operation_kind"] in {"query", "prompt"}:
        if not query_ids:
            raise ReportContractError("query or prompt step requires a QRY-ID")
    elif input_text is None:
        raise ReportContractError("executable step requires exact input_text")
    _text(value["expected_state"], "expected_state")
    if value["checkpoint_class"] not in CHECKPOINT_CLASSES:
        raise ReportContractError("checkpoint_class is invalid")
    if schema_version == "1.1":
        report_purpose = value["report_purpose"]
        if not isinstance(report_purpose, str) or report_purpose not in REPORT_PURPOSES:
            raise ReportContractError(
                "report_purpose must identify a report-relevant reproduction, objective, "
                "material negative result, or historical reconstruction; exploratory "
                "probes belong in attempts"
            )
    screenshot = _validate_screenshot_contract(value["screenshot"])
    if value["checkpoint_class"] != "other" and screenshot is None:
        raise ReportContractError("report-relevant checkpoint requires a screenshot contract")
    reject_secrets(
        workspace,
        value,
        allowed_credential_ids_by_path=secret_exemptions,
        context=active_context,
    )
    return value


def _reference_indexes(
    workspace: Path,
    *,
    context: ValidationContext | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    active_context = _validation_context(workspace, context)
    return {
        "attempt": active_context.attempts,
        "evidence": active_context.evidence,
        "path": active_context.paths,
        "query": active_context.query_index(),
        "credential": active_context.credentials,
        "loot": active_context.loot,
    }


def validate_outcome_payload(
    workspace: Path,
    event: str,
    value: dict[str, Any],
    *,
    host_id: str | None = None,
    secret_exemptions: dict[str, set[str]] | None = None,
    context: ValidationContext | None = None,
) -> dict[str, Any]:
    active_context = _validation_context(workspace, context)
    if set(value) != OUTCOME_FIELDS:
        raise ReportContractError("step outcome payload has unexpected fields")
    refs = _reference_indexes(workspace, context=active_context)
    attempt = value["attempt_id"]
    if attempt is not None and (
        not isinstance(attempt, str)
        or ATTEMPT_ID_RE.fullmatch(attempt) is None
        or attempt not in refs["attempt"]
    ):
        raise ReportContractError("step outcome references an unknown attempt")
    lists = {
        "evidence_ids": (EVIDENCE_ID_RE, refs["evidence"]),
        "path_event_ids": (PATH_ID_RE, refs["path"]),
        "query_ids": (QUERY_ID_RE, refs["query"]),
        "credential_ids": (CREDENTIAL_ID_RE, refs["credential"]),
    }
    for field, (pattern, known) in lists.items():
        supplied = _string_list(value[field], field, pattern)
        if any(item not in known for item in supplied):
            raise ReportContractError(f"step outcome {field} contains an unknown reference")
    for field in ("resulting_access", "resulting_route", "note"):
        _text(value[field], field, nullable=True)
    proof = value["resulting_objective_loot_id"]
    if proof is not None and (
        not isinstance(proof, str)
        or LOOT_ID_RE.fullmatch(proof) is None
        or proof not in refs["loot"]
    ):
        raise ReportContractError("step outcome references an unknown objective proof item")
    if event in {"completed", "failed", "partial"} and attempt is None and not value["evidence_ids"]:
        raise ReportContractError("observed outcome requires attempt or evidence provenance")
    if event == "legacy_missing" and any(
        value[field]
        for field in (
            "attempt_id",
            "evidence_ids",
            "path_event_ids",
            "query_ids",
            "credential_ids",
            "resulting_access",
            "resulting_route",
            "resulting_objective_loot_id",
        )
    ):
        raise ReportContractError("legacy_missing must not claim unavailable provenance")
    if host_id is not None:
        if attempt is not None and not active_context.same_host(refs["attempt"][attempt].get("host_id"), host_id):
            raise ReportContractError("step outcome attempt belongs to an unrelated host")
        if any(
            not active_context.same_host(refs["evidence"][item].get("host_id"), host_id)
            for item in value["evidence_ids"]
        ):
            raise ReportContractError("step outcome evidence belongs to an unrelated host")
        if any(
            not active_context.same_host(refs["path"][item].get("destination_host_id"), host_id)
            for item in value["path_event_ids"]
        ):
            raise ReportContractError("step outcome path belongs to an unrelated host")
        if any(
            not _query_matches_host(refs["query"][item], host_id, active_context)
            for item in value["query_ids"]
        ):
            raise ReportContractError("step outcome query belongs to an unrelated host")
        if any(
            not active_context.same_host(refs["credential"][item].get("host_id"), host_id)
            for item in value["credential_ids"]
        ):
            raise ReportContractError("step outcome credential belongs to an unrelated host")
        if proof is not None and not active_context.same_host(refs["loot"][proof].get("host_id"), host_id):
            raise ReportContractError("step outcome objective proof belongs to an unrelated host")
    reject_secrets(
        workspace,
        value,
        allowed_credential_ids_by_path=secret_exemptions,
        context=active_context,
    )
    return value


def _validate_step_event(
    workspace: Path,
    record: dict[str, Any],
    *,
    line_number: int,
    states: dict[str, dict[str, Any]],
    event_ids: set[str],
    secret_exemptions: dict[str, set[str]] | None,
    context: ValidationContext,
) -> None:
    required = {
        "schema_version",
        "step_event_id",
        "created_at_utc",
        "event",
        "step_id",
        "host_id",
    }
    schema_version = record.get("schema_version")
    if not required.issubset(record) or schema_version not in {"1.0", "1.1"}:
        raise ReportContractError(
            f"report step line {line_number} has invalid metadata"
        )
    event_id = record["step_event_id"]
    step_id = record["step_id"]
    host_id = record["host_id"]
    match = STEP_ID_RE.fullmatch(str(step_id))
    if (
        not isinstance(event_id, str)
        or STEP_EVENT_ID_RE.fullmatch(event_id) is None
        or event_id in event_ids
        or match is None
        or match.group(1) != host_id
        or record["event"] not in STEP_EVENTS
    ):
        raise ReportContractError(
            f"report step line {line_number} has malformed identity"
        )
    event = record["event"]
    if event == "planned":
        plan_fields = LEGACY_PLAN_FIELDS if schema_version == "1.0" else PLAN_FIELDS
        if schema_version == "1.1" and "report_purpose" not in record:
            raise ReportContractError(
                "new report step plan requires an explicit report_purpose; "
                "exploratory probes belong in attempts"
            )
        if step_id in states or set(record) != required | plan_fields:
            raise ReportContractError("report step contains duplicate or malformed plan")
        payload = {field: record[field] for field in plan_fields}
        validate_plan_payload(
            workspace,
            host_id,
            payload,
            secret_exemptions=secret_exemptions,
            context=context,
            schema_version=str(schema_version),
        )
        event_ids.add(event_id)
        states[step_id] = {"plan": record, "transition": None}
        return
    if step_id not in states or states[step_id]["transition"] is not None:
        raise ReportContractError("report step transition is out of sequence")
    if event == "superseded":
        if set(record) != required | {"replacement_step_id", "reason"}:
            raise ReportContractError("superseded step event is malformed")
        replacement = record["replacement_step_id"]
        if replacement not in states or replacement == step_id:
            raise ReportContractError("superseded step references an unknown replacement")
        replacement_state = states[replacement]
        replacement_match = STEP_ID_RE.fullmatch(replacement)
        source_match = STEP_ID_RE.fullmatch(step_id)
        assert replacement_match is not None and source_match is not None
        if (
            replacement_state["transition"] is not None
            or replacement_state["plan"]["host_id"] != host_id
            or int(replacement_match.group(2)) <= int(source_match.group(2))
        ):
            raise ReportContractError(
                "superseded step requires a newer open replacement on the same host"
            )
        _text(record["reason"], "superseded reason")
        reject_secrets(
            workspace,
            {"reason": record["reason"]},
            allowed_credential_ids_by_path=secret_exemptions,
            context=context,
        )
    else:
        if set(record) != required | OUTCOME_FIELDS:
            raise ReportContractError("report step outcome is malformed")
        payload = {field: record[field] for field in OUTCOME_FIELDS}
        validate_outcome_payload(
            workspace,
            event,
            payload,
            host_id=host_id,
            secret_exemptions=secret_exemptions,
            context=context,
        )
    event_ids.add(event_id)
    states[step_id]["transition"] = record


def _validate_step_sequence(
    workspace: Path,
    records: list[dict[str, Any]],
    *,
    extra_secret_adjudications: list[dict[str, Any]] | None = None,
    context: ValidationContext | None = None,
) -> dict[str, dict[str, Any]]:
    active_context = _validation_context(workspace, context)
    states: dict[str, dict[str, Any]] = {}
    event_ids: set[str] = set()
    exemptions = _secret_adjudication_exemptions(
        workspace,
        records,
        extra_records=extra_secret_adjudications,
        context=active_context,
    )
    for line_number, record in enumerate(records, 1):
        _validate_step_event(
            workspace,
            record,
            line_number=line_number,
            states=states,
            event_ids=event_ids,
            secret_exemptions=exemptions.get(record.get("step_event_id", "")),
            context=active_context,
        )
    return states


def load_steps(
    workspace: Path,
    *,
    context: ValidationContext | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    active_context = _validation_context(workspace, context)
    records = _jsonl(workspace / STEP_LEDGER_NAME, "report step ledger", missing_ok=True)
    return records, _validate_step_sequence(
        workspace, records, context=active_context
    )


def _ensure_step_ledger(workspace: Path) -> Path:
    path = workspace / STEP_LEDGER_NAME
    if _lexists(path):
        _real_file(path, "report step ledger", MAX_LEDGER_BYTES)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    return path


def _reject_unavailable_step_with_provenance(
    workspace: Path,
    step_id: str,
    states: dict[str, dict[str, Any]],
    context: ValidationContext,
) -> None:
    try:
        if __package__:
            from . import execution_provenance
        else:
            import execution_provenance  # type: ignore[no-redef]

        required = (
            workspace / execution_provenance.RUN_LEDGER,
            workspace / execution_provenance.CLAIM_LEDGER,
            workspace / execution_provenance.RUN_DIRECTORY,
        )
        present = tuple(_lexists(path) for path in required)
        if not any(present):
            return
        if not all(present):
            raise ReportContractError("provenance state is incomplete")
        runs = execution_provenance._load_runs_with_context(
            workspace,
            states,
            context,
            verify_artifacts=True,
        )
        claims = execution_provenance._load_claims_with_context(
            workspace, states, runs, context
        )
    except execution_provenance.ProvenanceError as exc:
        raise ReportContractError(str(exc)) from exc
    if any(record["report_step_id"] == step_id for record in runs.values()) or any(
        record["report_step_id"] == step_id for record in claims.values()
    ):
        raise ReportContractError(
            "report step with execution provenance cannot become unavailable"
        )


def _append_step_locked(workspace: Path, build: Any) -> dict[str, Any]:
    descriptor = _acquire_ledger_lock(
        workspace, ".report_steps.lock", fcntl.LOCK_EX
    )
    dependent_descriptors: list[int] = []
    try:
        context = ValidationContext(workspace)
        records, states = load_steps(workspace, context=context)
        record = build(records, states)
        if record.get("event") in {"superseded", "legacy_missing"}:
            dependent_descriptors.append(
                _acquire_ledger_lock(
                    workspace, ".execution_runs.lock", fcntl.LOCK_SH
                )
            )
            dependent_descriptors.append(
                _acquire_ledger_lock(
                    workspace, ".claims.lock", fcntl.LOCK_SH
                )
            )
            _reject_unavailable_step_with_provenance(
                workspace,
                record["step_id"],
                states,
                context,
            )
        event_ids = {item["step_event_id"] for item in records}
        _validate_step_event(
            workspace,
            record,
            line_number=len(records) + 1,
            states=states,
            event_ids=event_ids,
            secret_exemptions=None,
            context=context,
        )
        ledger = _ensure_step_ledger(workspace)
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_RECORD_BYTES:
            raise ReportContractError("report step event is too large")
        if _real_file(
            ledger, "report step ledger", MAX_LEDGER_BYTES
        ).st_size + len(encoded) > MAX_LEDGER_BYTES:
            raise ReportContractError("report step ledger exceeds its size limit")
        try:
            ledger_io.append_json_record(
                ledger,
                record,
                create=False,
                maximum_bytes=MAX_RECORD_BYTES,
            )
        except ledger_io.LedgerIOError as exc:
            raise ReportContractError(str(exc)) from exc
        return record
    finally:
        for dependent in reversed(dependent_descriptors):
            os.close(dependent)
        os.close(descriptor)


def plan_step(workspace: Path, host_id: str, record_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    payload = _json_file(record_path, "step plan input", MAX_RECORD_BYTES)
    moment = now or datetime.now(UTC)

    def build(records: list[dict[str, Any]], states: dict[str, dict[str, Any]]) -> dict[str, Any]:
        numbers = [int(match.group(2)) for step_id in states if (match := STEP_ID_RE.fullmatch(step_id)) and match.group(1) == host_id]
        step_id = f"{host_id}-ST-{max(numbers, default=0) + 1:02d}"
        return {
            "schema_version": "1.1",
            "step_event_id": identifier("RSE", moment),
            "created_at_utc": timestamp(moment),
            "event": "planned",
            "step_id": step_id,
            "host_id": host_id,
            **payload,
        }

    return _append_step_locked(workspace, build)


def transition_step(
    workspace: Path,
    step_id: str,
    event: str,
    record_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if event not in {"completed", "failed", "partial", "legacy_missing"}:
        raise ReportContractError("unsupported step outcome")
    payload = _json_file(record_path, "step outcome input", MAX_RECORD_BYTES)
    moment = now or datetime.now(UTC)

    def build(records: list[dict[str, Any]], states: dict[str, dict[str, Any]]) -> dict[str, Any]:
        state = states.get(step_id)
        if state is None or state["transition"] is not None:
            raise ReportContractError("report step is missing or already closed")
        return {
            "schema_version": "1.1",
            "step_event_id": identifier("RSE", moment),
            "created_at_utc": timestamp(moment),
            "event": event,
            "step_id": step_id,
            "host_id": state["plan"]["host_id"],
            **payload,
        }

    return _append_step_locked(workspace, build)


def supersede_step(
    workspace: Path,
    step_id: str,
    replacement_step_id: str,
    reason: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    normalized_reason = _text(reason, "supersede reason")
    assert normalized_reason is not None
    moment = now or datetime.now(UTC)

    def build(records: list[dict[str, Any]], states: dict[str, dict[str, Any]]) -> dict[str, Any]:
        state = states.get(step_id)
        replacement = states.get(replacement_step_id)
        if (
            state is None
            or state["transition"] is not None
            or replacement is None
            or replacement["transition"] is not None
            or replacement["plan"]["host_id"] != state["plan"]["host_id"]
        ):
            raise ReportContractError("supersede references an unavailable step")
        return {
            "schema_version": "1.1",
            "step_event_id": identifier("RSE", moment),
            "created_at_utc": timestamp(moment),
            "event": "superseded",
            "step_id": step_id,
            "host_id": state["plan"]["host_id"],
            "replacement_step_id": replacement_step_id,
            "reason": normalized_reason,
        }

    return _append_step_locked(workspace, build)


def effective_steps(
    workspace: Path,
    *,
    context: ValidationContext | None = None,
) -> dict[str, dict[str, Any]]:
    _, states = load_steps(workspace, context=context)
    return _effective_step_states(states)


def _effective_step_states(
    states: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        step_id: state
        for step_id, state in states.items()
        if not state["transition"] or state["transition"]["event"] != "superseded"
    }


def _step_requirement(workspace: Path, step_id: str, state: dict[str, Any]) -> ScreenshotRequirement | None:
    plan = state["plan"]
    checkpoint = plan["checkpoint_class"]
    screenshot = plan["screenshot"]
    if checkpoint == "other" and screenshot is None:
        return None
    assert screenshot is not None
    priority = "recommended" if checkpoint == "credential_discovery" else "required"
    transition = state["transition"]
    evidence_ids: tuple[str, ...] = ()
    attempt_id = None
    path_event_id = None
    query_ids = tuple(plan["query_ids"])
    if transition and transition["event"] != "superseded":
        evidence_ids = tuple(transition.get("evidence_ids", []))
        attempt_id = transition.get("attempt_id")
        paths = transition.get("path_event_ids", [])
        path_event_id = paths[0] if len(paths) == 1 else None
        query_ids = tuple(dict.fromkeys([*query_ids, *transition.get("query_ids", [])]))
    return ScreenshotRequirement(
        coverage_key=f"step:{step_id}:{checkpoint}",
        host_id=plan["host_id"],
        priority=priority,
        stage=screenshot["stage"],
        reason=plan["objective"],
        interface=screenshot["interface"],
        protocol=screenshot["protocol"],
        port=screenshot["port"],
        endpoint=screenshot["endpoint"],
        safe_url=screenshot["safe_url"],
        service=screenshot["service"],
        steps=("Display the operation and its decisive result.",),
        must_include=tuple(screenshot["must_include"]),
        must_exclude=tuple(screenshot["must_exclude"]),
        reproducibility=screenshot["reproducibility"],
        attempt_id=attempt_id,
        evidence_ids=evidence_ids,
        query_ids=query_ids,
        path_event_id=path_event_id,
        report_step_id=step_id,
        legacy_missing=plan["operation_origin"] in {"reconstructed", "missing"},
    )


def derive_screenshot_requirements(workspace: Path) -> list[ScreenshotRequirement]:
    requirements: list[ScreenshotRequirement] = []
    context = ValidationContext(workspace)
    _, all_step_states = load_steps(workspace, context=context)
    step_states = _effective_step_states(all_step_states)
    for step_id, state in step_states.items():
        requirement = _step_requirement(workspace, step_id, state)
        if requirement is not None:
            requirements.append(requirement)
    covered_paths = {
        path_id
        for step_id, state in step_states.items()
        if _step_requirement(workspace, step_id, state) is not None
        if state["transition"] and state["transition"]["event"] != "superseded"
        for path_id in state["transition"].get("path_event_ids", [])
    }
    stage_map = {
        "initial_access": "access",
        "identity_switch": "identity",
        "privilege_escalation": "identity",
        "pivot": "transition",
        "tunnel": "transition",
        "lateral_movement": "transition",
    }
    for record in _jsonl(workspace / "attack_paths.jsonl", "attack path ledger", missing_ok=True):
        if record.get("status") != "success" or record.get("transition") not in stage_map:
            continue
        path_id = record.get("path_event_id")
        host_id = record.get("destination_host_id")
        if (
            not isinstance(path_id, str)
            or PATH_ID_RE.fullmatch(path_id) is None
            or host_id not in context.known_hosts
        ):
            raise ReportContractError("attack path contains invalid report references")
        if path_id in covered_paths:
            continue
        transition = record["transition"]
        endpoint = _host_endpoint(workspace, host_id)
        requirements.append(
            ScreenshotRequirement(
                coverage_key=f"path:{path_id}",
                host_id=host_id,
                priority="required",
                stage=stage_map[transition],
                reason=f"Document successful {transition.replace('_', ' ')}",
                interface="terminal",
                protocol=str(record.get("service") or transition),
                port=None,
                endpoint=endpoint,
                safe_url=None,
                service=str(record.get("service") or transition),
                steps=("Show the successful transition and validate the destination identity.",),
                must_include=("destination host context", "effective identity", "successful result"),
                must_exclude=("unrelated credentials", "unrelated private data"),
                reproducibility="time-sensitive",
                attempt_id=record.get("attempt_id"),
                evidence_ids=tuple(record.get("evidence_ids", [])),
                query_ids=(),
                path_event_id=path_id,
                report_step_id=None,
                legacy_missing=True,
            )
        )
    manifest = load_manifest(workspace, context=context)
    if manifest is not None:
        objective_hosts = {
            state["plan"]["host_id"]
            for state in step_states.values()
            if state["plan"]["checkpoint_class"] in {"objective", "admin_proof"}
        }
        for target in manifest["assessment_objectives"]:
            if target["host_id"] in objective_hosts:
                continue
            requirements.append(
                ScreenshotRequirement(
                    coverage_key=f"target:{target['host_id']}:objective",
                    host_id=target["host_id"],
                    priority="required",
                    stage="objective",
                    reason="Assessment objective has no canonical objective step",
                    interface="terminal",
                    protocol="objective",
                    port=None,
                    endpoint=_host_endpoint(workspace, target["host_id"]),
                    safe_url=None,
                    service=None,
                    steps=("Create a canonical objective step before requesting a capture.",),
                    must_include=("target identity", "objective value or proof"),
                    must_exclude=("unrelated credentials",),
                    reproducibility="time-sensitive",
                    attempt_id=None,
                    evidence_ids=(),
                    query_ids=(),
                    path_event_id=None,
                    report_step_id=None,
                    legacy_missing=True,
                )
            )
    return sorted(requirements, key=lambda item: (item.host_id, item.coverage_key))


def evaluate_contract(workspace: Path) -> ContractReadiness:
    blockers: list[str] = []
    context = ValidationContext(workspace)
    manifest = load_manifest(workspace, context=context)
    _, all_states = load_steps(workspace, context=context)
    states = _effective_step_states(all_states)
    if manifest is None:
        blockers.append("manifest:missing")
        targets: list[dict[str, Any]] = []
    else:
        targets = manifest["assessment_objectives"]
    completed_by_host: dict[str, list[dict[str, Any]]] = {}
    for state in states.values():
        transition = state["transition"]
        if transition and transition["event"] == "completed":
            completed_by_host.setdefault(state["plan"]["host_id"], []).append(state)
        elif transition is None:
            blockers.append(f"step:{state['plan']['step_id']}:pending")
        elif transition["event"] in {"legacy_missing", "partial", "failed"}:
            blockers.append(f"step:{state['plan']['step_id']}:{transition['event']}")
    reviewed_targets: list[str] = []
    for target in targets:
        if manifest['schema_version'] == '2.0' and any(context.same_host(target["host_id"], prior) for prior in reviewed_targets):
            blockers.append(f"target:{target['host_id']}:merged-objective-target-requires-review")
        reviewed_targets.append(target["host_id"])
        host_steps = [
            state
            for owner, completed in completed_by_host.items()
            if context.same_host(owner, target["host_id"])
            for state in completed
        ]
        objective_steps = [
            state
            for state in host_steps
            if state["plan"]["checkpoint_class"] == "objective"
            or (
                target["category"] == "identity"
                and state["plan"]["checkpoint_class"] == "admin_proof"
            )
        ]
        if not objective_steps:
            blockers.append(f"target:{target['host_id']}:objective-step-missing")
        if target["objective_loot_id"] is None:
            blockers.append(f"target:{target['host_id']}:objective-loot-missing")
        elif not any(
            state["transition"].get("resulting_objective_loot_id")
            == target["objective_loot_id"]
            for state in objective_steps
        ):
            blockers.append(f"target:{target['host_id']}:objective-proof-mismatch")
    credentials = context.credentials
    credential_ready = True
    for state in states.values():
        ids = list(state["plan"]["credential_ids"])
        if state["transition"] and state["transition"]["event"] != "superseded":
            ids.extend(state["transition"].get("credential_ids", []))
        for credential_id in ids:
            record = credentials.get(credential_id)
            if record is None or not isinstance(record.get("secret"), str) or not record["secret"]:
                credential_ready = False
                blockers.append(f"credential:{credential_id}:unavailable")
    try:
        query_records = context.query_index(verify_hashes=True)
        queries = set(query_records)
        appendix = workspace / "report/AI_QUERY_APPENDIX.md"
        if queries:
            _real_file(appendix, "AI query appendix", 16 * 1024 * 1024)
            appendix_text = appendix.read_text(encoding="utf-8")
            query_ready = _query_appendix_matches(
                workspace, list(query_records.values()), appendix_text
            )
        else:
            query_ready = True
    except (OSError, UnicodeError, ReportContractError):
        query_ready = False
    if not query_ready:
        blockers.append("queries:appendix-missing-or-stale")
    if manifest and manifest['schema_version'] == '2.1':
        if __package__:
            from . import configuration_report
        else:
            import configuration_report
        if not configuration_report.is_current(workspace, manifest):
            blockers.append('configuration:report-snapshot-requires-refresh-and-review')
    try:
        if __package__:
            from . import execution_provenance
        else:
            import execution_provenance  # type: ignore[no-redef]

        provenance = execution_provenance._evaluate_provenance_with_context(
            workspace,
            strict=True,
            context=context,
            states=all_states,
        )
    except execution_provenance.ProvenanceError as exc:
        raise ReportContractError(str(exc)) from exc
    blockers.extend(provenance.blockers)
    if any(item.startswith("credential:") for item in provenance.blockers):
        credential_ready = False
    content_blockers = [item for item in blockers if not item.startswith("credential:") and not item.startswith("queries:")]
    return ContractReadiness(
        content_ready=not content_blockers,
        credential_ready=credential_ready,
        query_appendix_ready=query_ready,
        blockers=tuple(blockers),
        manifest_targets=len(targets),
        active_steps=len(states),
    )
