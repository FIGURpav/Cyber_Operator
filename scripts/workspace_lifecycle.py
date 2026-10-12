"""Operator-gated workspace target-action closure and explicit reopen."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

if __package__:
    from . import (
        host_state,
        ledger_io,
        operational_profile,
        operational_trace,
        report_contract,
        restore_checkpoint,
        structured_state,
        token_lifecycle,
        workspace_transaction,
    )
else:
    import host_state  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]
    import operational_profile  # type: ignore[no-redef]
    import operational_trace  # type: ignore[no-redef]
    import report_contract  # type: ignore[no-redef]
    import restore_checkpoint  # type: ignore[no-redef]
    import structured_state  # type: ignore[no-redef]
    import token_lifecycle  # type: ignore[no-redef]
    import workspace_transaction  # type: ignore[no-redef]

LEDGER = "workspace_lifecycle.jsonl"
EVENT_RE = re.compile(r"^WSE-\d{8}T\d{12}Z$")
TOKEN_RE = re.compile(r"^TOK-\d{8}T\d{12}Z$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
EVENTS = ("closed", "reopened")
MAX_LEDGER = 4 * 1024 * 1024
FIELDS = (
    "schema_version", "workspace_event_id", "created_at_utc", "event",
    "workspace_instance_id", "operational_profile", "reason",
    "operator_acknowledged", "close_plan_sha256", "standing_authorization_id",
    "retained_change_ids", "warning_token_ids", "local_artifact_ids",
    "stale_host_views", "report_summary", "work_summary",
)


class WorkspaceLifecycleError(ValueError):
    """A deterministic closure lifecycle failure."""


@dataclass(frozen=True)
class ClosePlan:
    workspace: Path
    profile: str
    workspace_instance_id: str
    standing_authorization_id: str | None
    standing_authorization_status: str
    pending_change_ids: tuple[str, ...]
    retained_change_ids: tuple[str, ...]
    warning_token_ids: tuple[str, ...]
    token_orphan_count: int
    local_artifact_ids: tuple[str, ...]
    host_view_status: tuple[tuple[str, str], ...]
    report_summary: tuple[tuple[str, int], ...]
    work_summary: tuple[tuple[str, int], ...]
    projection_source_sha256: str
    plan_sha256: str

    @property
    def has_active_state(self) -> bool:
        return bool(
            self.standing_authorization_status == "active"
            or self.pending_change_ids
            or self.retained_change_ids
            or self.warning_token_ids
            or self.token_orphan_count
            or self.local_artifact_ids
        )


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identifier(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("WSE-%Y%m%dT%H%M%S%fZ")


def _text(value: str, name: str, maximum: int = 1024) -> str:
    if (
        value != value.strip() or not value or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise WorkspaceLifecycleError(f"{name} must be bounded printable single-line text")
    return value


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.exists() and not path.is_symlink():
        return []
    try:
        info = path.lstat()
    except OSError as exc:
        raise WorkspaceLifecycleError(f"cannot inspect {LEDGER}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkspaceLifecycleError(f"{LEDGER} must be a dedicated regular file")
    if info.st_size > MAX_LEDGER:
        raise WorkspaceLifecycleError(f"{LEDGER} exceeds its size limit")
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise WorkspaceLifecycleError(f"{LEDGER} has an unterminated final record")
    result = []
    for number, line in enumerate(raw.splitlines(), start=1):
        try:
            item = ledger_io.loads_json(line)
        except ledger_io.LedgerIOError as exc:
            raise WorkspaceLifecycleError(f"{LEDGER} line {number} is invalid") from exc
        if not isinstance(item, dict):
            raise WorkspaceLifecycleError(f"{LEDGER} line {number} must be an object")
        result.append(item)
    return result


def load_events(workspace: str | Path) -> list[dict[str, Any]]:
    root = operational_trace.validate_workspace(workspace)
    records = _read(root / LEDGER)
    identifiers: set[str] = set()
    expected_event = "closed"
    for number, record in enumerate(records, start=1):
        source = f"{LEDGER} line {number}"
        if tuple(record) != FIELDS or record.get("schema_version") != "1.0":
            raise WorkspaceLifecycleError(f"{source} has an invalid schema")
        event_id, created = record["workspace_event_id"], record["created_at_utc"]
        if not isinstance(event_id, str) or EVENT_RE.fullmatch(event_id) is None or event_id in identifiers:
            raise WorkspaceLifecycleError(f"{source} has a malformed or duplicate event ID")
        if not isinstance(created, str) or TIMESTAMP_RE.fullmatch(created) is None:
            raise WorkspaceLifecycleError(f"{source} has a malformed timestamp")
        try:
            moment = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        except ValueError as exc:
            raise WorkspaceLifecycleError(f"{source} has a malformed timestamp") from exc
        if event_id != _identifier(moment):
            raise WorkspaceLifecycleError(f"{source} event ID and timestamp do not match")
        if record["event"] != expected_event:
            raise WorkspaceLifecycleError(f"{source} violates close/reopen ordering")
        expected_event = "reopened" if record["event"] == "closed" else "closed"
        if record["operational_profile"] not in operational_profile.PROFILES:
            raise WorkspaceLifecycleError(f"{source} has an invalid profile")
        _text(record["workspace_instance_id"], "workspace_instance_id", 160)
        _text(record["reason"], "reason")
        if record["operator_acknowledged"] is not True:
            raise WorkspaceLifecycleError(f"{source} lacks operator acknowledgement")
        nullable = record["close_plan_sha256"]
        if record["event"] == "closed":
            if not isinstance(nullable, str) or SHA_RE.fullmatch(nullable) is None:
                raise WorkspaceLifecycleError(f"{source} has an invalid close plan hash")
        elif nullable is not None:
            raise WorkspaceLifecycleError(f"{source} reopen must not reference a close plan")
        for field, pattern in (
            ("retained_change_ids", operational_trace.CHANGE_ID_RE),
            ("warning_token_ids", TOKEN_RE),
            ("local_artifact_ids", structured_state.LOCAL_ARTIFACT_RE),
        ):
            values = record[field]
            if not isinstance(values, list) or values != sorted(set(values)) or any(
                not isinstance(value, str) or pattern.fullmatch(value) is None for value in values
            ):
                raise WorkspaceLifecycleError(f"{source} has invalid {field}")
        if not isinstance(record["stale_host_views"], list) or any(not isinstance(value, str) for value in record["stale_host_views"]):
            raise WorkspaceLifecycleError(f"{source} has invalid stale_host_views")
        for field in ("report_summary", "work_summary"):
            if not isinstance(record[field], dict) or any(
                not isinstance(key, str) or type(value) is not int or value < 0
                for key, value in record[field].items()
            ):
                raise WorkspaceLifecycleError(f"{source} has invalid {field}")
        identifiers.add(event_id)
    return records


def is_closed(workspace: str | Path) -> bool:
    events = load_events(workspace)
    return bool(events and events[-1]["event"] == "closed")


def assert_target_actions_open(workspace: str | Path) -> None:
    if is_closed(workspace):
        raise WorkspaceLifecycleError(
            "workspace target actions are closed; an explicit operator-authorized reopen is required"
        )


def authorization_is_current(workspace: str | Path, activation: dict[str, Any]) -> bool:
    events = load_events(workspace)
    if events and events[-1]["event"] == "closed":
        return False
    closed = [record for record in events if record["event"] == "closed"]
    if not closed:
        return True
    return activation["created_at_utc"] > closed[-1]["created_at_utc"]


def _instance(root: Path) -> str:
    try:
        state = restore_checkpoint.state(root)
    except (restore_checkpoint.RestoreError, OSError) as exc:
        raise WorkspaceLifecycleError(str(exc)) from exc
    return state["instance_id"] if state else "original"


def _closable_standing(
    root: Path, moment: datetime
) -> tuple[str | None, str]:
    if __package__:
        from . import engagement_policy
    else:
        import engagement_policy
    records = engagement_policy.load_standing_authorizations(root)
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        latest[record["standing_authorization_id"]] = record
    candidates = [
        record for record in latest.values()
        if record["event"] == "activated" and authorization_is_current(root, record)
    ]
    if len(candidates) > 1:
        raise WorkspaceLifecycleError("workspace has multiple closable standing authorizations")
    if not candidates:
        return None, "none"
    record = candidates[0]
    expiry = record["expires_at_utc"]
    status = "active"
    if expiry is not None:
        parsed = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC
        )
        if moment >= parsed:
            status = "expired"
    return record["standing_authorization_id"], status


def _summaries(root: Path) -> tuple[dict[str, int], dict[str, int]]:
    try:
        states = report_contract.effective_steps(root)
        report: Counter[str] = Counter(
            state["transition"]["event"] if state["transition"] else "planned"
            for state in states.values()
        )
        readiness = report_contract.evaluate_contract(root)
        report.update(
            {
                "content_ready": int(readiness.content_ready),
                "credential_ready": int(readiness.credential_ready),
                "query_appendix_ready": int(readiness.query_appendix_ready),
                "readiness_blockers": len(readiness.blockers),
            }
        )
    except report_contract.ReportContractError:
        report = Counter({"unavailable": 1})
    work = Counter(item["state"] for item in structured_state.work_item_states(root).values())
    if (root / 'assessment_events.jsonl').exists():
        if __package__:
            from . import assessment_journal, assessment_model, assessment_reporting
        else:
            import assessment_journal
            import assessment_model
            import assessment_reporting
        work['activities_recorded'] = len(assessment_journal.states(root,'activity'))
        entities = assessment_model.states(root)
        for event in entities.values():
            data = event['data']
            if event['entity_kind']=='finding':
                report['finding_'+data['confidence']] += 1
                report['remediation_'+data['remediation_status']] += 1
                report['retest_'+data['retest_status']] += 1
            elif event['entity_kind']=='objective':
                work['objective_'+data['status']] += 1
        if any(event['entity_kind']=='objective' for event in entities.values()):
            try:
                readiness = assessment_reporting.readiness(root)
                report['content_ready'] = int(readiness['ready'])
                report['readiness_blockers'] = len(readiness['blockers'])
            except (ValueError,RuntimeError):
                report['content_ready'] = 0
                report['readiness_blockers'] += 1
    return dict(sorted(report.items())), dict(sorted(work.items()))


def build_close_plan(
    workspace: str | Path, *, now: datetime | None = None
) -> ClosePlan:
    root = operational_trace.validate_workspace(workspace)
    if is_closed(root):
        raise WorkspaceLifecycleError("workspace target actions are already closed")
    profile = operational_profile.workspace_profile(root)
    moment = now or datetime.now(UTC)
    changes = operational_trace.load_changes(root)
    pending: list[str] = []
    retained: list[str] = []
    for change_id, history in operational_trace.change_histories(changes).items():
        if not operational_trace.change_is_active(history):
            continue
        (retained if history[-1]["event"] == "retained" else pending).append(change_id)
    readiness = token_lifecycle.closure_readiness(root)
    token_ids = tuple(sorted(value for value in readiness.blockers if TOKEN_RE.fullmatch(value)))
    orphan_count = len(readiness.blockers) - len(token_ids)
    if readiness.blockers:
        raise WorkspaceLifecycleError(
            "workspace closure is blocked by unresolved session-token state; run cyber-token closure-check"
        )
    artifacts = tuple(sorted(
        identifier for identifier, record in structured_state.local_artifact_states(root).items()
        if record["state"] not in {"disposed", "missing"}
    ))
    try:
        projection = host_state._source_snapshot(root)
        view = tuple(sorted(host_state.view_status(root, index=projection).items()))
        projection_source_sha256 = host_state.global_digest(projection)
    except (host_state.HostStateError, operational_trace.TraceError, OSError):
        view = (("unavailable", "malformed"),)
        projection_source_sha256 = hashlib.sha256(b"unavailable").hexdigest()
    report, work = _summaries(root)
    if (root / 'assessment_events.jsonl').exists():
        if __package__:
            from . import assessment_journal
        else:
            import assessment_journal
        events = assessment_journal.load(root)
        source = events[-1]['event_sha256'] if events else 'empty'
        projection_source_sha256 = hashlib.sha256((projection_source_sha256 + ':' + source).encode()).hexdigest()
    standing_id, standing_status = _closable_standing(root, moment)
    payload = {
        "schema_version": "1.0", "workspace_instance_id": _instance(root),
        "operational_profile": profile, "standing_authorization_id": standing_id,
        "standing_authorization_status": standing_status,
        "pending_change_ids": sorted(pending), "retained_change_ids": sorted(retained),
        "warning_token_ids": list(token_ids), "token_orphan_count": orphan_count,
        "local_artifact_ids": list(artifacts), "host_view_status": dict(view),
        "report_summary": report, "work_summary": work,
        "projection_source_sha256": projection_source_sha256,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ClosePlan(
        workspace=root,
        profile=profile,
        workspace_instance_id=payload["workspace_instance_id"],
        standing_authorization_id=standing_id,
        standing_authorization_status=standing_status,
        pending_change_ids=tuple(payload["pending_change_ids"]),
        retained_change_ids=tuple(payload["retained_change_ids"]),
        warning_token_ids=token_ids,
        token_orphan_count=orphan_count,
        local_artifact_ids=artifacts,
        host_view_status=view,
        report_summary=tuple(report.items()),
        work_summary=tuple(work.items()),
        projection_source_sha256=projection_source_sha256,
        plan_sha256=digest,
    )


def apply_close(
    plan: ClosePlan, *, supplied_plan_sha256: str, operator_acknowledged: bool,
    retain_active_state: bool, reason: str, now: datetime | None = None,
) -> dict[str, Any]:
    if not operator_acknowledged:
        raise WorkspaceLifecycleError("apply requires --ack-operator-requested-close")
    if supplied_plan_sha256 != plan.plan_sha256:
        raise WorkspaceLifecycleError("close plan hash does not match preview")
    reason = _text(reason, "reason")
    operational_trace._reject_secret_content(plan.workspace, [reason])
    if plan.has_active_state and not retain_active_state:
        raise WorkspaceLifecycleError("active or retained state requires --ack-retain-active-state")
    moment = now or datetime.now(UTC)
    with workspace_transaction.write_guard(plan.workspace):
        current = build_close_plan(plan.workspace, now=moment)
        if current != plan:
            raise WorkspaceLifecycleError("closure state changed after preview")
        # Retention records a decision only. It executes no rollback, deletion, or target command.
        for offset, change_id in enumerate(plan.pending_change_ids):
            operational_trace.log_change(
                workspace=plan.workspace, event="retained", change_id=change_id,
                note=f"Operator accepted retained state under close plan {plan.plan_sha256}",
                now=moment + timedelta(microseconds=offset),
            )
        event_time = moment + timedelta(microseconds=len(plan.pending_change_ids))
        record = {
            "schema_version": "1.0", "workspace_event_id": _identifier(event_time),
            "created_at_utc": _timestamp(event_time), "event": "closed",
            "workspace_instance_id": plan.workspace_instance_id,
            "operational_profile": plan.profile, "reason": reason,
            "operator_acknowledged": True, "close_plan_sha256": plan.plan_sha256,
            "standing_authorization_id": plan.standing_authorization_id,
            "retained_change_ids": sorted((*plan.pending_change_ids, *plan.retained_change_ids)),
            "warning_token_ids": list(plan.warning_token_ids),
            "local_artifact_ids": list(plan.local_artifact_ids),
            "stale_host_views": sorted(name for name, state in plan.host_view_status if state != "current"),
            "report_summary": dict(plan.report_summary), "work_summary": dict(plan.work_summary),
        }
        with ledger_io.exclusive_ledger_lock(plan.workspace / LEDGER):
            lifecycle = load_events(plan.workspace)
            if lifecycle and lifecycle[-1]["event"] == "closed":
                raise WorkspaceLifecycleError("workspace target actions are already closed")
            if any(
                item["workspace_event_id"] == record["workspace_event_id"]
                for item in lifecycle
            ):
                raise WorkspaceLifecycleError("duplicate workspace lifecycle event ID")
            ledger_io.append_json_record(plan.workspace / LEDGER, record, create=True, maximum_bytes=64 * 1024)
    return record


def reopen(
    workspace: str | Path, *, operator_acknowledged: bool, reason: str,
    apply: bool, now: datetime | None = None,
) -> dict[str, Any]:
    root = operational_trace.validate_workspace(workspace)
    if not is_closed(root):
        raise WorkspaceLifecycleError("workspace target actions are not closed")
    if apply and not operator_acknowledged:
        raise WorkspaceLifecycleError("apply requires --ack-operator-requested-reopen")
    moment = now or datetime.now(UTC)
    last = load_events(root)[-1]
    record = {
        "schema_version": "1.0", "workspace_event_id": _identifier(moment),
        "created_at_utc": _timestamp(moment), "event": "reopened",
        "workspace_instance_id": _instance(root),
        "operational_profile": operational_profile.workspace_profile(root),
        "reason": _text(reason, "reason"), "operator_acknowledged": True,
        "close_plan_sha256": None, "standing_authorization_id": last["standing_authorization_id"],
        "retained_change_ids": [], "warning_token_ids": [], "local_artifact_ids": [],
        "stale_host_views": [], "report_summary": {}, "work_summary": {},
    }
    operational_trace._reject_secret_content(root, [record["reason"]])
    if apply:
        with ledger_io.exclusive_ledger_lock(root / LEDGER):
            lifecycle = load_events(root)
            if not lifecycle or lifecycle[-1]["event"] != "closed":
                raise WorkspaceLifecycleError("workspace lifecycle changed after preview")
            if any(
                item["workspace_event_id"] == record["workspace_event_id"]
                for item in lifecycle
            ):
                raise WorkspaceLifecycleError("duplicate workspace lifecycle event ID")
            ledger_io.append_json_record(root / LEDGER, record, create=True, maximum_bytes=64 * 1024)
    return record


def print_close_plan(plan: ClosePlan, *, apply: bool) -> None:
    print(f"mode: {'APPLY' if apply else 'PREVIEW'}")
    print(f"workspace_state: {'closed' if apply else 'open'}")
    print(f"close_plan_sha256: {plan.plan_sha256}")
    print(f"standing_authorization_id: {plan.standing_authorization_id or 'none'}")
    print(f"standing_authorization_status: {plan.standing_authorization_status}")
    print(f"pending_change_ids: {','.join(plan.pending_change_ids) or 'none'}")
    print(f"retained_change_ids: {','.join(plan.retained_change_ids) or 'none'}")
    print(f"warning_token_ids: {','.join(plan.warning_token_ids) or 'none'}")
    print(f"token_orphan_count: {plan.token_orphan_count}")
    print(f"local_artifact_ids: {','.join(plan.local_artifact_ids) or 'none'}")
    print("host_views: " + ",".join(f"{name}={state}" for name, state in plan.host_view_status))
    print("report_summary: " + json.dumps(dict(plan.report_summary), sort_keys=True, separators=(",", ":")))
    print("work_summary: " + json.dumps(dict(plan.work_summary), sort_keys=True, separators=(",", ":")))
    print(f"projection_source_sha256: {plan.projection_source_sha256}")
    print("cleanup_performed: no")
