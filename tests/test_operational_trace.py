"""Tests for autonomous impact envelopes and operational trace ledgers."""

import hashlib
import json
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import ledger_io, new_host, operational_trace
from scripts.operational_trace import (
    ATTACK_PATH_LEDGER,
    AUTHORIZATION_LEDGER,
    CHANGE_LEDGER,
    TraceError,
    build_operational_trace,
    change_histories,
    load_attack_paths,
    load_authorizations,
    load_changes,
    log_attack_path,
    log_authorization,
    log_change,
)
from scripts.workspace_status import generate_status

BASE_TIME = datetime(2026, 8, 8, 18, 0, 0, tzinfo=UTC)


def make_workspace(tmp_path: Path, *, legacy: bool = False) -> Path:
    """Create a canonical two-host synthetic workspace."""
    workspace = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(workspace, script_dir, "H01", "192.0.2.10", "entry")
    new_host.bootstrap_host(workspace, script_dir, "H02", "198.51.100.20", "internal")
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n",
        encoding="utf-8",
    )
    if legacy:
        for name in (AUTHORIZATION_LEDGER, CHANGE_LEDGER, ATTACK_PATH_LEDGER):
            (workspace / name).unlink()
    return workspace


def add_attempt(
    workspace: Path,
    host_id: str,
    suffix: int,
    *,
    status: str = "success",
) -> str:
    """Append a minimal canonical attempt and return its ID."""
    now = BASE_TIME + timedelta(seconds=suffix)
    attempt_id = now.strftime("ATT-%Y%m%dT%H%M%S%fZ")
    record = {
        "schema_version": "1.0",
        "attempt_id": attempt_id,
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": host_id,
        "action": "synthetic authorized action",
        "status": status,
        "result_sha256": "0" * 64,
        "result_text": "synthetic result",
        "evidence_refs": [],
        "next_step": "continue",
    }
    with (workspace / "attempts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return attempt_id


def add_evidence(workspace: Path, host_id: str, suffix: int) -> str:
    """Create a synthetic evidence metadata filename and return its ID."""
    now = BASE_TIME + timedelta(seconds=suffix)
    evidence_id = now.strftime("EVD-%Y%m%dT%H%M%S%fZ")
    content = b"synthetic evidence\n"
    artifact_relative = f"evidence/{host_id}/{evidence_id}.txt"
    (workspace / artifact_relative).write_bytes(content)
    metadata = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": host_id,
        "kind": "synthetic",
        "label": "synthetic-evidence",
        "artifact_path": artifact_relative,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    (workspace / "evidence" / host_id / f"{evidence_id}.json").write_text(
        json.dumps(metadata) + "\n", encoding="utf-8"
    )
    return evidence_id


def add_credential(workspace: Path, suffix: int, secret: str) -> str:
    """Add one minimal private credential record."""
    now = BASE_TIME + timedelta(seconds=suffix)
    credential_id = now.strftime("CRED-%Y%m%dT%H%M%S%fZ")
    credentials = workspace / "private" / "credentials"
    credentials.mkdir(parents=True)
    (credentials / "credentials.jsonl").write_text(
        json.dumps({"credential_id": credential_id, "host_id": "H02", "secret": secret})
        + "\n",
        encoding="utf-8",
    )
    return credential_id


def authorize(
    workspace: Path,
    *,
    hosts: list[str] | None = None,
    categories: list[str] | None = None,
    techniques: list[str] | None = None,
    impact: str = "high",
    offset: int = 0,
) -> str:
    """Create one synthetic authorization envelope."""
    _, record = log_authorization(
        workspace=workspace,
        host_ids=hosts or ["H01"],
        categories=categories or ["persistence"],
        maximum_impact=impact,
        techniques=techniques or ["sudoers drop"],
        exclusions=["denial of service"],
        source="operator-chat",
        summary="Authorized synthetic impact envelope",
        now=BASE_TIME + timedelta(seconds=offset),
    )
    return record["authorization_id"]


def plan_change(
    workspace: Path,
    authorization_id: str,
    *,
    host_id: str = "H01",
    category: str = "persistence",
    impact: str = "high",
    technique: str = "sudoers drop",
    offset: int = 10,
) -> str:
    """Append one planned change and return its root change ID."""
    _, record = log_change(
        workspace=workspace,
        event="planned",
        authorization_id=authorization_id,
        host_id=host_id,
        category=category,
        impact_level=impact,
        technique=technique,
        target="/etc/synthetic.conf",
        description="Synthetic persistent access change",
        reversibility="reversible",
        before_state="target absent",
        rollback_steps=["remove the synthetic target"],
        validation_steps=["verify the synthetic target is absent"],
        evidence_ids=[],
        now=BASE_TIME + timedelta(seconds=offset),
    )
    return record["change_id"]


def test_validate_only_covers_authorization_change_and_attack_path(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    authorization_ledger = workspace / AUTHORIZATION_LEDGER
    before_authorizations = authorization_ledger.read_bytes()
    _, prospective_authorization = log_authorization(
        workspace=workspace,
        host_ids=["H01"],
        categories=["persistence"],
        maximum_impact="high",
        techniques=["sudoers drop"],
        exclusions=[],
        source="operator-chat",
        summary="Synthetic authorization validation",
        now=BASE_TIME,
        validate_only=True,
    )
    assert prospective_authorization["authorization_id"].startswith("AUTH-")
    assert authorization_ledger.read_bytes() == before_authorizations

    authorization_id = authorize(workspace)
    change_ledger = workspace / CHANGE_LEDGER
    before_changes = change_ledger.read_bytes()
    _, prospective_change = log_change(
        workspace=workspace,
        event="planned",
        authorization_id=authorization_id,
        host_id="H01",
        category="persistence",
        impact_level="high",
        technique="sudoers drop",
        target="/etc/synthetic.conf",
        description="Synthetic prospective change",
        reversibility="reversible",
        before_state="target absent",
        rollback_steps=["remove synthetic target"],
        validation_steps=["verify target is absent"],
        validate_only=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert prospective_change["change_event_id"].startswith("CHGE-")
    assert change_ledger.read_bytes() == before_changes

    path_authorization = authorize(
        workspace,
        hosts=["H01", "H02"],
        categories=["lateral-movement"],
        techniques=["ssh"],
        offset=2,
    )
    attempt_id = add_attempt(workspace, "H01", 3)
    path_ledger = workspace / ATTACK_PATH_LEDGER
    before_paths = path_ledger.read_bytes()
    _, prospective_path = log_attack_path(
        workspace=workspace,
        authorization_id=path_authorization,
        transition="lateral_movement",
        impact_level="high",
        source_host_id="H01",
        source_identity="synthetic-user",
        destination_host_id="H02",
        destination_identity="synthetic-admin",
        source_segment="segment-a",
        destination_segment="segment-b",
        service="ssh",
        technique="ssh",
        status="success",
        credential_id=None,
        attempt_id=attempt_id,
        evidence_ids=[],
        validate_only=True,
        now=BASE_TIME + timedelta(seconds=4),
    )
    assert prospective_path["path_event_id"].startswith("PTH-")
    assert path_ledger.read_bytes() == before_paths


def install_append_gate(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ledger_name: str,
    first_thread: str,
    second_thread: str,
) -> tuple[threading.Event, threading.Event, threading.Event]:
    """Hold the first writer after validation and observe the second lock attempt."""
    first_in_append = threading.Event()
    release_first = threading.Event()
    second_at_lock = threading.Event()
    original_append = operational_trace._append_record
    original_flock = ledger_io.fcntl.flock

    def delayed_append(path: Path, record: dict[str, object]) -> None:
        if path.name == ledger_name and threading.current_thread().name == first_thread:
            first_in_append.set()
            assert release_first.wait(timeout=5)
        original_append(path, record)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == second_thread
            and operation == ledger_io.fcntl.LOCK_EX
        ):
            second_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(operational_trace, "_append_record", delayed_append)
    monkeypatch.setattr(ledger_io.fcntl, "flock", observed_flock)
    return first_in_append, release_first, second_at_lock


def test_bootstrap_creates_empty_operational_ledgers(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    for name in (
        "standing_authorizations.jsonl",
        AUTHORIZATION_LEDGER,
        CHANGE_LEDGER,
        ATTACK_PATH_LEDGER,
    ):
        ledger = workspace / name
        assert ledger.read_bytes() == b""
        assert stat.S_IMODE(ledger.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "payload",
    [
        b'{"authorization_id":"AUTH-20260808T175959000000Z","value":NaN}\n',
        (
            b'{"authorization_id":"AUTH-20260808T175959000000Z",'
            b'"nested":{"value":1,"value":2}}\n'
        ),
    ],
)
def test_operational_ledger_reader_rejects_non_rfc_json(
    tmp_path: Path,
    payload: bytes,
) -> None:
    workspace = make_workspace(tmp_path)
    ledger = workspace / AUTHORIZATION_LEDGER
    ledger.write_bytes(payload)

    with pytest.raises(TraceError, match="invalid JSON"):
        load_authorizations(workspace)

    assert ledger.read_bytes() == payload


def test_legacy_ledgers_are_created_on_first_valid_append(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, legacy=True)
    authorization_id = authorize(workspace)

    assert authorization_id.startswith("AUTH-")
    assert (workspace / AUTHORIZATION_LEDGER).is_file()
    assert stat.S_IMODE((workspace / AUTHORIZATION_LEDGER).stat().st_mode) == 0o600
    assert not (workspace / CHANGE_LEDGER).exists()
    assert not (workspace / ATTACK_PATH_LEDGER).exists()


def test_concurrent_authorization_id_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    first_in_append, release_first, second_at_lock = install_append_gate(
        monkeypatch,
        ledger_name=AUTHORIZATION_LEDGER,
        first_thread="authorization-first",
        second_thread="authorization-second",
    )
    outcomes: dict[str, str] = {}

    def invoke(label: str) -> None:
        try:
            log_authorization(
                workspace=workspace,
                host_ids=["H01"],
                categories=["persistence"],
                maximum_impact="high",
                techniques=["sudoers drop"],
                exclusions=[],
                source="operator-chat",
                summary=f"Synthetic authorization {label}",
                now=BASE_TIME,
            )
        except TraceError:
            outcomes[label] = "rejected"
        else:
            outcomes[label] = "appended"

    first = threading.Thread(
        target=invoke,
        args=("first",),
        name="authorization-first",
    )
    second = threading.Thread(
        target=invoke,
        args=("second",),
        name="authorization-second",
    )
    first.start()
    assert first_in_append.wait(timeout=5)
    second.start()
    assert second_at_lock.wait(timeout=5)
    assert "second" not in outcomes
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == {"first": "appended", "second": "rejected"}
    records = load_authorizations(workspace)
    assert len(records) == 1
    assert records[0]["summary"] == "Synthetic authorization first"


def test_authorization_and_change_lifecycle_is_append_only(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(workspace)
    change_id = plan_change(workspace, authorization_id)
    before = (workspace / CHANGE_LEDGER).read_bytes()
    attempt = add_attempt(workspace, "H01", 20)

    _, applied = log_change(
        workspace=workspace,
        event="applied",
        change_id=change_id,
        attempt_id=attempt,
        evidence_ids=[],
        note="Change applied as planned",
        now=BASE_TIME + timedelta(seconds=21),
    )

    after = (workspace / CHANGE_LEDGER).read_bytes()
    assert after.startswith(before)
    assert applied["change_id"] == change_id
    assert [record["event"] for record in load_changes(workspace)] == [
        "planned",
        "applied",
    ]


def test_concurrent_change_transition_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(workspace)
    change_id = plan_change(workspace, authorization_id)
    first_attempt = add_attempt(workspace, "H01", 20)
    second_attempt = add_attempt(workspace, "H01", 21)
    first_in_append, release_first, second_at_lock = install_append_gate(
        monkeypatch,
        ledger_name=CHANGE_LEDGER,
        first_thread="change-first",
        second_thread="change-second",
    )
    outcomes: dict[str, str] = {}

    def invoke(label: str, attempt_id: str, moment: datetime) -> None:
        try:
            log_change(
                workspace=workspace,
                event="applied",
                change_id=change_id,
                attempt_id=attempt_id,
                note=f"Applied by {label}",
                now=moment,
            )
        except TraceError:
            outcomes[label] = "rejected"
        else:
            outcomes[label] = "appended"

    first = threading.Thread(
        target=invoke,
        args=("first", first_attempt, BASE_TIME + timedelta(seconds=30)),
        name="change-first",
    )
    second = threading.Thread(
        target=invoke,
        args=("second", second_attempt, BASE_TIME + timedelta(seconds=31)),
        name="change-second",
    )
    first.start()
    assert first_in_append.wait(timeout=5)
    second.start()
    assert second_at_lock.wait(timeout=5)
    assert "second" not in outcomes
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == {"first": "appended", "second": "rejected"}
    history = change_histories(load_changes(workspace))[change_id]
    assert [record["event"] for record in history] == ["planned", "applied"]
    assert history[-1]["attempt_id"] == first_attempt


def test_change_lifecycle_requires_planned_and_applied(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    attempt = add_attempt(workspace, "H01", 1)

    with pytest.raises(TraceError, match="does not exist"):
        log_change(
            workspace=workspace,
            event="applied",
            change_id="CHG-20260808T180000000000Z",
            attempt_id=attempt,
        )
    assert (workspace / CHANGE_LEDGER).read_bytes() == b""


def test_failed_apply_can_be_retried_without_rewriting_history(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(workspace)
    change_id = plan_change(workspace, authorization_id)
    failed_attempt = add_attempt(workspace, "H01", 20, status="failed")
    success_attempt = add_attempt(workspace, "H01", 21)
    log_change(
        workspace=workspace,
        event="failed",
        change_id=change_id,
        attempt_id=failed_attempt,
        note="First apply failed",
        now=BASE_TIME + timedelta(seconds=22),
    )
    log_change(
        workspace=workspace,
        event="applied",
        change_id=change_id,
        attempt_id=success_attempt,
        note="Retry succeeded",
        now=BASE_TIME + timedelta(seconds=23),
    )

    history = change_histories(load_changes(workspace))[change_id]
    assert [record["event"] for record in history] == [
        "planned",
        "failed",
        "applied",
    ]


@pytest.mark.parametrize(
    ("host_id", "category", "impact", "technique", "message"),
    [
        ("H02", "persistence", "high", "sudoers drop", "authorization hosts"),
        ("H01", "service", "high", "sudoers drop", "category"),
        ("H01", "persistence", "critical", "sudoers drop", "impact"),
        ("H01", "persistence", "high", "ssh key", "technique"),
    ],
)
def test_change_outside_envelope_is_rejected_without_append(
    tmp_path: Path,
    host_id: str,
    category: str,
    impact: str,
    technique: str,
    message: str,
) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(workspace)

    with pytest.raises(TraceError, match=message):
        plan_change(
            workspace,
            authorization_id,
            host_id=host_id,
            category=category,
            impact=impact,
            technique=technique,
        )
    assert (workspace / CHANGE_LEDGER).read_bytes() == b""


def test_trace_text_rejects_stored_credentials(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    add_credential(workspace, 1, "synthetic-secret-value")
    authorization_id = authorize(workspace)

    with pytest.raises(TraceError, match="stored credential"):
        log_change(
            workspace=workspace,
            event="planned",
            authorization_id=authorization_id,
            host_id="H01",
            category="persistence",
            impact_level="high",
            technique="sudoers drop",
            target="/etc/synthetic.conf",
            description="contains synthetic-secret-value",
            reversibility="reversible",
            before_state="absent",
            rollback_steps=["remove target"],
            validation_steps=["verify absent"],
            now=BASE_TIME + timedelta(seconds=10),
        )
    assert (workspace / CHANGE_LEDGER).read_bytes() == b""


def test_concurrent_attack_path_id_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(
        workspace,
        categories=["initial-access"],
        techniques=["password login"],
    )
    attempt_id = add_attempt(workspace, "H01", 20)
    first_in_append, release_first, second_at_lock = install_append_gate(
        monkeypatch,
        ledger_name=ATTACK_PATH_LEDGER,
        first_thread="path-first",
        second_thread="path-second",
    )
    outcomes: dict[str, str] = {}

    def invoke(label: str) -> None:
        try:
            log_attack_path(
                workspace=workspace,
                authorization_id=authorization_id,
                transition="initial_access",
                impact_level="high",
                source_host_id="OPERATOR",
                source_identity="operator",
                destination_host_id="H01",
                destination_identity="user",
                source_segment="operator",
                destination_segment="target",
                service="ssh",
                technique="password login",
                status="success",
                credential_id=None,
                attempt_id=attempt_id,
                evidence_ids=[],
                now=BASE_TIME + timedelta(seconds=30),
            )
        except TraceError:
            outcomes[label] = "rejected"
        else:
            outcomes[label] = "appended"

    first = threading.Thread(target=invoke, args=("first",), name="path-first")
    second = threading.Thread(target=invoke, args=("second",), name="path-second")
    first.start()
    assert first_in_append.wait(timeout=5)
    second.start()
    assert second_at_lock.wait(timeout=5)
    assert "second" not in outcomes
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == {"first": "appended", "second": "rejected"}
    records = load_attack_paths(workspace)
    assert len(records) == 1
    assert records[0]["path_event_id"] == (BASE_TIME + timedelta(seconds=30)).strftime(
        "PTH-%Y%m%dT%H%M%S%fZ"
    )


def test_multihost_attack_graph_and_recovery_reports(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(
        workspace,
        hosts=["H01", "H02"],
        categories=["privilege-escalation", "pivot", "persistence"],
        techniques=["local exploit", "ssh pivot", "sudoers drop"],
    )
    attempt_h01 = add_attempt(workspace, "H01", 10)
    attempt_h02 = add_attempt(workspace, "H02", 11)
    evidence_h01 = add_evidence(workspace, "H01", 12)
    credential_id = add_credential(workspace, 13, "private-synthetic-password")

    log_attack_path(
        workspace=workspace,
        authorization_id=authorization_id,
        transition="privilege_escalation",
        impact_level="high",
        source_host_id="H01",
        source_identity="user",
        destination_host_id="H01",
        destination_identity='root"] --> injected',
        source_segment="dmz",
        destination_segment="dmz",
        service="local",
        technique="local exploit",
        status="success",
        credential_id=None,
        attempt_id=attempt_h01,
        evidence_ids=[evidence_h01],
        now=BASE_TIME + timedelta(seconds=20),
    )
    log_attack_path(
        workspace=workspace,
        authorization_id=authorization_id,
        transition="pivot",
        impact_level="high",
        source_host_id="H01",
        source_identity="root",
        destination_host_id="H02",
        destination_identity="service",
        source_segment="dmz",
        destination_segment="internal",
        service="ssh",
        technique="ssh pivot",
        status="success",
        credential_id=credential_id,
        attempt_id=attempt_h02,
        evidence_ids=[],
        now=BASE_TIME + timedelta(seconds=21),
    )
    change_id = plan_change(workspace, authorization_id, offset=30)
    log_change(
        workspace=workspace,
        event="applied",
        change_id=change_id,
        attempt_id=attempt_h01,
        now=BASE_TIME + timedelta(seconds=31),
    )

    _, outputs = build_operational_trace(
        workspace=workspace,
        replace=False,
        now=BASE_TIME + timedelta(seconds=40),
    )

    assert {path.name for path in outputs} == {
        "ATTACK_GRAPH.md",
        "RECOVERY_PLAN.md",
        "IMPACT_SUMMARY.md",
    }
    graph = (workspace / "report" / "ATTACK_GRAPH.md").read_text()
    recovery = (workspace / "report" / "RECOVERY_PLAN.md").read_text()
    summary = (workspace / "report" / "IMPACT_SUMMARY.md").read_text()
    assert "subgraph" in graph
    assert "dmz" in graph and "internal" in graph
    assert "H01:user" in graph and "H02:service" in graph
    assert 'root"] --> injected' not in graph
    assert "&quot;" in graph
    assert credential_id in graph
    assert "private-synthetic-password" not in graph + recovery + summary
    assert change_id in recovery
    assert "remove the synthetic target" in recovery
    assert "decision_pending" in recovery
    for output in outputs:
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_renderer_requires_replace_for_existing_reports(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    build_operational_trace(workspace=workspace, replace=False, now=BASE_TIME)

    with pytest.raises(TraceError, match="use --replace"):
        build_operational_trace(
            workspace=workspace,
            replace=False,
            now=BASE_TIME + timedelta(seconds=1),
        )
    build_operational_trace(
        workspace=workspace,
        replace=True,
        now=BASE_TIME + timedelta(seconds=2),
    )


def test_status_reports_active_changes_and_latest_path(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(
        workspace,
        categories=["persistence", "privilege-escalation"],
        techniques=["sudoers drop", "local exploit"],
    )
    attempt = add_attempt(workspace, "H01", 1)
    change_id = plan_change(workspace, authorization_id, offset=2)
    log_change(
        workspace=workspace,
        event="applied",
        change_id=change_id,
        attempt_id=attempt,
        now=BASE_TIME + timedelta(seconds=3),
    )
    log_attack_path(
        workspace=workspace,
        authorization_id=authorization_id,
        transition="privilege_escalation",
        impact_level="high",
        source_host_id="H01",
        source_identity="user",
        destination_host_id="H01",
        destination_identity="root",
        source_segment="dmz",
        destination_segment="dmz",
        service="local",
        technique="local exploit",
        status="success",
        credential_id=None,
        attempt_id=attempt,
        evidence_ids=[],
        now=BASE_TIME + timedelta(seconds=4),
    )

    output = "\n".join(generate_status(workspace, None, BASE_TIME))
    assert "Changes: 1 (active=1, pending_rollback=1, retained=0)" in output
    assert "Attack-path events: 1" in output
    assert "H01:user -> H01:root" in output


def test_status_fails_closed_on_malformed_authorization_ledger(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    (workspace / AUTHORIZATION_LEDGER).write_text("not-json\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        generate_status(workspace, None, BASE_TIME)


def test_retained_then_rolled_back_closes_active_change(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    authorization_id = authorize(workspace)
    change_id = plan_change(workspace, authorization_id)
    apply_attempt = add_attempt(workspace, "H01", 20)
    rollback_attempt = add_attempt(workspace, "H01", 30)
    log_change(
        workspace=workspace,
        event="applied",
        change_id=change_id,
        attempt_id=apply_attempt,
        now=BASE_TIME + timedelta(seconds=21),
    )
    log_change(
        workspace=workspace,
        event="retained",
        change_id=change_id,
        note="Operator retained access temporarily",
        now=BASE_TIME + timedelta(seconds=22),
    )
    log_change(
        workspace=workspace,
        event="rolled_back",
        change_id=change_id,
        attempt_id=rollback_attempt,
        now=BASE_TIME + timedelta(seconds=31),
    )

    history = change_histories(load_changes(workspace))[change_id]
    assert [record["event"] for record in history] == [
        "planned",
        "applied",
        "retained",
        "rolled_back",
    ]
    assert load_authorizations(workspace)[0]["authorization_id"] == authorization_id
    assert load_attack_paths(workspace) == []
