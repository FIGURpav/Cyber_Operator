"""Tests for local multi-stream coordination and the canonical writer lease."""

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import ledger_io, new_host
from scripts.stream_coordination import (
    CoordinationError,
    acquire_lease,
    initialize,
    issue_receipt,
    main,
    register_stream,
    release_lease,
    renew_lease,
    status_snapshot,
    submit_assignment,
    submit_intent,
    update_stream_status,
)

BASE_TIME = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)


def make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(workspace, script_dir, "H01", "192.0.2.10", "synthetic")
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n",
        encoding="utf-8",
    )
    initialize(
        workspace,
        "CTRL-01",
        "managed",
        "codex",
        apply=True,
        now=BASE_TIME,
    )
    return workspace


def register_worker(
    workspace: Path,
    stream_id: str = "WEB-01",
    *,
    role: str = "worker",
) -> None:
    register_stream(
        workspace,
        stream_id,
        role,
        "Synthetic bounded work",
        f"runtime-{stream_id}",
        apply=True,
        now=BASE_TIME,
    )


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def assignment_input(tmp_path: Path) -> Path:
    path = tmp_path / "assignment.json"
    write_json(
        path,
        {
            "schema_version": "1.0",
            "objective": "Analyze the synthetic web surface",
            "success_condition": "Return bounded evidence-backed findings",
            "stop_condition": "Stop at the first authorization boundary",
            "host_id": "H01",
            "target_generation": "generation-1",
            "authorization_refs": [],
            "input_refs": ["hosts/H01.md"],
            "exclusions": ["No target execution"],
        },
    )
    return path


def typed_write(workspace: Path, stream_id: str = "WEB-01") -> tuple[Path, str]:
    path = (
        workspace
        / "private"
        / "coordination"
        / "typed-inputs"
        / stream_id
        / "observation"
        / "candidate.json"
    )
    write_json(
        path,
        {
            "schema_version": "1.0",
            "record_type": "observation",
            "arguments": {
                "host_id": "H01",
                "kind": "note",
                "note": "Synthetic observation",
            },
        },
    )
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def intent_input(
    workspace: Path,
    tmp_path: Path,
    *,
    stream_id: str = "WEB-01",
    coordination_key: str = "web.synthetic.001",
) -> Path:
    typed_path, digest = typed_write(workspace, stream_id)
    path = tmp_path / f"intent-{stream_id}.json"
    write_json(
        path,
        {
            "schema_version": "1.0",
            "coordination_key": coordination_key,
            "assignment_id": None,
            "host_id": "H01",
            "target_generation": "generation-1",
            "authorization_refs": [],
            "input_refs": ["hosts/H01.md"],
            "action_status": "complete",
            "result_summary": "Synthetic result ready for canonical review",
            "requested_writes": [
                {
                    "record_type": "observation",
                    "input_path": typed_path.relative_to(workspace).as_posix(),
                    "input_sha256": digest,
                }
            ],
            "artifact_refs": [],
            "stop_or_recovery": "No target changes were made",
        },
    )
    return path


def test_init_preview_is_read_only_and_apply_is_idempotent(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(workspace, script_dir, "H01", "192.0.2.10", "synthetic")
    (workspace / "TASK_CONTEXT.md").write_text("- Current task: synthetic\n")

    _, preview, status = initialize(
        workspace,
        "CTRL-01",
        "manual-windows",
        "codex",
        apply=False,
        now=BASE_TIME,
    )
    assert status == "preview"
    assert preview["capability_source"] == "operator-declared"
    assert not (workspace / "private" / "coordination").exists()

    _, created, status = initialize(
        workspace,
        "CTRL-01",
        "manual-windows",
        "codex",
        apply=True,
        now=BASE_TIME,
    )
    _, existing, status_again = initialize(
        workspace,
        "CTRL-01",
        "manual-windows",
        "codex",
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert status == "initialized"
    assert status_again == "existing"
    assert existing["session_id"] == created["session_id"]
    assert (workspace / "private" / "coordination").stat().st_mode & 0o077 == 0


def test_stream_registry_has_no_framework_agent_limit(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    for number in range(1, 81):
        register_worker(workspace, f"W-{number:03d}")

    snapshot = status_snapshot(workspace, now=BASE_TIME)
    assert snapshot["stream_count"] == 81
    assert snapshot["agent_limit"] is None
    assert len(snapshot["streams"]) == 81


def test_assignment_validate_only_and_status_are_non_mutating(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    path = assignment_input(tmp_path)

    _, preview, state = submit_assignment(
        workspace,
        "CTRL-01",
        "WEB-01",
        str(path),
        apply=False,
        now=BASE_TIME,
    )
    assert state == "validated"
    assert preview["worker_stream_id"] == "WEB-01"
    assert not list(
        (workspace / "private" / "coordination" / "assignments" / "WEB-01").iterdir()
    )

    _, record, state = submit_assignment(
        workspace,
        "CTRL-01",
        "WEB-01",
        str(path),
        apply=True,
        now=BASE_TIME,
    )
    assert state == "submitted"
    _, status_record, status_state = update_stream_status(
        workspace,
        "WEB-01",
        "running",
        "Reviewing the synthetic assignment",
        record["assignment_id"],
        apply=True,
        now=BASE_TIME,
    )
    assert status_state == "updated"
    assert status_record["current_assignment_id"] == record["assignment_id"]


def test_typed_intent_validate_only_idempotency_and_hash_binding(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    path = intent_input(workspace, tmp_path)

    _, preview, state = submit_intent(
        workspace, "WEB-01", str(path), apply=False, now=BASE_TIME
    )
    assert state == "validated"
    assert preview["coordination_key"] == "web.synthetic.001"
    assert not list(
        (workspace / "private" / "coordination" / "intents" / "WEB-01").iterdir()
    )

    _, first, state = submit_intent(
        workspace, "WEB-01", str(path), apply=True, now=BASE_TIME
    )
    _, second, second_state = submit_intent(
        workspace,
        "WEB-01",
        str(path),
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert state == "submitted"
    assert second_state == "duplicate"
    assert second["intent_id"] == first["intent_id"]
    key_directory = workspace / "private" / "coordination" / "intent-keys"
    key_files = list(key_directory.glob("*.json"))
    assert len(key_files) == 1

    key_files[0].unlink()
    _, recovered, recovered_state = submit_intent(
        workspace,
        "WEB-01",
        str(path),
        apply=True,
        now=BASE_TIME + timedelta(seconds=2),
    )
    assert recovered_state == "duplicate"
    assert recovered["intent_id"] == first["intent_id"]
    assert len(list(key_directory.glob("*.json"))) == 1

    typed_path, _digest = typed_write(workspace)
    typed_path.write_text(
        '{"schema_version":"1.0","record_type":"observation","arguments":{}}\n'
    )
    with pytest.raises(CoordinationError, match="hash does not match"):
        submit_intent(workspace, "WEB-01", str(path), apply=False, now=BASE_TIME)


def test_intent_rejects_other_stream_typed_directory(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    register_worker(workspace, "API-01")
    path = intent_input(workspace, tmp_path, stream_id="API-01")

    with pytest.raises(CoordinationError, match="submitting stream"):
        submit_intent(workspace, "WEB-01", str(path), apply=False, now=BASE_TIME)


def test_only_one_live_writer_and_expired_takeover_fences_old_writer(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace, "WR-01", role="writer")
    register_worker(workspace, "WR-02", role="writer")

    _, first, state = acquire_lease(workspace, "WR-01", 30, apply=True, now=BASE_TIME)
    assert state == "acquired"
    with pytest.raises(CoordinationError, match="another writer"):
        acquire_lease(
            workspace,
            "WR-02",
            30,
            apply=True,
            now=BASE_TIME + timedelta(seconds=1),
        )

    _, second, takeover_state = acquire_lease(
        workspace,
        "WR-02",
        30,
        apply=True,
        now=BASE_TIME + timedelta(seconds=31),
    )
    assert takeover_state == "expired_takeover"
    assert second["fencing_token"] == first["fencing_token"] + 1
    with pytest.raises(CoordinationError, match="stale"):
        renew_lease(
            workspace,
            "WR-01",
            first["lease_id"],
            first["fencing_token"],
            None,
            apply=True,
            now=BASE_TIME + timedelta(seconds=32),
        )


def test_concurrent_writer_acquisition_has_one_winner(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace, "WR-01", role="writer")
    register_worker(workspace, "WR-02", role="writer")
    outcomes: list[tuple[str, str]] = []
    barrier = threading.Barrier(2)

    def acquire(writer_id: str) -> None:
        barrier.wait()
        try:
            _, record, _ = acquire_lease(
                workspace, writer_id, 30, apply=True, now=BASE_TIME
            )
        except CoordinationError:
            outcomes.append((writer_id, "rejected"))
        else:
            outcomes.append((writer_id, str(record["lease_id"])))

    threads = [
        threading.Thread(target=acquire, args=("WR-01",)),
        threading.Thread(target=acquire, args=("WR-02",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(outcomes) == 2
    assert sum(value != "rejected" for _writer, value in outcomes) == 1
    lease_lines = (
        (workspace / "private" / "coordination" / "stream_leases.jsonl")
        .read_text()
        .splitlines()
    )
    assert len(lease_lines) == 1


def test_acknowledged_active_takeover_increments_fence(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace, "WR-01", role="writer")
    register_worker(workspace, "WR-02", role="writer")
    _, first, _ = acquire_lease(
        workspace, "WR-01", 60, apply=True, now=BASE_TIME
    )

    _, second, state = acquire_lease(
        workspace,
        "WR-02",
        60,
        apply=True,
        allow_active_takeover=True,
        now=BASE_TIME + timedelta(seconds=1),
    )

    assert state == "forced_takeover"
    assert second["fencing_token"] == first["fencing_token"] + 1
    with pytest.raises(CoordinationError, match="stale"):
        release_lease(
            workspace,
            "WR-01",
            first["lease_id"],
            first["fencing_token"],
            apply=True,
            now=BASE_TIME + timedelta(seconds=2),
        )


def test_receipt_is_bound_to_live_lease_and_is_immutable(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    register_worker(workspace, "WR-01", role="writer")
    intent_path = intent_input(workspace, tmp_path)
    _, intent, _ = submit_intent(
        workspace, "WEB-01", str(intent_path), apply=True, now=BASE_TIME
    )
    _, lease, _ = acquire_lease(workspace, "WR-01", 30, apply=True, now=BASE_TIME)

    _, receipt, state = issue_receipt(
        workspace,
        "WR-01",
        lease["lease_id"],
        lease["fencing_token"],
        "WEB-01",
        intent["intent_id"],
        "applied",
        ["OBS-20260903T100001000000Z"],
        "Validated and appended by the canonical writer",
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert state == "issued"
    assert receipt["writer_stream_id"] == "WR-01"
    assert receipt["fencing_token"] == lease["fencing_token"]

    _, repeated, state = issue_receipt(
        workspace,
        "WR-01",
        lease["lease_id"],
        lease["fencing_token"],
        "WEB-01",
        intent["intent_id"],
        "applied",
        ["OBS-20260903T100001000000Z"],
        "Validated and appended by the canonical writer",
        apply=True,
        now=BASE_TIME + timedelta(seconds=2),
    )
    assert state == "duplicate"
    assert repeated["receipt_id"] == receipt["receipt_id"]

    with pytest.raises(CoordinationError, match="different immutable receipt"):
        issue_receipt(
            workspace,
            "WR-01",
            lease["lease_id"],
            lease["fencing_token"],
            "WEB-01",
            intent["intent_id"],
            "rejected",
            [],
            "Different outcome",
            apply=True,
            now=BASE_TIME + timedelta(seconds=3),
        )

    _, released, state = release_lease(
        workspace,
        "WR-01",
        lease["lease_id"],
        lease["fencing_token"],
        apply=True,
        now=BASE_TIME + timedelta(seconds=4),
    )
    assert state == "released"
    assert released["state"] == "released"


def test_cli_schema_and_json_status(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert main(["schema", "--json"], now=BASE_TIME) == 0
    schema = json.loads(capsys.readouterr().out)
    assert set(schema) >= {"assignment_input", "typed_write_input", "intent_input"}

    workspace = make_workspace(tmp_path)
    assert main(["status", "--workspace", str(workspace), "--json"], now=BASE_TIME) == 0
    snapshot = json.loads(capsys.readouterr().out)
    assert snapshot["agent_limit"] is None
    assert snapshot["stream_count"] == 1


def test_summary_rejects_known_credentials(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    credentials = workspace / "private" / "credentials"
    credentials.mkdir(mode=0o700)
    (credentials / "credentials.jsonl").write_text(
        json.dumps(
            {
                "credential_id": "CRED-20260903T100000000000Z",
                "host_id": "H01",
                "secret": "SyntheticCredentialValue",
            }
        )
        + "\n"
    )
    path = intent_input(workspace, tmp_path)
    value = json.loads(path.read_text())
    value["result_summary"] = "Recovered SyntheticCredentialValue"
    write_json(path, value)

    with pytest.raises(CoordinationError, match="stored credential"):
        submit_intent(workspace, "WEB-01", str(path), apply=False, now=BASE_TIME)


def test_assignment_rejects_known_credentials(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace)
    credentials = workspace / "private" / "credentials"
    credentials.mkdir(mode=0o700)
    (credentials / "credentials.jsonl").write_text(
        json.dumps({"secret": "SyntheticAssignmentCredential"}) + "\n"
    )
    path = assignment_input(tmp_path)
    value = json.loads(path.read_text())
    value["objective"] = "Use SyntheticAssignmentCredential"
    write_json(path, value)

    with pytest.raises(CoordinationError, match="stored credential"):
        submit_assignment(
            workspace,
            "CTRL-01",
            "WEB-01",
            str(path),
            apply=False,
            now=BASE_TIME,
        )


def test_active_coordination_fences_every_canonical_jsonl_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = make_workspace(tmp_path)
    register_worker(workspace, "WR-01", role="writer")
    register_worker(workspace, "WR-02", role="writer")
    _, lease, _ = acquire_lease(
        workspace, "WR-01", 30, apply=True, now=datetime.now(UTC)
    )
    attempts = workspace / "attempts.jsonl"
    record = {"synthetic": "canonical append"}

    with (
        ledger_io.exclusive_ledger_lock(attempts),
        pytest.raises(ledger_io.LedgerIOError, match="active coordination"),
    ):
        ledger_io.append_json_record(attempts, record, create=False)
    assert attempts.read_bytes() == b""

    monkeypatch.setenv("CYBER_STREAM_ID", "WR-01")
    monkeypatch.setenv("CYBER_WRITER_LEASE_ID", str(lease["lease_id"]))
    monkeypatch.setenv("CYBER_WRITER_FENCING_TOKEN", str(lease["fencing_token"]))
    with ledger_io.exclusive_ledger_lock(attempts):
        ledger_io.append_json_record(attempts, record, create=False)
    assert json.loads(attempts.read_text()) == record

    acquire_lease(
        workspace,
        "WR-02",
        30,
        apply=True,
        allow_active_takeover=True,
        now=datetime.now(UTC),
    )
    before = attempts.read_bytes()
    with (
        ledger_io.exclusive_ledger_lock(attempts),
        pytest.raises(ledger_io.LedgerIOError, match="stale"),
    ):
        ledger_io.append_json_record(attempts, {"synthetic": "stale"}, create=False)
    assert attempts.read_bytes() == before
