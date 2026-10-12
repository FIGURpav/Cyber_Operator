"""Synthetic tests for exact execution receipts and atomic report claims."""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import (
    capture_evidence,
    execution_provenance,
    host_identity,
    report_contract,
)
from scripts.new_host import main as new_host_main

NOW = datetime(2026, 8, 30, 12, 0, 0, 123456, tzinfo=UTC)
ATTEMPT_ID = "ATT-20260830T115959123456Z"
EVIDENCE_ID = "EVD-20260830T115959223456Z"
CREDENTIAL_ID = "CRED-20260830T115959323456Z"
EVIDENCE_BYTES = b"Synthetic retained structured output\n"
EVIDENCE_SHA256 = hashlib.sha256(EVIDENCE_BYTES).hexdigest()


def write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def append_json(path: Path, value: object) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, separators=(",", ":")) + "\n")


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    assert (
        new_host_main(
            [
                "--workspace",
                str(root),
                "--host-id",
                "H01",
                "--ip",
                "192.0.2.10",
                "--hostname",
                "target.synthetic.test",
            ]
        )
        == 0
    )
    return root


def seed_evidence(root: Path) -> None:
    (root / "evidence/H01" / f"{EVIDENCE_ID}.txt").write_bytes(EVIDENCE_BYTES)
    append_json(
        root / "attempts.jsonl",
        {"attempt_id": ATTEMPT_ID, "host_id": "H01", "status": "success"},
    )
    write_json(
        root / "evidence/H01" / f"{EVIDENCE_ID}.json",
        {
            "schema_version": "1.0",
            "evidence_id": EVIDENCE_ID,
            "host_id": "H01",
            "description": "Synthetic structured helper output",
            "artifact_path": f"evidence/H01/{EVIDENCE_ID}.txt",
            "size_bytes": len(EVIDENCE_BYTES),
            "sha256": EVIDENCE_SHA256,
        },
    )


def plan_value(*, credential_ids: list[str] | None = None) -> dict[str, object]:
    return {
        "report_purpose": "confirmed_reproduction",
        "objective": "Validate one synthetic helper operation",
        "starting_context": {
            "principal": "synthetic-operator",
            "session": "synthetic shell",
            "route": "direct synthetic route",
            "working_directory": "/tmp/synthetic",
        },
        "operation_kind": "code",
        "operation_origin": "observed",
        "input_text": "python3 helper.py",
        "query_ids": [],
        "credential_ids": credential_ids or [],
        "expected_state": "One deterministic synthetic result",
        "checkpoint_class": "other",
        "screenshot": None,
    }


def create_step(root: Path, tmp_path: Path, *, credentials: bool = False) -> str:
    plan = report_contract.plan_step(
        root,
        "H01",
        write_json(
            tmp_path / "plan.json",
            plan_value(credential_ids=[CREDENTIAL_ID] if credentials else []),
        ),
        now=NOW,
    )
    return str(plan["step_id"])


def run_input(
    *,
    status: str = "success",
    exchanges: list[dict[str, object]] | None = None,
    assertions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "status": status,
        "started_at_utc": "2026-08-30T11:59:58.123456Z",
        "finished_at_utc": "2026-08-30T11:59:59.123456Z",
        "exit_code": 0 if status == "success" else 1,
        "source_generation": "synthetic-generation-1",
        "attempt_id": ATTEMPT_ID,
        "evidence_ids": [EVIDENCE_ID],
        "stdout_evidence_id": EVIDENCE_ID,
        "stderr_evidence_id": None,
        "http_exchanges": exchanges or [],
        "assertions": assertions or [],
    }


def helper(root: Path, source: str) -> Path:
    path = root / "workbench/helper.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    return path


def capture(
    root: Path,
    tmp_path: Path,
    step_id: str,
    value: dict[str, object],
    source: Path,
    *,
    now: datetime = NOW + timedelta(seconds=1),
) -> dict[str, object]:
    return execution_provenance.capture_run(
        root,
        step_id,
        write_json(tmp_path / f"run-{now.microsecond}.json", value),
        tool_path=source,
        dependency_paths=[],
        apply=True,
        now=now,
    )


def claim_value(
    run_id: str,
    *,
    claim_type: str = "text",
    verification: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "classification": "observed",
        "support_status": "supported",
        "claim_type": claim_type,
        "statement": "Synthetic helper produced the retained deterministic result",
        "run_id": run_id,
        "evidence_ids": [EVIDENCE_ID],
        "credential_ids": [],
        "verification": verification or {"basis": "manual-review"},
    }


def append_claim(
    root: Path,
    tmp_path: Path,
    step_id: str,
    value: dict[str, object],
    *,
    now: datetime = NOW + timedelta(seconds=2),
) -> dict[str, object]:
    return execution_provenance.append_claim(
        root,
        "H01",
        step_id,
        write_json(tmp_path / f"claim-{now.microsecond}.json", value),
        apply=True,
        now=now,
    )


def close_step(root: Path, tmp_path: Path, step_id: str) -> None:
    report_contract.transition_step(
        root,
        step_id,
        "completed",
        write_json(
            tmp_path / "outcome.json",
            {
                "attempt_id": ATTEMPT_ID,
                "evidence_ids": [EVIDENCE_ID],
                "path_event_ids": [],
                "query_ids": [],
                "credential_ids": [],
                "resulting_access": None,
                "resulting_route": None,
                "resulting_objective_loot_id": None,
                "note": "Synthetic helper completed",
            },
        ),
        now=NOW + timedelta(seconds=3),
    )


def test_get_only_helper_cannot_support_post_script_claim(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(
        root,
        "import urllib.request\n"
        "urllib.request.Request('http://target.synthetic.test/api/json')\n",
    )
    run = capture(
        root,
        tmp_path,
        step_id,
        run_input(
            exchanges=[
                {
                    "sequence": 1,
                    "method": "POST",
                    "scheme": "http",
                    "host": "target.synthetic.test",
                    "port": 8080,
                    "path": "/script",
                    "query_sha256": None,
                    "status_code": 200,
                    "evidence_id": EVIDENCE_ID,
                }
            ]
        ),
        source,
    )
    value = claim_value(
        str(run["run_id"]),
        claim_type="http_exchange",
        verification={"method": "POST", "path": "/script", "status_code": 200},
    )
    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="contradicts the snapshotted helper",
    ):
        append_claim(root, tmp_path, step_id, value)


def test_current_helper_drift_warns_but_exact_snapshot_remains_valid(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('first synthetic version')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    execution_provenance.render_index(root, apply=True)
    close_step(root, tmp_path, step_id)

    source.write_text("print('later synthetic version')\n", encoding="utf-8")
    state = execution_provenance.evaluate_provenance(root, strict=True)
    assert state.ready is True
    assert state.warnings == (f"run:{run['run_id']}:current-source-drift",)

    snapshot = root / str(run["tool"]["artifact_path"])  # type: ignore[index]
    snapshot.write_text("tampered snapshot\n", encoding="utf-8")
    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="hash validation failed",
    ):
        execution_provenance.evaluate_provenance(root, strict=True)


def test_provenance_write_does_not_run_full_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")

    def unexpected_full_check(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("full provenance readiness ran during capture")

    monkeypatch.setattr(
        execution_provenance, "evaluate_provenance", unexpected_full_check
    )
    run = capture(root, tmp_path, step_id, run_input(), source)
    claim = append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))

    assert run["report_step_id"] == step_id
    assert claim["report_step_id"] == step_id


def test_provenance_check_requires_declared_validation_barrier(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)

    with pytest.raises(SystemExit) as exc:
        execution_provenance.main(["check", "--workspace", str(root)])

    assert exc.value.code == 2


def test_second_helper_run_cannot_be_merged_into_one_step(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    capture(root, tmp_path, step_id, run_input(), source)
    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="already has an execution RUN-ID",
    ):
        capture(
            root,
            tmp_path,
            step_id,
            run_input(),
            source,
            now=NOW + timedelta(seconds=4),
        )


def test_reviewed_retroactive_run_match_is_exact_and_new_runs_stay_strict(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    old_run = capture(
        root,
        tmp_path,
        step_id,
        run_input(
            assertions=[
                {
                    "name": "synthetic.summary",
                    "status": "pass",
                    "value_sha256": None,
                    "evidence_id": EVIDENCE_ID,
                }
            ]
        ),
        source,
        now=NOW + timedelta(seconds=1),
    )
    old_claim_value = claim_value(str(old_run["run_id"]))
    old_claim_value["statement"] = "Synthetic summary was retained"
    old_claim = append_claim(
        root,
        tmp_path,
        step_id,
        old_claim_value,
        now=NOW + timedelta(seconds=1, microseconds=500_000),
    )
    credential_root = root / "private/credentials"
    credential_root.mkdir(parents=True, exist_ok=True)
    append_json(
        credential_root / "credentials.jsonl",
        {
            "credential_id": CREDENTIAL_ID,
            "created_at_utc": report_contract.timestamp(NOW + timedelta(seconds=2)),
            "host_id": "H01",
            "secret": "summary",
        },
    )

    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        execution_provenance.load_runs(root)

    preview = execution_provenance.adjudicate_retroactive_run_secret_matches(
        root,
        CREDENTIAL_ID,
        apply=False,
        acknowledged=False,
        now=NOW + timedelta(seconds=3),
    )
    assert preview["candidate_count"] == 1
    assert preview["matches"][0]["run_id"] == old_run["run_id"]
    assert preview["matches"][0]["field_path"] == "/assertions/0/name"
    assert not (root / execution_provenance.SECRET_ADJUDICATION_LEDGER).exists()

    execution_provenance.adjudicate_retroactive_run_secret_matches(
        root,
        CREDENTIAL_ID,
        apply=True,
        acknowledged=True,
        now=NOW + timedelta(seconds=3),
    )
    execution_provenance.load_runs(root)
    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        execution_provenance.load_claims(root)
    claim_preview = (
        execution_provenance.adjudicate_retroactive_claim_secret_matches(
            root,
            CREDENTIAL_ID,
            apply=False,
            acknowledged=False,
            now=NOW + timedelta(seconds=3, microseconds=500_000),
        )
    )
    assert claim_preview["candidate_count"] == 1
    assert claim_preview["matches"][0]["claim_id"] == old_claim["claim_id"]
    assert claim_preview["matches"][0]["field_path"] == "/statement"
    execution_provenance.adjudicate_retroactive_claim_secret_matches(
        root,
        CREDENTIAL_ID,
        apply=True,
        acknowledged=True,
        now=NOW + timedelta(seconds=3, microseconds=500_000),
    )
    execution_provenance.load_claims(root)

    new_step = report_contract.plan_step(
        root,
        "H01",
        write_json(tmp_path / "new-plan.json", plan_value()),
        now=NOW + timedelta(seconds=4),
    )
    new_step_id = str(new_step["step_id"])
    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        capture(
            root,
            tmp_path,
            new_step_id,
            run_input(
                assertions=[
                    {
                        "name": "synthetic.summary",
                        "status": "pass",
                        "value_sha256": None,
                        "evidence_id": EVIDENCE_ID,
                    }
                ]
            ),
            source,
            now=NOW + timedelta(seconds=5),
        )


def test_error_assertion_cannot_support_hostname_claim(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(
        root,
        tmp_path,
        step_id,
        run_input(
            assertions=[
                {
                    "name": "jenkins.hostname",
                    "status": "error",
                    "value_sha256": None,
                    "evidence_id": EVIDENCE_ID,
                }
            ]
        ),
        source,
    )
    value = claim_value(
        str(run["run_id"]),
        claim_type="helper_assertion",
        verification={"name": "jenkins.hostname", "value_sha256": None},
    )
    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="lacks one passing run assertion",
    ):
        append_claim(root, tmp_path, step_id, value)


def test_referenced_credential_requires_exact_source_provenance(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    credential_root = root / "private/credentials"
    credential_root.mkdir(parents=True)
    append_json(
        credential_root / "credentials.jsonl",
        {
            "credential_id": CREDENTIAL_ID,
            "created_at_utc": "2026-08-30T11:59:59.323456Z",
            "host_id": "H01",
            "secret_type": "token",
            "username": "synthetic-user",
            "service": "synthetic-service",
            "url": None,
            "realm": None,
            "note": None,
            "secret": "synthetic-private-value",
            "status": "unverified",
            "source": "operator",
            "credential_key": "a" * 64,
        },
    )
    step_id = create_step(root, tmp_path, credentials=True)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    execution_provenance.render_index(root, apply=True)
    close_step(root, tmp_path, step_id)

    state = execution_provenance.evaluate_provenance(root, strict=True)
    assert state.ready is False
    assert (
        f"credential:{CREDENTIAL_ID}:source-provenance-missing" in state.blockers
    )
    contract = report_contract.evaluate_contract(root)
    assert contract.credential_ready is False

    append_claim(
        root,
        tmp_path,
        step_id,
        {
            "classification": "configuration",
            "support_status": "supported",
            "claim_type": "credential_provenance",
            "statement": "Synthetic credential came from the retained configuration snapshot",
            "run_id": run["run_id"],
            "evidence_ids": [EVIDENCE_ID],
            "credential_ids": [CREDENTIAL_ID],
            "verification": {
                "source_kind": "snapshot",
                "source_locator": "snapshot/devhub/oauth2-proxy.json",
                "source_sha256": EVIDENCE_SHA256,
            },
        },
        now=NOW + timedelta(seconds=5),
    )
    execution_provenance.render_index(root, apply=True)
    assert execution_provenance.evaluate_provenance(root, strict=True).ready is True


@pytest.mark.parametrize("damage", ["missing", "same-size-tamper", "truncated", "symlink", "metadata-only"])
def test_provenance_gate_rechecks_retained_evidence(tmp_path: Path, damage: str) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    execution_provenance.render_index(root, apply=True)
    close_step(root, tmp_path, step_id)
    assert execution_provenance.evaluate_provenance(root, strict=True).ready
    artifact = root / "evidence/H01" / f"{EVIDENCE_ID}.txt"
    if damage == "same-size-tamper":
        artifact.write_bytes(b"X" * len(EVIDENCE_BYTES))
    elif damage == "truncated":
        artifact.write_bytes(b"X")
    else:
        artifact.unlink()
        if damage == "symlink":
            external = tmp_path / "external.txt"
            external.write_bytes(EVIDENCE_BYTES)
            artifact.symlink_to(external)
        elif damage == "metadata-only":
            write_json(artifact.with_suffix(".json"), {
                "evidence_id": EVIDENCE_ID, "host_id": "H01", "sha256": EVIDENCE_SHA256,
            })
    with pytest.raises(report_contract.ReportContractError, match="evidence"):
        execution_provenance.evaluate_provenance(root, strict=True)


def test_merged_source_evidence_can_support_destination_run_and_claim(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    assert new_host_main([
        "--workspace", str(root), "--host-id", "H02", "--ip", "192.0.2.20",
        "--hostname", "target.synthetic.test",
    ]) == 0
    source = tmp_path / "second-interface.txt"
    source.write_bytes(b"Synthetic second interface 192.0.2.20\n")
    _, _, second = capture_evidence.capture_evidence(
        str(root), "H02", "manual", "Synthetic interface", "txt", str(source),
        now=NOW - timedelta(seconds=1),
    )
    old_metadata = root / "evidence/H01" / f"{EVIDENCE_ID}.json"
    metadata_before = old_metadata.read_bytes()
    attempts_before = (root / "attempts.jsonl").read_bytes()
    host_identity.apply_merge_plan(host_identity.build_merge_plan(
        root, "H01", "H02", EVIDENCE_ID, second["evidence_id"], "Confirmed synthetic interfaces",
    ), now=NOW)
    step = report_contract.plan_step(
        root, "H02", write_json(tmp_path / "plan.json", plan_value()), now=NOW,
    )
    step_id = str(step["step_id"])
    run = capture(root, tmp_path, step_id, run_input(), helper(root, "print('synthetic')\n"))
    execution_provenance.append_claim(
        root, "H02", step_id, write_json(tmp_path / "claim.json", claim_value(str(run["run_id"]))),
        apply=True, now=NOW + timedelta(seconds=2),
    )
    close_step(root, tmp_path, step_id)
    execution_provenance.render_index(root, apply=True)
    assert execution_provenance.evaluate_provenance(root, strict=True).ready
    assert old_metadata.read_bytes() == metadata_before
    assert (root / "attempts.jsonl").read_bytes() == attempts_before
    assert run["host_id"] == "H02"
    assert run["report_step_id"].startswith("H02-ST-")


def test_strict_gate_blocks_empty_walkthrough(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    state = execution_provenance.evaluate_provenance(root, strict=True)
    assert state.ready is False
    assert "provenance:report-steps-empty" in state.blockers


def test_supported_run_claim_and_index_satisfy_provenance_gate(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    assert execution_provenance.render_index(root, apply=True) == "replace"
    close_step(root, tmp_path, step_id)

    state = execution_provenance.evaluate_provenance(root, strict=True)
    assert state.ready is True
    assert state.blockers == ()
    assert state.run_count == 1
    assert state.claim_count == 1
    assert hashlib.sha256(
        (root / str(run["tool"]["artifact_path"])).read_bytes()  # type: ignore[index]
    ).hexdigest() == run["tool"]["sha256"]  # type: ignore[index]


def test_provenance_check_reuses_step_and_reference_indexes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    execution_provenance.render_index(root, apply=True)
    close_step(root, tmp_path, step_id)
    calls: dict[str, int] = {}

    def count(module: object, name: str) -> None:
        original = getattr(module, name)

        def wrapper(*args: object, **kwargs: object) -> object:
            calls[name] = calls.get(name, 0) + 1
            return original(*args, **kwargs)

        monkeypatch.setattr(module, name, wrapper)

    count(report_contract, "load_steps")
    for name in (
        "_known_hosts",
        "_query_index",
        "_credential_index",
        "_attempt_index",
        "_evidence_index",
        "_path_index",
        "_loot_index",
    ):
        count(report_contract, name)

    state = execution_provenance.evaluate_provenance(root, strict=True)

    assert state.ready is True
    assert calls == {
        "load_steps": 1,
        "_known_hosts": 1,
        "_query_index": 1,
        "_credential_index": 1,
        "_attempt_index": 1,
        "_evidence_index": 1,
        "_path_index": 1,
        "_loot_index": 1,
    }


def test_provenance_index_render_reuses_one_validated_step_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    calls = 0
    original = report_contract.load_steps

    def counted_load_steps(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(report_contract, "load_steps", counted_load_steps)

    assert execution_provenance.render_index(root, apply=True) == "replace"
    assert calls == 1


@pytest.mark.parametrize("loader", ["runs", "claims"])
def test_public_provenance_loader_validates_steps_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loader: str,
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    calls = 0
    original = report_contract.load_steps

    def counted_load_steps(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(report_contract, "load_steps", counted_load_steps)

    if loader == "runs":
        execution_provenance.load_runs(root)
    else:
        execution_provenance.load_claims(root)

    assert calls == 1


@pytest.mark.parametrize("ledger_name", ["runs", "claims"])
def test_provenance_loader_rejects_valid_json_without_terminal_newline(
    tmp_path: Path, ledger_name: str
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    ledger = root / (
        execution_provenance.RUN_LEDGER
        if ledger_name == "runs"
        else execution_provenance.CLAIM_LEDGER
    )
    original = ledger.read_bytes()
    assert original.endswith(b"\n")
    ledger.write_bytes(original[:-1])

    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="missing its final newline",
    ):
        if ledger_name == "runs":
            execution_provenance.load_runs(root)
        else:
            execution_provenance.load_claims(root)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"run_id":"RUN-20260830T120000123456Z","value":Infinity}\n',
        (
            b'{"run_id":"RUN-20260830T120000123456Z",'
            b'"nested":{"value":1,"value":2}}\n'
        ),
    ],
)
def test_provenance_ledger_reader_rejects_non_rfc_json(
    tmp_path: Path,
    payload: bytes,
) -> None:
    ledger = tmp_path / "execution_runs.jsonl"
    ledger.write_bytes(payload)

    with pytest.raises(execution_provenance.ProvenanceError, match="invalid JSON"):
        execution_provenance._jsonl(ledger, "execution run ledger")

    assert ledger.read_bytes() == payload


def test_supersede_first_blocks_then_rejects_concurrent_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    replacement = report_contract.plan_step(
        root,
        "H01",
        write_json(tmp_path / "replacement-plan.json", plan_value()),
        now=NOW + timedelta(seconds=1),
    )
    source = helper(root, "print('synthetic')\n")
    supersede_holds_report_lock = threading.Event()
    allow_supersede = threading.Event()
    capture_reached_report_lock = threading.Event()
    original_reject = report_contract._reject_unavailable_step_with_provenance
    original_acquire = report_contract._acquire_ledger_lock

    def gated_reject(*args: object, **kwargs: object) -> None:
        supersede_holds_report_lock.set()
        if not allow_supersede.wait(timeout=5):
            raise AssertionError("test did not release supersede")
        original_reject(*args, **kwargs)

    def observed_acquire(
        target: Path, name: str, operation: int
    ) -> int:
        if (
            threading.current_thread().name.startswith("capture")
            and name == ".report_steps.lock"
        ):
            capture_reached_report_lock.set()
        return original_acquire(target, name, operation)

    monkeypatch.setattr(
        report_contract,
        "_reject_unavailable_step_with_provenance",
        gated_reject,
    )
    monkeypatch.setattr(report_contract, "_acquire_ledger_lock", observed_acquire)

    with (
        ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="supersede"
        ) as supersede_pool,
        ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="capture"
        ) as capture_pool,
    ):
        supersede_future = supersede_pool.submit(
            report_contract.supersede_step,
            root,
            step_id,
            str(replacement["step_id"]),
            "Synthetic replacement",
            now=NOW + timedelta(seconds=3),
        )
        assert supersede_holds_report_lock.wait(timeout=5)
        capture_future = capture_pool.submit(
            capture,
            root,
            tmp_path,
            step_id,
            run_input(),
            source,
            now=NOW + timedelta(seconds=2),
        )
        try:
            assert capture_reached_report_lock.wait(timeout=5)
            assert capture_future.done() is False
        finally:
            allow_supersede.set()
        assert supersede_future.result(timeout=5)["event"] == "superseded"
        with pytest.raises(
            execution_provenance.ProvenanceError,
            match="cannot bind unavailable report history",
        ):
            capture_future.result(timeout=5)

    assert execution_provenance.load_runs(root) == {}
    assert execution_provenance.load_claims(root) == {}
    assert execution_provenance.evaluate_provenance(root, strict=True).ready is True


def test_run_first_blocks_then_rejects_concurrent_supersede(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    replacement = report_contract.plan_step(
        root,
        "H01",
        write_json(tmp_path / "replacement-plan.json", plan_value()),
        now=NOW + timedelta(seconds=1),
    )
    source = helper(root, "print('synthetic')\n")
    capture_holds_locks = threading.Event()
    allow_capture = threading.Event()
    supersede_reached_report_lock = threading.Event()
    original_append = execution_provenance._append_record
    original_acquire = report_contract._acquire_ledger_lock

    def gated_append(path: Path, record: dict[str, object]) -> None:
        if (
            threading.current_thread().name.startswith("capture")
            and path == root / execution_provenance.RUN_LEDGER
        ):
            capture_holds_locks.set()
            if not allow_capture.wait(timeout=5):
                raise AssertionError("test did not release capture")
        original_append(path, record)

    def observed_acquire(
        target: Path, name: str, operation: int
    ) -> int:
        if (
            threading.current_thread().name.startswith("supersede")
            and name == ".report_steps.lock"
        ):
            supersede_reached_report_lock.set()
        return original_acquire(target, name, operation)

    monkeypatch.setattr(execution_provenance, "_append_record", gated_append)
    monkeypatch.setattr(report_contract, "_acquire_ledger_lock", observed_acquire)

    with (
        ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="capture"
        ) as capture_pool,
        ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="supersede"
        ) as supersede_pool,
    ):
        capture_future = capture_pool.submit(
            capture,
            root,
            tmp_path,
            step_id,
            run_input(),
            source,
            now=NOW + timedelta(seconds=2),
        )
        assert capture_holds_locks.wait(timeout=5)
        supersede_future = supersede_pool.submit(
            report_contract.supersede_step,
            root,
            step_id,
            str(replacement["step_id"]),
            "Synthetic replacement",
            now=NOW + timedelta(seconds=3),
        )
        try:
            assert supersede_reached_report_lock.wait(timeout=5)
            assert supersede_future.done() is False
        finally:
            allow_capture.set()
        run = capture_future.result(timeout=5)
        with pytest.raises(
            report_contract.ReportContractError,
            match="execution provenance cannot become unavailable",
        ):
            supersede_future.result(timeout=5)

    append_claim(root, tmp_path, step_id, claim_value(str(run["run_id"])))
    execution_provenance.render_index(root, apply=True)
    close_step(root, tmp_path, step_id)
    state = execution_provenance.evaluate_provenance(root, strict=True)
    assert state.ready is True
    assert state.run_count == 1
    assert state.claim_count == 1


def test_index_apply_holds_shared_snapshot_locks_through_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    run = capture(root, tmp_path, step_id, run_input(), source)
    render_reached_replace = threading.Event()
    allow_render = threading.Event()
    claim_reached_exclusive_lock = threading.Event()
    original_write = execution_provenance._atomic_write
    original_acquire = report_contract._acquire_ledger_lock

    def gated_write(path: Path, raw: bytes, *, replace: bool) -> None:
        if (
            threading.current_thread().name.startswith("render")
            and path == root / execution_provenance.INDEX_PATH
        ):
            render_reached_replace.set()
            if not allow_render.wait(timeout=5):
                raise AssertionError("test did not release index render")
        original_write(path, raw, replace=replace)

    def observed_acquire(
        target: Path, name: str, operation: int
    ) -> int:
        if (
            threading.current_thread().name.startswith("claim")
            and name == ".claims.lock"
        ):
            claim_reached_exclusive_lock.set()
        return original_acquire(target, name, operation)

    monkeypatch.setattr(execution_provenance, "_atomic_write", gated_write)
    monkeypatch.setattr(report_contract, "_acquire_ledger_lock", observed_acquire)

    with (
        ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="render"
        ) as render_pool,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="claim") as claim_pool,
    ):
        render_future = render_pool.submit(
            execution_provenance.render_index, root, apply=True
        )
        assert render_reached_replace.wait(timeout=5)
        claim_future = claim_pool.submit(
            append_claim,
            root,
            tmp_path,
            step_id,
            claim_value(str(run["run_id"])),
        )
        try:
            assert claim_reached_exclusive_lock.wait(timeout=5)
            assert claim_future.done() is False
        finally:
            allow_render.set()
        assert render_future.result(timeout=5) == "replace"
        claim = claim_future.result(timeout=5)

    assert str(claim["claim_id"]) not in (
        root / execution_provenance.INDEX_PATH
    ).read_text(encoding="utf-8")
    assert "provenance:index-stale" in execution_provenance.evaluate_provenance(
        root, strict=True
    ).blockers
    assert execution_provenance.render_index(root, apply=True) == "replace"
    close_step(root, tmp_path, step_id)
    assert execution_provenance.evaluate_provenance(root, strict=True).ready is True


def test_capture_preserves_snapshot_when_append_fails_after_record_is_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    moment = NOW + timedelta(seconds=10)
    run_id = execution_provenance._identifier("RUN", moment)
    final = root / execution_provenance.RUN_DIRECTORY / "H01" / run_id
    original_append = execution_provenance._append_record

    def append_then_fail(path: Path, record: dict[str, object]) -> None:
        original_append(path, record)
        raise execution_provenance.ProvenanceError(
            "synthetic post-commit durability failure"
        )

    monkeypatch.setattr(execution_provenance, "_append_record", append_then_fail)

    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="commit outcome is ambiguous.*snapshot was preserved",
    ):
        capture(root, tmp_path, step_id, run_input(), source, now=moment)

    runs = execution_provenance.load_runs(root)
    assert list(runs) == [run_id]
    assert final.is_dir()
    assert (root / str(runs[run_id]["tool"]["artifact_path"])).is_file()


def test_capture_removes_snapshot_when_append_fails_before_record_is_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    seed_evidence(root)
    step_id = create_step(root, tmp_path)
    source = helper(root, "print('synthetic')\n")
    moment = NOW + timedelta(seconds=10)
    run_id = execution_provenance._identifier("RUN", moment)
    final = root / execution_provenance.RUN_DIRECTORY / "H01" / run_id

    def fail_before_append(_path: Path, _record: dict[str, object]) -> None:
        raise execution_provenance.ProvenanceError(
            "synthetic pre-commit append failure"
        )

    monkeypatch.setattr(execution_provenance, "_append_record", fail_before_append)

    with pytest.raises(
        execution_provenance.ProvenanceError,
        match="synthetic pre-commit append failure",
    ):
        capture(root, tmp_path, step_id, run_input(), source, now=moment)

    assert execution_provenance.load_runs(root) == {}
    assert final.exists() is False
