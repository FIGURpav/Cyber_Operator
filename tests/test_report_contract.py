"""Synthetic tests for the canonical Cyber-Operator engagement reporting contract."""

from __future__ import annotations

import binascii
import hashlib
import json
import stat
import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import (
    build_query_appendix,
    capture_evidence,
    execution_provenance,
    host_identity,
    report_contract,
)
from scripts.new_host import main as new_host_main
from scripts.screenshot_workflow import report_main, screenshot_main

NOW = datetime(2026, 8, 10, 12, 0, 0, 123456, tzinfo=UTC)
ATTEMPT_ID = "ATT-20260810T115959123456Z"
EVIDENCE_ID = "EVD-20260810T115959223456Z"
LOOT_ID = "LOOT-20260810T115959323456Z"
CREDENTIAL_ID = "CRED-20260810T115959423456Z"
SECRET = "Synthetic-Report-Secret!"
PATH_ID = "PTH-20260810T115959523456Z"
AUTHORIZATION_ID = "AUTH-20260810T115959623456Z"
ALTERNATIVE_EVIDENCE_ID = "EVD-20260810T115959723456Z"
SECOND_LOOT_ID = "LOOT-20260810T115959823456Z"
SECOND_EVIDENCE_ID = "EVD-20260810T115959923456Z"


def run_report(
    capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, str, str]:
    arguments = list(args)
    if arguments and arguments[0] == "check" and "--barrier" not in arguments:
        arguments.extend(("--barrier", "manual"))
    try:
        code = report_main(arguments)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_screenshot(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    now: datetime = NOW,
) -> tuple[int, str, str]:
    try:
        code = screenshot_main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    assert (
        new_host_main(
            [
                "--workspace",
                str(workspace),
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
    capsys.readouterr()
    return workspace


def add_second_host(
    capsys: pytest.CaptureFixture[str], workspace: Path
) -> None:
    assert (
        new_host_main(
            [
                "--workspace",
                str(workspace),
                "--host-id",
                "H02",
                "--ip",
                "192.0.2.20",
                "--hostname",
                "other.synthetic.test",
            ]
        )
        == 0
    )
    capsys.readouterr()


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def append_json(path: Path, value: object) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, separators=(",", ":")) + "\n")


def manifest_value(*, name: str = "Synthetic Reviewer") -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "report_id": "RPT-20260810T115959123456Z",
        "assessment_team": {"team_id": "TEAM-00000", "name": name},
        "engagement": {
            "engagement_date": "2026-08-10",
            "scope_version": "Synthetic revision 2026-08-10",
            "scope_url": "https://example.org/hc/en-us/articles/synthetic",
            "approved_at_utc": "2026-08-10T11:59:59.123456Z",
        },
        "chains": [
            {
                "chain_id": "chain-1",
                "entry_host_id": "H01",
                "host_ids": ["H01"],
            }
        ],
        "assessment_objectives": [
            {
                "host_id": "H01",
                "chain_id": "chain-1",
                "category": "application",
                "objective_name": "objective-proof",
                "objective_loot_id": LOOT_ID,
            }
        ],
    }


def seed_loot(workspace: Path) -> None:
    append_json(
        workspace / "loot.jsonl",
        {
            "loot_id": LOOT_ID,
            "host_id": "H01",
            "category": "objective-proof",
            "label": "objective-proof",
            "value_text": "synthetic-objective-proof",
        },
    )


def authorization_value(
    *, host_ids: list[str] | None = None
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "authorization_id": AUTHORIZATION_ID,
        "created_at_utc": "2026-08-10T11:59:59.623456Z",
        "host_ids": host_ids or ["H01"],
        "categories": ["other"],
        "maximum_impact": "low",
        "techniques": ["screenshot-waiver"],
        "exclusions": [],
        "source": "operator",
        "summary": "Synthetic screenshot waiver authorization",
    }


def apply_manifest(workspace: Path, tmp_path: Path) -> None:
    seed_loot(workspace)
    source = write_json(tmp_path / "manifest.json", manifest_value())
    assert (
        report_contract.apply_manifest(
            workspace, source, apply=True, replace=False, now=NOW
        )
        == "create"
    )


def plan_value(
    *,
    origin: str = "planned",
    checkpoint: str = "objective",
    screenshot: bool = True,
    input_text: str | None = "display operator-retained objective evidence",
) -> dict[str, object]:
    screenshot_value: dict[str, object] | None = None
    if screenshot:
        screenshot_value = {
            "stage": "objective",
            "interface": "terminal",
            "protocol": "local",
            "port": None,
            "endpoint": "target.synthetic.test",
            "safe_url": None,
            "service": "terminal",
            "reproducibility": "repeatable",
            "must_include": ["target identity", "objective proof"],
            "must_exclude": ["unrelated credentials"],
        }
    return {
        "report_purpose": "assessment_objective",
        "objective": "Capture the synthetic scored objective",
        "starting_context": {
            "principal": "SYNTHETIC\\operator",
            "session": "local test session",
            "route": "direct synthetic route",
            "working_directory": "C:\\proof",
        },
        "operation_kind": "command",
        "operation_origin": origin,
        "input_text": input_text,
        "query_ids": [],
        "credential_ids": [],
        "expected_state": "Objective value is available with host context",
        "checkpoint_class": checkpoint,
        "screenshot": screenshot_value,
    }


def outcome_value(*, evidence_id: str = EVIDENCE_ID) -> dict[str, object]:
    return {
        "attempt_id": ATTEMPT_ID,
        "evidence_ids": [evidence_id],
        "path_event_ids": [],
        "query_ids": [],
        "credential_ids": [],
        "resulting_access": None,
        "resulting_route": None,
        "resulting_objective_loot_id": LOOT_ID,
        "note": "Synthetic objective captured",
    }


def seed_provenance(workspace: Path) -> None:
    append_json(
        workspace / "attempts.jsonl",
        {"attempt_id": ATTEMPT_ID, "host_id": "H01", "status": "success"},
    )
    evidence_dir = workspace / "evidence/H01"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw = b"Synthetic command output\n"
    (evidence_dir / f"{EVIDENCE_ID}.txt").write_bytes(raw)
    write_json(
        evidence_dir / f"{EVIDENCE_ID}.json",
        {
            "schema_version": "1.0",
            "evidence_id": EVIDENCE_ID,
            "host_id": "H01",
            "description": "Synthetic command output",
            "artifact_path": f"evidence/H01/{EVIDENCE_ID}.txt",
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
    )


def create_completed_objective(workspace: Path, tmp_path: Path) -> str:
    seed_provenance(workspace)
    plan_path = write_json(tmp_path / "plan.json", plan_value())
    plan = report_contract.plan_step(workspace, "H01", plan_path, now=NOW)
    tool = tmp_path / "synthetic-objective-helper.py"
    tool.write_text("print('synthetic objective')\n", encoding="utf-8")
    run = execution_provenance.capture_run(
        workspace,
        str(plan["step_id"]),
        write_json(
            tmp_path / "run.json",
            {
                "status": "success",
                "started_at_utc": "2026-08-10T11:59:59.223456Z",
                "finished_at_utc": "2026-08-10T11:59:59.323456Z",
                "exit_code": 0,
                "source_generation": "synthetic-generation-1",
                "attempt_id": ATTEMPT_ID,
                "evidence_ids": [EVIDENCE_ID],
                "stdout_evidence_id": EVIDENCE_ID,
                "stderr_evidence_id": None,
                "http_exchanges": [],
                "assertions": [],
            },
        ),
        tool_path=tool,
        dependency_paths=[],
        apply=True,
        now=NOW + timedelta(microseconds=100),
    )
    execution_provenance.append_claim(
        workspace,
        "H01",
        str(plan["step_id"]),
        write_json(
            tmp_path / "claim.json",
            {
                "classification": "observed",
                "support_status": "supported",
                "claim_type": "text",
                "statement": "Synthetic objective was retained in canonical evidence",
                "run_id": run["run_id"],
                "evidence_ids": [EVIDENCE_ID],
                "credential_ids": [],
                "verification": {"basis": "manual-review"},
            },
        ),
        apply=True,
        now=NOW + timedelta(microseconds=200),
    )
    execution_provenance.render_index(workspace, apply=True)
    outcome_path = write_json(tmp_path / "outcome.json", outcome_value())
    report_contract.transition_step(
        workspace,
        plan["step_id"],
        "completed",
        outcome_path,
        now=NOW + timedelta(seconds=1),
    )
    return str(plan["step_id"])


def png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        )

    rows = b"\x00" + bytes((12, 34, 56, 255)) * 2
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def request_pending_path(workspace: Path) -> Path:
    records = [
        json.loads(line)
        for line in (workspace / "screenshot_requests.jsonl").read_text().splitlines()
    ]
    request = next(record for record in records if record["event"] == "requested")
    return workspace / request["pending_path"]


def prepare_ready_workspace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Path:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    create_completed_objective(workspace, tmp_path)
    code, _, stderr = run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--apply",
        now=NOW + timedelta(seconds=2),
    )
    assert code == 0, stderr
    request_pending_path(workspace).write_bytes(png())
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--caption",
        "Synthetic objective with target identity",
        now=NOW + timedelta(seconds=3),
    )
    assert code == 0, stderr
    return workspace


def test_manifest_preview_apply_and_replacement_history(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    seed_loot(workspace)
    source = write_json(tmp_path / "manifest.json", manifest_value())

    code, stdout, stderr = run_report(
        capsys,
        "manifest",
        "--workspace",
        str(workspace),
        "--input",
        str(source),
        "--preview",
    )
    assert code == 0, stderr
    assert "manifest_action: create" in stdout
    assert not (workspace / "engagement_manifest.json").exists()
    assert not (workspace / "report/manifest_history").exists()

    code, _, stderr = run_report(
        capsys,
        "manifest",
        "--workspace",
        str(workspace),
        "--input",
        str(source),
        "--apply",
    )
    assert code == 0, stderr
    destination = workspace / "engagement_manifest.json"
    original = destination.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600

    replacement = write_json(
        tmp_path / "replacement.json", manifest_value(name="Replacement Candidate")
    )
    assert run_report(
        capsys,
        "manifest",
        "--workspace",
        str(workspace),
        "--input",
        str(replacement),
        "--apply",
    )[0] == 1
    code, stdout, stderr = run_report(
        capsys,
        "manifest",
        "--workspace",
        str(workspace),
        "--input",
        str(replacement),
        "--preview",
        "--replace",
    )
    assert code == 0, stderr
    assert "manifest_action: replace" in stdout
    assert destination.read_bytes() == original
    code, _, stderr = run_report(
        capsys,
        "manifest",
        "--workspace",
        str(workspace),
        "--input",
        str(replacement),
        "--apply",
        "--replace",
    )
    assert code == 0, stderr
    archives = list((workspace / "report/manifest_history").glob("*.json"))
    assert len(archives) == 1
    assert archives[0].read_bytes() == original


def test_step_ids_are_stable_and_gaps_are_not_reused(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    first = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "first.json", plan_value()),
        now=NOW,
    )
    second = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "second.json", plan_value()),
        now=NOW + timedelta(seconds=1),
    )
    report_contract.supersede_step(
        workspace,
        str(first["step_id"]),
        str(second["step_id"]),
        "Synthetic correction",
        now=NOW + timedelta(seconds=2),
    )
    third = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "third.json", plan_value()),
        now=NOW + timedelta(seconds=3),
    )
    assert [first["step_id"], second["step_id"], third["step_id"]] == [
        "H01-ST-01",
        "H01-ST-02",
        "H01-ST-03",
    ]
    records, _ = report_contract.load_steps(workspace)
    assert [record["event"] for record in records] == [
        "planned",
        "planned",
        "superseded",
        "planned",
    ]


def test_new_report_plan_rejects_exploratory_probe_purpose(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    payload = plan_value()
    payload["report_purpose"] = "exploratory_probe"

    with pytest.raises(
        report_contract.ReportContractError,
        match="exploratory probes belong in attempts",
    ):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "probe-plan.json", payload),
            now=NOW,
        )

    assert (workspace / report_contract.STEP_LEDGER_NAME).read_bytes() == b""


@pytest.mark.parametrize("purpose", [None, [], {"kind": "probe"}])
def test_new_report_plan_rejects_non_text_purpose(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, purpose: object
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    payload = plan_value()
    payload["report_purpose"] = purpose

    with pytest.raises(
        report_contract.ReportContractError,
        match="report_purpose must identify",
    ):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "non-text-purpose.json", payload),
            now=NOW,
        )


def test_new_report_plan_requires_explicit_report_purpose(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    payload = plan_value()
    del payload["report_purpose"]

    with pytest.raises(
        report_contract.ReportContractError,
        match="requires an explicit report_purpose",
    ):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "missing-purpose.json", payload),
            now=NOW,
        )


def test_legacy_v1_report_plan_remains_readable(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    payload = plan_value()
    del payload["report_purpose"]
    append_json(
        workspace / report_contract.STEP_LEDGER_NAME,
        {
            "schema_version": "1.0",
            "step_event_id": report_contract.identifier("RSE", NOW),
            "created_at_utc": report_contract.timestamp(NOW),
            "event": "planned",
            "step_id": "H01-ST-01",
            "host_id": "H01",
            **payload,
        },
    )

    records, states = report_contract.load_steps(workspace)

    assert records[0]["schema_version"] == "1.0"
    assert states["H01-ST-01"]["transition"] is None


def test_report_step_append_does_not_run_full_readiness(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(capsys, tmp_path)

    def unexpected_full_check(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("full report readiness ran during a step append")

    monkeypatch.setattr(report_contract, "evaluate_contract", unexpected_full_check)
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "barrier-plan.json", plan_value()),
        now=NOW,
    )

    assert plan["step_id"] == "H01-ST-01"


def test_report_check_requires_declared_validation_barrier(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)

    with pytest.raises(SystemExit) as exc:
        report_main(["check", "--workspace", str(workspace)])

    assert exc.value.code == 2
    assert "--barrier" in capsys.readouterr().err


def test_step_append_validates_history_once_and_reuses_reference_indexes(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    seed_loot(workspace)
    seed_provenance(workspace)
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "cached-plan.json", plan_value()),
        now=NOW,
    )
    ledger = workspace / report_contract.STEP_LEDGER_NAME
    before = ledger.read_bytes()
    calls: dict[str, int] = {}

    def count(name: str) -> None:
        original = getattr(report_contract, name)

        def wrapper(*args: object, **kwargs: object) -> object:
            calls[name] = calls.get(name, 0) + 1
            return original(*args, **kwargs)

        monkeypatch.setattr(report_contract, name, wrapper)

    for name in (
        "_validate_step_sequence",
        "_known_hosts",
        "_query_index",
        "_credential_index",
        "_attempt_index",
        "_evidence_index",
        "_path_index",
        "_loot_index",
    ):
        count(name)

    report_contract.transition_step(
        workspace,
        str(plan["step_id"]),
        "completed",
        write_json(tmp_path / "cached-outcome.json", outcome_value()),
        now=NOW + timedelta(seconds=1),
    )

    assert calls == {
        "_validate_step_sequence": 1,
        "_known_hosts": 1,
        "_query_index": 1,
        "_credential_index": 1,
        "_attempt_index": 1,
        "_evidence_index": 1,
        "_path_index": 1,
        "_loot_index": 1,
    }
    after = ledger.read_bytes()
    assert after.startswith(before)
    assert len(after.splitlines()) == len(before.splitlines()) + 1


def test_step_append_still_fails_closed_on_invalid_history(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "valid-plan.json", plan_value()),
        now=NOW,
    )
    ledger = workspace / report_contract.STEP_LEDGER_NAME
    append_json(ledger, plan)
    corrupted = ledger.read_bytes()

    with pytest.raises(
        report_contract.ReportContractError,
        match="malformed identity",
    ):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "blocked-plan.json", plan_value()),
            now=NOW + timedelta(seconds=1),
        )

    assert ledger.read_bytes() == corrupted


def test_step_append_rejects_valid_json_without_terminal_newline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "valid-plan.json", plan_value()),
        now=NOW,
    )
    ledger = workspace / report_contract.STEP_LEDGER_NAME
    original = ledger.read_bytes()
    assert original.endswith(b"\n")
    unterminated = original[:-1]
    ledger.write_bytes(unterminated)

    with pytest.raises(
        report_contract.ReportContractError,
        match="missing its final newline",
    ):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "blocked-plan.json", plan_value()),
            now=NOW + timedelta(seconds=1),
        )

    assert ledger.read_bytes() == unterminated


@pytest.mark.parametrize(
    "payload",
    [
        b'{"event":"plan","value":NaN}\n',
        b'{"event":"plan","nested":{"value":1,"value":2}}\n',
    ],
)
def test_report_ledger_reader_rejects_non_rfc_json(
    tmp_path: Path,
    payload: bytes,
) -> None:
    ledger = tmp_path / "report_steps.jsonl"
    ledger.write_bytes(payload)

    with pytest.raises(report_contract.ReportContractError, match="invalid JSON"):
        report_contract._jsonl(ledger, "report step ledger")

    assert ledger.read_bytes() == payload


def test_step_rejects_exact_stored_secret(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    credential_dir = workspace / "private/credentials"
    credential_dir.mkdir(parents=True, exist_ok=True)
    append_json(
        credential_dir / "credentials.jsonl",
        {"credential_id": CREDENTIAL_ID, "secret": SECRET},
    )
    payload = plan_value(input_text=f"tool --value {SECRET}")
    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(tmp_path / "secret-plan.json", payload),
            now=NOW,
        )
    assert (workspace / "report_steps.jsonl").read_text() == ""


def test_reviewed_retroactive_substring_match_is_exact_and_new_writes_stay_strict(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    retroactive_secret = "summary"
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(
            tmp_path / "old-plan.json",
            plan_value(input_text="collect summary"),
        ),
        now=NOW,
    )
    credential_dir = workspace / "private/credentials"
    credential_dir.mkdir(parents=True, exist_ok=True)
    append_json(
        credential_dir / "credentials.jsonl",
        {
            "credential_id": CREDENTIAL_ID,
            "created_at_utc": report_contract.timestamp(NOW + timedelta(seconds=1)),
            "host_id": "H01",
            "secret": retroactive_secret,
        },
    )

    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        report_contract.load_steps(workspace)

    preview = report_contract.adjudicate_retroactive_step_secret_matches(
        workspace,
        CREDENTIAL_ID,
        apply=False,
        acknowledged=False,
        now=NOW + timedelta(seconds=2),
    )
    assert preview["candidate_count"] == 1
    assert preview["matches"][0]["step_event_id"] == plan["step_event_id"]
    assert preview["matches"][0]["field_path"] == "/input_text"
    assert not (workspace / report_contract.SECRET_ADJUDICATION_LEDGER).exists()

    with pytest.raises(report_contract.ReportContractError, match="ack-reviewed"):
        report_contract.adjudicate_retroactive_step_secret_matches(
            workspace,
            CREDENTIAL_ID,
            apply=True,
            acknowledged=False,
            now=NOW + timedelta(seconds=2),
        )

    applied = report_contract.adjudicate_retroactive_step_secret_matches(
        workspace,
        CREDENTIAL_ID,
        apply=True,
        acknowledged=True,
        now=NOW + timedelta(seconds=2),
    )
    assert applied["candidate_count"] == 1
    adjudication_ledger = workspace / report_contract.SECRET_ADJUDICATION_LEDGER
    assert stat.S_IMODE(adjudication_ledger.stat().st_mode) == 0o600
    assert retroactive_secret not in adjudication_ledger.read_text(encoding="utf-8")
    report_contract.load_steps(workspace)

    with pytest.raises(report_contract.ReportContractError, match="credential value"):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(
                tmp_path / "new-plan.json",
                plan_value(input_text="collect summary again"),
            ),
            now=NOW + timedelta(seconds=3),
        )


def test_retroactive_secret_adjudication_is_hash_bound(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    report_contract.plan_step(
        workspace,
        "H01",
        write_json(
            tmp_path / "old-plan.json",
            plan_value(input_text="collect summary"),
        ),
        now=NOW,
    )
    credential_dir = workspace / "private/credentials"
    credential_dir.mkdir(parents=True, exist_ok=True)
    append_json(
        credential_dir / "credentials.jsonl",
        {
            "credential_id": CREDENTIAL_ID,
            "created_at_utc": report_contract.timestamp(NOW + timedelta(seconds=1)),
            "host_id": "H01",
            "secret": "summary",
        },
    )
    report_contract.adjudicate_retroactive_step_secret_matches(
        workspace,
        CREDENTIAL_ID,
        apply=True,
        acknowledged=True,
        now=NOW + timedelta(seconds=2),
    )
    ledger = workspace / report_contract.SECRET_ADJUDICATION_LEDGER
    record = json.loads(ledger.read_text(encoding="utf-8"))
    record["field_sha256"] = "0" * 64
    ledger.write_text(
        json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    with pytest.raises(report_contract.ReportContractError, match="no longer matches"):
        report_contract.load_steps(workspace)


@pytest.mark.parametrize(
    "key_header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_step_rejects_private_key_variants(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_header: str
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    with pytest.raises(report_contract.ReportContractError, match="private-key"):
        report_contract.plan_step(
            workspace,
            "H01",
            write_json(
                tmp_path / "private-key-plan.json",
                plan_value(input_text=f"note {key_header}"),
            ),
            now=NOW,
        )


def test_manifest_requires_a_scored_target(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    value = manifest_value()
    value["assessment_objectives"] = []
    with pytest.raises(report_contract.ReportContractError, match="non-empty"):
        report_contract.apply_manifest(
            workspace,
            write_json(tmp_path / "empty-targets.json", value),
            apply=False,
            replace=False,
            now=NOW,
        )


def test_manifest_binds_targets_to_chains_and_objective_loot(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    seed_loot(workspace)

    wrong_chain = manifest_value()
    wrong_chain["chains"][0]["host_ids"] = ["H02"]  # type: ignore[index]
    wrong_chain["chains"][0]["entry_host_id"] = "H02"  # type: ignore[index]
    with pytest.raises(report_contract.ReportContractError, match="does not belong"):
        report_contract.apply_manifest(
            workspace,
            write_json(tmp_path / "wrong-chain.json", wrong_chain),
            apply=False,
            replace=False,
            now=NOW,
        )

    wrong_loot = manifest_value()
    append_json(
        workspace / "loot.jsonl",
        {
            "loot_id": SECOND_LOOT_ID,
            "host_id": "H02",
            "category": "objective-proof",
            "label": "objective-proof",
            "value_text": "other-host-proof",
        },
    )
    wrong_loot["assessment_objectives"][0]["objective_loot_id"] = SECOND_LOOT_ID  # type: ignore[index]
    with pytest.raises(report_contract.ReportContractError, match="host and name"):
        report_contract.apply_manifest(
            workspace,
            write_json(tmp_path / "wrong-loot.json", wrong_loot),
            apply=False,
            replace=False,
            now=NOW,
        )


def test_zero_requests_is_not_screenshot_ready(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    create_completed_objective(workspace, tmp_path)
    assert (workspace / "screenshot_requests.jsonl").read_text() == ""
    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 1, stderr
    assert "report_content_ready: yes" in stdout
    assert "screenshot_ready: no" in stdout
    assert "blocking_ids: step:H01-ST-01:objective" in stdout


def test_reconcile_preview_is_read_only_and_apply_is_deduplicated(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    create_completed_objective(workspace, tmp_path)
    ledger = workspace / "screenshot_requests.jsonl"
    before = ledger.read_bytes()

    code, stdout, stderr = run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--preview",
    )
    assert code == 1, stderr
    assert "new_requests: 1" in stdout
    assert ledger.read_bytes() == before

    code, stdout, stderr = run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--apply",
    )
    assert code == 0, stderr
    assert "SCREENSHOT NOW — S001 [REQUIRED]" in stdout
    applied = ledger.read_bytes()
    code, stdout, stderr = run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--apply",
    )
    assert code == 0, stderr
    assert "new_requests: 0" in stdout
    assert ledger.read_bytes() == applied


def test_accepted_and_embedded_screenshot_satisfies_documentation_contract(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = prepare_ready_workspace(capsys, tmp_path)
    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 0, stderr
    assert "report_ready: yes" in stdout
    assert "report_content_ready: yes" in stdout
    assert "screenshot_ready: yes" in stdout
    assert "credential_ready: yes" in stdout
    assert "query_appendix_ready: yes" in stdout
    assert "render_ready: not_evaluated" in stdout
    assert "submission_ready: not_evaluated" in stdout
    report_text = (workspace / "report/H01.md").read_text()
    assert "![S001 — accepted screenshot](../evidence/H01/" in report_text


def test_accepted_but_not_embedded_screenshot_remains_blocking(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = prepare_ready_workspace(capsys, tmp_path)
    report = workspace / "report/H01.md"
    report.write_text(
        "\n".join(
            line
            for line in report.read_text().splitlines()
            if not line.lstrip().startswith("![S001 — accepted screenshot]")
        )
        + "\n",
        encoding="utf-8",
    )
    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 1, stderr
    assert "screenshot_ready: no" in stdout
    assert "step:H01-ST-01:objective:not-embedded" in stdout


@pytest.mark.parametrize("wrapper", ["comment", "fence"])
def test_commented_or_fenced_image_does_not_count_as_embedded(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, wrapper: str
) -> None:
    workspace = prepare_ready_workspace(capsys, tmp_path)
    report = workspace / "report/H01.md"
    text = report.read_text(encoding="utf-8")
    image_line = next(line for line in text.splitlines() if line.strip().startswith("!["))
    normalized_image = image_line.strip()
    replacement = (
        f"<!-- {normalized_image} -->"
        if wrapper == "comment"
        else f"```markdown\n{normalized_image}\n```"
    )
    report.write_text(text.replace(image_line, replacement), encoding="utf-8")

    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 1, stderr
    assert "screenshot_ready: no" in stdout
    assert "step:H01-ST-01:objective:not-embedded" in stdout


def test_tampered_derived_coverage_request_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = prepare_ready_workspace(capsys, tmp_path)
    ledger = workspace / "screenshot_requests.jsonl"
    records = [json.loads(line) for line in ledger.read_text().splitlines()]
    request = next(record for record in records if record["event"] == "requested")
    request["coverage_key"] = "step:H01-ST-99:objective"
    ledger.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )

    code, _, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 1
    assert "coverage key does not resolve" in stderr


@pytest.mark.parametrize(
    "transition",
    ["initial_access", "privilege_escalation", "pivot"],
)
def test_legacy_attack_path_is_reported_without_creating_a_request(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, transition: str
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    append_json(
        workspace / "attack_paths.jsonl",
        {
            "path_event_id": PATH_ID,
            "status": "success",
            "transition": transition,
            "destination_host_id": "H01",
            "service": "ssh",
            "attempt_id": ATTEMPT_ID,
            "evidence_ids": [EVIDENCE_ID],
        },
    )
    ledger = workspace / "screenshot_requests.jsonl"
    before = ledger.read_bytes()
    code, stdout, stderr = run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--apply",
    )
    assert code == 1, stderr
    assert "legacy_missing: 1" in stdout
    assert f"coverage: path:{PATH_ID} H01 required legacy_missing" in stdout
    assert ledger.read_bytes() == before


def test_required_waiver_has_provenance_but_still_blocks_engagement_readiness(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    create_completed_objective(workspace, tmp_path)
    assert run_screenshot(
        capsys,
        "reconcile",
        "--workspace",
        str(workspace),
        "--apply",
    )[0] == 0
    append_json(
        workspace / "authorizations.jsonl",
        authorization_value(),
    )
    evidence_dir = workspace / "evidence/H01"
    (evidence_dir / f"{ALTERNATIVE_EVIDENCE_ID}.txt").write_bytes(b"alternative")
    write_json(
        evidence_dir / f"{ALTERNATIVE_EVIDENCE_ID}.json",
        {
            "schema_version": "1.0",
            "evidence_id": ALTERNATIVE_EVIDENCE_ID,
            "host_id": "H01",
            "artifact_path": f"evidence/H01/{ALTERNATIVE_EVIDENCE_ID}.txt",
            "size_bytes": len(b"alternative"),
            "sha256": hashlib.sha256(b"alternative").hexdigest(),
        },
    )
    code, _, stderr = run_screenshot(
        capsys,
        "waive",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reason",
        "Synthetic moment cannot be reproduced",
        "--authorization-id",
        AUTHORIZATION_ID,
        "--alternative-evidence-id",
        ALTERNATIVE_EVIDENCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    assert code == 0, stderr
    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "engagement",
    )
    assert code == 1, stderr
    assert "screenshot_ready: no" in stdout
    assert "step:H01-ST-01:objective:waived" in stdout


def test_invalid_manifest_and_step_references_are_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    malformed_manifest = manifest_value()
    malformed_manifest["assessment_objectives"][0]["objective_loot_id"] = LOOT_ID  # type: ignore[index]
    source = write_json(tmp_path / "bad-manifest.json", malformed_manifest)
    with pytest.raises(report_contract.ReportContractError, match="does not exist"):
        report_contract.apply_manifest(
            workspace, source, apply=False, replace=False, now=NOW
        )

    seed_provenance(workspace)
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "plan.json", plan_value()),
        now=NOW,
    )
    bad_outcome = outcome_value(evidence_id="EVD-20260810T115959999999Z")
    with pytest.raises(report_contract.ReportContractError, match="unknown reference"):
        report_contract.transition_step(
            workspace,
            str(plan["step_id"]),
            "completed",
            write_json(tmp_path / "bad-outcome.json", bad_outcome),
            now=NOW + timedelta(seconds=1),
        )


def test_contract_check_reuses_one_validated_step_history(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    create_completed_objective(workspace, tmp_path)
    calls = 0
    original = report_contract.load_steps

    def counted_load_steps(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(report_contract, "load_steps", counted_load_steps)

    report_contract.evaluate_contract(workspace)

    assert calls == 1


@pytest.mark.parametrize("duplicate_target", [False, True])
def test_report_resolves_historical_objective_without_duplicate_objectives(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, duplicate_target: bool,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    card = workspace / "hosts/H02.md"
    card.write_text(card.read_text().replace("other.synthetic.test", "target.synthetic.test"))
    seed_loot(workspace)
    create_completed_objective(workspace, tmp_path)
    input_path = tmp_path / "second-interface.txt"
    input_path.write_text("Synthetic confirmed second interface\n")
    _, _, evidence = capture_evidence.capture_evidence(
        str(workspace), "H02", "manual", "Synthetic interface", "txt", str(input_path), now=NOW,
    )
    retained_steps = (workspace / report_contract.STEP_LEDGER_NAME).read_bytes()
    host_identity.apply_merge_plan(host_identity.build_merge_plan(
        workspace, "H01", "H02", EVIDENCE_ID, evidence["evidence_id"], "Confirmed synthetic interfaces",
    ), now=NOW + timedelta(seconds=2))
    manifest = manifest_value()
    manifest["chains"][0]["entry_host_id"] = "H02"
    manifest["chains"][0]["host_ids"] = ["H02"]
    manifest["assessment_objectives"][0]["host_id"] = "H02"
    if duplicate_target:
        manifest["chains"][0]["host_ids"].append("H01")
        manifest["assessment_objectives"].append({**manifest["assessment_objectives"][0], "host_id": "H01"})
    report_contract.apply_manifest(
        workspace, write_json(tmp_path / "merged-manifest.json", manifest), apply=True, replace=False,
    )
    execution_provenance.render_index(workspace, apply=True)
    readiness = report_contract.evaluate_contract(workspace)
    if duplicate_target:
        assert not readiness.content_ready
        assert "target:H01:merged-objective-target-requires-review" in readiness.blockers
    else:
        assert readiness.content_ready, readiness.blockers
    assert (workspace / report_contract.STEP_LEDGER_NAME).read_bytes() == retained_steps


def test_step_outcome_rejects_cross_host_provenance(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    seed_loot(workspace)
    seed_provenance(workspace)
    evidence_dir = workspace / "evidence/H02"
    (evidence_dir / f"{SECOND_EVIDENCE_ID}.txt").write_bytes(b"another host")
    write_json(
        evidence_dir / f"{SECOND_EVIDENCE_ID}.json",
        {
            "schema_version": "1.0",
            "evidence_id": SECOND_EVIDENCE_ID,
            "host_id": "H02",
            "description": "Synthetic evidence from another host",
            "artifact_path": f"evidence/H02/{SECOND_EVIDENCE_ID}.txt",
            "size_bytes": len(b"another host"),
            "sha256": hashlib.sha256(b"another host").hexdigest(),
        },
    )
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "cross-host-plan.json", plan_value()),
        now=NOW,
    )
    cross_host = outcome_value(evidence_id=SECOND_EVIDENCE_ID)
    with pytest.raises(report_contract.ReportContractError, match="unrelated host"):
        report_contract.transition_step(
            workspace,
            str(plan["step_id"]),
            "completed",
            write_json(tmp_path / "cross-host-outcome.json", cross_host),
            now=NOW + timedelta(seconds=1),
        )


def test_objective_step_must_reference_the_manifest_objective_loot(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    apply_manifest(workspace, tmp_path)
    seed_provenance(workspace)
    append_json(
        workspace / "loot.jsonl",
        {
            "loot_id": SECOND_LOOT_ID,
            "host_id": "H01",
            "category": "objective-proof",
            "label": "secondary-objective-proof",
            "value_text": "different-synthetic-proof",
        },
    )
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "mismatched-proof-plan.json", plan_value()),
        now=NOW,
    )
    outcome = outcome_value()
    outcome["resulting_objective_loot_id"] = SECOND_LOOT_ID
    report_contract.transition_step(
        workspace,
        str(plan["step_id"]),
        "completed",
        write_json(tmp_path / "mismatched-proof-outcome.json", outcome),
        now=NOW + timedelta(seconds=1),
    )
    state = report_contract.evaluate_contract(workspace)
    assert state.content_ready is False
    assert "target:H01:objective-proof-mismatch" in state.blockers


def test_non_report_step_does_not_suppress_attack_path_coverage(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    seed_loot(workspace)
    seed_provenance(workspace)
    append_json(
        workspace / "attack_paths.jsonl",
        {
            "path_event_id": PATH_ID,
            "status": "success",
            "transition": "pivot",
            "destination_host_id": "H01",
            "service": "socks",
            "attempt_id": ATTEMPT_ID,
            "evidence_ids": [EVIDENCE_ID],
        },
    )
    plan = report_contract.plan_step(
        workspace,
        "H01",
        write_json(
            tmp_path / "other-plan.json",
            plan_value(checkpoint="other", screenshot=False),
        ),
        now=NOW,
    )
    outcome = outcome_value()
    outcome["path_event_ids"] = [PATH_ID]
    outcome["resulting_objective_loot_id"] = None
    report_contract.transition_step(
        workspace,
        str(plan["step_id"]),
        "completed",
        write_json(tmp_path / "other-outcome.json", outcome),
        now=NOW + timedelta(seconds=1),
    )
    requirements = report_contract.derive_screenshot_requirements(workspace)
    assert [item.coverage_key for item in requirements] == [f"path:{PATH_ID}"]


def test_supersede_requires_newer_open_step_on_same_host(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    first = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "supersede-first.json", plan_value()),
        now=NOW,
    )
    other_host = report_contract.plan_step(
        workspace,
        "H02",
        write_json(tmp_path / "supersede-other.json", plan_value()),
        now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(report_contract.ReportContractError, match="unavailable"):
        report_contract.supersede_step(
            workspace,
            str(first["step_id"]),
            str(other_host["step_id"]),
            "Cross-host replacement",
            now=NOW + timedelta(seconds=2),
        )

    replacement = report_contract.plan_step(
        workspace,
        "H01",
        write_json(tmp_path / "supersede-replacement.json", plan_value()),
        now=NOW + timedelta(seconds=3),
    )
    report_contract.supersede_step(
        workspace,
        str(first["step_id"]),
        str(replacement["step_id"]),
        "Valid replacement",
        now=NOW + timedelta(seconds=4),
    )
    with pytest.raises(report_contract.ReportContractError, match="unavailable"):
        report_contract.supersede_step(
            workspace,
            str(replacement["step_id"]),
            str(first["step_id"]),
            "Would create a cycle through a closed older step",
            now=NOW + timedelta(seconds=5),
        )


def test_query_hash_and_appendix_are_required_when_a_query_is_referenced(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    query_id = "QRY-20260810T115959823456Z"
    prompt = "Synthetic prompt without secrets"
    write_json(
        workspace / "queries" / f"{query_id}.json",
        {
            "schema_version": "1.0",
            "query_id": query_id,
            "timestamp_utc": "2026-08-10T11:59:59.823456Z",
            "scope": "host",
            "host_ids": ["H01"],
            "purpose": "Synthetic reporting contract validation",
            "model": "synthetic-model",
            "context_refs": [],
            "prompt_text": prompt,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        },
    )
    state = report_contract.evaluate_contract(workspace)
    assert state.query_appendix_ready is False
    appendix = workspace / "report/AI_QUERY_APPENDIX.md"
    appendix.write_text(f"# Query appendix\n\n- {query_id}\n", encoding="utf-8")
    state = report_contract.evaluate_contract(workspace)
    assert state.query_appendix_ready is False
    record = json.loads(
        (workspace / "queries" / f"{query_id}.json").read_text(encoding="utf-8")
    )
    appendix.write_text(
        build_query_appendix.build_appendix(workspace, [record], NOW),
        encoding="utf-8",
    )
    state = report_contract.evaluate_contract(workspace)
    assert state.query_appendix_ready is True
