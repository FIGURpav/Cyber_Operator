"""Synthetic coverage for operator-gated close and managed host-state views."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from policy_support import synthetic_configuration

from scripts import (
    capture_evidence,
    credential_intake,
    engagement_policy,
    host_identity,
    host_state,
    log_observation,
    new_host,
    operational_trace,
    structured_state,
    workspace_lifecycle,
)

BASE = datetime(2026, 9, 9, 20, 0, 0, tzinfo=UTC)


def workspace(tmp_path: Path, *, profile: str = "controlled-engagement") -> Path:
    root = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(root, script_dir, "H01", "192.0.2.10", "alpha.test")
    (root / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n"
        f"- Operational profile: {profile}\n"
        "- Intake mode: chat\n"
        "- Artifact handling: standard\n",
        encoding="utf-8",
    )
    local_processing = root / "private/local_processing"
    local_processing.mkdir(parents=True, mode=0o700)
    (root / "private").chmod(0o700)
    local_processing.chmod(0o700)
    return root


def activate(root: Path, *, offset: int = 0) -> str:
    _, record = engagement_policy.build_activation(
        workspace=root,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.1/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Synthetic operator-authorized policy",
        now=BASE + timedelta(seconds=offset),
    )
    engagement_policy.apply_activation(root, record)
    return record["standing_authorization_id"]


def attempt(root: Path, offset: int) -> str:
    moment = BASE + timedelta(seconds=offset)
    identifier = moment.strftime("ATT-%Y%m%dT%H%M%S%fZ")
    record = {
        "schema_version": "1.0",
        "attempt_id": identifier,
        "timestamp_utc": moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": "H01",
        "action": "synthetic action",
        "status": "success",
        "result_sha256": "0" * 64,
        "result_text": "synthetic result",
        "evidence_refs": [],
        "next_step": "continue",
    }
    with (root / "attempts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return identifier


def active_change(root: Path) -> str:
    _, authorization = operational_trace.log_authorization(
        workspace=root,
        host_ids=["H01"],
        categories=["persistence"],
        maximum_impact="high",
        techniques=["synthetic marker"],
        exclusions=[],
        source="operator-chat",
        summary="Synthetic authorization",
        now=BASE + timedelta(seconds=10),
    )
    _, planned = operational_trace.log_change(
        workspace=root,
        event="planned",
        authorization_id=authorization["authorization_id"],
        host_id="H01",
        category="persistence",
        impact_level="high",
        technique="synthetic marker",
        target="/tmp/synthetic-marker",
        description="Synthetic retained marker",
        reversibility="reversible",
        before_state="absent",
        rollback_steps=["remove marker"],
        validation_steps=["verify marker absent"],
        now=BASE + timedelta(seconds=11),
    )
    _, _ = operational_trace.log_change(
        workspace=root,
        event="applied",
        change_id=planned["change_id"],
        attempt_id=attempt(root, 12),
        now=BASE + timedelta(seconds=13),
    )
    return planned["change_id"]


def test_close_preview_is_read_only_and_hash_bound(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    activate(root)
    before = (root / "workspace_lifecycle.jsonl").read_bytes()
    plan = workspace_lifecycle.build_close_plan(root)
    assert len(plan.plan_sha256) == 64
    assert plan.standing_authorization_id is not None
    assert (root / "workspace_lifecycle.jsonl").read_bytes() == before
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="hash"):
        workspace_lifecycle.apply_close(
            plan,
            supplied_plan_sha256="0" * 64,
            operator_acknowledged=True,
            retain_active_state=False,
            reason="Explicit synthetic close",
            now=BASE + timedelta(seconds=20),
        )
    assert not workspace_lifecycle.is_closed(root)


def test_cyber_policy_close_is_a_compatible_frontend(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = workspace(tmp_path)
    assert (
        engagement_policy.main(
            [
                "close",
                "--workspace",
                str(root),
                "--reason",
                "Operator requested compatibility close",
            ],
            now=BASE,
        )
        == 0
    )
    preview = capsys.readouterr().out
    digest = next(
        line.split(": ", 1)[1]
        for line in preview.splitlines()
        if line.startswith("close_plan_sha256:")
    )
    assert (
        engagement_policy.main(
            [
                "close",
                "--workspace",
                str(root),
                "--reason",
                "Operator requested compatibility close",
                "--close-plan-sha256",
                digest,
                "--ack-operator-requested-close",
                "--apply",
            ],
            now=BASE + timedelta(seconds=1),
        )
        == 0
    )
    assert workspace_lifecycle.is_closed(root)


def test_close_requires_operator_ack_and_does_no_cleanup(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    activate(root)
    key = root / "private/local_processing/deploy_ed25519"
    key.write_text("synthetic private key bytes", encoding="utf-8")
    key.chmod(0o600)
    artifact = structured_state.register_local_artifact(
        root,
        path=str(key),
        artifact_class="ssh-key",
        purpose="Synthetic deploy access",
        host_ids=["H01"],
        apply=True,
        now=BASE + timedelta(seconds=2),
    )
    plan = workspace_lifecycle.build_close_plan(root)
    assert artifact["local_artifact_id"] in plan.local_artifact_ids
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="ack-operator"):
        workspace_lifecycle.apply_close(
            plan,
            supplied_plan_sha256=plan.plan_sha256,
            operator_acknowledged=False,
            retain_active_state=True,
            reason="Explicit synthetic close",
        )
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="active"):
        workspace_lifecycle.apply_close(
            plan,
            supplied_plan_sha256=plan.plan_sha256,
            operator_acknowledged=True,
            retain_active_state=False,
            reason="Explicit synthetic close",
        )
    workspace_lifecycle.apply_close(
        plan,
        supplied_plan_sha256=plan.plan_sha256,
        operator_acknowledged=True,
        retain_active_state=True,
        reason="Explicit synthetic close",
        now=BASE + timedelta(seconds=20),
    )
    assert key.read_text(encoding="utf-8") == "synthetic private key bytes"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert workspace_lifecycle.is_closed(root)


def test_local_artifact_lifecycle_verifies_bytes_and_never_deletes(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    artifact_path = root / "private/local_processing/helper.bin"
    artifact_path.write_bytes(b"synthetic helper bytes")
    artifact_path.chmod(0o600)
    record = structured_state.register_local_artifact(
        root,
        path=str(artifact_path),
        artifact_class="helper",
        purpose="Synthetic local processing",
        host_ids=["H01"],
        apply=True,
        now=BASE,
    )
    structured_state.transition_local_artifact(
        root,
        local_artifact_id=record["local_artifact_id"],
        state="in_use",
        apply=True,
        now=BASE + timedelta(seconds=1),
    )
    assert artifact_path.read_bytes() == b"synthetic helper bytes"
    artifact_path.write_bytes(b"changed helper bytes")
    with pytest.raises(structured_state.StructuredStateError, match="bytes changed"):
        structured_state.transition_local_artifact(
            root,
            local_artifact_id=record["local_artifact_id"],
            state="retained",
            apply=True,
            now=BASE + timedelta(seconds=2),
        )
    artifact_path.unlink()
    structured_state.transition_local_artifact(
        root,
        local_artifact_id=record["local_artifact_id"],
        state="disposed",
        apply=True,
        now=BASE + timedelta(seconds=3),
    )
    with pytest.raises(structured_state.StructuredStateError, match="unsupported"):
        structured_state.transition_local_artifact(
            root,
            local_artifact_id=record["local_artifact_id"],
            state="in_use",
            apply=True,
            now=BASE + timedelta(seconds=4),
        )


def test_close_marks_active_changes_retained_without_removing_target_state(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    activate(root)
    change_id = active_change(root)
    local_marker = root / "private/local_processing/local-marker"
    local_marker.write_text("still present", encoding="utf-8")
    local_marker.chmod(0o600)
    plan = workspace_lifecycle.build_close_plan(root)
    assert plan.pending_change_ids == (change_id,)
    workspace_lifecycle.apply_close(
        plan,
        supplied_plan_sha256=plan.plan_sha256,
        operator_acknowledged=True,
        retain_active_state=True,
        reason="Retain exact synthetic state",
        now=BASE + timedelta(seconds=30),
    )
    history = operational_trace.change_histories(
        operational_trace.load_changes(root)
    )[change_id]
    assert history[-1]["event"] == "retained"
    assert local_marker.read_text(encoding="utf-8") == "still present"


def test_closed_workspace_blocks_permit_and_reopen_does_not_restore_policy(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    old = activate(root)
    plan = workspace_lifecycle.build_close_plan(root)
    workspace_lifecycle.apply_close(
        plan,
        supplied_plan_sha256=plan.plan_sha256,
        operator_acknowledged=True,
        retain_active_state=True,
        reason="Explicit synthetic close",
        now=BASE + timedelta(seconds=20),
    )
    assert engagement_policy.active_standing_authorization(root, BASE + timedelta(seconds=21)) is None
    with pytest.raises(engagement_policy.EngagementPolicyError, match="closed"):
        engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
            workspace=root,
            host_ids=["H01"],
            category="network",
            impact_level="low",
            technique_family="enumeration",
            technique="synthetic enumeration",
            callback=None,
            summary="must be blocked",
            apply=False,
            now=BASE + timedelta(seconds=21),
        )
    workspace_lifecycle.reopen(
        root,
        operator_acknowledged=True,
        reason="Operator requested resumed testing",
        apply=True,
        now=BASE + timedelta(seconds=22),
    )
    assert not workspace_lifecycle.is_closed(root)
    assert engagement_policy.active_standing_authorization(root, BASE + timedelta(seconds=23)) is None
    new = activate(root, offset=24)
    assert new != old


def test_closed_workspace_blocks_new_exact_authorization(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    plan = workspace_lifecycle.build_close_plan(root, now=BASE)
    workspace_lifecycle.apply_close(
        plan,
        supplied_plan_sha256=plan.plan_sha256,
        operator_acknowledged=True,
        retain_active_state=False,
        reason="Explicit synthetic close",
        now=BASE + timedelta(seconds=1),
    )
    with pytest.raises(operational_trace.TraceError, match="closed"):
        operational_trace.log_authorization(
            workspace=root,
            host_ids=["H01"],
            categories=["network"],
            maximum_impact="low",
            techniques=["synthetic enumeration"],
            exclusions=[],
            source="operator-chat",
            summary="Must not authorize a closed workspace",
            now=BASE + timedelta(seconds=2),
        )


def test_close_plan_reports_expired_standing_authorization(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    _, record = engagement_policy.build_activation(
        workspace=root,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.1/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=(BASE + timedelta(seconds=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        source="operator-cli",
        summary="Short synthetic authorization",
        now=BASE,
    )
    engagement_policy.apply_activation(root, record)
    plan = workspace_lifecycle.build_close_plan(
        root, now=BASE + timedelta(seconds=3)
    )
    assert plan.standing_authorization_id == record["standing_authorization_id"]
    assert plan.standing_authorization_status == "expired"
    assert not plan.has_active_state


def test_close_rejects_state_changed_after_preview(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    plan = workspace_lifecycle.build_close_plan(root, now=BASE)
    structured_state.create_work_item(
        root,
        kind="recon",
        external_ref="tcp-services",
        host_ids=["H01"],
        state="identified",
        summary="New recon scope appeared after preview",
        apply=True,
        now=BASE + timedelta(seconds=1),
    )
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="changed"):
        workspace_lifecycle.apply_close(
            plan,
            supplied_plan_sha256=plan.plan_sha256,
            operator_acknowledged=True,
            retain_active_state=False,
            reason="Stale synthetic close",
            now=BASE + timedelta(seconds=2),
        )
    assert not workspace_lifecycle.is_closed(root)


def test_token_closure_blocks_both_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_id = "TOK-20260909T210000123456Z"
    readiness = type("Readiness", (), {"blockers": (token_id,)})()
    monkeypatch.setattr(
        workspace_lifecycle.token_lifecycle,
        "closure_readiness",
        lambda _root: readiness,
    )
    strict = workspace(tmp_path / "strict", profile="strict")
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="blocked"):
        workspace_lifecycle.build_close_plan(strict, now=BASE)

    fast = workspace(tmp_path / "fast", profile="controlled-engagement")
    with pytest.raises(workspace_lifecycle.WorkspaceLifecycleError, match="unresolved"):
        workspace_lifecycle.build_close_plan(fast, now=BASE)


def test_interrupted_close_leaves_open_and_retention_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    activate(root)
    change_id = active_change(root)
    plan = workspace_lifecycle.build_close_plan(root, now=BASE + timedelta(seconds=20))
    real_append = workspace_lifecycle.ledger_io.append_json_record

    def fail_terminal_append(path: Path, *args: object, **kwargs: object) -> None:
        if path.name == workspace_lifecycle.LEDGER:
            raise workspace_lifecycle.ledger_io.LedgerIOError("synthetic interruption")
        real_append(path, *args, **kwargs)

    monkeypatch.setattr(
        workspace_lifecycle.ledger_io, "append_json_record", fail_terminal_append
    )
    with pytest.raises(workspace_lifecycle.ledger_io.LedgerIOError):
        workspace_lifecycle.apply_close(
            plan,
            supplied_plan_sha256=plan.plan_sha256,
            operator_acknowledged=True,
            retain_active_state=True,
            reason="Interrupted synthetic close",
            now=BASE + timedelta(seconds=30),
        )
    assert not workspace_lifecycle.is_closed(root)
    retry = workspace_lifecycle.build_close_plan(
        root, now=BASE + timedelta(seconds=31)
    )
    assert retry.pending_change_ids == ()
    assert retry.retained_change_ids == (change_id,)


def test_refresh_preserves_manual_text_and_tracks_staleness(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    host = root / "hosts/H01.md"
    host.write_text(host.read_text(encoding="utf-8") + "\nManual sentinel stays.\n", encoding="utf-8")
    log_observation.log_observation(
        workspace=str(root),
        host_id="H01",
        kind="service",
        state="confirmed",
        source_tool="synthetic",
        note="Synthetic service",
        evidence_ids=[],
        transport="tcp",
        port=443,
        service="https",
        now=BASE,
    )
    assert host_state.view_status(root)["H01"] == "stale"
    result = host_state.refresh(
        root, host_id="H01", refresh_all=False, apply=True, now=BASE
    )
    assert result["hosts"] == ["H01"]
    text = host.read_text(encoding="utf-8")
    assert "Manual sentinel stays." in text
    assert "| tcp | 443 | https | confirmed |" in text
    assert host_state.view_status(root) == {"H01": "current", "global": "current"}
    log_observation.log_observation(
        workspace=str(root),
        host_id="H01",
        kind="service",
        state="observed",
        source_tool="synthetic",
        note="Synthetic SSH",
        evidence_ids=[],
        transport="tcp",
        port=22,
        service="ssh",
        now=BASE + timedelta(seconds=1),
    )
    assert host_state.view_status(root)["H01"] == "stale"


def test_projection_contains_metadata_but_not_credential_value(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    secret = "fictional-secret-value-987654"
    result = credential_intake.store_credential_bytes(
        root,
        (
            "host: H01\nusername: test-user\nservice: ssh\n"
            f"password: {secret}\n"
        ).encode(),
        now=BASE,
    )
    attempt_id = attempt(root, 1)
    structured_state.create_finding(
        root,
        host_ids=["H01"],
        state="confirmed",
        severity="high",
        title="Synthetic privilege boundary finding",
        impact="Synthetic privilege-boundary impact",
        references=[attempt_id],
        apply=True,
        now=BASE + timedelta(seconds=2),
    )
    host_state.refresh(root, host_id="H01", refresh_all=False, apply=True, now=BASE)
    combined = (root / "hosts/H01.md").read_text() + (root / "global.md").read_text()
    assert result.credential_ids[0] in combined
    assert "Synthetic privilege boundary finding" in combined
    assert secret not in combined


def test_finding_rejects_nonexistent_canonical_reference(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    before = (root / structured_state.FINDING_LEDGER).read_bytes()
    with pytest.raises(structured_state.StructuredStateError, match="does not exist"):
        structured_state.create_finding(
            root,
            host_ids=["H01"],
            state="confirmed",
            severity="medium",
            title="Unsupported synthetic finding",
            impact="Would be unsupported without retained provenance",
            references=["EVD-20260909T200000999999Z"],
            apply=True,
            now=BASE,
        )
    assert (root / structured_state.FINDING_LEDGER).read_bytes() == before


def test_work_item_local_completion_does_not_imply_review(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    item = structured_state.create_work_item(
        root,
        kind="assessment-task",
        external_ref="Task 16",
        host_ids=["H01"],
        state="locally_complete",
        summary="Local proof is ready for operator grading",
        apply=True,
        now=BASE,
    )
    assert structured_state.work_item_states(root)[item["work_item_id"]]["state"] == "locally_complete"
    host_state.refresh(root, host_id="H01", refresh_all=False, apply=True, now=BASE)
    global_text = (root / "global.md").read_text()
    assert "Tasks locally complete: 1; reviewed: 0" in global_text
    structured_state.transition_work_item(
        root,
        work_item_id=item["work_item_id"],
        state="reviewed", reviewer="reviewer-synthetic", review_basis="Evidence verified",
        note="Operator reported that grade passed",
        apply=True,
        now=BASE + timedelta(seconds=1),
    )
    assert structured_state.work_item_states(root)[item["work_item_id"]]["state"] == "reviewed"


def test_malformed_managed_marker_fails_without_overwrite(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    host = root / "hosts/H01.md"
    original = host.read_text().replace(host_state.HOST_END, "")
    host.write_text(original)
    with pytest.raises(host_state.HostStateError, match="markers"):
        host_state.refresh(root, host_id="H01", refresh_all=False, apply=True)
    assert host.read_text() == original


def test_concurrent_manual_edit_causes_cas_conflict_without_losing_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    host = root / "hosts/H01.md"
    original_cas = host_state._cas_replace
    injected = False

    def edit_then_publish(
        path: Path,
        expected: bytes,
        expected_info: object,
        replacement: bytes,
    ) -> None:
        nonlocal injected
        if path == host and not injected:
            injected = True
            path.write_text(
                path.read_text(encoding="utf-8") + "\nConcurrent operator note.\n",
                encoding="utf-8",
            )
        original_cas(path, expected, expected_info, replacement)

    monkeypatch.setattr(host_state, "_cas_replace", edit_then_publish)
    with pytest.raises(host_state.HostStateError, match="changed"):
        host_state.refresh(
            root, host_id="H01", refresh_all=False, apply=True, now=BASE
        )
    assert "Concurrent operator note." in host.read_text(encoding="utf-8")


def test_single_host_refresh_does_not_rewrite_unaffected_host(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    new_host.bootstrap_host(
        root,
        Path(__file__).parents[1] / "scripts",
        "H02",
        "192.0.2.11",
        "beta.test",
    )
    host_state.refresh(root, host_id=None, refresh_all=True, apply=True, now=BASE)
    unaffected = root / "hosts/H02.md"
    before = unaffected.read_bytes()
    log_observation.log_observation(
        workspace=str(root),
        host_id="H01",
        kind="service",
        state="observed",
        source_tool="synthetic",
        note="Affected-host-only refresh",
        evidence_ids=[],
        transport="tcp",
        port=8080,
        service="http-alt",
        now=BASE + timedelta(seconds=1),
    )
    host_state.refresh(
        root,
        host_id="H01",
        refresh_all=False,
        apply=True,
        now=BASE + timedelta(seconds=2),
    )
    assert unaffected.read_bytes() == before
    assert host_state.view_status(root) == {
        "H01": "current",
        "H02": "current",
        "global": "current",
    }


def test_closed_workspace_allows_local_findings_review_and_view_refresh(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    plan = workspace_lifecycle.build_close_plan(root, now=BASE)
    workspace_lifecycle.apply_close(
        plan,
        supplied_plan_sha256=plan.plan_sha256,
        operator_acknowledged=True,
        retain_active_state=False,
        reason="Close target actions but continue local documentation",
        now=BASE + timedelta(seconds=1),
    )
    finding = structured_state.create_finding(
        root,
        host_ids=["H01"],
        state="hypothesis",
        severity="low",
        title="Post-close local documentation remains allowed",
        impact="Potential local documentation impact only",
        apply=True,
        now=BASE + timedelta(seconds=2),
    )
    work = structured_state.create_work_item(
        root,
        kind="assessment-task",
        external_ref="Task synthetic",
        host_ids=["H01"],
        state="reviewed", reviewer="reviewer-synthetic", review_basis="Evidence verified",
        summary="Operator supplied the grade after target-action closure",
        apply=True,
        now=BASE + timedelta(seconds=3),
    )
    host_state.refresh(
        root,
        host_id="H01",
        refresh_all=False,
        apply=True,
        now=BASE + timedelta(seconds=4),
    )
    rendered = (root / "hosts/H01.md").read_text(encoding="utf-8")
    assert finding["finding_id"] in rendered
    assert work["work_item_id"] in rendered


def test_projection_aggregates_merged_host_history_and_cloud_interface(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(root, script_dir, "H02", "198.51.100.44", "alpha.test")
    destination_input = tmp_path / "destination-interface.txt"
    destination_input.write_text("alpha.test 192.0.2.10\n", encoding="utf-8")
    source_input = tmp_path / "cloud-interface.txt"
    source_input.write_text("alpha.test 198.51.100.44\n", encoding="utf-8")
    _, _, destination_evidence = capture_evidence.capture_evidence(
        str(root),
        "H01",
        "ip-address",
        "Primary interface identity",
        "txt",
        str(destination_input),
        now=BASE,
    )
    _, _, source_evidence = capture_evidence.capture_evidence(
        str(root),
        "H02",
        "cloud-metadata",
        "Cloud interface identity",
        "txt",
        str(source_input),
        now=BASE + timedelta(microseconds=1),
    )
    finding = structured_state.create_finding(
        root,
        host_ids=["H02"],
        state="confirmed",
        severity="medium",
        title="Finding retained on the pre-merge cloud identity",
        impact="Synthetic service exposure",
        references=[source_evidence["evidence_id"]],
        apply=True,
        now=BASE + timedelta(seconds=1),
    )
    merge = host_identity.build_merge_plan(
        root,
        "H02",
        "H01",
        source_evidence["evidence_id"],
        destination_evidence["evidence_id"],
        "Evidence confirms a cloud interface of the same host.",
    )
    host_identity.apply_merge_plan(merge, now=BASE + timedelta(seconds=2))

    host_state.refresh(
        root, host_id="H01", refresh_all=False, apply=True, now=BASE
    )
    rendered = host_identity.resolve_host(root, "H01").path.read_text(encoding="utf-8")
    assert "192.0.2.10, 198.51.100.44" in rendered
    assert finding["finding_id"] in rendered


@pytest.mark.parametrize("host_count", [22, 100])
def test_refresh_scales_without_reloading_structured_ledgers_per_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host_count: int,
) -> None:
    root = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    hosts = tuple(
        (
            f"H{number:02d}",
            f"192.0.2.{number}",
            f"host-{number}.test",
        )
        for number in range(1, host_count + 1)
    )
    new_host.apply_bootstrap_plan(
        new_host.prepare_bootstrap(root, script_dir, hosts),
        new_host.CreationTracker(),
    )
    reads: dict[str, int] = {}
    original = structured_state._read_jsonl

    def counted(path: Path) -> list[dict[str, object]]:
        reads[path.name] = reads.get(path.name, 0) + 1
        return original(path)

    monkeypatch.setattr(structured_state, "_read_jsonl", counted)
    result = host_state.refresh(
        root, host_id=None, refresh_all=True, apply=True, now=BASE
    )
    assert len(result["hosts"]) == host_count
    assert reads == {
        structured_state.FINDING_LEDGER: 1,
        structured_state.WORK_ITEM_LEDGER: 1,
        structured_state.LOCAL_ARTIFACT_LEDGER: 1,
    }
