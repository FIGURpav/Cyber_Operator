"""Synthetic configuration governance checks; no network or target execution."""

import copy
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import (
    artifact_handling,
    build_brief,
    create_checkpoint,
    engagement_intake,
    engagement_policy,
    new_host,
    operational_profile,
    operational_trace,
    remote_storage,
    restore_checkpoint,
    screenshot_workflow,
    task_collection,
    workspace_health,
    workspace_lifecycle,
    workspace_transaction,
)
from scripts import (
    engagement_config as config,
)

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
SCRIPTS = Path(__file__).parents[1] / "scripts"


def facts():
    return {
        "team_id": "TEAM-SYNTHETIC", "operator_id": "OP-SYNTHETIC",
        "reviewer_id": "RV-SYNTHETIC", "scope_reference": "ROE-SYNTHETIC",
        "in_scope": ["https://app.example.test/"],
        "excluded": ["Unlisted applications, services and third-party systems"],
        "objectives": ["Review the application within the approved scope"],
        "starts_at": "2020-01-01T00:00:00Z", "ends_at": "2099-01-01T00:00:00Z",
    }


def workspace(tmp_path, **settings):
    value = config.draft("synthetic-web", "pentest-web-app-standard", {**facts(), **settings})
    return engagement_intake.initialize(tmp_path, value, apply=True)


def mutate(root, event, **kwargs):
    loaded = config.load(root)
    return config.change(root, event=event, actor="RV-SYNTHETIC" if event == "approved" else "OP-SYNTHETIC",
                         reason="Synthetic reviewed configuration change",
                         expected_revision=loaded["definition"]["revision"], expected_event=len(loaded["events"]),
                         now=NOW, **kwargs)


def approve(root, **kwargs):
    return mutate(root, "approved", approval_reference="CHANGE-SYNTHETIC", apply=True, **kwargs)


def propose(root, changes, **kwargs):
    return mutate(root, "proposed", changes=changes, basis="engagement-restriction", basis_reference="ROE-SYNTHETIC", apply=True, **kwargs)


def tree(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_partial_intake_creates_draft_with_questions_and_no_approval(tmp_path):
    root = engagement_intake.initialize(tmp_path, {"name": "synthetic-web"}, apply=True, template_id="pentest-web-app-standard")
    result = config.status(root, now=NOW)
    assert result["status"] == "draft"
    assert result["configuration_approved"] is False
    assert {item["field"] for item in result["missing"]} == set(config.QUESTIONS)
    assert not (root / "engagement_intake.json").exists()
    assert not (tmp_path / "ACTIVE_TASK").exists()
    assert list((root / "hosts").iterdir()) == []
    with pytest.raises(config.ConfigurationError):
        mutate(root, "approved", approval_reference="CHANGE-SYNTHETIC", apply=True)


def test_preview_creates_nothing_and_initialization_is_atomic(tmp_path):
    value = config.draft("synthetic-web", "pentest-web-app-standard", facts())
    path = engagement_intake.initialize(tmp_path, value)
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []
    root = engagement_intake.initialize(tmp_path, value, apply=True)
    assert config.status(root, now=NOW)["status"] == "ready-for-review"
    assert config.load(root)["definition"] == value
    for name in (config.DEFINITION, config.EVENTS):
        assert (root / name).stat().st_mode & 0o777 == 0o600


def test_download_proposal_preserves_current_policy_until_exact_review(tmp_path):
    root = workspace(tmp_path)
    approve(root)
    assert config.status(root, now=NOW)["status"] == "active"
    snapshot = tree(root)
    result = mutate(root, "proposed", changes={"artifact_handling": "standard"})
    assert tree(root) == snapshot
    assert result["changes"][0]["before"] == "no-download"
    proposal = propose(root, {"artifact_handling": "standard"})
    assert artifact_handling.workspace_mode(root) == "no-download"
    assert config.status(root, now=NOW)["revision"] == 1
    assert config.status(root, now=NOW)["pending_proposals"] == [3]
    with pytest.raises(artifact_handling.ArtifactHandlingError, match="no-download"):
        artifact_handling.require_local_persistence(root, "target-file")
    approve(root, proposal_sequence=proposal["record"]["sequence"])
    assert artifact_handling.workspace_mode(root) == "standard"
    artifact_handling.require_local_persistence(root, "target-file")
    loaded = config.load(root)
    assert loaded["definition"]["revision"] == 2
    assert [event["event"] for event in loaded["events"]] == ["created", "approved", "proposed", "approved"]
    assert loaded["events"][-1]["approval_reference"] == "CHANGE-SYNTHETIC"
    assert loaded["events"][-1]["changes"][0]["before"] == "no-download"
    assert loaded["events"][-1]["changes"][0]["after"] == "standard"
    assert config.status(root, now=NOW)["pending_proposals"] == []


def test_compare_and_swap_covers_both_revision_and_event_sequence(tmp_path):
    root = workspace(tmp_path)
    propose(root, {"retention_days": 60})
    for revision, sequence in [(1, 1), (0, 2), (True, 2)]:
        with pytest.raises(config.ConfigurationError, match="changed"):
            config.change(root, event="proposed", actor="OP-SYNTHETIC", reason="Synthetic", expected_revision=revision, expected_event=sequence, changes={"retention_days": 45}, apply=True)


def test_stale_proposal_cannot_override_a_new_revision(tmp_path):
    root = workspace(tmp_path)
    first = propose(root, {"retention_days": 45})
    second = propose(root, {"retention_days": 60})
    approve(root, proposal_sequence=first["record"]["sequence"])
    with pytest.raises(config.ConfigurationError, match="stale"):
        approve(root, proposal_sequence=second["record"]["sequence"])
    assert config.load(root)["definition"]["retention_days"] == 45


def test_approval_requires_reviewer_and_rejects_empty_reference(tmp_path):
    root = workspace(tmp_path)
    for actor, reference in [("OP-SYNTHETIC", "CHANGE-1"), ("RV-SYNTHETIC", "")]:
        with pytest.raises(config.ConfigurationError):
            config.change(root, event="approved", actor=actor, reason="Synthetic", expected_revision=1, expected_event=1, approval_reference=reference, now=NOW, apply=True)
    assert len(config.load(root)["events"]) == 1


@pytest.mark.parametrize("answer", [None, "None", "none", "NULL", " null "])
def test_explicit_no_document_is_complete_but_unapproved(tmp_path, answer):
    root = workspace(tmp_path, scope_reference=answer)
    loaded = config.load(root)
    state = config.status(root, now=NOW)
    assert loaded["definition"]["scope_reference"] is None
    assert loaded["definition"]["origins"]["scope_reference"]["kind"] == "operator-preference"
    assert state["scope_reference_state"] == "no-external-document"
    assert state["missing"] == []
    assert state["status"] == "ready-for-review"
    assert state["configuration_approved"] is False
    assert state["target_action_authorization"] == "not provided by configuration"
    assert loaded["definition"]["maximum_impact"] == "low"
    assert loaded["definition"]["artifact_handling"] == "no-download"
    assert (root / "authorizations.jsonl").read_bytes() == b""


def test_omitted_document_answer_stays_missing_until_reviewed_explicit_null(tmp_path):
    supplied = {key: value for key, value in facts().items() if key != "scope_reference"}
    definition = config.draft("synthetic-web", "pentest-web-app-standard", supplied)
    root = engagement_intake.initialize(tmp_path, definition, apply=True)
    assert config.status(root, now=NOW)["scope_reference_state"] == "unanswered"
    assert [item["field"] for item in config.missing(definition)] == ["scope_reference"]
    with pytest.raises(config.ConfigurationError, match="incomplete"):
        mutate(root, "approved", apply=True)
    proposal = propose(root, {"scope_reference": None})
    assert config.status(root, now=NOW)["scope_reference_state"] == "unanswered"
    assert proposal["changes"][0]["before"] is None
    assert proposal["changes"][0]["after"] is None
    assert proposal["changes"][0]["origin_before"] != proposal["changes"][0]["origin_after"]
    mutate(root, "approved", proposal_sequence=proposal["record"]["sequence"], apply=True)
    assert config.status(root, now=NOW)["scope_reference_state"] == "no-external-document"
    assert config.status(root, now=NOW)["revision"] == 2


@pytest.mark.parametrize("reference", [None, "None", "null"])
def test_review_without_external_reference_has_a_stable_local_receipt(tmp_path, reference):
    root = workspace(tmp_path, scope_reference=None)
    before = tree(root)
    preview = mutate(root, "approved", approval_reference=reference)
    assert tree(root) == before
    applied = mutate(root, "approved", approval_reference=reference, apply=True)
    receipt = applied["record"]["approval_reference"]
    assert receipt == preview["record"]["approval_reference"]
    assert receipt == f"local-review:{applied['definition']['engagement_id']}:2"
    loaded = config.load(root)
    assert loaded["events"][-1]["actor"] == "RV-SYNTHETIC"
    assert loaded["events"][-1]["approval_reference"] == receipt
    assert config.status(root, now=NOW)["status"] == "active"
    assert (root / "authorizations.jsonl").read_bytes() == b""
    with pytest.raises(artifact_handling.ArtifactHandlingError, match="no-download"):
        artifact_handling.require_local_persistence(root, "target-file")


def test_removing_a_document_keeps_history_and_needs_exact_review(tmp_path):
    root = workspace(tmp_path)
    approve(root)
    previous_events = (root / config.EVENTS).read_bytes()
    proposal = propose(root, {"scope_reference": "None"})
    assert config.load(root)["definition"]["scope_reference"] == "ROE-SYNTHETIC"
    mutate(root, "approved", proposal_sequence=proposal["record"]["sequence"], apply=True)
    loaded = config.load(root)
    assert loaded["definition"]["scope_reference"] is None
    assert (root / config.EVENTS).read_bytes().startswith(previous_events)
    assert loaded["events"][-1]["changes"][0]["before"] == "ROE-SYNTHETIC"
    assert loaded["events"][-1]["changes"][0]["after"] is None
    assert loaded["definition"]["artifact_handling"] == "no-download"
    assert loaded["definition"]["maximum_impact"] == "low"


@pytest.mark.parametrize("setting", ["operator_id", "reviewer_id", "in_scope", "starts_at", "ends_at"])
def test_no_document_does_not_waive_other_required_facts(tmp_path, setting):
    supplied = {**facts(), "scope_reference": None}
    supplied.pop(setting)
    root = engagement_intake.initialize(tmp_path, {"name": "synthetic-web", **supplied}, apply=True, template_id="pentest-web-app-standard")
    assert setting in {item["field"] for item in config.status(root, now=NOW)["missing"]}
    with pytest.raises(config.ConfigurationError):
        mutate(root, "approved", apply=True)


@pytest.mark.parametrize("answer", ["", "  ", False, 0, [], {}])
def test_invalid_document_answers_do_not_create_workspace(tmp_path, answer):
    with pytest.raises(config.ConfigurationError):
        engagement_intake.initialize(tmp_path, {"name": "synthetic-web", **facts(), "scope_reference": answer}, apply=True, template_id="pentest-web-app-standard")
    assert list(tmp_path.iterdir()) == []


def test_cli_approval_without_document_reference(tmp_path, capsys):
    root = workspace(tmp_path, scope_reference="None")
    args = ["approve", "--workspace", str(root), "--actor", "RV-SYNTHETIC",
            "--reason", "Explicit synthetic configuration review in this conversation",
            "--expected-revision", "1", "--expected-event", "1"]
    before = tree(root)
    assert config.main(args) == 0
    preview = json.loads(capsys.readouterr().out)
    assert tree(root) == before
    assert config.main([*args, "--apply"]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["record"]["approval_reference"] == preview["record"]["approval_reference"]
    assert config.main(["questions", "--workspace", str(root)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_existing_documented_configuration_reads_without_rewriting_history(tmp_path):
    root = workspace(tmp_path)
    approve(root)
    before = tree(root)
    assert config.status(root, now=NOW)["scope_reference_state"] == "provided"
    assert config.load(root)["events"][-1]["approval_reference"] == "CHANGE-SYNTHETIC"
    assert tree(root) == before


@pytest.mark.parametrize("field,value", [
    ("in_scope", ["192.0.2.10"]),
    ("in_scope", ["https://user:secret@app.example.test/"]),
    ("in_scope", ["https://*.example.test/"]),
    ("in_scope", ["https://app.example.test/?token=secret"]),
    ("ends_at", "2019-01-01T00:00:00Z"),
    ("ends_at", "2099-01-01T00:00:00"),
    ("retention_days", True),
    ("callback_ports", [12345]),
    ("report_contract", "operational"),
    ("excluded", ["https://app.example.test/"]),
])
def test_invalid_or_conflicting_proposal_leaves_history_unchanged(tmp_path, field, value):
    root = workspace(tmp_path)
    snapshot = (root / config.EVENTS).read_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        propose(root, {field: value})
    assert (root / config.EVENTS).read_bytes() == snapshot


def test_template_restrictions_cannot_be_dropped_or_changed_in_a_proposal(tmp_path):
    root = workspace(tmp_path)
    value = config.load(root)["definition"]
    assert config.WEB_PROHIBITIONS <= set(value["policy"]["prohibited"])
    value["policy"]["prohibited"].remove("interactive-shells")
    with pytest.raises(config.ConfigurationError, match="prohibitions"):
        config.validate(value)
    with pytest.raises(config.ConfigurationError, match="mutable"):
        propose(root, {"policy": {}})


def test_template_changes_do_not_reinterpret_an_existing_snapshot(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    before = config.load(root)["definition"]
    def unexpected_template_read(_):
        pytest.fail("existing definitions must not be reloaded from mutable templates")
    monkeypatch.setattr(config, "template", unexpected_template_read)
    assert config.load(root)["definition"] == before


@pytest.mark.parametrize("mode", ["standard", "no-download"])
@pytest.mark.parametrize("remote", ["disabled", "approved"])
def test_storage_choices_remain_independent(tmp_path, mode, remote):
    settings = {"artifact_handling": mode, "remote_storage": remote}
    if remote == "approved":
        settings.update(remote_location="https://store.example.test/assessment", remote_approval="STORE-1")
    root = workspace(tmp_path, **settings)
    approve(root)
    assert artifact_handling.workspace_mode(root) == mode
    assert remote_storage.workspace_settings(root).mode == remote


def test_downloads_need_current_review_and_stop_on_pause_or_expiry(tmp_path):
    root = workspace(tmp_path, artifact_handling="standard")
    with pytest.raises(artifact_handling.ArtifactHandlingError, match="reviewed"):
        artifact_handling.require_local_persistence(root, "target-file")
    artifact_handling.require_local_persistence(root, "operator-generated")
    approve(root)
    assert config.status(root, now=datetime(2100, 1, 1, tzinfo=UTC))["status"] == "expired"
    assert not config.status(root, now=datetime(2100, 1, 1, tzinfo=UTC))["configuration_approved"]
    mutate(root, "paused", apply=True)
    assert config.status(root, now=NOW)["status"] == "paused"
    with pytest.raises(artifact_handling.ArtifactHandlingError, match="reviewed"):
        artifact_handling.require_local_persistence(root, "target-file")
    artifact_handling.require_local_persistence(root, "operator-generated")
    approve(root)
    assert config.status(root, now=NOW)["status"] == "active"


def test_future_window_is_scheduled(tmp_path):
    root = workspace(tmp_path, starts_at="2098-01-01T00:00:00Z")
    approve(root)
    assert config.status(root, now=NOW)["status"] == "scheduled"
    with pytest.raises(artifact_handling.ArtifactHandlingError):
        artifact_handling.require_local_persistence(root, "target-file")


def test_engagement_restriction_cannot_be_reclassified_as_preference(tmp_path):
    root = workspace(tmp_path)
    item = propose(root, {"artifact_handling": "standard"})
    approve(root, proposal_sequence=item["record"]["sequence"])
    with pytest.raises(config.ConfigurationError, match="downgraded"):
        mutate(root, "proposed", changes={"artifact_handling": "no-download"}, basis="operator-preference")


@pytest.mark.parametrize("kind", ["projection", "snapshot", "history", "symlink", "hardlink", "permissions"])
def test_corrupt_or_unsafe_state_fails_closed(tmp_path, kind):
    root = workspace(tmp_path)
    path = root / config.DEFINITION
    if kind == "projection":
        context = root / "TASK_CONTEXT.md"
        context.write_text(context.read_text().replace("- Artifact handling: no-download", "- Artifact handling: standard"))
    elif kind == "snapshot":
        value = json.loads(path.read_text())
        value["artifact_handling"] = "standard"
        path.write_text(json.dumps(value))
    elif kind == "history":
        history = root / config.EVENTS
        history.write_bytes(history.read_bytes().replace(b"Initial draft", b"Altered draft"))
    elif kind == "permissions":
        path.chmod(0o644)
    else:
        outside = tmp_path / "saved-definition"
        path.rename(outside)
        if kind == "symlink":
            path.symlink_to(outside)
        else:
            os.link(outside, path)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        config.load(root)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        artifact_handling.require_local_persistence(root, "target-file")


def test_legacy_setters_and_legacy_grants_cannot_override_managed_configuration(tmp_path):
    root = workspace(tmp_path)
    approve(root)
    assert operational_profile.workspace_profile(root) == "strict"
    assert engagement_policy.active_standing_authorization(root, NOW) is None
    with pytest.raises(config.ConfigurationError):
        task_collection.write_module_profile(tmp_path, root.name, "controlled-engagement")
    with pytest.raises(config.ConfigurationError):
        task_collection.write_module_artifact_handling(tmp_path, root.name, "standard", acknowledge_local_full_file_risk=True)
    assert task_collection.main(["--root", str(tmp_path), "remote-storage", "--module", root.name, "--set", "disabled", "--apply"]) == 1
    with pytest.raises(engagement_policy.EngagementPolicyError, match="managed configuration"):
        engagement_policy.build_activation(workspace=root, preset="custom", host_scope="canonical-current", callback_cidrs=[], callback_port_ranges=[], expires_at_utc=None, source="Synthetic", summary="Synthetic")
    with pytest.raises(operational_trace.TraceError, match="managed configuration"):
        operational_trace.log_authorization(workspace=root, host_ids=[], categories=[], maximum_impact="low", techniques=[], exclusions=[], source="Synthetic", summary="Synthetic")


def test_new_host_is_inventory_only_and_brief_includes_scope_revision(tmp_path):
    root = workspace(tmp_path)
    before = config.load(root)["definition"]
    new_host.bootstrap_host(root, SCRIPTS, "H01", "192.0.2.10", "outside.example.test")
    assert config.load(root)["definition"] == before
    content, _ = build_brief.build_brief(root, "H01", 5, 5, 3, 5, NOW)
    assert '"revision": 1' in content
    assert "interactive-shells" in content
    assert "https://app.example.test/" in content


def test_report_contract_comes_from_definition_and_cannot_be_overridden(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    from argparse import Namespace
    monkeypatch.setattr(screenshot_workflow, "_resolve_active", lambda _: root)
    with pytest.raises(ValueError, match="contract override"):
        screenshot_workflow.report_check(Namespace(workspace=str(root), barrier="final", contract="operational"))


def test_restore_instance_invalidates_old_configuration_review(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    approve(root)
    monkeypatch.setattr(restore_checkpoint, "state", lambda _: {"instance_id": "WSI-" + "a" * 32, "status": "active"})
    result = config.status(root, now=NOW)
    assert result["status"] == "ready-for-review"
    assert result["configuration_approved"] is False


@pytest.mark.parametrize("interrupted_step", [0, 1, 2])
def test_interrupted_approval_is_recoverable_and_never_silently_readable(tmp_path, monkeypatch, interrupted_step):
    root = workspace(tmp_path)
    item = propose(root, {"artifact_handling": "standard"})
    original = workspace_transaction._after_operation
    def fail(_identifier, index):
        if index == interrupted_step:
            raise OSError("Synthetic interruption")
    monkeypatch.setattr(workspace_transaction, "_after_operation", fail)
    with pytest.raises(OSError, match="interruption"):
        approve(root, proposal_sequence=item["record"]["sequence"])
    with pytest.raises(config.ConfigurationError, match="unfinished"):
        config.load(root)
    pending = workspace_transaction.incomplete(root)
    assert len(pending) == 1
    monkeypatch.setattr(workspace_transaction, "_after_operation", original)
    workspace_transaction.replay(root, pending[0])
    assert config.load(root)["definition"]["revision"] == 2
    assert artifact_handling.workspace_mode(root) == "standard"
    health = workspace_health.snapshot(root, now=NOW)
    assert health["history_readable"] is True


def test_cli_preview_history_and_questions(tmp_path, capsys):
    assert config.main(["templates"]) == 0
    assert "pentest-web-app-standard" in capsys.readouterr().out
    root = workspace(tmp_path)
    before = tree(root)
    assert config.main(["status", "--workspace", str(root)]) == 0
    assert "ready-for-review" in capsys.readouterr().out
    assert config.main(["questions", "--workspace", str(root)]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert config.main(["history", "--workspace", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["event"] == "created"
    assert tree(root) == before


def test_initial_schema_rejects_unknown_fields_and_duplicate_json_keys(tmp_path):
    value = config.draft("synthetic-web", "pentest-web-app-standard", facts())
    invalid = copy.deepcopy(value)
    invalid["allow_everything"] = True
    with pytest.raises(config.ConfigurationError):
        engagement_intake.initialize(tmp_path, invalid, apply=True)
    path = tmp_path / "input.json"
    path.write_text('{"name":"first","name":"second"}')
    with pytest.raises(RuntimeError):
        config.read_input(path)


def test_rejected_proposal_remains_in_history_and_cannot_be_approved(tmp_path):
    root = workspace(tmp_path)
    proposed = propose(root, {"artifact_handling": "standard"})
    mutate(root, "rejected", proposal_sequence=proposed["record"]["sequence"], apply=True)
    assert config.status(root, now=NOW)["pending_proposals"] == []
    with pytest.raises(config.ConfigurationError, match="rejected"):
        approve(root, proposal_sequence=proposed["record"]["sequence"])
    assert artifact_handling.workspace_mode(root) == "no-download"
    assert config.load(root)["events"][-1]["event"] == "rejected"


def test_concurrent_proposals_do_not_overwrite_each_other(tmp_path):
    root = workspace(tmp_path)
    def writer(days):
        try:
            config.change(root, event="proposed", actor="OP-SYNTHETIC", reason="Synthetic", expected_revision=1, expected_event=1, changes={"retention_days": days}, apply=True)
            return "written"
        except config.ConfigurationError:
            return "stale"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(writer, [45, 60]))
    assert sorted(results) == ["stale", "written"]
    assert len(config.load(root)["events"]) == 2


def test_close_and_reopen_require_fresh_configuration_review(tmp_path):
    root = workspace(tmp_path)
    approve(root)
    plan = workspace_lifecycle.build_close_plan(root, now=NOW)
    workspace_lifecycle.apply_close(plan, supplied_plan_sha256=plan.plan_sha256, operator_acknowledged=True, retain_active_state=True, reason="Synthetic close", now=NOW)
    assert config.status(root, now=NOW)["status"] == "closed"
    workspace_lifecycle.reopen(root, operator_acknowledged=True, reason="Synthetic reopen", apply=True, now=NOW + timedelta(seconds=1))
    assert config.status(root, now=NOW)["status"] == "ready-for-review"
    approve(root)
    assert config.status(root, now=NOW)["status"] == "active"


def test_real_checkpoint_restore_preserves_history_and_requires_new_review(tmp_path, monkeypatch):
    collection = tmp_path / "collection"
    collection.mkdir(mode=0o700)
    root = workspace(collection)
    approve(root)
    _, checkpoint, _, _ = create_checkpoint.create_checkpoint(root, tmp_path / "snapshots", NOW, profile="strict", unresolved_session_token_count=0, contains_ephemeral_session_secrets=False)
    result = restore_checkpoint.restore(checkpoint, collection, "restored-web", apply=True)
    restored = Path(result["destination"])
    assert (root / config.EVENTS).read_bytes() == (restored / config.EVENTS).read_bytes()
    assert config.status(restored, now=NOW)["configuration_approved"] is False
    restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", restore_checkpoint.state(restored)["instance_id"])
    assert config.status(restored, now=NOW)["status"] == "ready-for-review"
    approve(restored)
    assert config.status(restored, now=NOW)["status"] == "active"


def legacy_workspace(tmp_path):
    plan = task_collection.build_module_plan(tmp_path, "synthetic-web", "strict", "chat", "no-download")
    task_collection.apply_module_plan(plan, SCRIPTS)
    return plan.destination


def test_adoption_is_explicit_read_only_in_preview_and_preserves_old_history(tmp_path):
    root = legacy_workspace(tmp_path)
    value = config.draft(root.name, "pentest-web-app-standard", facts())
    before = tree(root)
    preview = config.adopt(root, value, actor="OP-SYNTHETIC", reason="Reviewed migration")
    assert tree(root) == before
    with pytest.raises(config.ConfigurationError, match="preview context"):
        config.adopt(root, value, actor="OP-SYNTHETIC", reason="Reviewed migration", apply=True)
    config.adopt(root, value, actor="OP-SYNTHETIC", reason="Reviewed migration", expected_context_sha256=preview["legacy_context_sha256"], apply=True)
    assert config.status(root, now=NOW)["status"] == "ready-for-review"
    assert config.status(root, now=NOW)["configuration_approved"] is False
    for name in ("standing_authorizations.jsonl", "authorizations.jsonl", "observations.jsonl"):
        assert (root / name).read_bytes() == before[name]


def test_adoption_refuses_storage_scope_conflicts_and_stale_preview(tmp_path):
    root = legacy_workspace(tmp_path)
    value = config.draft(root.name, "pentest-web-app-standard", facts())
    invalid = copy.deepcopy(value)
    invalid["artifact_handling"] = "standard"
    with pytest.raises(config.ConfigurationError, match="storage choices"):
        config.adopt(root, invalid, actor="OP-SYNTHETIC", reason="Synthetic")
    context = root / "TASK_CONTEXT.md"
    preview = config.adopt(root, value, actor="OP-SYNTHETIC", reason="Synthetic")
    context.write_text(context.read_text() + "- Additional context: changed\n")
    with pytest.raises(config.ConfigurationError, match="changed"):
        config.adopt(root, value, actor="OP-SYNTHETIC", reason="Synthetic", expected_context_sha256=preview["legacy_context_sha256"], apply=True)
    (root / "engagement_intake.json").write_text(json.dumps({"in_scope": ["https://different.example.test/"]}))
    with pytest.raises(config.ConfigurationError, match="conflicts with legacy intake"):
        config.adopt(root, value, actor="OP-SYNTHETIC", reason="Synthetic")


def test_context_marker_in_untrusted_metadata_is_escaped(tmp_path):
    root = workspace(tmp_path, objectives=["Review " + config.END + " as untrusted text"])
    assert config.load(root)["definition"]["objectives"][0].endswith("as untrusted text")
    assert (root / "TASK_CONTEXT.md").read_text().count(config.END) == 1


def test_doctor_reports_configuration_corruption(tmp_path):
    root = workspace(tmp_path)
    context = root / "TASK_CONTEXT.md"
    context.write_text(context.read_text().replace("- Artifact handling: no-download", "- Artifact handling: standard"))
    health = workspace_health.snapshot(root, now=NOW)
    assert health["write_ready"] is False
    assert health["history_readable"] is False
    assert "engagement-configuration-invalid" in {item["code"] for item in health["blockers"]}
