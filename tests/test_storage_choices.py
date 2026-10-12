"""Behavioral checks for independent storage policy and blank team intake."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import (
    artifact_handling,
    capture_evidence,
    engagement_intake,
    engagement_policy,
    new_host,
    remote_storage,
    structured_state,
    task_collection,
)


def initialize(tmp_path, mode="no-download", remote=remote_storage.DISABLED):
    plan = task_collection.build_module_plan(tmp_path, "assessment", "strict", "chat", mode, remote)
    task_collection.apply_module_plan(plan, Path(__file__).parents[1] / "scripts")
    new_host.bootstrap_host(plan.destination, Path(__file__).parents[1] / "scripts", "H01", "192.0.2.10", "synthetic.test")
    return plan.destination


@pytest.mark.parametrize("mode", artifact_handling.MODES)
@pytest.mark.parametrize("remote", [remote_storage.DISABLED, remote_storage.Settings("approved", "https://storage.example.test/assessment", "ROE-001")])
def test_switches_are_independent_and_scope_starts_empty(tmp_path, mode, remote):
    root = initialize(tmp_path, mode, remote)
    text = (root / "TASK_CONTEXT.md").read_text()
    assert artifact_handling.workspace_mode(root) == mode
    assert remote_storage.parse(text) == remote
    assert str(root) in text
    assert str(tmp_path) in text
    assert (root / "standing_authorizations.jsonl").read_bytes() == b""
    assert not (tmp_path / "ACTIVE_TASK").exists()


@pytest.mark.parametrize("remote", [remote_storage.DISABLED, remote_storage.Settings("approved", "ssh://storage.example.test/approved", "ROE-002")])
def test_no_download_refuses_target_files_before_reading_input(tmp_path, monkeypatch, remote):
    root = initialize(tmp_path, remote=remote)
    def forbidden_read(_):
        pytest.fail("target file bytes must not be read when no-download is active")
    monkeypatch.setattr(capture_evidence, "read_input", forbidden_read)
    with pytest.raises(SystemExit):
        capture_evidence.capture_evidence(str(root), "H01", "file", "Synthetic file", "txt", None)
    assert list((root / "evidence/H01").iterdir()) == []


def test_operator_generated_evidence_is_retained_with_no_download(tmp_path, monkeypatch):
    root = initialize(tmp_path)
    monkeypatch.setattr(capture_evidence, "read_input", lambda _: b"synthetic observation")
    _, path, record = capture_evidence.capture_evidence(str(root), "H01", "observation", "Synthetic", "txt", None, origin="operator-generated")
    assert path.read_bytes() == b"synthetic observation"
    assert record["size_bytes"] == 21
    assert record["origin"] == "operator-generated"
    assert json.loads(path.with_suffix(".json").read_text())["origin"] == "operator-generated"


def test_no_local_processing_exception_for_target_files(tmp_path):
    root = initialize(tmp_path)
    with pytest.raises(structured_state.StructuredStateError, match="no-download"):
        structured_state.register_local_artifact(root, path="private/local_processing/key", artifact_class="ssh-key", purpose="Synthetic")


def test_remote_preview_apply_disable_and_malformed_metadata(tmp_path):
    root = initialize(tmp_path)
    context = root / "TASK_CONTEXT.md"
    before = context.read_bytes()
    args = ["--root", str(tmp_path), "remote-storage", "--module", "assessment", "--set", "approved", "--location", "https://store.example.test/assessment", "--approval", "ROE-001"]
    assert task_collection.main(args) == 0
    assert context.read_bytes() == before
    assert task_collection.main([*args, "--apply"]) == 0
    assert remote_storage.parse(context.read_text()).mode == "approved"
    assert artifact_handling.workspace_mode(root) == "no-download"
    assert task_collection.main(["--root", str(tmp_path), "remote-storage", "--module", "assessment", "--set", "disabled", "--apply"]) == 0
    assert remote_storage.parse(context.read_text()) == remote_storage.DISABLED
    context.write_text(context.read_text() + "- Remote storage: approved\n")
    with pytest.raises(task_collection.CollectionError):
        task_collection.build_module_plan(tmp_path, "assessment")


@pytest.mark.parametrize("uri", ["https://user:password@store.test/path", "https://store.test/path?token=x", "file:///tmp/secret", "ssh://host:99999/path"])
def test_remote_location_rejects_secrets_local_paths_and_bad_ports(uri):
    with pytest.raises(remote_storage.RemoteStorageError):
        remote_storage.Settings("approved", uri, "ROE-001").validate()


def intake_value():
    return {
        "name": "team-assessment", "team_id": "team-synthetic", "operator_id": "operator-synthetic",
        "reviewer_id": "reviewer-synthetic", "scope_reference": "ROE-001",
        "in_scope": ["192.0.2.10"], "excluded": [],
        "starts_at": "2026-10-09T08:00:00Z", "ends_at": "2026-10-09T18:00:00Z",
        "maximum_risk": "low", "stop_conditions": "Stop on any unexpected impact",
        "classification": "restricted", "retention_days": 30,
        "callback_cidrs": [], "callback_ports": [], "profile": "strict",
        "artifact_handling": "no-download", "remote_storage": "disabled",
        "remote_location": "none", "remote_approval": "none",
    }


def test_intake_preview_is_read_only_and_apply_creates_blank_inactive_workspace(tmp_path):
    value = intake_value()
    destination = engagement_intake.initialize(tmp_path, value)
    assert not destination.exists()
    engagement_intake.initialize(tmp_path, value, apply=True)
    metadata = json.loads((destination / "engagement.json").read_text())
    assert metadata["revision"] == 1
    assert "authorization_active" not in metadata
    assert not (destination / "engagement_intake.json").exists()
    assert list((destination / "hosts").iterdir()) == []
    assert (destination / "authorizations.jsonl").read_bytes() == b""
    assert not (tmp_path / "ACTIVE_TASK").exists()
    with pytest.raises(ValueError, match="existing"):
        engagement_intake.initialize(tmp_path, value, apply=True)


@pytest.mark.parametrize("answer", [None, "None", "null"])
def test_legacy_intake_accepts_no_external_scope_document(tmp_path, answer):
    value = intake_value()
    value["scope_reference"] = answer
    root = engagement_intake.initialize(tmp_path, value, apply=True)
    definition = json.loads((root / "engagement.json").read_text())
    assert definition["scope_reference"] is None
    assert definition["origins"]["scope_reference"]["kind"] == "operator-preference"
    assert (root / "authorizations.jsonl").read_bytes() == b""


@pytest.mark.parametrize("field,value", [("in_scope", []), ("ends_at", "2026-10-08T18:00:00Z"), ("callback_ports", [4444]), ("retention_days", True), ("maximum_risk", "unbounded")])
def test_intake_invalid_boundaries_create_nothing(tmp_path, field, value):
    payload = intake_value()
    payload[field] = value
    with pytest.raises(ValueError):
        engagement_intake.initialize(tmp_path, payload, apply=True)
    assert list(tmp_path.iterdir()) == []


def test_review_requires_named_reviewer_and_basis(tmp_path):
    root = initialize(tmp_path)
    with pytest.raises(structured_state.StructuredStateError, match="reviewed requires"):
        structured_state.create_work_item(root, kind="assessment-task", external_ref="TASK-1", host_ids=["H01"], state="reviewed", summary="Synthetic", apply=True)
    moment = datetime(2026, 10, 9, tzinfo=UTC)
    record = structured_state.create_work_item(root, kind="assessment-task", external_ref="TASK-1", host_ids=["H01"], state="reviewed", summary="Synthetic", owner="operator-1", reviewer="reviewer-1", review_basis="Evidence accepted", now=moment, apply=True)
    retained = structured_state.work_item_states(root)[record["work_item_id"]]
    assert retained["review"]["reviewer_id"] == "reviewer-1"
    assert retained["review"]["reviewed_at_utc"] == retained["created_at_utc"]


def test_policy_has_no_automatic_presets_or_unreviewed_authorization(tmp_path):
    root = initialize(tmp_path)
    assert engagement_policy.PRESETS == {"custom"}
    with pytest.raises(engagement_policy.EngagementPolicyError, match="review reference"):
        engagement_policy.permit_operation(workspace=root, host_ids=["H01"], category="filesystem", impact_level="low", technique_family="filesystem-data", technique="Synthetic record", callback=None, summary="Synthetic", apply=True)
