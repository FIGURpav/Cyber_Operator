"""Synthetic process-death, conflict, host migration and restore tests."""

import binascii
import fcntl
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from policy_support import synthetic_configuration

from scripts import (
    artifact_io,
    capture_evidence,
    create_checkpoint,
    engagement_policy,
    host_identity,
    ledger_io,
    new_host,
    restore_checkpoint,
    scanner_intake,
    screenshot_workflow,
    stream_coordination,
    task_collection,
    token_lifecycle,
    workspace_health,
    workspace_status,
)
from scripts import (
    workspace_transaction as tx,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)


def module(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir(mode=0o700)
    plan = task_collection.build_module_plan(collection, "source", intake_mode="chat")
    task_collection.apply_module_plan(plan, ROOT / "scripts")
    workspace = collection / "source"
    new_host.bootstrap_host(workspace, ROOT / "scripts", "H01", "192.0.2.10", "same.synthetic.test")
    return workspace


def retain(workspace, host_id, moment, content=b"synthetic evidence"):
    source = workspace.parent / "synthetic-input.txt"
    source.write_bytes(content)
    return capture_evidence.capture_evidence(
        str(workspace), host_id, "manual", "Synthetic provenance", "txt", str(source), now=moment,
    )


def merge_setup(workspace):
    new_host.bootstrap_host(workspace, ROOT / "scripts", "H02", "192.0.2.20", "same.synthetic.test")
    retain(workspace, "H01", NOW)
    retain(workspace, "H02", NOW + timedelta(seconds=1))
    return host_identity.build_merge_plan(
        workspace, "H01", "H02", "EVD-20260820T120000000000Z", "EVD-20260820T120001000000Z",
        "Synthetic retained identity evidence for the same host.",
    )


def make_png():
    def chunk(kind, raw):
        return struct.pack(">I", len(raw)) + kind + raw + struct.pack(">I", binascii.crc32(kind + raw) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0" * 14)) + chunk(b"IEND", b""))


def request(workspace):
    args = screenshot_workflow.screenshot_parser().parse_args([
        "request", "--workspace", str(workspace), "--host-id", "H01", "--stage", "discovery",
        "--priority", "required", "--reason", "Synthetic screenshot", "--interface", "application",
        "--protocol", "local", "--endpoint", "Synthetic application", "--slug", "synthetic",
        "--step", "Open synthetic view", "--must-include", "Host context", "--must-exclude", "Secrets",
    ])
    screenshot_workflow.request_screenshot(args, NOW + timedelta(seconds=2))
    event = screenshot_workflow._load_events(workspace / screenshot_workflow.LEDGER_NAME)[0]
    (workspace / event["pending_path"]).write_bytes(make_png())
    return event


def review_arguments(workspace):
    return ["review", "--workspace", str(workspace), "--screenshot-id", "S001", "--accept",
            "--visual-reviewed", "--caption", "Synthetic reviewed pixels"]


def checkpoint(workspace, tmp_path):
    return create_checkpoint.create_checkpoint(
        workspace, tmp_path / "checkpoints", NOW, profile="strict", unresolved_session_token_count=0,
        contains_ephemeral_session_secrets=False,
    )[1]


def hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def killed(code, *arguments):
    result = subprocess.run([sys.executable, "-c", code, *map(str, arguments)], cwd=ROOT,
                            capture_output=True, check=False, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == -signal.SIGKILL, result.stderr.decode()


@pytest.mark.parametrize("operation", [0, 1])
def test_evidence_sigkill_replays_identical_bytes_and_ids(tmp_path, operation):
    workspace = module(tmp_path)
    source = tmp_path / "input.txt"
    source.write_bytes(b"retained once")
    killed('''
import os, signal, sys
from scripts import capture_evidence, workspace_transaction as tx
from datetime import datetime, UTC
tx._after_operation = lambda _, index: os.kill(os.getpid(), signal.SIGKILL) if index == int(sys.argv[3]) else None
capture_evidence.capture_evidence(sys.argv[1], "H01", "manual", "Synthetic", "txt", sys.argv[2], now=datetime(2026,8,20,12,tzinfo=UTC))
''', workspace, source, operation)
    identifier, = tx.incomplete(workspace)
    with pytest.raises(tx.TransactionError, match="unfinished"), tx.write_guard(workspace):
        pass
    with pytest.raises(create_checkpoint.CheckpointError, match="unfinished"):
        checkpoint(workspace, tmp_path)
    source.unlink()  # Recovery needs only the retained journal bytes.
    tx.replay(workspace, identifier)
    before = hashes(workspace)
    tx.replay(workspace, identifier)
    assert hashes(workspace) == before
    metadata = host_identity.locate_evidence_metadata(workspace, "H01", "EVD-20260820T120000000000Z")
    record = json.loads(metadata.read_bytes())
    assert host_identity.verify_evidence_artifact(metadata, record).read_bytes() == b"retained once"


@pytest.mark.parametrize("operation", range(4))
def test_screenshot_sigkill_never_creates_an_unreviewed_capture(tmp_path, operation):
    workspace = module(tmp_path)
    requested = request(workspace)
    killed('''
import os, signal, sys
from scripts import screenshot_workflow as screenshots, workspace_transaction as tx
from datetime import datetime, UTC
tx._after_operation = lambda _, index: os.kill(os.getpid(), signal.SIGKILL) if index == int(sys.argv[1]) else None
screenshots.screenshot_main(sys.argv[2:], now=datetime(2026,8,20,12,0,3,tzinfo=UTC))
''', operation, *review_arguments(workspace))
    identifier, = tx.incomplete(workspace)
    tx.replay(workspace, identifier)
    events = screenshot_workflow._load_events(workspace / screenshot_workflow.LEDGER_NAME)
    assert [event["event"] for event in events] == ["requested", "captured"]
    screenshot_workflow._verify_evidence(workspace, requested, events[-1])
    assert events[-1]["sha256"] == hashlib.sha256(make_png()).hexdigest()
    assert not (workspace / requested["pending_path"]).exists()
    before = hashes(workspace)
    tx.replay(workspace, identifier)
    assert hashes(workspace) == before


@pytest.mark.parametrize("operation", range(4))
def test_merge_sigkill_resumes_without_rewriting_historical_evidence(tmp_path, operation, capsys):
    workspace = module(tmp_path)
    merge_setup(workspace)
    evidence_before = hashes(workspace / "evidence")
    killed('''
import os, signal, sys
from pathlib import Path
from datetime import datetime, UTC
from scripts import host_identity as hosts, workspace_transaction as tx
tx._after_operation = lambda _, index: os.kill(os.getpid(), signal.SIGKILL) if index == int(sys.argv[2]) else None
plan = hosts.build_merge_plan(Path(sys.argv[1]), "H01", "H02", "EVD-20260820T120000000000Z", "EVD-20260820T120001000000Z", "Synthetic matching identity")
hosts.apply_merge_plan(plan, now=datetime(2026,8,20,12,0,3,tzinfo=UTC))
''', workspace, operation)
    assert not workspace_health.snapshot(workspace)["history_readable"]
    assert workspace_status.main(["--workspace", str(workspace), "--host-id", "H01"]) == 2
    assert "unfinished-transactions" in capsys.readouterr().out
    identifier, = tx.incomplete(workspace)
    tx.replay(workspace, identifier)
    assert host_identity.canonical_host_id(workspace, "H01") == "H02"
    assert hashes(workspace / "evidence") == evidence_before
    events = [json.loads(line) for line in (workspace / "host_merges.jsonl").read_bytes().splitlines()]
    assert [event["status"] for event in events] == ["planned", "applied"]
    tx.replay(workspace, identifier)
    assert len(host_identity.applied_merges(workspace)) == 1


@pytest.mark.parametrize("captured_before", [False, True])
def test_open_and_captured_requests_survive_merge_with_immutable_history(tmp_path, captured_before):
    workspace = module(tmp_path)
    requested = request(workspace)
    if captured_before:
        screenshot_workflow.screenshot_main(review_arguments(workspace), now=NOW + timedelta(seconds=3))
    plan = merge_setup(workspace)
    ledger_before = (workspace / screenshot_workflow.LEDGER_NAME).read_bytes()
    evidence_before = hashes(workspace / "evidence")
    host_identity.apply_merge_plan(plan, now=NOW + timedelta(seconds=4))
    assert (workspace / screenshot_workflow.LEDGER_NAME).read_bytes() == ledger_before
    assert hashes(workspace / "evidence") == evidence_before
    if not captured_before:
        screenshot_workflow.screenshot_main(review_arguments(workspace), now=NOW + timedelta(seconds=5))
    events = screenshot_workflow._load_events(workspace / screenshot_workflow.LEDGER_NAME)
    assert events[0] == requested
    assert events[-1]["host_id"] == "H01"
    screenshot_workflow._verify_evidence(workspace, requested, events[-1])
    index = (workspace / "report" / screenshot_workflow.INDEX_NAME).read_text()
    assert "| S001 | H02 |" in index
    assert events[-1]["screenshot_evidence_id"] in host_identity.host_paths(workspace, "H02").report.read_text()


def test_partial_ledger_tail_is_completed_from_exact_prepared_bytes(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    plan = merge_setup(workspace)
    def stop(_identifier, index):
        if index == 0:
            raise RuntimeError("interrupted")
    monkeypatch.setattr(tx, "_after_operation", stop)
    with pytest.raises(host_identity.HostIdentityError):
        host_identity.apply_merge_plan(plan, now=NOW + timedelta(seconds=3))
    identifier, = tx.incomplete(workspace)
    ledger = workspace / "host_merges.jsonl"
    original = ledger.read_bytes()
    ledger.write_bytes(original[:21])  # Simulate a process dying mid-append.
    monkeypatch.setattr(tx, "_after_operation", lambda *_: None)
    tx.replay(workspace, identifier)
    assert ledger.read_bytes().startswith(original)
    assert len(host_identity.applied_merges(workspace)) == 1


def test_unprepared_staging_is_retained_in_quarantine(tmp_path):
    workspace = module(tmp_path)
    directory = workspace / tx.DIRECTORY / ("TXN-" + "a" * 32)
    directory.mkdir(parents=True, mode=0o700)
    (directory / "0000.bin").write_bytes(b"unpublished bytes")
    tx.quarantine_staging(workspace, directory.name)
    assert not tx.incomplete(workspace)
    assert (workspace / "private/transaction_orphans" / directory.name / "0000.bin").read_bytes() == b"unpublished bytes"


@pytest.mark.parametrize("damage", ["bytes", "path", "kind", "review"])
def test_recovery_rejects_damaged_or_unreviewed_plans_before_writes(tmp_path, monkeypatch, damage):
    workspace = module(tmp_path)
    request(workspace)
    monkeypatch.setattr(tx, "_after_operation", lambda *_: (_ for _ in ()).throw(RuntimeError("interrupt")))
    with pytest.raises(SystemExit):
        screenshot_workflow.screenshot_main(review_arguments(workspace), now=NOW + timedelta(seconds=3))
    identifier, = tx.incomplete(workspace)
    directory = workspace / tx.DIRECTORY / identifier
    plan_path = directory / "plan.json"
    plan = json.loads(plan_path.read_bytes())
    if damage == "bytes":
        (directory / "0000.bin").write_bytes(b"different bytes")
    elif damage == "path":
        plan["operations"][0]["path"] = "evidence/../../outside"
    elif damage == "kind":
        plan["kind"] = ["shell"]
    else:
        plan["references"]["visual_reviewed"] = False
    plan_path.write_text(json.dumps(plan))
    before = hashes(workspace)
    with pytest.raises((tx.TransactionError, ledger_io.LedgerIOError)):
        tx.replay(workspace, identifier)
    assert hashes(workspace) == before


def test_restore_is_inactive_independent_verified_and_fences_old_runtime(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    retain(workspace, "H01", NOW)
    saved = checkpoint(workspace, tmp_path)
    collection = workspace.parent
    task_collection.write_active_module(collection, workspace.name)
    before = hashes(collection)
    restore_checkpoint.restore(saved, collection, "restored", apply=False)
    assert hashes(collection) == before
    result = restore_checkpoint.restore(saved, collection, "restored", apply=True)
    restored = collection / "restored"
    assert result["status"] == "restored-inactive"
    assert task_collection.read_active_module(collection) == "source"
    assert hashes(restored / "evidence") == hashes(workspace / "evidence")
    assert hashes(workspace) == {name.removeprefix("source/"): value for name, value in before.items() if name.startswith("source/")}
    for path in restored.rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    with pytest.raises(task_collection.CollectionError, match="inactive"):
        task_collection.write_active_module(collection, "restored")
    with pytest.raises(restore_checkpoint.RestoreError, match="inactive"):
        artifact_io.publish_file(restored / "queries/test.json", "{}")
    with pytest.raises(ledger_io.LedgerIOError, match="inactive"):
        ledger_io.append_json_record(restored / "attempts.jsonl", {}, create=False)
    with pytest.raises(restore_checkpoint.RestoreError, match="ack-new-runtime"):
        restore_checkpoint.activate(restored, apply=True, acknowledge=False)
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    with pytest.raises(restore_checkpoint.RestoreError, match="stale"):
        artifact_io.publish_file(restored / "queries/test.json", "{}")
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    restore_checkpoint.require_write_instance(restored)
    task_collection.write_active_module(collection, "restored")
    assert task_collection.read_active_module(collection) == "restored"
    operation, = (collection / "_archive").glob("RST-*")
    restore_checkpoint.resume(operation)
    assert restore_checkpoint.restore(saved, collection, "restored", apply=True)["status"] == "already-restored"


def test_restore_keeps_standing_authorization_historical(tmp_path):
    workspace = module(tmp_path)
    task_collection.write_module_profile(workspace.parent, workspace.name, "controlled-engagement")
    _, policy = engagement_policy.build_activation(
        workspace=workspace, preset="custom", configuration=synthetic_configuration(), host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"], callback_port_ranges=["4400-4500"], expires_at_utc=None,
        source="operator-cli", summary="Synthetic authorized policy", now=NOW,
    )
    engagement_policy.apply_activation(workspace, policy)
    assert engagement_policy.active_standing_authorization(workspace, NOW) is not None
    saved = create_checkpoint.create_checkpoint(
        workspace, tmp_path / "checkpoints", NOW, profile="controlled-engagement", unresolved_session_token_count=0,
        contains_ephemeral_session_secrets=False,
    )[1]
    restore_checkpoint.restore(saved, workspace.parent, "restored", apply=True)
    restored = workspace.parent / "restored"
    assert engagement_policy.active_standing_authorization(restored, NOW) is None
    assert engagement_policy.load_standing_authorizations(restored) == engagement_policy.load_standing_authorizations(workspace)


@pytest.mark.parametrize("after_publish", [False, True])
def test_restore_resumes_after_process_death_around_publication(tmp_path, after_publish):
    workspace = module(tmp_path)
    saved = checkpoint(workspace, tmp_path)
    killed('''
import os, signal, sys
from pathlib import Path
from scripts import artifact_io, restore_checkpoint
original = artifact_io.publish_directory
def stop(source, destination):
    if sys.argv[3] == "True":
        original(source, destination)
    os.kill(os.getpid(), signal.SIGKILL)
artifact_io.publish_directory = stop
restore_checkpoint.restore(Path(sys.argv[1]), Path(sys.argv[2]), "restored", apply=True)
''', saved, workspace.parent, after_publish)
    operation, = (workspace.parent / "_archive").glob("RST-*")
    restore_checkpoint.resume(operation)
    restored = workspace.parent / "restored"
    assert restore_checkpoint.state(restored)["status"] == "inactive"
    assert (operation / "COMMITTED.json").exists()
    restore_checkpoint.resume(operation)


def test_restore_damaged_checkpoint_and_existing_destination_are_never_overwritten(tmp_path):
    workspace = module(tmp_path)
    saved = checkpoint(workspace, tmp_path)
    destination = workspace.parent / "occupied"
    destination.mkdir()
    (destination / "keep").write_bytes(b"preserve")
    with pytest.raises(restore_checkpoint.RestoreError, match="already exists"):
        restore_checkpoint.restore(saved, workspace.parent, "occupied", apply=True)
    assert (destination / "keep").read_bytes() == b"preserve"
    (saved / "workspace/global.md").write_bytes(b"tampered")
    with pytest.raises(create_checkpoint.CheckpointError):
        restore_checkpoint.restore(saved, workspace.parent, "restored", apply=True)
    assert not (workspace.parent / "restored").exists()


def test_restore_archives_old_coordination_and_requires_fresh_registration(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    _, original, _ = stream_coordination.initialize(
        workspace, "CTRL-01", "manual-windows", "synthetic", apply=True, now=NOW,
    )
    coordination_before = hashes(workspace / "private/coordination")
    saved = checkpoint(workspace, tmp_path)
    restore_checkpoint.restore(saved, workspace.parent, "restored", apply=True)
    restored = workspace.parent / "restored"
    assert not (restored / "private/coordination").exists()
    assert hashes(restored / "private/restore_source/coordination") == coordination_before
    with pytest.raises(stream_coordination.CoordinationError, match="inactive"):
        stream_coordination.initialize(restored, "CTRL-02", "manual-windows", "synthetic", apply=True)
    assert not (restored / "private/coordination").exists()
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    _, fresh, _ = stream_coordination.initialize(
        restored, "CTRL-02", "manual-windows", "synthetic", apply=True,
    )
    assert fresh["session_id"] != original["session_id"]
    assert not (restored / "private/coordination/streams/CTRL-01.json").exists()


def test_restored_token_needs_new_validation_provenance_before_promotion(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    task_collection.write_module_profile(workspace.parent, workspace.name, "controlled-engagement")
    retain(workspace, "H01", NOW)
    evidence_id = "EVD-20260820T120000000000Z"
    monkeypatch.setattr(token_lifecycle, "_read_secret_stdin", lambda: b"synthetic-session-for-restore")
    capture = token_lifecycle.parser().parse_args([
        "capture", "--workspace", str(workspace), "--host-id", "H01", "--service", "synthetic-web",
        "--source-evidence-id", evidence_id, "--secret-stdin",
    ])
    token_lifecycle.capture_token(capture, NOW + timedelta(seconds=1))
    token_id = token_lifecycle._load_events(workspace)[0]["token_id"]
    validation = token_lifecycle.parser().parse_args([
        "validate", "--workspace", str(workspace), "--token-id", token_id, "--result", "valid",
        "--evidence-id", evidence_id,
    ])
    token_lifecycle.record_validation(validation, NOW + timedelta(seconds=2))
    saved = create_checkpoint.create_checkpoint(
        workspace, tmp_path / "checkpoints", NOW, profile="controlled-engagement", unresolved_session_token_count=1,
        contains_ephemeral_session_secrets=True,
    )[1]
    restore_checkpoint.restore(saved, workspace.parent, "restored", apply=True)
    restored = workspace.parent / "restored"
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    promotion = token_lifecycle.parser().parse_args([
        "promote", "--workspace", str(restored), "--token-id", token_id,
    ])
    with pytest.raises(token_lifecycle.TokenLifecycleError, match="historical"):
        token_lifecycle.promote_token(promotion, NOW + timedelta(seconds=3))
    validation.workspace = str(restored)
    with pytest.raises(token_lifecycle.TokenLifecycleError, match="new evidence"):
        token_lifecycle.record_validation(validation, NOW + timedelta(seconds=4))
    retain(restored, "H01", NOW + timedelta(seconds=5), b"new synthetic validation trace")
    validation.evidence_id = "EVD-20260820T120005000000Z"
    token_lifecycle.record_validation(validation, NOW + timedelta(seconds=6))
    assert token_lifecycle.promote_token(promotion, NOW + timedelta(seconds=7)) == 0


def test_restore_of_a_restored_checkpoint_gets_another_instance(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    saved = checkpoint(workspace, tmp_path)
    first = restore_checkpoint.restore(saved, workspace.parent, "first", apply=True)
    restored = workspace.parent / "first"
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    second_checkpoint = create_checkpoint.create_checkpoint(
        restored, tmp_path / "checkpoints", NOW + timedelta(seconds=1), profile="strict",
        unresolved_session_token_count=0, contains_ephemeral_session_secrets=False,
    )[1]
    second = restore_checkpoint.restore(second_checkpoint, workspace.parent, "second", apply=True)
    assert second["instance_id"] != first["instance_id"]
    assert restore_checkpoint.state(workspace.parent / "second")["status"] == "inactive"


def test_restore_rejects_symlinked_resume_archive(tmp_path):
    workspace = module(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace.parent / "_archive").symlink_to(outside)
    with pytest.raises(restore_checkpoint.RestoreError, match="invalid"):
        restore_checkpoint.resume(workspace.parent / "_archive" / ("RST-" + "a" * 32))
    assert not any(outside.iterdir())


def test_writer_lease_is_checked_before_evidence_or_screenshot_publication(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    stream_coordination.initialize(workspace, "CTRL-01", "manual-windows", "synthetic", apply=True)
    stream_coordination.register_stream(workspace, "WR-01", "writer", "Synthetic writes", None, apply=True)
    before = hashes(workspace / "evidence")
    with pytest.raises(SystemExit):
        retain(workspace, "H01", NOW)
    with pytest.raises(screenshot_workflow.ScreenshotError, match="active coordination"):
        request(workspace)
    assert hashes(workspace / "evidence") == before
    assert (workspace / screenshot_workflow.LEDGER_NAME).read_bytes() == b""
    assert not tx.incomplete(workspace)

    _, lease, _ = stream_coordination.acquire_lease(workspace, "WR-01", 60, apply=True)
    monkeypatch.setenv("CYBER_STREAM_ID", "WR-01")
    monkeypatch.setenv("CYBER_WRITER_LEASE_ID", lease["lease_id"])
    monkeypatch.setenv("CYBER_WRITER_FENCING_TOKEN", str(lease["fencing_token"]))
    retain(workspace, "H01", NOW)
    request(workspace)
    assert not tx.incomplete(workspace)


def test_diagnostics_are_read_only_and_resolve_keeps_its_path_contract(tmp_path, capsys):
    workspace = module(tmp_path)
    task_collection.write_active_module(workspace.parent, workspace.name)
    before = hashes(workspace)
    modes = {str(path): path.stat().st_mode for path in workspace.rglob("*")}
    args = ["--root", str(workspace.parent)]
    assert task_collection.main([*args, "doctor", "--json"]) == 0
    health = json.loads(capsys.readouterr().out)
    assert health["write_ready"] and health["lease"] == "not-configured"
    assert task_collection.main([*args, "resolve", "--check-write"]) == 0
    output = capsys.readouterr()
    assert output.out == str(workspace) + "\n" and output.err == ""
    assert hashes(workspace) == before
    assert {str(path): path.stat().st_mode for path in workspace.rglob("*")} == modes
    assert not (workspace / ".workspace_mutation.lock").exists()


def test_diagnostics_never_load_journal_payloads_or_evidence(tmp_path, monkeypatch):
    workspace = module(tmp_path)
    retain(workspace, "H01", NOW, b"SYNTHETIC-PRIVATE-EVIDENCE")
    original = tx.read_file
    visited = []
    def metadata_only(path, maximum=tx.MAX_PAYLOAD):
        assert path.suffix != ".bin"
        assert not path.is_relative_to(workspace / "evidence")
        visited.append(path)
        return original(path, maximum)
    monkeypatch.setattr(tx, "read_file", metadata_only)
    health = workspace_health.snapshot(workspace)
    assert health["write_ready"] and visited
    assert "SYNTHETIC-PRIVATE-EVIDENCE" not in json.dumps(health)
    monkeypatch.setattr(workspace_health, "MAX_METADATA_BYTES", 1)
    limited = workspace_health.snapshot(workspace)
    assert limited["blockers"][0]["code"] == "diagnostic-limit"
    assert not limited["write_ready"]


def test_diagnostic_details_are_bounded_without_hiding_pending_count(tmp_path):
    workspace = module(tmp_path)
    for number in range(workspace_health.DETAIL_LIMIT + 1):
        (workspace / tx.DIRECTORY / f"TXN-{number:032x}").mkdir(parents=True, mode=0o700)
    health = workspace_health.snapshot(workspace)
    assert health["pending_count"] == workspace_health.DETAIL_LIMIT + 1
    assert len(health["transactions"]) == workspace_health.DETAIL_LIMIT
    assert health["details_truncated"] and not health["write_ready"]


@pytest.mark.parametrize("condition, expected", [
    ("missing", "missing"), ("expired", "expired"), ("unset", "environment-missing"),
    ("mismatch", "identity-mismatch"), ("valid", "valid"), ("invalid", "invalid"),
])
def test_diagnostics_identify_lease_blockers_without_echoing_environment(tmp_path, monkeypatch, condition, expected):
    workspace = module(tmp_path)
    stream_coordination.initialize(workspace, "CTRL-01", "manual-windows", "synthetic", apply=True)
    stream_coordination.register_stream(workspace, "WR-01", "writer", "Synthetic", None, apply=True)
    if condition != "missing":
        _, lease, _ = stream_coordination.acquire_lease(workspace, "WR-01", 60, apply=True, now=NOW)
        monkeypatch.setenv("CYBER_STREAM_ID", "WR-01")
        monkeypatch.setenv("CYBER_WRITER_LEASE_ID", lease["lease_id"])
        monkeypatch.setenv("CYBER_WRITER_FENCING_TOKEN", str(lease["fencing_token"]))
    if condition == "unset":
        monkeypatch.delenv("CYBER_STREAM_ID")
    if condition == "mismatch":
        monkeypatch.setenv("CYBER_WRITER_LEASE_ID", "SYNTHETIC-ENV-SECRET")
    if condition == "invalid":
        path = workspace / "private/coordination/runtime/writer_lease.json"
        path.write_bytes(b'{"SYNTHETIC-RECORD-SECRET": invalid-json}')
    before = hashes(workspace)
    health = workspace_health.snapshot(workspace, now=NOW + timedelta(seconds=61 if condition == "expired" else 1))
    assert health["lease"] == expected
    assert health["write_ready"] is (condition == "valid")
    assert "SYNTHETIC-ENV-SECRET" not in json.dumps(health)
    assert "SYNTHETIC-RECORD-SECRET" not in json.dumps(health)
    assert hashes(workspace) == before


def test_busy_writer_is_reported_immediately_without_history_parsing(tmp_path, capsys):
    workspace = module(tmp_path)
    descriptor = os.open(workspace / ".workspace_mutation.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        health = workspace_health.snapshot(workspace)
        assert health["blockers"][0]["code"] == "workspace-busy"
        assert not health["history_readable"]
        assert workspace_status.main(["--workspace", str(workspace), "--host-id", "H01"]) == 2
        assert "workspace-busy" in capsys.readouterr().out
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("damage", ["symlink", "malformed", "limit", "unprepared"])
def test_diagnostics_fail_closed_on_journal_damage_and_bound_details(tmp_path, monkeypatch, damage):
    workspace = module(tmp_path)
    directory = workspace / tx.DIRECTORY / ("TXN-" + "a" * 32)
    directory.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"SYNTHETIC-UNTRUSTED-SECRET")
    if damage == "symlink":
        (directory / "plan.json").symlink_to(outside)
    elif damage == "malformed":
        (directory / "plan.json").write_bytes(outside.read_bytes())
    elif damage == "limit":
        monkeypatch.setattr(workspace_health, "MAX_ENTRIES", 0)
    before = hashes(workspace)
    health = workspace_health.snapshot(workspace)
    assert not health["write_ready"] and not health["history_readable"]
    assert "SYNTHETIC-UNTRUSTED-SECRET" not in json.dumps(health)
    if damage == "unprepared":
        assert health["transactions"] == [{"transaction_id": directory.name, "state": "unprepared-staging"}]
    if damage == "limit":
        assert health["details_truncated"]
    assert hashes(workspace) == before


def test_full_local_flow_intake_merge_crash_recovery_restore_session_report(tmp_path, monkeypatch, capsys):
    workspace = module(tmp_path)
    task_collection.write_active_module(workspace.parent, workspace.name)
    first = scanner_intake.build_plan(
        workspace=str(workspace), host_id="H01", source_tool="manual", label="Synthetic interface identity",
        extension="txt", input_bytes=b"same.synthetic.test 192.0.2.10\n",
    )
    first_record, _ = scanner_intake.apply_plan(first, now=NOW)
    requested = request(workspace)
    new_host.bootstrap_host(workspace, ROOT / "scripts", "H02", "192.0.2.20", "same.synthetic.test")
    second = scanner_intake.build_plan(
        workspace=str(workspace), host_id="H02", source_tool="manual", label="Synthetic second interface",
        extension="txt", input_bytes=b"same.synthetic.test 192.0.2.20\n",
    )
    second_record, _ = scanner_intake.apply_plan(second, now=NOW + timedelta(seconds=1))
    plan = host_identity.build_merge_plan(
        workspace, "H01", "H02", first_record["evidence_id"], second_record["evidence_id"],
        "Synthetic retained identity matches both interfaces.",
    )
    host_identity.apply_merge_plan(plan, now=NOW + timedelta(seconds=4))
    killed('''
import os, signal, sys
from datetime import datetime, UTC
from scripts import screenshot_workflow, workspace_transaction as tx
tx._after_operation = lambda _, index: os.kill(os.getpid(), signal.SIGKILL) if index == 2 else None
screenshot_workflow.screenshot_main(sys.argv[1:], now=datetime(2026,8,20,12,0,5,tzinfo=UTC))
''', *review_arguments(workspace))
    capsys.readouterr()
    before_diagnostics = hashes(workspace)
    assert workspace_status.main(["--workspace", str(workspace)]) == 2
    assert "unfinished-transactions" in capsys.readouterr().out
    args = ["--root", str(workspace.parent)]
    assert task_collection.main([*args, "doctor", "--json"]) == 2
    health = json.loads(capsys.readouterr().out)
    identifier = health["transactions"][0]["transaction_id"]
    assert health["pending_count"] == 1
    assert task_collection.main([*args, "resolve", "--check-write"]) == 2
    assert capsys.readouterr().out == ""
    assert task_collection.main([*args, "resolve"]) == 0
    output = capsys.readouterr()
    assert output.out == str(workspace) + "\n"
    assert "unfinished-transactions" in output.err
    assert hashes(workspace) == before_diagnostics
    assert tx.main(["apply", "--workspace", str(workspace), "--transaction", identifier]) == 0
    assert tx.main(["apply", "--workspace", str(workspace), "--transaction", identifier]) == 0
    assert workspace_health.snapshot(workspace)["write_ready"]
    events = screenshot_workflow._load_events(workspace / screenshot_workflow.LEDGER_NAME)
    assert events[0] == requested and [item["event"] for item in events] == ["requested", "captured"]
    assert host_identity.canonical_host_id(workspace, "H01") == "H02"
    screenshot_workflow._verify_evidence(workspace, requested, events[1])
    check = ["check", "--workspace", str(workspace), "--contract", "operational", "--barrier", "manual"]
    assert screenshot_workflow.report_main(check) == 0
    original_session = stream_coordination.initialize(
        workspace, "CTRL-OLD", "manual-windows", "synthetic", apply=True,
    )[1]
    saved = checkpoint(workspace, tmp_path)
    source_before = hashes(workspace)
    restore_checkpoint.restore(saved, workspace.parent, "restored", apply=True)
    restored = workspace.parent / "restored"
    capsys.readouterr()
    assert task_collection.main([*args, "doctor", "--module", "restored", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["runtime"] == "inactive"
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    assert workspace_health.snapshot(restored)["runtime"] == "instance-mismatch"
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    task_collection.write_active_module(workspace.parent, "restored")
    fresh_session = stream_coordination.initialize(
        restored, "CTRL-NEW", "manual-windows", "synthetic", apply=True,
    )[1]
    assert fresh_session["session_id"] != original_session["session_id"]
    stream_coordination.register_stream(restored, "WR-NEW", "writer", "Synthetic local continuation", None, apply=True)
    _, lease, _ = stream_coordination.acquire_lease(restored, "WR-NEW", 60, apply=True)
    monkeypatch.setenv("CYBER_STREAM_ID", "WR-NEW")
    monkeypatch.setenv("CYBER_WRITER_LEASE_ID", lease["lease_id"])
    monkeypatch.setenv("CYBER_WRITER_FENCING_TOKEN", str(lease["fencing_token"]))
    assert task_collection.main([*args, "resolve", "--check-write"]) == 0
    assert workspace_health.snapshot(restored)["write_ready"]
    assert workspace_status.main(["--workspace", str(restored)]) == 0
    check[2] = str(restored)
    assert screenshot_workflow.report_main(check) == 0
    restore_checkpoint.validate_restored(restored)
    assert hashes(restored / "evidence") == hashes(workspace / "evidence")
    assert host_identity.host_paths(restored, "H02").report.read_bytes() == host_identity.host_paths(workspace, "H02").report.read_bytes()
    assert hashes(workspace) == source_before
    assert len(host_identity.applied_merges(restored)) == 1
    assert len(screenshot_workflow._load_events(restored / screenshot_workflow.LEDGER_NAME)) == 2

    # A real supported local write proves that the new instance/lease combination works.
    _, artifact, record = retain(restored, "H02", NOW + timedelta(seconds=6), b"Synthetic local continuation")
    assert record["host_id"] == "H02"
    assert artifact.read_bytes() == b"Synthetic local continuation"
    assert workspace_health.snapshot(restored)["write_ready"]
    assert screenshot_workflow.report_main(check) == 0
    assert hashes(workspace) == source_before
