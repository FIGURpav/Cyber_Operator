"""Synthetic retention tests: duplicate bytes only, reviewed plans, crash recovery."""

import json
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import (
    capture_evidence,
    create_checkpoint,
    new_host,
    restore_checkpoint,
    task_collection,
    workspace_health,
)
from scripts import (
    storage_retention as storage,
)
from scripts import (
    workspace_transaction as tx,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 9, tzinfo=UTC)


def workspace(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir(mode=0o700)
    task_collection.apply_module_plan(task_collection.build_module_plan(collection, "source", intake_mode="chat"), ROOT / "scripts")
    root = collection / "source"
    new_host.bootstrap_host(root, ROOT / "scripts", "H01", "192.0.2.10", "synthetic.test")
    source = tmp_path / "input.txt"
    source.write_bytes(b"SYNTHETIC-RETAINED-EVIDENCE" * 200)
    _, artifact, _ = capture_evidence.capture_evidence(str(root), "H01", "manual", "Synthetic", "txt", str(source), now=NOW)
    identifier, = [path.name for path in (root / tx.DIRECTORY).iterdir()]
    return root, identifier, artifact


def tree(root):
    return {str(path.relative_to(root)): (path.stat().st_mode, path.read_bytes())
            for path in root.rglob("*") if path.is_file() and not path.is_symlink()}


def checkpoint(root, tmp_path):
    return create_checkpoint.create_checkpoint(root, tmp_path / "checkpoints", NOW, profile="strict",
                                              unresolved_session_token_count=0, contains_ephemeral_session_secrets=False)[1]


def restored_with_copy(root, tmp_path):
    saved = checkpoint(root, tmp_path)
    restore_checkpoint.restore(saved, root.parent, "restored", apply=True)
    operation, = (root.parent / "_archive").glob("RST-*")
    copy = operation / ("copy-" + "b" * 32)
    copy.mkdir(mode=0o700)
    create_checkpoint.copy_workspace(saved / "workspace", copy)
    return saved, operation, copy


def test_usage_and_preview_are_read_only_and_content_free(tmp_path):
    root, identifier, _ = workspace(tmp_path)
    before = tree(root)
    usage = storage.inventory(root)
    assert usage["logical_bytes"] > 0 and usage["allocated_bytes"] > 0
    assert usage["items"][0]["id"] == identifier
    assert usage["workspace_volume"]["available_bytes"] > 0
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    assert preview["candidate_files"] == 2 and preview["candidate_bytes"] > 0
    assert "SYNTHETIC-RETAINED-EVIDENCE" not in json.dumps([usage, preview])
    assert tree(root) == before


def test_compaction_keeps_canonical_bytes_audit_and_replay(tmp_path):
    root, identifier, artifact = workspace(tmp_path)
    evidence_before = tree(root / "evidence")
    directory = root / tx.DIRECTORY / identifier
    plan_before = (directory / "plan.json").read_bytes()
    receipt_before = (directory / "COMMITTED.json").read_bytes()
    before_bytes = storage.inventory(root)["logical_bytes"]
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    result = storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert result["status"] == "pruned"
    assert tree(root / "evidence") == evidence_before and artifact.is_file()
    assert (directory / "plan.json").read_bytes() == plan_before
    assert (directory / "COMMITTED.json").read_bytes() == receipt_before
    assert not list(directory.glob("*.bin"))
    assert storage.inventory(root)["logical_bytes"] < before_bytes
    assert tx.replay(root, identifier) == identifier
    assert workspace_health.snapshot(root)["write_ready"]
    assert storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)["status"] == "already-pruned"


@pytest.mark.parametrize("damage", ["ack", "age", "canonical", "payload", "symlink", "uncommitted"])
def test_compaction_refuses_changed_or_unreviewed_inputs(tmp_path, damage):
    root, identifier, artifact = workspace(tmp_path)
    directory = root / tx.DIRECTORY / identifier
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    if damage == "canonical":
        artifact.write_bytes(b"modified canonical data")
    elif damage == "payload":
        (directory / "0000.bin").write_bytes(b"modified candidate")
    elif damage == "symlink":
        (directory / "0000.bin").unlink()
        (directory / "0000.bin").symlink_to(artifact)
    elif damage == "uncommitted":
        (directory / "COMMITTED.json").unlink()
    before = tree(root)
    with pytest.raises((OSError, RuntimeError, ValueError)):
        storage.compact(root, identifier, apply=True,
                        expected_hash=None if damage == "ack" else preview["plan_hash"],
                        min_age_days=7 if damage == "age" else 0)
    assert tree(root) == before


@pytest.mark.parametrize("seam", ["_after_quarantine", "_after_unlink"])
def test_compaction_survives_sigkill_and_preserves_ids(tmp_path, seam):
    root, identifier, _ = workspace(tmp_path)
    canonical = tree(root / "evidence")
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    code = '''
import os, signal, sys
from pathlib import Path
from scripts import storage_retention as storage
setattr(storage, sys.argv[4], lambda _: os.kill(os.getpid(), signal.SIGKILL))
storage.compact(Path(sys.argv[1]), sys.argv[2], apply=True, expected_hash=sys.argv[3], min_age_days=0)
'''
    result = subprocess.run([sys.executable, "-c", code, str(root), identifier, preview["plan_hash"], seam],
                            cwd=ROOT, capture_output=True, check=False, timeout=20)
    assert result.returncode == -signal.SIGKILL, result.stderr.decode()
    assert tx.replay(root, identifier) == identifier
    resumed = storage.compact(root, identifier, apply=False, min_age_days=0)
    assert resumed["plan_hash"] == preview["plan_hash"]
    storage.compact(root, identifier, apply=True, expected_hash=resumed["plan_hash"], min_age_days=0)
    assert tree(root / "evidence") == canonical
    assert not list((root / tx.DIRECTORY / identifier).glob("*.bin"))
    assert not list((root / tx.DIRECTORY / identifier).glob(".retention-*"))


def test_compacted_journals_survive_checkpoint_and_restore(tmp_path, monkeypatch):
    root, identifier, _ = workspace(tmp_path)
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    saved = checkpoint(root, tmp_path)
    restore_checkpoint.restore(saved, root.parent, "restored", apply=True)
    restored = root.parent / "restored"
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    assert tx.replay(restored, identifier) == identifier
    assert workspace_health.snapshot(restored)["write_ready"]
    assert tree(root / "evidence") == tree(restored / "evidence")


def test_restore_prune_removes_only_checkpoint_identical_files(tmp_path):
    root, _, _ = workspace(tmp_path)
    saved, operation, copy = restored_with_copy(root, tmp_path)
    changed = copy / "workspace/TASK_CONTEXT.md"
    changed.write_bytes(b"Different context retained for review")
    unknown = copy / "operator-note.txt"
    unknown.write_bytes(b"Keep this unknown file")
    unknown.chmod(0o600)
    source_before, checkpoint_before, restored_before = tree(root), tree(saved), tree(root.parent / "restored")
    before = tree(copy)
    preview = storage.prune_restore(root.parent, operation.name, copy.name, apply=False, min_age_days=0)
    assert preview["candidate_files"] > 0 and tree(copy) == before
    storage.prune_restore(root.parent, operation.name, copy.name, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert tree(copy) == {"workspace/TASK_CONTEXT.md": before["workspace/TASK_CONTEXT.md"], "operator-note.txt": before["operator-note.txt"]}
    assert tree(root) == source_before and tree(saved) == checkpoint_before
    assert tree(root.parent / "restored") == restored_before
    restore_checkpoint.resume(operation)


@pytest.mark.parametrize("damage", ["checkpoint", "symlink", "uncommitted", "changed-copy"])
def test_restore_prune_refuses_unsafe_sources(tmp_path, damage):
    root, _, _ = workspace(tmp_path)
    saved, operation, copy = restored_with_copy(root, tmp_path)
    preview = storage.prune_restore(root.parent, operation.name, copy.name, apply=False, min_age_days=0)
    if damage == "checkpoint":
        (saved / "workspace/global.md").write_bytes(b"damaged")
    elif damage == "symlink":
        (copy / "linked").symlink_to(root / "global.md")
    elif damage == "uncommitted":
        (operation / "COMMITTED.json").unlink()
    else:
        (copy / "workspace/global.md").write_bytes(b"changed after preview")
    before = tree(copy)
    with pytest.raises((OSError, RuntimeError, ValueError, create_checkpoint.CheckpointError)):
        storage.prune_restore(root.parent, operation.name, copy.name, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert tree(copy) == before


def test_restore_prune_resume_after_interrupted_deletion(tmp_path, monkeypatch):
    root, _, _ = workspace(tmp_path)
    _, operation, copy = restored_with_copy(root, tmp_path)
    preview = storage.prune_restore(root.parent, operation.name, copy.name, apply=False, min_age_days=0)
    def fail(_):
        raise RuntimeError("synthetic interruption")
    monkeypatch.setattr(storage, "_after_unlink", fail)
    with pytest.raises(RuntimeError):
        storage.prune_restore(root.parent, operation.name, copy.name, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    monkeypatch.setattr(storage, "_after_unlink", lambda _: None)
    resumed = storage.prune_restore(root.parent, operation.name, copy.name, apply=False, min_age_days=0)
    assert resumed["plan_hash"] == preview["plan_hash"]
    storage.prune_restore(root.parent, operation.name, copy.name, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert not tree(copy)


def test_inventory_uses_metadata_only_and_a_shared_entry_budget(tmp_path, monkeypatch):
    root, _, _ = workspace(tmp_path)
    _, _, _ = restored_with_copy(root, tmp_path)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("inventory must not read payloads")
    monkeypatch.setattr(tx, "read_file", forbidden)
    monkeypatch.setattr(create_checkpoint, "_file_digest", forbidden)
    usage = storage.inventory(root, root.parent)
    assert {item["category"] for item in usage["items"]} == {"journal", "restore-copy"}
    monkeypatch.setattr(storage, "MAX_ENTRIES", 2)
    with pytest.raises(storage.RetentionError, match="entry limit"):
        storage.inventory(root, root.parent)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_inventory_refuses_linked_recovery_data(tmp_path, kind):
    root, identifier, artifact = workspace(tmp_path)
    linked = root / tx.DIRECTORY / identifier / "unexpected"
    if kind == "symlink":
        linked.symlink_to(artifact)
    else:
        linked.hardlink_to(artifact)
    with pytest.raises(storage.RetentionError):
        storage.inventory(root)


def test_compaction_preserves_unknown_files_and_replaced_candidates(tmp_path, monkeypatch):
    root, identifier, _ = workspace(tmp_path)
    directory = root / tx.DIRECTORY / identifier
    unknown = directory / "operator-note.txt"
    unknown.write_bytes(b"unrecognized data must remain")
    unknown.chmod(0o600)
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    def replace(trash):
        trash.write_bytes(b"substitution after quarantine")
    monkeypatch.setattr(storage, "_after_quarantine", replace)
    with pytest.raises(storage.RetentionError, match="quarantined entry changed"):
        storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert unknown.read_bytes() == b"unrecognized data must remain"
    retained, = directory.glob(".retention-*")
    assert retained.read_bytes() == b"substitution after quarantine"
    assert not (directory / "COMPACTED.json").exists()


@pytest.mark.parametrize("damage", ["uncommitted", "path", "receipt"])
def test_compaction_replay_refuses_fabricated_metadata(tmp_path, monkeypatch, damage):
    root, identifier, _ = workspace(tmp_path)
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    directory = root / tx.DIRECTORY / identifier
    if damage == "uncommitted":
        (directory / "COMMITTED.json").unlink()
    elif damage == "receipt":
        (directory / "COMPACTED.json").write_text("{}")
    else:
        job = json.loads((directory / "COMPACTION.json").read_text())
        job["files"][0]["path"] = "../../global.md"
        (directory / "COMPACTION.json").write_text(json.dumps(job))
    before = tree(root)
    with pytest.raises((OSError, RuntimeError, ValueError)):
        tx.replay(root, identifier)
    assert tree(root) == before


def test_interrupted_compaction_checkpoint_restores_usable_history(tmp_path, monkeypatch):
    root, identifier, _ = workspace(tmp_path)
    preview = storage.compact(root, identifier, apply=False, min_age_days=0)
    def fail(_):
        raise RuntimeError("synthetic interruption")
    monkeypatch.setattr(storage, "_after_quarantine", fail)
    with pytest.raises(RuntimeError):
        storage.compact(root, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    saved = checkpoint(root, tmp_path)
    restore_checkpoint.restore(saved, root.parent, "restored", apply=True)
    restored = root.parent / "restored"
    active = restore_checkpoint.activate(restored, apply=True, acknowledge=True)
    monkeypatch.setenv("CYBER_WORKSPACE_INSTANCE", active["instance_id"])
    assert tx.replay(restored, identifier) == identifier
    assert workspace_health.snapshot(restored)["write_ready"]
    before = tree(restored)
    # Retained byte hashes remain valid, but deletion approval is bound to the
    # original file identities. Restoring does not transfer that approval.
    with pytest.raises(storage.RetentionError, match="changed after preview"):
        storage.compact(restored, identifier, apply=True, expected_hash=preview["plan_hash"], min_age_days=0)
    assert tree(restored) == before
