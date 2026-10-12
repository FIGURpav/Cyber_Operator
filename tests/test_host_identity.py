"""Synthetic tests for friendly host storage and automatic first relabel."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import (
    build_brief,
    capture_evidence,
    credential_intake,
    host_identity,
    log_attempt,
    log_loot,
    log_observation,
    log_query,
    new_host,
    operational_trace,
    operator_intake,
    report_contract,
    workspace_status,
)

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
CAPTURE_TIME = datetime(2026, 8, 17, 12, 0, 0, 123456, tzinfo=UTC)
RELABEL_TIME = datetime(2026, 8, 17, 12, 1, 0, 123456, tzinfo=UTC)
EVIDENCE_ID = "EVD-20260817T120000123456Z"
SOURCE_EVIDENCE_ID = "EVD-20260817T120100123456Z"
MERGE_TIME = datetime(2026, 8, 17, 12, 2, 0, 123456, tzinfo=UTC)


def workspace_with_evidence(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    new_host.bootstrap_host(workspace, SCRIPTS, "H01", "192.0.2.40", "initial")
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n",
        encoding="utf-8",
    )
    source = tmp_path / "scan.txt"
    source.write_bytes(b"confirmed hostname Client04\n")
    capture_evidence.capture_evidence(
        str(workspace),
        "H01",
        "nmap",
        "hostname enumeration",
        "txt",
        str(source),
        now=CAPTURE_TIME,
    )
    return workspace


def workspace_with_merge_candidates(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    new_host.bootstrap_host(workspace, SCRIPTS, "H01", "192.0.2.40", "ENG-WS02")
    new_host.bootstrap_host(workspace, SCRIPTS, "H02", "198.51.100.80", "ENG-WS02")
    destination = tmp_path / "destination.txt"
    destination.write_bytes(b"ENG-WS02 192.0.2.40\n")
    source = tmp_path / "source.txt"
    source.write_bytes(b"ENG-WS02 198.51.100.80\n")
    capture_evidence.capture_evidence(
        str(workspace),
        "H01",
        "ipconfig",
        "destination hostname and endpoint",
        "txt",
        str(destination),
        now=CAPTURE_TIME,
    )
    capture_evidence.capture_evidence(
        str(workspace),
        "H02",
        "ipconfig",
        "source hostname and endpoint",
        "txt",
        str(source),
        now=CAPTURE_TIME.replace(minute=1),
    )
    return workspace


def merge_plan(workspace: Path) -> host_identity.MergePlan:
    return host_identity.build_merge_plan(
        workspace,
        "H02",
        "H01",
        SOURCE_EVIDENCE_ID,
        EVIDENCE_ID,
        "Confirmed second interface of the same host.",
    )


def test_preview_is_read_only_and_shows_friendly_destinations(tmp_path: Path) -> None:
    workspace = workspace_with_evidence(tmp_path)
    before = sorted(path.relative_to(workspace) for path in workspace.rglob("*"))

    plan = host_identity.build_relabel_plan(
        workspace, "H01", "Client04", EVIDENCE_ID
    )

    assert plan.automatic_relabel is True
    assert plan.target_storage_key == "Client04-192.0.2.40-H01"
    assert len(plan.root_renames) == 4
    assert {item.destination.name for item in plan.evidence_renames} == {
        f"Client04-{EVIDENCE_ID}.json",
        f"Client04-{EVIDENCE_ID}.txt",
    }
    assert sorted(path.relative_to(workspace) for path in workspace.rglob("*")) == before


def test_apply_relabels_explorer_paths_without_changing_canonical_ids(
    tmp_path: Path,
) -> None:
    workspace = workspace_with_evidence(tmp_path)
    old_metadata = workspace / "evidence" / "H01" / f"{EVIDENCE_ID}.json"
    metadata_bytes = old_metadata.read_bytes()

    plan = host_identity.build_relabel_plan(
        workspace, "H01", "Client04", EVIDENCE_ID
    )
    event = host_identity.apply_relabel_plan(plan, now=RELABEL_TIME)

    storage = "Client04-192.0.2.40-H01"
    assert event["status"] == "applied"
    assert not (workspace / "hosts" / "H01.md").exists()
    assert (workspace / "hosts" / f"{storage}.md").is_file()
    assert (workspace / "report" / f"{storage}.md").is_file()
    assert (workspace / "inbox" / storage).is_dir()
    evidence_dir = workspace / "evidence" / storage
    metadata = evidence_dir / f"Client04-{EVIDENCE_ID}.json"
    artifact = evidence_dir / f"Client04-{EVIDENCE_ID}.txt"
    assert metadata.read_bytes() == metadata_bytes
    assert artifact.read_bytes() == b"confirmed hostname Client04\n"
    record = json.loads(metadata.read_text(encoding="utf-8"))
    assert record["host_id"] == "H01"
    assert record["evidence_id"] == EVIDENCE_ID
    assert host_identity.resolve_host(workspace, "Client04").host_id == "H01"
    assert host_identity.resolve_host(workspace, storage).host_id == "H01"
    assert host_identity.locate_evidence_metadata(
        workspace, "H01", EVIDENCE_ID
    ) == metadata
    assert host_identity.locate_evidence_artifact(metadata, record) == artifact


def test_new_evidence_after_relabel_uses_friendly_filename(tmp_path: Path) -> None:
    workspace = workspace_with_evidence(tmp_path)
    host_identity.apply_relabel_plan(
        host_identity.build_relabel_plan(workspace, "H01", "Client04", EVIDENCE_ID),
        now=RELABEL_TIME,
    )
    source = tmp_path / "later.txt"
    source.write_bytes(b"later evidence\n")
    later = datetime(2026, 8, 17, 12, 2, 0, 654321, tzinfo=UTC)

    _, artifact, record = capture_evidence.capture_evidence(
        str(workspace),
        "H01",
        "nmap",
        "later scan",
        "txt",
        str(source),
        now=later,
    )

    assert artifact.name == "Client04-EVD-20260817T120200654321Z.txt"
    assert record["host_id"] == "H01"
    assert record["evidence_id"] == "EVD-20260817T120200654321Z"


def test_subsequent_confirmed_name_is_alias_only(tmp_path: Path) -> None:
    workspace = workspace_with_evidence(tmp_path)
    host_identity.apply_relabel_plan(
        host_identity.build_relabel_plan(workspace, "H01", "Client04", EVIDENCE_ID),
        now=RELABEL_TIME,
    )

    plan = host_identity.build_relabel_plan(
        workspace, "H01", "client04.lab", EVIDENCE_ID
    )
    event = host_identity.apply_relabel_plan(
        plan, now=RELABEL_TIME.replace(minute=3)
    )

    assert plan.automatic_relabel is False
    assert event["status"] == "alias_recorded"
    assert host_identity.resolve_host(workspace, "H01").storage_key == (
        "Client04-192.0.2.40-H01"
    )
    assert host_identity.resolve_host(workspace, "client04.lab").host_id == "H01"


def test_relocated_evidence_remains_valid_across_consumers(tmp_path: Path) -> None:
    workspace = workspace_with_evidence(tmp_path)
    host_identity.apply_relabel_plan(
        host_identity.build_relabel_plan(workspace, "H01", "Client04", EVIDENCE_ID),
        now=RELABEL_TIME,
    )

    observation_code = log_observation.main(
        [
            "--workspace",
            str(workspace),
            "--host-id",
            "H01",
            "--kind",
            "note",
            "--state",
            "confirmed",
            "--source-tool",
            "hostname",
            "--note",
            "Confirmed friendly host identity",
            "--evidence",
            EVIDENCE_ID,
        ],
        now=RELABEL_TIME.replace(minute=4),
    )

    assert observation_code == 0
    assert operational_trace._evidence_ids(workspace) == {EVIDENCE_ID}
    assert set(report_contract._evidence_index(workspace)) == {EVIDENCE_ID}
    status = workspace_status.generate_status(
        workspace, "H01", RELABEL_TIME.replace(minute=5)
    )
    assert "Host Client04-192.0.2.40-H01 (canonical: H01)" in status


def test_host_bootstrap_cannot_duplicate_a_relabelled_canonical_id(
    tmp_path: Path,
) -> None:
    workspace = workspace_with_evidence(tmp_path)
    host_identity.apply_relabel_plan(
        host_identity.build_relabel_plan(workspace, "H01", "Client04", EVIDENCE_ID),
        now=RELABEL_TIME,
    )

    try:
        new_host.bootstrap_host(
            workspace, SCRIPTS, "H01", "192.0.2.40", "Client04"
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("relabelled H01 was duplicated")

    assert not (workspace / "hosts" / "H01.md").exists()
    assert len(host_identity.discover_hosts(workspace)) == 1


def test_merge_preview_is_byte_and_mode_read_only(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    before = {
        path.relative_to(workspace): (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            os.stat(path, follow_symlinks=False).st_mode,
        )
        for path in workspace.rglob("*")
        if path.is_file() and not path.is_symlink()
    }

    plan = merge_plan(workspace)

    after = {
        path.relative_to(workspace): (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            os.stat(path, follow_symlinks=False).st_mode,
        )
        for path in workspace.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    assert plan.destination.path.name == "H01.md"
    assert plan.archive_path == workspace / "hosts" / "_merged" / "H02.md"
    assert before == after
    assert (workspace / host_identity.MERGE_LEDGER_NAME).read_bytes() == b""


def test_merge_apply_preserves_destination_and_historical_evidence(
    tmp_path: Path,
) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    old_source_metadata = (
        workspace / "evidence" / "H02" / f"{SOURCE_EVIDENCE_ID}.json"
    )
    old_hash = hashlib.sha256(old_source_metadata.read_bytes()).hexdigest()

    event = host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)

    assert event["status"] == "applied"
    assert event["rollback_status"] == "not-required"
    assert (workspace / "hosts" / "H01.md").is_file()
    assert not (workspace / "hosts" / "H02.md").exists()
    assert (workspace / "hosts" / "_merged" / "H02.md").is_file()
    assert stat_mode(workspace / "hosts" / "_merged") == 0o700
    text = (workspace / "hosts" / "H01.md").read_text(encoding="utf-8")
    assert "## Canonical endpoints" in text
    assert "- Primary: `192.0.2.40`" in text
    assert "- Additional: `198.51.100.80`" in text
    assert host_identity.host_endpoints(workspace, "H01") == (
        "192.0.2.40",
        "198.51.100.80",
    )
    assert host_identity.merged_host_ids(workspace, "H01") == ("H02",)
    for selector in ("H01", "H02", "192.0.2.40", "198.51.100.80", "ENG-WS02"):
        assert host_identity.resolve_host(workspace, selector).host_id == "H01"
    assert host_identity.known_host_ids(workspace) == {"H01", "H02"}
    metadata = host_identity.locate_evidence_metadata(
        workspace, "H02", SOURCE_EVIDENCE_ID
    )
    assert hashlib.sha256(metadata.read_bytes()).hexdigest() == old_hash
    assert set(report_contract._evidence_index(workspace)) == {
        EVIDENCE_ID,
        SOURCE_EVIDENCE_ID,
    }
    assert operational_trace._evidence_ids(workspace) == {
        EVIDENCE_ID,
        SOURCE_EVIDENCE_ID,
    }
    ledger = [
        json.loads(line)
        for line in (workspace / host_identity.MERGE_LEDGER_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [item["status"] for item in ledger] == ["planned", "applied"]
    assert len({item["merge_id"] for item in ledger}) == 1


def test_merged_history_is_visible_without_rewriting_records(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    (workspace / "TASK_CONTEXT.md").write_text("- Current task: synthetic\n")
    summary = tmp_path / "summary.txt"
    summary.write_text("Synthetic history summary\n")
    _, _, attempt = log_attempt.log_attempt(
        str(workspace), "H02", "Synthetic history", "success", "review",
        [SOURCE_EVIDENCE_ID], str(summary), now=CAPTURE_TIME,
    )
    log_loot.log_loot(
        str(workspace), "H02", "note", "Synthetic note", "manual", None,
        str(summary), now=CAPTURE_TIME,
    )
    log_query.log_query(
        str(workspace), "Synthetic history", ["H01", "H02"],
        prompt_file=str(summary), now=CAPTURE_TIME,
    )
    assert log_observation.main([
        "--workspace", str(workspace), "--host-id", "H02", "--kind", "note",
        "--state", "confirmed", "--source-tool", "manual", "--note", "Synthetic history",
        "--evidence", SOURCE_EVIDENCE_ID,
    ], now=CAPTURE_TIME) == 0
    retained = {
        path: path.read_bytes()
        for pattern in ("*.jsonl", "queries/*.json", "evidence/*/*")
        for path in workspace.glob(pattern)
        if path.is_file() and path.name != host_identity.MERGE_LEDGER_NAME
    }
    host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)
    for selector in ("H01", "H02"):
        brief, stats = build_brief.build_brief(workspace, selector, 10, 10, 10, 10, MERGE_TIME)
        assert stats["host_id"] == "H01"
        for field in ("total_attempts", "total_loot", "total_queries", "total_observations"):
            assert stats[field] == 1
        assert str(attempt["attempt_id"]) in brief
        status = "\n".join(workspace_status.generate_status(workspace, selector, MERGE_TIME))
        assert "Attempts: 1 (success=1" in status
        assert "Loot: 1" in status
        assert "AI queries: 1" in status
        assert "Evidence: 2" in status
        assert "Observations: 1" in status
    assert {path: path.read_bytes() for path in retained} == retained
    # A new reference to the retained source EVD is valid on the merged host.
    _, _, latest = log_attempt.log_attempt(
        str(workspace), "H01", "Review retained history", "success", "review",
        [SOURCE_EVIDENCE_ID], str(summary), now=CAPTURE_TIME.replace(hour=11),
    )
    # A historical backfill appended later must remain last in ledger order.
    status = "\n".join(workspace_status.generate_status(workspace, "H01", MERGE_TIME))
    assert f"Latest attempt: {latest['attempt_id']}" in status


def test_new_evidence_through_merged_selector_is_canonicalized(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)
    source = tmp_path / "later.txt"
    source.write_bytes(b"later\n")

    _, artifact, record = capture_evidence.capture_evidence(
        str(workspace),
        "H02",
        "manual",
        "canonicalized merged selector",
        "txt",
        str(source),
        now=MERGE_TIME.replace(minute=3),
    )

    assert record["host_id"] == "H01"
    assert artifact.parent == workspace / "evidence" / "H01"


def test_merge_rejects_mismatched_hostname_and_foreign_evidence(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    source_card = workspace / "hosts" / "H02.md"
    source_card.write_text(
        source_card.read_text(encoding="utf-8").replace("ENG-WS02", "OTHER"),
        encoding="utf-8",
    )
    with pytest.raises(host_identity.HostIdentityError, match="matching confirmed"):
        merge_plan(workspace)
    source_card.write_text(
        source_card.read_text(encoding="utf-8").replace("OTHER", "ENG-WS02"),
        encoding="utf-8",
    )
    with pytest.raises(host_identity.HostIdentityError, match="does not resolve uniquely"):
        host_identity.build_merge_plan(
            workspace,
            "H02",
            "H01",
            EVIDENCE_ID,
            SOURCE_EVIDENCE_ID,
            "Evidence ownership is deliberately reversed.",
        )


@pytest.mark.parametrize(
    "selector",
    (
        "host: H01",
        "host: H02",
        "ip: 192.0.2.40",
        "ip: 198.51.100.80",
        "hostname: ENG-WS02",
    ),
)
def test_credential_selectors_canonicalize_to_destination(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    selector: str,
) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)
    intake = tmp_path / "credential.txt"
    intake.write_text(
        f"{selector}\nusername: fictional\nservice: synthetic\npassword: MergeSynthetic-7!\n",
        encoding="utf-8",
    )

    result = credential_intake.main(
        [
            "--workspace",
            str(workspace),
            "--input-file",
            str(intake),
            "--preview",
        ],
        now=MERGE_TIME.replace(minute=4),
    )

    output = capsys.readouterr()
    assert result == 0, output.err
    assert "host_id=H01" in output.out
    assert "MergeSynthetic-7!" not in output.out + output.err


def test_host_mapping_intake_treats_additional_endpoint_as_existing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)
    intake = tmp_path / "mapping.txt"
    intake.write_text("198.51.100.80 ENG-WS02\n", encoding="utf-8")

    result = operator_intake.main(
        [
            "--workspace",
            str(workspace),
            "--input-file",
            str(intake),
            "--preview",
        ],
        now=MERGE_TIME.replace(minute=5),
    )

    output = capsys.readouterr()
    assert result == 0, output.err
    assert "status=existing host_id=H01" in output.out
    assert "new_mappings: 0" in output.out


def test_merge_apply_rejects_state_changed_after_preview(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    plan = merge_plan(workspace)
    destination = workspace / "hosts" / "H01.md"
    destination.write_text(
        destination.read_text(encoding="utf-8") + "\nOperator note changed.\n",
        encoding="utf-8",
    )

    with pytest.raises(host_identity.HostIdentityError, match="changed after preview"):
        host_identity.apply_merge_plan(plan, now=MERGE_TIME)

    assert (workspace / "hosts" / "H02.md").is_file()
    assert not (workspace / "hosts" / "_merged").exists()
    assert (workspace / host_identity.MERGE_LEDGER_NAME).read_bytes() == b""


def test_merge_apply_fails_closed_on_archive_symlink(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    plan = merge_plan(workspace)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "hosts" / "_merged").symlink_to(outside, target_is_directory=True)

    with pytest.raises(host_identity.HostIdentityError, match="symlink"):
        host_identity.apply_merge_plan(plan, now=MERGE_TIME)

    assert (workspace / "hosts" / "H02.md").is_file()
    assert not any(outside.iterdir())
    assert (workspace / host_identity.MERGE_LEDGER_NAME).read_bytes() == b""


def test_merge_rejects_archive_collision_and_merged_chain(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    archive = workspace / "hosts" / "_merged"
    archive.mkdir(mode=0o700)
    (archive / "H02.md").write_text("collision\n", encoding="utf-8")
    with pytest.raises(host_identity.HostIdentityError, match="already exists"):
        merge_plan(workspace)
    (archive / "H02.md").unlink()
    archive.rmdir()
    host_identity.apply_merge_plan(merge_plan(workspace), now=MERGE_TIME)

    with pytest.raises(host_identity.HostIdentityError, match="both be active"):
        host_identity.build_merge_plan(
            workspace,
            "H01",
            "H02",
            EVIDENCE_ID,
            SOURCE_EVIDENCE_ID,
            "A merged host cannot become a destination.",
        )


def test_merge_rejects_evidence_hash_mismatch(tmp_path: Path) -> None:
    workspace = workspace_with_merge_candidates(tmp_path)
    artifact = workspace / "evidence" / "H02" / f"{SOURCE_EVIDENCE_ID}.txt"
    artifact.write_bytes(artifact.read_bytes().replace(b"ENG", b"BAD", 1))

    with pytest.raises(host_identity.HostIdentityError, match="hash validation failed"):
        merge_plan(workspace)


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777
