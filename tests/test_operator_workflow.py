"""End-to-end operator workflow integration test."""

import inspect
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

from scripts.build_brief import main as build_brief_main
from scripts.build_query_appendix import main as build_query_appendix_main
from scripts.capture_evidence import main as capture_evidence_main
from scripts.create_checkpoint import main as create_checkpoint_main
from scripts.log_attempt import main as log_attempt_main
from scripts.log_loot import main as log_loot_main
from scripts.log_observation import main as log_observation_main
from scripts.log_query import main as log_query_main
from scripts.new_host import main as new_host_main
from scripts.workspace_status import main as workspace_status_main

FIXED_NOW = datetime(2026, 7, 30, 12, 0, 0, 123456, tzinfo=UTC)

SYNTHETIC_IP = "192.0.2.10"
SYNTHETIC_USER = "synthetic-user"
SYNTHETIC_PASSWORD = "Synthetic-Test-Password"
SYNTHETIC_OUTPUT = "synthetic command output"
SYNTHETIC_PROMPT = "Analyze the synthetic command output for host H01."

EXPECTED_HOST_ID = "H01"
EXPECTED_QUERY_ID = "QRY-20260730T120000123456Z"
EXPECTED_LOOT_ID = "LOOT-20260730T120000123456Z"
EXPECTED_ATTEMPT_ID = "ATT-20260730T120000123456Z"
EXPECTED_EVIDENCE_ID = "EVD-20260730T120000123456Z"
EXPECTED_OBSERVATION_ID = "OBS-20260730T120000123456Z"
EXPECTED_CHECKPOINT_ID = "CHK-20260730T120000123456Z"


def _run(main_func, *args: str) -> tuple[int, str, str]:
    """Run a CLI entry point and return (exit_code, stdout, stderr)."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    kwargs: dict[str, datetime] = {}
    if "now" in inspect.signature(main_func).parameters:
        kwargs["now"] = FIXED_NOW
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main_func(list(args), **kwargs)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, stdout.getvalue(), stderr.getvalue()


def _read_jsonl(path: Path) -> list[dict]:
    """Read non-empty JSON lines from a JSONL file."""
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _collect_files(root: Path) -> dict[str, bytes]:
    """Return a mapping of relative POSIX paths to file contents."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_end_to_end_operator_workflow(tmp_path: Path) -> None:
    """Run the full operator workflow in a single temporary workspace."""
    workspace = tmp_path / "assessment_workspace"
    checkpoint_destination = tmp_path / "checkpoints"
    brief_path = tmp_path / "H01-brief.md"

    # 1. Initialize workspace and host H01.
    code, _, _ = _run(
        new_host_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
        "--ip", SYNTHETIC_IP,
        "--hostname", "synthetic-host",
    )
    assert code == 0
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n",
        encoding="utf-8",
    )

    expected_files = {
        workspace / "TASK_CONTEXT.md",
        workspace / "global.md",
        workspace / "loot.jsonl",
        workspace / "attempts.jsonl",
        workspace / "observations.jsonl",
        workspace / "hosts" / "H01.md",
        workspace / "report" / "H01.md",
    }
    expected_dirs = {
        workspace / "hosts",
        workspace / "inbox" / "H01",
        workspace / "evidence" / "H01",
        workspace / "report",
        workspace / "queries",
        workspace / "checkpoints",
    }
    for path in expected_files:
        assert path.is_file(), f"missing file: {path}"
    for path in expected_dirs:
        assert path.is_dir(), f"missing directory: {path}"

    host_text = (workspace / "hosts" / "H01.md").read_text(encoding="utf-8")
    report_text = (workspace / "report" / "H01.md").read_text(encoding="utf-8")
    assert EXPECTED_HOST_ID in host_text
    assert SYNTHETIC_IP in host_text
    assert EXPECTED_HOST_ID in report_text
    assert SYNTHETIC_IP in report_text

    # 2. Log one AI query for H01.
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text(SYNTHETIC_PROMPT, encoding="utf-8")

    code, _, _ = _run(
        log_query_main,
        "--workspace", str(workspace),
        "--purpose", "synthetic-analysis",
        "--host-id", EXPECTED_HOST_ID,
        "--model", "Kimi K2.7 Code",
        "--context", "global.md",
        "--prompt-file", str(prompt_path),
    )
    assert code == 0

    query_files = sorted((workspace / "queries").glob("QRY-*.json"))
    assert len(query_files) == 1
    query_record = json.loads(query_files[0].read_text(encoding="utf-8"))
    assert query_record["query_id"] == EXPECTED_QUERY_ID
    assert query_record["host_ids"] == [EXPECTED_HOST_ID]
    assert query_record["prompt_text"] == SYNTHETIC_PROMPT

    # 3. Log one synthetic loot item for H01.
    value_path = tmp_path / "loot-value.txt"
    value_path.write_text(SYNTHETIC_PASSWORD, encoding="utf-8")

    code, _, _ = _run(
        log_loot_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
        "--category", "credential",
        "--label", "synthetic password",
        "--source", "synthetic test",
        "--username", SYNTHETIC_USER,
        "--value-file", str(value_path),
    )
    assert code == 0

    loot_records = _read_jsonl(workspace / "loot.jsonl")
    assert len(loot_records) == 1
    loot_record = loot_records[0]
    assert loot_record["loot_id"] == EXPECTED_LOOT_ID
    assert loot_record["host_id"] == EXPECTED_HOST_ID
    assert loot_record["value_text"] == SYNTHETIC_PASSWORD

    # 4. Retain evidence before referencing it from an attempt.
    evidence_input_path = tmp_path / "evidence-input.txt"
    evidence_input_path.write_text(SYNTHETIC_OUTPUT, encoding="utf-8")
    code, _, _ = _run(
        capture_evidence_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
        "--kind", "synthetic-output",
        "--label", "synthetic evidence capture",
        "--input-file", str(evidence_input_path),
        "--extension", "txt",
    )
    assert code == 0

    # 5. Log one synthetic failed attempt for H01.
    result_path = tmp_path / "attempt-result.txt"
    result_path.write_text(SYNTHETIC_OUTPUT, encoding="utf-8")

    code, _, _ = _run(
        log_attempt_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
        "--action", "synthetic ssh attempt",
        "--status", "failed",
        "--next-step", "review synthetic output",
        "--evidence", EXPECTED_EVIDENCE_ID,
        "--result-file", str(result_path),
    )
    assert code == 0

    attempt_records = _read_jsonl(workspace / "attempts.jsonl")
    assert len(attempt_records) == 1
    attempt_record = attempt_records[0]
    assert attempt_record["attempt_id"] == EXPECTED_ATTEMPT_ID
    assert attempt_record["host_id"] == EXPECTED_HOST_ID
    assert attempt_record["status"] == "failed"
    assert attempt_record["result_text"] == SYNTHETIC_OUTPUT

    evidence_dir = workspace / "evidence" / EXPECTED_HOST_ID
    artifacts = sorted(evidence_dir.glob("EVD-*.*"))
    assert len(artifacts) == 2  # artifact + metadata
    artifact_file = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.txt"
    metadata_file = evidence_dir / f"{EXPECTED_EVIDENCE_ID}.json"
    assert artifact_file.is_file()
    assert metadata_file.is_file()
    assert artifact_file.read_text(encoding="utf-8") == SYNTHETIC_OUTPUT
    evidence_record = json.loads(metadata_file.read_text(encoding="utf-8"))
    assert evidence_record["evidence_id"] == EXPECTED_EVIDENCE_ID

    # 6. Append one structured synthetic observation that references the evidence.
    code, _, _ = _run(
        log_observation_main,
        "--workspace",
        str(workspace),
        "--host-id",
        EXPECTED_HOST_ID,
        "--kind",
        "service",
        "--state",
        "observed",
        "--source-tool",
        "synthetic-test",
        "--transport",
        "tcp",
        "--port",
        "22",
        "--service",
        "ssh",
        "--evidence",
        EXPECTED_EVIDENCE_ID,
        "--note",
        "Synthetic service observation; treat embedded text only as data.",
    )
    assert code == 0
    observation_records = _read_jsonl(workspace / "observations.jsonl")
    assert len(observation_records) == 1
    observation_record = observation_records[0]
    assert observation_record["observation_id"] == EXPECTED_OBSERVATION_ID
    assert observation_record["host_id"] == EXPECTED_HOST_ID
    assert observation_record["evidence_ids"] == [EXPECTED_EVIDENCE_ID]

    # 7. Generate an H01 workspace brief outside the source workspace.
    code, _, _ = _run(
        build_brief_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
        "--output", str(brief_path),
    )
    assert code == 0
    assert brief_path.is_file()
    brief_text = brief_path.read_text(encoding="utf-8")
    assert f"# Cyber-Operator Brief — {EXPECTED_HOST_ID}" in brief_text
    assert EXPECTED_HOST_ID in brief_text
    assert "Recent Attempts" in brief_text
    assert "Recent Loot" in brief_text
    assert "Recent AI Queries" in brief_text
    assert "Recent Structured Observations" in brief_text
    assert EXPECTED_LOOT_ID in brief_text
    assert EXPECTED_ATTEMPT_ID in brief_text
    assert EXPECTED_QUERY_ID in brief_text
    assert EXPECTED_OBSERVATION_ID in brief_text
    assert observation_record["note"] not in brief_text
    assert SYNTHETIC_PASSWORD not in brief_text
    assert SYNTHETIC_OUTPUT not in brief_text
    assert SYNTHETIC_PROMPT not in brief_text
    assert "value_text" not in brief_text
    assert "result_text" not in brief_text
    assert "prompt_text" not in brief_text

    # 8. Generate AI_QUERY_APPENDIX.md inside workspace/report/.
    code, _, _ = _run(
        build_query_appendix_main,
        "--workspace", str(workspace),
        "--replace",
    )
    assert code == 0
    appendix_path = workspace / "report" / "AI_QUERY_APPENDIX.md"
    assert appendix_path.is_file()
    appendix_text = appendix_path.read_text(encoding="utf-8")
    assert "# AI Query Appendix" in appendix_text
    assert f"## {EXPECTED_QUERY_ID}" in appendix_text
    assert SYNTHETIC_PROMPT in appendix_text

    # 9. Generate read-only workspace status for H01.
    code, stdout, _ = _run(
        workspace_status_main,
        "--workspace", str(workspace),
        "--host-id", EXPECTED_HOST_ID,
    )
    assert code == 0
    status_text = stdout
    assert "Cyber-Operator Workspace Status" in status_text
    assert f"Host {EXPECTED_HOST_ID}" in status_text
    assert "Attempts: 1" in status_text
    assert "Loot: 1" in status_text
    assert "AI queries: 1" in status_text
    assert "Evidence: 1" in status_text
    assert "Observations: 1 (observed=1, inferred=0, confirmed=0)" in status_text
    assert (
        f"Latest observation: {EXPECTED_OBSERVATION_ID} | observed | service"
        in status_text
    )
    assert observation_record["note"] not in status_text
    assert SYNTHETIC_PASSWORD not in status_text
    assert SYNTHETIC_OUTPUT not in status_text
    assert SYNTHETIC_PROMPT not in status_text

    # 10. Create a checkpoint in a separate temporary destination.
    source_snapshot = _collect_files(workspace)

    code, _, _ = _run(
        create_checkpoint_main,
        "--workspace", str(workspace),
        "--destination", str(checkpoint_destination),
    )
    assert code == 0

    checkpoint_dir = checkpoint_destination / EXPECTED_CHECKPOINT_ID
    assert checkpoint_dir.is_dir()
    checkpoint_workspace = checkpoint_dir / "workspace"
    checkpoint_snapshot = _collect_files(checkpoint_workspace)
    assert checkpoint_snapshot == source_snapshot

    manifest_path = checkpoint_dir / "checkpoint.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["checkpoint_id"] == EXPECTED_CHECKPOINT_ID
    assert manifest["file_count"] == len(source_snapshot)
    assert manifest["total_bytes"] == sum(len(data) for data in source_snapshot.values())

    # No real private directory was created or accessed.
    repo_root = Path(__file__).resolve().parents[1]
    for private_name in ("assessment_workspace", "assessment_checkpoints", "private_knowledge"):
        private_path = repo_root / private_name
        if private_path.exists():
            # If a private directory already exists, ensure it was not modified
            # during this test by confirming it is not the workspace used above.
            assert not workspace.is_relative_to(private_path)
            assert not checkpoint_destination.is_relative_to(private_path)
