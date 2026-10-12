"""Tests for scripts/build_query_appendix.py."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.build_query_appendix import _fence, main

FIXED_NOW = datetime(2026, 7, 29, 21, 45, 12, 123456, tzinfo=UTC)


def make_workspace(tmp_path: Path) -> Path:
    """Create a minimal valid workspace under a temporary path."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# global\n")
    (workspace / "queries").mkdir()
    (workspace / "report").mkdir()
    return workspace


def add_query(
    workspace: Path,
    query_id: str,
    prompt_text: str,
    **kwargs: object,
) -> dict[str, object]:
    """Write a query record to queries/<query_id>.json."""
    prompt_bytes = prompt_text.encode("utf-8")
    host_ids = kwargs.get("host_ids", [])
    record: dict[str, object] = {
        "schema_version": "1.0",
        "query_id": query_id,
        "timestamp_utc": kwargs.get("timestamp_utc", "2026-07-29T21:45:12.123456Z"),
        "scope": kwargs.get("scope", "host" if host_ids else "global"),
        "host_ids": host_ids,
        "purpose": kwargs.get("purpose", "test purpose"),
        "model": kwargs.get("model", "Kimi K2.7 Code"),
        "context_refs": kwargs.get("context_refs", []),
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_text": prompt_text,
    }
    (workspace / "queries" / f"{query_id}.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    return record


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args), now=FIXED_NOW)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def read_appendix(workspace: Path) -> str:
    """Read the generated appendix file."""
    return (workspace / "report" / "AI_QUERY_APPENDIX.md").read_text(encoding="utf-8")


def test_complete_appendix_generation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A complete appendix is generated with all expected sections."""
    workspace = make_workspace(tmp_path)
    add_query(
        workspace,
        "QRY-20260729T214512123456Z",
        "prompt one",
        host_ids=["H01"],
        context_refs=["global.md"],
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    output = workspace / "report" / "AI_QUERY_APPENDIX.md"
    assert output.is_file()
    text = read_appendix(workspace)
    assert "# AI Query Appendix" in text
    assert "## Appendix Metadata" in text
    assert "## QRY-20260729T214512123456Z" in text
    assert "### Prompt" in text
    assert "prompt one" in text
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_exact_query_ordering(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Query sections appear in filename-sorted order."""
    workspace = make_workspace(tmp_path)
    add_query(workspace, "QRY-20260729T214512123457Z", "second")
    add_query(workspace, "QRY-20260729T214512123456Z", "first")

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    text = read_appendix(workspace)
    assert text.index("## QRY-20260729T214512123456Z") < text.index(
        "## QRY-20260729T214512123457Z"
    )


def test_full_prompt_preservation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Prompt text, whitespace, and line endings are preserved."""
    workspace = make_workspace(tmp_path)
    prompt = "line one\nline two\n  indented\n trailing \n\n"
    add_query(workspace, "QRY-20260729T214512123456Z", prompt)

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    text = read_appendix(workspace)
    fence = _fence(prompt)
    start = text.index(fence + "\n") + len(fence) + 1
    end = text.index("\n" + fence, start)
    assert text[start:end] == prompt


def test_prompt_with_long_backtick_runs(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Prompts containing Markdown fences use a longer enclosing fence."""
    workspace = make_workspace(tmp_path)
    prompt = "before ```code``` after ````four````"
    add_query(workspace, "QRY-20260729T214512123456Z", prompt)

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    text = read_appendix(workspace)
    assert prompt in text
    assert "`````" in text


def test_metadata_and_query_count(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Metadata contains workspace path and total query count."""
    workspace = make_workspace(tmp_path)
    add_query(workspace, "QRY-20260729T214512123456Z", "one")
    add_query(workspace, "QRY-20260729T214512123457Z", "two")

    code, stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    text = read_appendix(workspace)
    assert "**Total Queries**: 2" in text
    assert str(workspace) in text
    assert "2026-07-29T21:45:12.123456Z" in text
    assert "queries: 2" in stdout


def test_zero_query_appendix(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An empty queries directory produces a valid zero-count appendix."""
    workspace = make_workspace(tmp_path)

    code, stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    text = read_appendix(workspace)
    assert "**Total Queries**: 0" in text
    assert "no ai queries have been logged." in text.lower()
    assert "queries: 0" in stdout


def test_sha256_verification_failure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A mismatched prompt_sha256 causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    record = add_query(workspace, "QRY-20260729T214512123456Z", "prompt")
    record["prompt_sha256"] = "0" * 64
    (workspace / "queries" / "QRY-20260729T214512123456Z.json").write_text(
        json.dumps(record), encoding="utf-8"
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "sha256" in stderr.lower()


def test_filename_query_id_mismatch(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A query_id that does not match the filename causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    record = add_query(workspace, "QRY-20260729T214512123456Z", "prompt")
    record["query_id"] = "QRY-OTHER"
    (workspace / "queries" / "QRY-20260729T214512123456Z.json").write_text(
        json.dumps(record), encoding="utf-8"
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "query_id" in stderr.lower()


def test_malformed_json(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Malformed JSON in a query file causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    (workspace / "queries" / "QRY-20260729T214512123456Z.json").write_text(
        "not json", encoding="utf-8"
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "json" in stderr.lower()


def test_missing_fields(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Missing required fields cause a non-zero exit."""
    workspace = make_workspace(tmp_path)
    record: dict[str, object] = {
        "schema_version": "1.0",
        "query_id": "QRY-20260729T214512123456Z",
    }
    (workspace / "queries" / "QRY-20260729T214512123456Z.json").write_text(
        json.dumps(record), encoding="utf-8"
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "missing" in stderr.lower()


def test_invalid_utf8_query_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An invalid UTF-8 query file causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    (workspace / "queries" / "QRY-20260729T214512123456Z.json").write_bytes(
        b'{"query_id": "\xff\xfe"}'
    )

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "utf-8" in stderr.lower()


def test_missing_workspace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A missing workspace causes a non-zero exit."""
    code, _stdout, stderr = run(capsys, "--workspace", str(tmp_path / "nonexistent"))

    assert code != 0
    assert "workspace" in stderr.lower()


def test_missing_queries_dir(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A missing queries/ directory causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    (workspace / "queries").rmdir()

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "queries" in stderr.lower()


def test_missing_report_dir(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A missing report/ directory causes a non-zero exit."""
    workspace = make_workspace(tmp_path)
    (workspace / "report").rmdir()

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "report" in stderr.lower()


def test_output_conflict_without_replace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An existing appendix is not overwritten without --replace."""
    workspace = make_workspace(tmp_path)
    (workspace / "report" / "AI_QUERY_APPENDIX.md").write_text("existing\n")

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code != 0
    assert "exists" in stderr.lower()
    assert (workspace / "report" / "AI_QUERY_APPENDIX.md").read_text() == "existing\n"


def test_successful_atomic_replacement(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--replace atomically replaces an existing appendix."""
    workspace = make_workspace(tmp_path)
    (workspace / "report" / "AI_QUERY_APPENDIX.md").write_text("existing\n")
    add_query(workspace, "QRY-20260729T214512123456Z", "prompt")

    code, stdout, stderr = run(capsys, "--workspace", str(workspace), "--replace")

    assert code == 0, stderr
    text = read_appendix(workspace)
    assert "prompt" in text
    assert "existing" not in text
    assert "status: replaced" in stdout


def test_cleanup_after_replacement_failure(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Temporary files are cleaned up when atomic replacement fails."""
    workspace = make_workspace(tmp_path)
    (workspace / "report" / "AI_QUERY_APPENDIX.md").write_text("existing\n")
    add_query(workspace, "QRY-20260729T214512123456Z", "prompt")

    def failing_replace(self: Path, target: Path) -> Path:
        raise OSError("simulated failure")

    monkeypatch.setattr(Path, "replace", failing_replace)

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace), "--replace")

    assert code != 0
    assert "simulated failure" in stderr
    assert not (workspace / "report" / "AI_QUERY_APPENDIX.md.tmp").exists()
    assert (workspace / "report" / "AI_QUERY_APPENDIX.md").read_text() == "existing\n"


def test_source_query_files_unchanged(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Source query JSON files are not modified by generation."""
    workspace = make_workspace(tmp_path)
    add_query(workspace, "QRY-20260729T214512123456Z", "prompt")
    query_path = workspace / "queries" / "QRY-20260729T214512123456Z.json"
    original = query_path.read_text(encoding="utf-8")

    code, _stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    assert query_path.read_text(encoding="utf-8") == original


def test_success_output_no_prompt_text(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Success output does not include prompt contents."""
    workspace = make_workspace(tmp_path)
    secret = "secret prompt content"
    add_query(workspace, "QRY-20260729T214512123456Z", secret)

    code, stdout, stderr = run(capsys, "--workspace", str(workspace))

    assert code == 0, stderr
    assert secret not in stdout
    assert secret not in stderr
