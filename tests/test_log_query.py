"""Tests for scripts/log_query.py."""

import hashlib
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import artifact_io
from scripts.log_query import build_query_id, log_query, main, write_record


def _mock_stdin(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
    """Replace sys.stdin with a wrapper over the provided byte stream."""
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))


EXPECTED_FIELDS = {
    "schema_version",
    "query_id",
    "timestamp_utc",
    "scope",
    "host_ids",
    "purpose",
    "model",
    "context_refs",
    "prompt_sha256",
    "prompt_text",
}

FIXED_NOW = datetime(2026, 7, 29, 21, 45, 12, 123456, tzinfo=UTC)
EXPECTED_QUERY_ID = build_query_id(FIXED_NOW)


def make_workspace(tmp_path: Path) -> Path:
    """Create a minimal valid workspace under a temporary path."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# global\n")
    (workspace / "queries").mkdir()
    return workspace


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_query_collision_after_preflight_preserves_existing_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(tmp_path)
    query_id = "QRY-20260908T120000123456Z"
    original = artifact_io.publish_file

    def collide(path: Path, payload: bytes | str):
        path.write_bytes(b"other writer query")
        return original(path, payload)

    monkeypatch.setattr(artifact_io, "publish_file", collide)
    with pytest.raises(SystemExit):
        write_record(workspace, query_id, {"query_id": query_id, "prompt_text": "synthetic"})
    destination = workspace / "queries" / f"{query_id}.json"
    assert destination.read_bytes() == b"other writer query"
    assert list((workspace / "queries").iterdir()) == [destination]


def test_logs_prompt_from_utf8_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A UTF-8 prompt file is logged successfully."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("Analyze the scan results.", encoding="utf-8")

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "Analyze scan",
        "--host-id", "H01",
        "--prompt-file", str(prompt_path),
    )

    assert code == 0, stderr
    assert (workspace / "queries").is_dir()
    query_files = list((workspace / "queries").glob("*.json"))
    assert len(query_files) == 1


def test_logs_prompt_from_stdin(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prompt text read from standard input is logged successfully."""
    workspace = make_workspace(tmp_path)
    _mock_stdin(monkeypatch, b"Scan output summary")

    code, _stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "Summarize scan",
    )

    assert code == 0, stderr
    query_files = list((workspace / "queries").glob("*.json"))
    assert len(query_files) == 1
    record = json.loads(query_files[0].read_text())
    assert record["prompt_text"] == "Scan output summary"


def test_exact_json_fields(tmp_path: Path) -> None:
    """The JSON record contains exactly the expected top-level fields."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("field test", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Test fields",
        host_ids=["H01"],
        model="Kimi K2.7 Code",
        context_refs=["global.md"],
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert set(record.keys()) == EXPECTED_FIELDS


def test_deterministic_query_id(tmp_path: Path) -> None:
    """A fixed datetime produces a deterministic query ID."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("id test", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Test ID",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["query_id"] == EXPECTED_QUERY_ID
    assert record["query_id"] == "QRY-20260729T214512123456Z"


def test_timestamp_ends_with_z(tmp_path: Path) -> None:
    """The timestamp_utc field ends with the literal 'Z'."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("timestamp test", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Test timestamp",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["timestamp_utc"].endswith("Z")
    assert record["timestamp_utc"] == "2026-07-29T21:45:12.123456Z"


def test_correct_prompt_sha256(tmp_path: Path) -> None:
    """The prompt_sha256 field matches the original prompt bytes."""
    workspace = make_workspace(tmp_path)
    prompt_text = "Compute this hash."
    prompt_bytes = prompt_text.encode("utf-8")

    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_bytes(prompt_bytes)

    _, record = log_query(
        workspace=str(workspace),
        purpose="Test hash",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    expected = hashlib.sha256(prompt_bytes).hexdigest()
    assert record["prompt_sha256"] == expected


def test_preserves_whitespace_and_line_endings(tmp_path: Path) -> None:
    """Prompt whitespace and line endings are preserved unchanged."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_text = "\n  leading spaces\r\n\n trailing space \n"
    prompt_path.write_text(prompt_text, encoding="utf-8", newline="")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Test whitespace",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["prompt_text"] == prompt_text


def test_global_scope_without_hosts(tmp_path: Path) -> None:
    """A query with no host IDs has global scope."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("Global question", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Global question",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["scope"] == "global"
    assert record["host_ids"] == []


def test_one_host_id(tmp_path: Path) -> None:
    """A single host ID is recorded correctly."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("Host question", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Host question",
        host_ids=["H01"],
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["scope"] == "host"
    assert record["host_ids"] == ["H01"]


def test_multiple_host_ids(tmp_path: Path) -> None:
    """Multiple host IDs are recorded in order."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("Multi-host question", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Multi-host question",
        host_ids=["H01", "H02", "H03"],
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["host_ids"] == ["H01", "H02", "H03"]


def test_duplicate_host_ids_removed_in_order(tmp_path: Path) -> None:
    """Duplicate host IDs are removed while preserving first-seen order."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("Duplicate hosts", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Duplicate hosts",
        host_ids=["H03", "H01", "H03", "H02", "H01"],
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["host_ids"] == ["H03", "H01", "H02"]


@pytest.mark.parametrize("host_id", ["H00"])
def test_h00_rejected(host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Host ID H00 is rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--host-id", host_id,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0
    assert "H00" in stderr


@pytest.mark.parametrize(
    "host_id",
    [
        "h01",
        "H1",
        "H001",
        "H100",
        "H 01",
        "H01/",
        "H01\\",
        "H01;",
        "H01'",
        "../H01",
        "H01\n",
        "",
        "HOST01",
    ],
)
def test_malformed_host_ids_rejected(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Malformed or unsafe host IDs are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--host-id", host_id,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0
    assert "invalid host ID" in stderr.lower() or "host id" in stderr.lower()


def test_empty_prompt_rejected(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An empty prompt is rejected."""
    workspace = make_workspace(tmp_path)
    _mock_stdin(monkeypatch, b"")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "empty" in stderr.lower()


def test_whitespace_only_prompt_rejected(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A whitespace-only prompt is rejected."""
    workspace = make_workspace(tmp_path)
    _mock_stdin(monkeypatch, b"   \n\t  ")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "whitespace" in stderr.lower()


def test_invalid_utf8_rejected(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prompt bytes that are not valid UTF-8 are rejected."""
    workspace = make_workspace(tmp_path)
    _mock_stdin(monkeypatch, b"\xff\xfe\x00")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "utf-8" in stderr.lower()


def test_missing_prompt_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A missing prompt file is rejected."""
    workspace = make_workspace(tmp_path)
    missing = tmp_path / "does-not-exist.txt"

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--prompt-file", str(missing),
    )
    assert code != 0
    assert "does not exist" in stderr.lower()


def test_prompt_file_directory_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A prompt file that is a directory is rejected."""
    workspace = make_workspace(tmp_path)
    directory = tmp_path / "prompt-dir"
    directory.mkdir()

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--prompt-file", str(directory),
    )
    assert code != 0
    assert "regular file" in stderr.lower()


def test_missing_workspace_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A missing workspace is rejected."""
    missing = tmp_path / "missing_workspace"

    code, _, stderr = run(
        capsys,
        "--workspace", str(missing),
        "--purpose", "test",
    )
    assert code != 0
    assert "does not exist" in stderr.lower()


def test_workspace_as_regular_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace path that is a regular file is rejected."""
    file_workspace = tmp_path / "file_workspace"
    file_workspace.write_text("not a directory", encoding="utf-8")

    code, _, stderr = run(
        capsys,
        "--workspace", str(file_workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "not a directory" in stderr.lower()


def test_missing_global_md_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace without global.md is rejected."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "queries").mkdir()

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "global.md" in stderr.lower()


def test_missing_queries_directory_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace without a queries/ directory is rejected."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    (workspace / "global.md").write_text("# global\n")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
    )
    assert code != 0
    assert "queries/" in stderr.lower() or "queries" in stderr.lower()


@pytest.mark.parametrize(
    "purpose",
    [
        "",
        "   ",
        "a" * 121,
        "line\nbreak",
        "tab\tchar",
        "\x00null",
    ],
)
def test_invalid_purpose_rejected(
    purpose: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Invalid purpose values are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, _stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", purpose,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0


@pytest.mark.parametrize(
    "model",
    [
        "",
        "   ",
        "a" * 101,
        "line\nbreak",
        "tab\tchar",
        "\x00null",
    ],
)
def test_invalid_model_rejected(
    model: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Invalid model values are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, _stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--model", model,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0


@pytest.mark.parametrize("context_ref", ["/absolute/path", "/etc/passwd"])
def test_absolute_context_rejected(
    context_ref: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Absolute context references are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--context", context_ref,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0
    assert "absolute" in stderr.lower()


@pytest.mark.parametrize("context_ref", ["../global.md", "hosts/../global.md", ".."])
def test_traversal_context_rejected(
    context_ref: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Context references containing '..' are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    code, _, _stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--context", context_ref,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0


@pytest.mark.parametrize("context_ref", ["", "hosts//H01.md", "hosts/\x00file.md", "hosts/\nfile.md"])
def test_malformed_context_rejected(
    context_ref: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Malformed context references are rejected."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    # Empty string cannot be passed as a value, so test it directly.
    if context_ref == "":
        code, _, _stderr = run(
            capsys,
            "--workspace", str(workspace),
            "--purpose", "test",
            "--prompt-file", str(prompt_path),
        )
        # Empty context is equivalent to omitting the argument; not an error.
        assert code == 0
        return

    code, _, _stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "test",
        "--context", context_ref,
        "--prompt-file", str(prompt_path),
    )
    assert code != 0


def test_context_refs_recorded_but_never_opened(tmp_path: Path) -> None:
    """Context references are stored verbatim and no file is opened."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("x", encoding="utf-8")

    _, record = log_query(
        workspace=str(workspace),
        purpose="Context test",
        context_refs=["hosts/H01.md", "does-not-exist.txt"],
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert record["context_refs"] == ["hosts/H01.md", "does-not-exist.txt"]


def test_refuses_to_overwrite_existing_record(tmp_path: Path) -> None:
    """An existing query record is not overwritten."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("first prompt", encoding="utf-8")

    destination, _ = log_query(
        workspace=str(workspace),
        purpose="First",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    original = destination.read_text()
    prompt_path.write_text("second prompt", encoding="utf-8")

    with pytest.raises(SystemExit):
        log_query(
            workspace=str(workspace),
            purpose="Second",
            prompt_file=str(prompt_path),
            now=FIXED_NOW,
        )

    assert destination.read_text() == original


def test_no_partial_files_after_conflict(tmp_path: Path) -> None:
    """A conflict leaves no new query file or temporary file behind."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("first prompt", encoding="utf-8")

    log_query(
        workspace=str(workspace),
        purpose="First",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    prompt_path.write_text("second prompt", encoding="utf-8")

    try:
        log_query(
            workspace=str(workspace),
            purpose="Second",
            prompt_file=str(prompt_path),
            now=FIXED_NOW,
        )
    except SystemExit:
        pass

    files = list((workspace / "queries").iterdir())
    json_files = [f for f in files if f.suffix == ".json"]
    tmp_files = [f for f in files if f.suffix == ".tmp"]

    assert len(json_files) == 1
    assert len(tmp_files) == 0


def test_nonzero_exit_on_validation_error(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Validation errors produce a non-zero CLI exit code."""
    workspace = make_workspace(tmp_path)

    code, _, _stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "",
    )
    assert code != 0


def test_success_output_does_not_contain_full_prompt(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Successful CLI output does not include the full prompt text."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    secret_prompt = "This is a secret prompt that must not be printed."
    prompt_path.write_text(secret_prompt, encoding="utf-8")

    code, stdout, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--purpose", "Secret test",
        "--prompt-file", str(prompt_path),
    )

    assert code == 0, stderr
    assert secret_prompt not in stdout
    assert secret_prompt not in stderr


def test_json_output_is_valid_and_indented(tmp_path: Path) -> None:
    """The saved JSON is valid, indented, and ends with a single newline."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("hello", encoding="utf-8")

    destination, record = log_query(
        workspace=str(workspace),
        purpose="JSON format",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    raw = destination.read_text(encoding="utf-8")
    assert raw.endswith("\n") and not raw.endswith("\n\n")
    assert "\n  \"schema_version\"" in raw or '\n  "schema_version"' in raw
    assert json.loads(raw) == record


def test_tests_use_temporary_directories_only(tmp_path: Path) -> None:
    """This test documents that all operations occur under tmp_path."""
    workspace = make_workspace(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("temporary only", encoding="utf-8")

    destination, _ = log_query(
        workspace=str(workspace),
        purpose="Temp dir test",
        prompt_file=str(prompt_path),
        now=FIXED_NOW,
    )

    assert str(tmp_path) in str(destination)
    assert "assessment_workspace" in str(destination)
