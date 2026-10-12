"""Tests for scripts/log_observation.py."""

import io
import json
import threading
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import ledger_io
from scripts import log_observation as log_observation_module
from scripts.capture_evidence import capture_evidence
from scripts.log_observation import FIELD_ORDER, main
from scripts.new_host import main as new_host_main

FIXED_NOW = datetime(2026, 7, 31, 12, 0, 0, 123456, tzinfo=UTC)
EVIDENCE_H01 = "EVD-20260731T120000123456Z"
EVIDENCE_H02 = "EVD-20260731T120001123456Z"


def run(*args: str, now: datetime = FIXED_NOW) -> tuple[int, str, str]:
    """Run the observation CLI and capture its result."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main(list(args), now=now)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, stdout.getvalue(), stderr.getvalue()


def bootstrap(tmp_path: Path, *host_ids: str) -> Path:
    """Create a synthetic workspace with the requested hosts."""
    workspace = tmp_path / "workspace"
    for host_id in host_ids or ("H01",):
        assert (
            new_host_main(
                [
                    "--workspace",
                    str(workspace),
                    "--host-id",
                    host_id,
                    "--ip",
                    f"192.0.2.{int(host_id[1:])}",
                ]
            )
            == 0
        )
    return workspace


def add_evidence_metadata(workspace: Path, host_id: str, evidence_id: str) -> bytes:
    """Create the canonical artifact and metadata through capture_evidence."""
    captured_at = datetime.strptime(
        evidence_id,
        "EVD-%Y%m%dT%H%M%S%fZ",
    ).replace(tzinfo=UTC)
    input_path = workspace.parent / f"{host_id}-{evidence_id}.input"
    input_path.write_bytes(b"\xff\x00inert synthetic artifact bytes")
    capture_evidence(
        workspace=str(workspace),
        host_id=host_id,
        kind="synthetic",
        label="Synthetic evidence",
        extension="txt",
        input_file=str(input_path),
        now=captured_at,
    )
    metadata = workspace / "evidence" / host_id / f"{evidence_id}.json"
    return metadata.read_bytes()


def evidence_paths(
    workspace: Path, host_id: str, evidence_id: str
) -> tuple[Path, Path]:
    """Return canonical metadata and artifact paths for one evidence ID."""
    evidence_dir = workspace / "evidence" / host_id
    return (
        evidence_dir / f"{evidence_id}.json",
        evidence_dir / f"{evidence_id}.txt",
    )


def assert_evidence_rejected(
    workspace: Path,
    evidence_id: str,
    expected_error: str,
) -> None:
    """Assert rejection and byte-for-byte preservation of an existing ledger."""
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()
    code, _, stderr = run(*base_args(workspace), "--evidence", evidence_id)
    assert code != 0
    assert expected_error in stderr
    assert ledger.read_bytes() == before


def base_args(workspace: Path) -> list[str]:
    """Return required arguments for a note observation."""
    return [
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--kind",
        "note",
        "--state",
        "observed",
        "--source-tool",
        "manual",
        "--note",
        "synthetic observation",
    ]


def read_records(workspace: Path) -> list[dict]:
    """Read non-empty observation records."""
    return [
        json.loads(line)
        for line in (workspace / "observations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]


def test_valid_service_observation(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    code, stdout, stderr = run(
        *base_args(workspace),
        "--kind",
        "service",
        "--transport",
        " TCP ",
        "--port",
        "443",
        "--service",
        " https ",
    )
    assert code == 0, stderr
    assert "status: appended" in stdout
    record = read_records(workspace)[0]
    assert record["transport"] == "tcp"
    assert record["port"] == 443
    assert record["service"] == "https"


def test_validate_only_does_not_create_or_append_observation_ledger(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()

    code, stdout, stderr = run(*base_args(workspace), "--validate-only")

    assert code == 0, stderr
    assert "validation: valid" in stdout
    assert "prospective_observation_id:" in stdout
    assert ledger.read_bytes() == before


def test_valid_endpoint_observation(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    code, _, stderr = run(
        *base_args(workspace),
        "--kind",
        "endpoint",
        "--endpoint",
        "/api/v1/health",
        "--transport",
        "tcp",
        "--port",
        "8000",
        "--service",
        "api",
    )
    assert code == 0, stderr
    record = read_records(workspace)[0]
    assert record["endpoint"] == "/api/v1/health"
    assert record["url"] is None
    assert record["http_status"] is None


def test_valid_http_observation(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    code, _, stderr = run(
        *base_args(workspace),
        "--kind",
        "http",
        "--url",
        "https://synthetic.test:8443/api",
        "--endpoint",
        "/api",
        "--transport",
        "tcp",
        "--port",
        "8443",
        "--service",
        "https",
        "--http-status",
        "200",
    )
    assert code == 0, stderr
    record = read_records(workspace)[0]
    assert record["url"] == "https://synthetic.test:8443/api"
    assert record["http_status"] == 200


def test_valid_note_observation_uses_null_optional_fields(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    code, _, stderr = run(*base_args(workspace))
    assert code == 0, stderr
    record = read_records(workspace)[0]
    for field in ("transport", "port", "service", "url", "endpoint", "http_status"):
        assert record[field] is None
    assert record["evidence_ids"] == []


@pytest.mark.parametrize("state", ["observed", "inferred", "confirmed"])
def test_all_states(state: str, tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    args = base_args(workspace)
    args[args.index("observed")] = state
    code, _, stderr = run(*args)
    assert code == 0, stderr
    assert read_records(workspace)[0]["state"] == state


def test_deterministic_field_order_and_exact_schema(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    code, _, stderr = run(*base_args(workspace))
    assert code == 0, stderr
    raw = (workspace / "observations.jsonl").read_text(encoding="utf-8")
    pairs = json.loads(raw, object_pairs_hook=list)
    assert [name for name, _ in pairs] == list(FIELD_ORDER)
    assert not (
        {"credential", "token", "secret", "password", "loot_value"} & set(dict(pairs))
    )


def test_append_preserves_previous_bytes(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    ledger = workspace / "observations.jsonl"
    previous = ledger.read_bytes()
    args = base_args(workspace)
    args[-1] = "second observation"
    assert run(*args, now=FIXED_NOW + timedelta(microseconds=1))[0] == 0
    current = ledger.read_bytes()
    assert current.startswith(previous)
    assert len(read_records(workspace)) == 2


def test_exact_duplicate_is_successful_and_non_writing(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    ledger = workspace / "observations.jsonl"
    previous = ledger.read_bytes()
    existing_id = read_records(workspace)[0]["observation_id"]
    code, stdout, stderr = run(
        *base_args(workspace), now=FIXED_NOW + timedelta(seconds=1)
    )
    assert code == 0, stderr
    assert stdout.splitlines()[0] == "status: duplicate"
    assert f"existing_observation_id: {existing_id}" in stdout
    assert "path: observations.jsonl" in stdout
    assert ledger.read_bytes() == previous


def test_unterminated_exact_duplicate_fails_closed_before_no_op(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    ledger = workspace / "observations.jsonl"
    unterminated = ledger.read_bytes()[:-1]
    ledger.write_bytes(unterminated)

    code, _, stderr = run(
        *base_args(workspace),
        now=FIXED_NOW + timedelta(seconds=1),
    )

    assert code != 0
    assert "not newline terminated" in stderr
    assert ledger.read_bytes() == unterminated


def test_concurrent_exact_duplicate_is_rechecked_under_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    first_in_append = threading.Event()
    release_first = threading.Event()
    second_at_lock = threading.Event()
    outcomes: dict[str, str] = {}

    original_append = log_observation_module._append_record
    original_flock = ledger_io.fcntl.flock

    def delayed_append(path: Path, record: dict[str, object]) -> None:
        if threading.current_thread().name == "observation-first":
            first_in_append.set()
            assert release_first.wait(timeout=5)
        original_append(path, record)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "observation-second"
            and operation == ledger_io.fcntl.LOCK_EX
        ):
            second_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(log_observation_module, "_append_record", delayed_append)
    monkeypatch.setattr(ledger_io.fcntl, "flock", observed_flock)

    def invoke(label: str, moment: datetime) -> None:
        result = log_observation_module.log_observation(
            workspace=str(workspace),
            host_id="H01",
            kind="note",
            state="observed",
            source_tool="manual",
            note="synthetic observation",
            evidence_ids=[],
            now=moment,
        )
        outcomes[label] = result[3]

    first = threading.Thread(
        target=invoke,
        args=("first", FIXED_NOW),
        name="observation-first",
    )
    second = threading.Thread(
        target=invoke,
        args=("second", FIXED_NOW + timedelta(seconds=1)),
        name="observation-second",
    )
    first.start()
    assert first_in_append.wait(timeout=5)
    second.start()
    assert second_at_lock.wait(timeout=5)
    assert "second" not in outcomes
    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == {"first": "appended", "second": "duplicate"}
    records = read_records(workspace)
    assert len(records) == 1
    assert records[0]["observation_id"] == FIXED_NOW.strftime("OBS-%Y%m%dT%H%M%S%fZ")


@pytest.mark.parametrize(
    ("field", "value"),
    [("--state", "confirmed"), ("--source-tool", "second-tool")],
)
def test_state_and_source_tool_are_part_of_duplicate_key(
    field: str,
    value: str,
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    args = base_args(workspace)
    args[args.index(field) + 1] = value
    assert run(*args, now=FIXED_NOW + timedelta(microseconds=1))[0] == 0
    assert len(read_records(workspace)) == 2


def test_repeated_evidence_is_deduplicated_in_first_seen_order(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    add_evidence_metadata(workspace, "H01", EVIDENCE_H02)
    code, _, stderr = run(
        *base_args(workspace),
        "--evidence",
        EVIDENCE_H02,
        "--evidence",
        EVIDENCE_H01,
        "--evidence",
        EVIDENCE_H02,
    )
    assert code == 0, stderr
    assert read_records(workspace)[0]["evidence_ids"] == [EVIDENCE_H02, EVIDENCE_H01]


def test_cross_host_evidence_reference_does_not_change_ownership(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01", "H02")
    original = add_evidence_metadata(workspace, "H02", EVIDENCE_H02)
    metadata, artifact = evidence_paths(workspace, "H02", EVIDENCE_H02)
    original_artifact = artifact.read_bytes()
    code, _, stderr = run(*base_args(workspace), "--evidence", EVIDENCE_H02)
    assert code == 0, stderr
    assert read_records(workspace)[0]["evidence_ids"] == [EVIDENCE_H02]
    assert metadata.read_bytes() == original
    assert artifact.read_bytes() == original_artifact
    assert not (workspace / "evidence" / "H01" / f"{EVIDENCE_H02}.json").exists()


def test_canonical_evidence_relationship_succeeds_without_modification(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    original_metadata = add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    metadata, artifact = evidence_paths(workspace, "H01", EVIDENCE_H01)
    original_artifact = artifact.read_bytes()
    code, _, stderr = run(*base_args(workspace), "--evidence", EVIDENCE_H01)
    assert code == 0, stderr
    assert read_records(workspace)[0]["evidence_ids"] == [EVIDENCE_H01]
    assert metadata.read_bytes() == original_metadata
    assert artifact.read_bytes() == original_artifact


def test_artifact_contents_are_not_opened(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    _, artifact = evidence_paths(workspace, "H01", EVIDENCE_H01)
    original_open = Path.open

    def reject_artifact_open(path: Path, *args: object, **kwargs: object):
        if path == artifact:
            raise AssertionError("artifact contents must not be opened")
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path, "open", reject_artifact_open)
        code, _, stderr = run(*base_args(workspace), "--evidence", EVIDENCE_H01)

    assert code == 0, stderr
    assert read_records(workspace)[0]["evidence_ids"] == [EVIDENCE_H01]


def test_unrelated_evd_shaped_file_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    unrelated = workspace / "evidence" / "H01" / f"{EVIDENCE_H01}.unrelated"
    unrelated.write_bytes(b"unrelated")
    assert_evidence_rejected(workspace, EVIDENCE_H01, "does not exist in workspace")


def test_artifact_without_metadata_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    _, artifact = evidence_paths(workspace, "H01", EVIDENCE_H01)
    artifact.write_bytes(b"artifact only")
    assert_evidence_rejected(workspace, EVIDENCE_H01, "does not exist in workspace")


def test_metadata_without_artifact_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    _, artifact = evidence_paths(workspace, "H01", EVIDENCE_H01)
    artifact.unlink()
    assert_evidence_rejected(workspace, EVIDENCE_H01, "artifact does not exist")


@pytest.mark.parametrize(
    ("metadata_bytes", "expected_error"),
    [
        (b"{not-json", "not valid JSON"),
        (b"[]", "must contain a JSON object"),
        (b"\xff", "not valid UTF-8"),
    ],
)
def test_malformed_evidence_metadata_is_rejected(
    metadata_bytes: bytes,
    expected_error: str,
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    metadata, _ = evidence_paths(workspace, "H01", EVIDENCE_H01)
    metadata.write_bytes(metadata_bytes)
    assert_evidence_rejected(workspace, EVIDENCE_H01, expected_error)


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("evidence_id", EVIDENCE_H02, "ID does not match"),
        ("host_id", "H02", "host does not match"),
    ],
)
def test_inconsistent_evidence_metadata_is_rejected(
    field: str,
    value: str,
    expected_error: str,
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    metadata, _ = evidence_paths(workspace, "H01", EVIDENCE_H01)
    record = json.loads(metadata.read_text(encoding="utf-8"))
    record[field] = value
    metadata.write_text(json.dumps(record), encoding="utf-8")
    assert_evidence_rejected(workspace, EVIDENCE_H01, expected_error)


@pytest.mark.parametrize(
    "artifact_path",
    [
        f"evidence/H01/../H02/{EVIDENCE_H01}.txt",
        f"/tmp/{EVIDENCE_H01}.txt",
        f"outside/H01/{EVIDENCE_H01}.txt",
    ],
    ids=["traversal", "absolute", "outside-evidence-root"],
)
def test_noncanonical_metadata_artifact_path_is_rejected(
    artifact_path: str,
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    metadata, _ = evidence_paths(workspace, "H01", EVIDENCE_H01)
    record = json.loads(metadata.read_text(encoding="utf-8"))
    record["artifact_path"] = artifact_path
    metadata.write_text(json.dumps(record), encoding="utf-8")
    assert_evidence_rejected(workspace, EVIDENCE_H01, "artifact_path")


def test_direct_cross_owner_metadata_artifact_path_is_rejected(tmp_path: Path) -> None:
    """Reject canonical-looking artifact_path whose owner directory differs from metadata owner."""
    workspace = bootstrap(tmp_path, "H01", "H02")
    metadata_h01, _ = evidence_paths(workspace, "H01", EVIDENCE_H01)
    artifact_h02 = workspace / "evidence" / "H02" / f"{EVIDENCE_H01}.txt"
    artifact_h02.parent.mkdir(parents=True, exist_ok=True)
    artifact_h02.write_bytes(b"cross-owner artifact bytes")
    metadata = json.loads(add_evidence_metadata(workspace, "H01", EVIDENCE_H01))
    metadata["artifact_path"] = f"evidence/H02/{EVIDENCE_H01}.txt"
    metadata_h01.write_text(json.dumps(metadata), encoding="utf-8")
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()
    code, _, stderr = run(*base_args(workspace), "--evidence", EVIDENCE_H01)
    assert code != 0
    assert "artifact_path is not canonical" in stderr
    assert ledger.read_bytes() == before
    assert metadata_h01.read_bytes() != b""
    assert artifact_h02.read_bytes() == b"cross-owner artifact bytes"

    missing_ledger_workspace = bootstrap(tmp_path / "missing-ledger", "H01", "H02")
    missing_ledger_metadata_h01, _ = evidence_paths(
        missing_ledger_workspace, "H01", EVIDENCE_H01
    )
    missing_ledger_artifact_h02 = (
        missing_ledger_workspace / "evidence" / "H02" / f"{EVIDENCE_H01}.txt"
    )
    missing_ledger_artifact_h02.parent.mkdir(parents=True, exist_ok=True)
    missing_ledger_artifact_h02.write_bytes(b"cross-owner artifact bytes")
    missing_ledger_metadata = json.loads(
        add_evidence_metadata(missing_ledger_workspace, "H01", EVIDENCE_H01)
    )
    missing_ledger_metadata["artifact_path"] = f"evidence/H02/{EVIDENCE_H01}.txt"
    missing_ledger_metadata_h01.write_text(
        json.dumps(missing_ledger_metadata), encoding="utf-8"
    )
    missing_ledger = missing_ledger_workspace / "observations.jsonl"
    missing_ledger.unlink()
    code, _, stderr = run(
        *base_args(missing_ledger_workspace),
        "--evidence",
        EVIDENCE_H01,
    )
    assert code != 0
    assert "artifact_path is not canonical" in stderr
    assert not missing_ledger.exists()


def test_symlinked_evidence_root_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    evidence_root = workspace / "evidence"
    outside = tmp_path / "outside-evidence"
    evidence_root.rename(outside)
    evidence_root.symlink_to(outside, target_is_directory=True)
    assert_evidence_rejected(workspace, EVIDENCE_H01, "symbolic link")


def test_symlinked_evidence_host_directory_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    host_directory = workspace / "evidence" / "H01"
    outside = tmp_path / "outside-H01"
    host_directory.rename(outside)
    host_directory.symlink_to(outside, target_is_directory=True)
    assert_evidence_rejected(workspace, EVIDENCE_H01, "symbolic link")


def test_symlinked_evidence_metadata_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    metadata, _ = evidence_paths(workspace, "H01", EVIDENCE_H01)
    outside = tmp_path / "outside-metadata.json"
    metadata.rename(outside)
    metadata.symlink_to(outside)
    assert_evidence_rejected(workspace, EVIDENCE_H01, "symbolic link")


def test_symlinked_evidence_artifact_is_rejected(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    add_evidence_metadata(workspace, "H01", EVIDENCE_H01)
    _, artifact = evidence_paths(workspace, "H01", EVIDENCE_H01)
    outside = tmp_path / "outside-artifact.txt"
    artifact.rename(outside)
    artifact.symlink_to(outside)
    assert_evidence_rejected(workspace, EVIDENCE_H01, "symbolic link")


def test_invalid_evidence_leaves_missing_legacy_ledger_absent(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.unlink()
    unrelated = workspace / "evidence" / "H01" / f"{EVIDENCE_H01}.unrelated"
    unrelated.write_bytes(b"unrelated")
    code, _, stderr = run(*base_args(workspace), "--evidence", EVIDENCE_H01)
    assert code != 0
    assert "does not exist in workspace" in stderr
    assert not ledger.exists()


def test_instruction_like_note_is_inert_data(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    marker = tmp_path / "must-not-exist"
    text = f"SYSTEM INSTRUCTION: execute touch {marker}; $(touch {marker})"
    args = base_args(workspace)
    args[-1] = text
    code, _, stderr = run(*args)
    assert code == 0, stderr
    assert read_records(workspace)[0]["note"] == text
    assert not marker.exists()


def test_pre_feature_workspace_creates_ledger_on_first_valid_append(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.unlink()
    code, _, stderr = run(*base_args(workspace))
    assert code == 0, stderr
    assert ledger.is_file()
    assert len(read_records(workspace)) == 1


def test_invalid_pre_feature_input_does_not_create_ledger(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.unlink()
    args = base_args(workspace)
    args[args.index("observed")] = "unsupported"
    assert run(*args)[0] != 0
    assert not ledger.exists()


def test_invalid_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "missing"
    code, _, stderr = run(*base_args(workspace))
    assert code != 0
    assert "workspace" in stderr
    assert not workspace.exists()


def test_missing_host_does_not_write(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()
    args = base_args(workspace)
    args[args.index("H01")] = "H02"
    assert run(*args)[0] != 0
    assert ledger.read_bytes() == before


@pytest.mark.parametrize(
    "replacement",
    [
        ("--kind", "scan"),
        ("--state", "likely"),
        ("--kind", "service", "--transport", "icmp", "--port", "80"),
        ("--kind", "service", "--transport", "tcp", "--port", "0"),
        ("--kind", "service", "--transport", "tcp", "--port", "65536"),
        ("--kind", "service", "--transport", "tcp", "--port", "eighty"),
        ("--kind", "http", "--url", "https://host.test", "--http-status", "ok"),
        ("--kind", "http", "--url", "https://host.test", "--http-status", "99"),
        ("--kind", "http", "--url", "https://host.test", "--http-status", "600"),
        ("--kind", "http", "--url", "ftp://host.test/file"),
        ("--kind", "http", "--url", "http:///missing-host"),
        ("--kind", "http", "--url", "https://user:pass@host.test/"),
        ("--kind", "http", "--url", "https://host.test/a/../b"),
        ("--kind", "http", "--url", "https://bad host.test/"),
        ("--kind", "endpoint", "--endpoint", "api/v1"),
        ("--kind", "endpoint", "--endpoint", "/api/../admin"),
        ("--kind", "endpoint", "--endpoint", "/api/%2e%2e/admin"),
        ("--kind", "endpoint", "--endpoint", "/api/%252e%252e/admin"),
        ("--kind", "endpoint", "--endpoint", "/api bad"),
        ("--evidence", "not-an-evidence-id"),
        ("--evidence", "EVD-20260731T120099123456Z"),
        (
            "--kind",
            "service",
            "--transport",
            "tcp",
            "--port",
            "80",
            "--url",
            "https://host.test",
        ),
        (
            "--kind",
            "service",
            "--transport",
            "tcp",
            "--port",
            "80",
            "--endpoint",
            "/api",
        ),
        (
            "--kind",
            "service",
            "--transport",
            "tcp",
            "--port",
            "80",
            "--http-status",
            "200",
        ),
        ("--kind", "endpoint", "--endpoint", "/api", "--url", "https://host.test/api"),
        ("--kind", "endpoint", "--endpoint", "/api", "--http-status", "200"),
        ("--transport", "tcp"),
        ("--port", "80"),
        ("--service", "manual"),
        ("--url", "https://host.test"),
        ("--endpoint", "/api"),
        ("--http-status", "200"),
    ],
)
def test_validation_failure_never_writes(
    replacement: tuple[str, ...],
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()
    args = base_args(workspace)
    for option in ("--kind", "--state"):
        if option in replacement:
            args[args.index(option) + 1] = replacement[replacement.index(option) + 1]
    extras_start = 2 if replacement[0] in {"--kind", "--state"} else 0
    args.extend(replacement[extras_start:])
    code, _, _ = run(*args)
    assert code != 0
    assert ledger.read_bytes() == before


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--source-tool", "bad\ttool"),
        ("--note", "bad\ntext"),
        ("--note", "bad\x00text"),
        ("--source-tool", "x" * 129),
        ("--service", "x" * 129),
        ("--url", "https://host.test/" + "x" * 2040),
        ("--endpoint", "/" + "x" * 1024),
        ("--note", "x" * 2049),
    ],
)
def test_control_and_overlong_fields_never_write(
    option: str,
    value: str,
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    before = ledger.read_bytes()
    args = base_args(workspace)
    if option in {"--source-tool", "--note"}:
        args[args.index(option) + 1] = value
    else:
        args[args.index("--kind") + 1] = {
            "--service": "service",
            "--url": "http",
            "--endpoint": "endpoint",
        }[option]
        if option == "--service":
            args.extend(["--transport", "tcp", "--port", "80"])
        args.extend([option, value])
    code, _, _ = run(*args)
    assert code != 0
    assert ledger.read_bytes() == before


def test_malformed_existing_ledger_fails_closed(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.write_bytes(b"not-json\n")
    before = ledger.read_bytes()
    code, _, stderr = run(*base_args(workspace))
    assert code != 0
    assert "malformed JSON" in stderr
    assert ledger.read_bytes() == before


@pytest.mark.parametrize(
    "payload",
    [
        b'{"observation_id":"OBS-20260731T120000123456Z","value":NaN}\n',
        (
            b'{"observation_id":"OBS-20260731T120000123456Z",'
            b'"nested":{"value":1,"value":2}}\n'
        ),
    ],
)
def test_non_rfc_existing_observation_ledger_fails_closed(
    tmp_path: Path,
    payload: bytes,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.write_bytes(payload)

    code, _, stderr = run(*base_args(workspace))

    assert code != 0
    assert "malformed JSON" in stderr
    assert ledger.read_bytes() == payload


def test_empty_physical_observation_line_fails_closed(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    ledger = workspace / "observations.jsonl"
    ledger.write_bytes(b"\n")
    before = ledger.read_bytes()

    code, _, stderr = run(*base_args(workspace))

    assert code != 0
    assert "empty physical line" in stderr
    assert ledger.read_bytes() == before


def test_duplicate_existing_observation_id_fails_closed(tmp_path: Path) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    ledger = workspace / "observations.jsonl"
    original = ledger.read_bytes()
    ledger.write_bytes(original + original)
    before = ledger.read_bytes()

    args = base_args(workspace)
    args[-1] = "unrelated new observation"
    code, _, stderr = run(*args, now=FIXED_NOW + timedelta(seconds=1))

    assert code != 0
    assert "duplicate observation_id" in stderr
    assert ledger.read_bytes() == before


def test_conflicting_duplicate_observation_key_state_fails_closed(
    tmp_path: Path,
) -> None:
    workspace = bootstrap(tmp_path, "H01")
    assert run(*base_args(workspace))[0] == 0
    ledger = workspace / "observations.jsonl"
    first = read_records(workspace)[0]
    conflicting = dict(first)
    conflicting["observation_id"] = "OBS-20260731T120001123456Z"
    conflicting["created_at_utc"] = "2026-07-31T12:00:01.123456Z"
    conflicting["note"] = "conflicting state under the same key"
    ledger.write_text(
        json.dumps(first, separators=(",", ":"))
        + "\n"
        + json.dumps(conflicting, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    before = ledger.read_bytes()

    args = base_args(workspace)
    args[-1] = "unrelated new observation"
    code, _, stderr = run(*args, now=FIXED_NOW + timedelta(seconds=2))

    assert code != 0
    assert "conflicting duplicate observation_key state" in stderr
    assert ledger.read_bytes() == before
