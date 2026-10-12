"""Tests for scripts/new_host.py."""

import os
from pathlib import Path

import pytest

from scripts import new_host
from scripts.new_host import atomic_write_text, main


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    """Run the CLI entry point and return (exit_code, stdout, stderr)."""
    try:
        code = main(list(args))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_creates_workspace_and_host(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A new workspace and host are created successfully."""
    code, stdout, stderr = run(
        capsys,
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", "H01",
        "--ip", "192.0.2.10",
        "--hostname", "entry-a",
    )
    assert code == 0, stderr
    assert "Created host H01" in stdout


def test_creates_missing_parent_chain_for_workspace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A new nested workspace retains the established parent-creation behavior."""
    workspace = tmp_path / "missing-parent" / "assessment_workspace"
    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
    )
    assert code == 0, stderr
    assert (workspace / "hosts" / "H01.md").is_file()


def test_common_workspace_layout(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The expected common workspace layout is created."""
    workspace = tmp_path / "assessment_workspace"
    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert code == 0

    assert (workspace / "global.md").is_file()
    assert (workspace / "hosts").is_dir()
    assert (workspace / "inbox").is_dir()
    assert (workspace / "evidence").is_dir()
    assert (workspace / "execution_runs").is_dir()
    assert (workspace / "execution_runs/H01").is_dir()
    assert (workspace / "report").is_dir()
    assert (workspace / "queries").is_dir()
    assert (workspace / "checkpoints").is_dir()
    assert (workspace / "loot.jsonl").is_file()
    assert (workspace / "attempts.jsonl").is_file()
    observations = workspace / "observations.jsonl"
    assert observations.is_file()
    assert observations.read_bytes() == b""
    for ledger_name in (
        "findings.jsonl",
        "work_items.jsonl",
        "local_artifacts.jsonl",
        "workspace_lifecycle.jsonl",
        "standing_authorizations.jsonl",
        "plaintext_report_policy.jsonl",
        "plaintext_report_exports.jsonl",
        "authorizations.jsonl",
        "changes.jsonl",
        "attack_paths.jsonl",
        "report_steps.jsonl",
        "execution_runs.jsonl",
        "claims.jsonl",
    ):
        ledger = workspace / ledger_name
        assert ledger.is_file()
        assert ledger.read_bytes() == b""


def test_host_specific_layout(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The expected host-specific layout is created."""
    workspace = tmp_path / "assessment_workspace"
    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert code == 0

    assert (workspace / "hosts" / "H01.md").is_file()
    assert (workspace / "inbox" / "H01").is_dir()
    assert (workspace / "evidence" / "H01").is_dir()
    assert (workspace / "report" / "H01.md").is_file()


def test_host_state_and_report_files_exist(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Host state and report files are created from the templates."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )

    host_state = (workspace / "hosts" / "H01.md").read_text()
    report = (workspace / "report" / "H01.md").read_text()

    assert "# Host H01" in host_state
    assert "## Identity and reachability" in host_state
    assert "## Report notes" in host_state
    assert "<!-- CYBER:HOST-STATE:START -->" in host_state
    assert "<!-- CYBER:HOST-STATE:END -->" in host_state

    assert "# H01 — Report working notes" in report
    assert "## Target overview" in report
    assert "## Outstanding documentation" in report
    assert "<!-- CYBER:SCREENSHOTS:START -->" in report
    assert "Accepted PNGs are inserted here as direct Markdown image references" in report
    assert "<!-- CYBER:SCREENSHOTS:END -->" in report


def test_metadata_inserted(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Host ID, IP, and hostname are inserted into generated files."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--ip", "192.0.2.10",
        "--hostname", "entry-a",
    )

    host_state = (workspace / "hosts" / "H01.md").read_text()
    report = (workspace / "report" / "H01.md").read_text()

    for text in (host_state, report):
        assert "- Host ID: `H01`" in text
        assert "- IP address: `192.0.2.10`" in text
        assert "- Hostname: `entry-a`" in text


def test_unknown_values_for_optional_metadata(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Omitted optional metadata is represented exactly as 'unknown'."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )

    host_state = (workspace / "hosts" / "H01.md").read_text()
    report = (workspace / "report" / "H01.md").read_text()

    for text in (host_state, report):
        assert "- Host ID: `H01`" in text
        assert "- IP address: `unknown`" in text
        assert "- Hostname: `unknown`" in text


@pytest.mark.parametrize(
    "host_id",
    [
        "h01",
        "HOST01",
        "H1",
        "H001",
        "../H01",
        "H 01",
        "H01/",
        "H01\\",
        "H01;",
        "H00a",
        "H000",
        "",
    ],
)
def test_invalid_host_ids_rejected(host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Invalid host IDs are rejected with a non-zero exit code."""
    code, _, stderr = run(
        capsys,
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", host_id,
    )
    assert code != 0
    assert "invalid host ID" in stderr.lower() or "host id" in stderr.lower()


@pytest.mark.parametrize("host_id", ["../H01", "..", "H01/../H02", "H01/.."])
def test_host_id_traversal_rejected(host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Host IDs that contain traversal syntax are rejected."""
    code, _, _ = run(
        capsys,
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", host_id,
    )
    assert code != 0


@pytest.mark.parametrize("ip", ["not-an-ip", "999.999.999.999", "192.0.2", "::gggg"])
def test_invalid_ip_rejected(ip: str, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Invalid IP addresses are rejected."""
    code, _, stderr = run(
        capsys,
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", "H01",
        "--ip", ip,
    )
    assert code != 0
    assert "invalid ip address" in stderr.lower()


@pytest.mark.parametrize(
    "hostname",
    [
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "host..name",
        "host/name",
        "host\\name",
        "host name",
        "host:name",
        "http://host",
        "host:80",
        "user@host",
        "host;rm",
        ".leading.dot",
        "trailing.dot.",
        "a" * 64 + ".local",
    ],
)
def test_unsafe_hostname_rejected(hostname: str, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Unsafe hostnames are rejected."""
    # Values beginning with '-' must be passed with '--hostname=-value' syntax
    # so argparse does not interpret them as flags.
    if hostname.startswith("-"):
        hostname_arg = f"--hostname={hostname}"
    else:
        hostname_arg = "--hostname"
    args = [
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", "H01",
    ]
    if hostname_arg.startswith("--hostname="):
        args.append(hostname_arg)
    else:
        args.extend([hostname_arg, hostname])
    code, _, stderr = run(capsys, *args)
    assert code != 0
    assert "invalid hostname" in stderr.lower()


def test_refuses_to_overwrite_existing_host(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """An existing host record is not overwritten."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--hostname", "first",
    )

    original = (workspace / "hosts" / "H01.md").read_text()

    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--hostname", "second",
    )
    assert code != 0
    assert (workspace / "hosts" / "H01.md").read_text() == original


def test_preserves_existing_global_md(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Existing global.md is preserved during workspace initialization."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    custom_global = "# Custom global\n\nKeep me.\n"
    (workspace / "global.md").write_text(custom_global)

    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert code == 0
    assert (workspace / "global.md").read_text() == custom_global


def test_preserves_existing_loot_jsonl(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Existing loot.jsonl is preserved during workspace initialization."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    custom_loot = '{"test": true}\n'
    (workspace / "loot.jsonl").write_text(custom_loot)

    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert (workspace / "loot.jsonl").read_text() == custom_loot


def test_preserves_existing_attempts_jsonl(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Existing attempts.jsonl is preserved during workspace initialization."""
    workspace = tmp_path / "assessment_workspace"
    workspace.mkdir()
    custom_attempts = '{"attempt": 1}\n'
    (workspace / "attempts.jsonl").write_text(custom_attempts)

    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert (workspace / "attempts.jsonl").read_text() == custom_attempts


def test_adding_host_preserves_existing_observations_bytes(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Adding another host never truncates or rewrites observations.jsonl."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
    )
    observations = workspace / "observations.jsonl"
    original = b'{"synthetic":"observation"}\n\x00byte-preservation-check'
    observations.write_bytes(original)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H02",
    )
    assert code == 0, stderr
    assert observations.read_bytes() == original


def test_h00_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Host ID H00 is rejected before any workspace or files are created."""
    workspace = tmp_path / "assessment_workspace"
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H00",
    )
    assert code != 0
    assert "H00" in stderr
    assert not workspace.exists()


@pytest.mark.parametrize("host_id", ["H01", "H09", "H10", "H99", "H100"])
def test_valid_host_ids_accepted(
    host_id: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Canonical host IDs from H01 onward are accepted and created."""
    workspace = tmp_path / "assessment_workspace"
    code, _, stderr = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", host_id,
    )
    assert code == 0, stderr
    assert (workspace / "hosts" / f"{host_id}.md").is_file()


def test_no_partial_paths_after_preflight_conflict(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """No host-specific paths are created when preflight detects a conflict."""
    workspace = tmp_path / "assessment_workspace"
    run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )

    # Create only one conflicting path to trigger the preflight failure.
    (workspace / "inbox" / "H02").mkdir(parents=True)
    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H02",
    )
    assert code != 0

    assert not (workspace / "hosts" / "H02.md").exists()
    assert not (workspace / "report" / "H02.md").exists()
    assert not (workspace / "evidence" / "H02").exists()
    # inbox/H02 already existed and must remain.
    assert (workspace / "inbox" / "H02").exists()


def test_common_workspace_directories_already_exist(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Existing common directories do not cause an error."""
    workspace = tmp_path / "assessment_workspace"
    for name in ("hosts", "inbox", "evidence", "report", "queries", "checkpoints"):
        (workspace / name).mkdir(parents=True)

    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
    )
    assert code == 0
    assert (workspace / "hosts" / "H01.md").is_file()


def test_workspace_path_existing_regular_file_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A workspace path that is an existing regular file is rejected."""
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("I am a file.\n")

    code, _, stderr = run(
        capsys,
        "--workspace", str(file_path),
        "--host-id", "H01",
    )
    assert code != 0
    assert "workspace path is an existing file" in stderr.lower()


def test_workspace_path_with_parent_traversal_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Workspace paths containing '..' are rejected."""
    code, _, stderr = run(
        capsys,
        "--workspace", str(tmp_path / ".." / "somewhere"),
        "--host-id", "H01",
    )
    assert code != 0
    assert "must not contain '..'" in stderr.lower()


def test_non_zero_exit_on_validation_error(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Validation errors produce a non-zero exit code."""
    code, _, _ = run(
        capsys,
        "--workspace", str(tmp_path / "assessment_workspace"),
        "--host-id", "bad-id",
    )
    assert code != 0


def test_ipv6_address_supported(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """IPv6 addresses are accepted."""
    workspace = tmp_path / "assessment_workspace"
    code, _, _ = run(
        capsys,
        "--workspace", str(workspace),
        "--host-id", "H01",
        "--ip", "2001:db8::1",
    )
    assert code == 0
    host_state = (workspace / "hosts" / "H01.md").read_text()
    assert "- IP address: `2001:db8::1`" in host_state


@pytest.mark.parametrize(
    "relative_sidecar",
    ["hosts/H01.md.tmp", "report/H01.md.tmp", "global.md.tmp"],
    ids=["host-markdown", "report-markdown", "common-global"],
)
def test_predictable_sidecar_symlink_is_never_followed(
    relative_sidecar: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Legacy predictable sidecars remain unrelated and cannot redirect writes."""
    workspace = tmp_path / "assessment_workspace"
    (workspace / "hosts").mkdir(parents=True)
    (workspace / "report").mkdir()
    sentinel = tmp_path / "external-sentinel.txt"
    sentinel.write_bytes(b"sentinel-unchanged")
    sidecar = workspace / relative_sidecar
    sidecar.symlink_to(sentinel)

    code, _, stderr = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--ip",
        "192.0.2.10",
        "--hostname",
        "sidecar-test",
    )

    assert code == 0, stderr
    assert sentinel.read_bytes() == b"sentinel-unchanged"
    assert sidecar.is_symlink()
    assert os.readlink(sidecar) == str(sentinel)
    final_name = relative_sidecar.removesuffix(".tmp")
    final_path = workspace / final_name
    assert final_path.is_file()
    assert not final_path.is_symlink()


@pytest.mark.parametrize(
    "relative_destination",
    ["hosts/H01.md", "report/H01.md"],
    ids=["host", "report"],
)
def test_existing_final_symlink_is_rejected_without_external_write(
    relative_destination: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A canonical host or report symlink is never replaced or followed."""
    workspace = tmp_path / "assessment_workspace"
    (workspace / "hosts").mkdir(parents=True)
    (workspace / "report").mkdir()
    sentinel = tmp_path / "external-final-sentinel.txt"
    sentinel.write_bytes(b"final-sentinel")
    destination = workspace / relative_destination
    destination.symlink_to(sentinel)

    code, _, _ = run(
        capsys,
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
    )

    assert code != 0
    assert destination.is_symlink()
    assert sentinel.read_bytes() == b"final-sentinel"
    assert not (workspace / "inbox" / "H01").exists()
    assert not (workspace / "evidence" / "H01").exists()


def test_secure_atomic_temporary_file_is_removed_after_success(tmp_path: Path) -> None:
    """A successful atomic write leaves only its regular final file."""
    destination = tmp_path / "result.md"
    atomic_write_text(destination, "complete\n")
    assert destination.read_text(encoding="utf-8") == "complete\n"
    assert not destination.is_symlink()
    assert list(tmp_path.glob(".result.md.*.tmp")) == []


def test_secure_atomic_temporary_file_is_removed_after_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A write-phase failure removes the unique temporary regular file."""
    destination = tmp_path / "result.md"

    def fail_fsync(descriptor: int) -> None:
        raise OSError("synthetic write-phase failure")

    monkeypatch.setattr(new_host, "_fsync_file", fail_fsync)
    with pytest.raises(OSError, match="synthetic write-phase failure"):
        atomic_write_text(destination, "complete\n")

    assert not destination.exists()
    assert list(tmp_path.glob(".result.md.*.tmp")) == []
