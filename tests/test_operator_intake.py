"""Tests for bounded natural-text host mapping intake."""

import errno
import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import operator_intake
from scripts.new_host import main as new_host_main
from scripts.operator_intake import MAX_INPUT_BYTES, main

FIXED_NOW = datetime(2026, 7, 31, 12, 34, 56, 123456, tzinfo=UTC)
EXAMPLE = (
    b"192.0.2.20\nGitlab\n\n"
    b"192.0.2.22\nWORKSTATION-B\n\n"
    b"192.0.2.21\nWORKSTATION-A\n"
)


def run_intake(
    capsys: pytest.CaptureFixture[str],
    workspace: Path,
    input_path: Path,
    mode: str = "--preview",
) -> tuple[int, str, str]:
    """Run intake in process and capture its public CLI streams."""
    try:
        code = main(
            [
                "--workspace",
                str(workspace),
                "--input-file",
                str(input_path),
                mode,
            ],
            now=FIXED_NOW,
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def create_host(
    capsys: pytest.CaptureFixture[str],
    workspace: Path,
    host_id: str,
    ip: str,
    label: str,
) -> None:
    """Create a host through the canonical bootstrap CLI entry point."""
    code = new_host_main(
        [
            "--workspace",
            str(workspace),
            "--host-id",
            host_id,
            "--ip",
            ip,
            "--hostname",
            label,
        ]
    )
    assert code == 0
    capsys.readouterr()


def write_input(tmp_path: Path, data: bytes, name: str = "input.txt") -> Path:
    """Write fictional operator input outside its target workspace."""
    path = tmp_path / name
    path.write_bytes(data)
    return path


def snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
    """Capture file bytes, object types, and permission bits for mutation checks."""
    if not root.exists() and not root.is_symlink():
        return {}
    result: dict[str, tuple[str, int, bytes | None]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        relative = "." if path == root else path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            result[relative] = ("symlink", stat.S_IMODE(metadata.st_mode), os.readlink(path).encode())
        elif path.is_dir():
            result[relative] = ("directory", stat.S_IMODE(metadata.st_mode), None)
        else:
            result[relative] = ("file", stat.S_IMODE(metadata.st_mode), path.read_bytes())
    return result


def test_exact_user_example_two_line_records(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The exact three-record user example maps to H01, H02, and H03."""
    input_path = write_input(tmp_path, EXAMPLE)
    code, stdout, stderr = run_intake(capsys, tmp_path / "workspace", input_path)
    assert code == 0, stderr
    assert "parsed_mappings: 3" in stdout
    assert "status=create host_id=H01 ip=192.0.2.20 label=Gitlab" in stdout
    assert "status=create host_id=H02 ip=192.0.2.22 label=WORKSTATION-B" in stdout
    assert "status=create host_id=H03 ip=192.0.2.21 label=WORKSTATION-A" in stdout


def test_three_one_line_records(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Equivalent one-line records preserve input order."""
    data = b"192.0.2.20 Gitlab\n\n192.0.2.22 WORKSTATION-B\n\n192.0.2.21 WORKSTATION-A\n"
    code, stdout, _ = run_intake(capsys, tmp_path / "workspace", write_input(tmp_path, data))
    assert code == 0
    assert [stdout.index(f"host_id=H0{number}") for number in (1, 2, 3)] == sorted(
        stdout.index(f"host_id=H0{number}") for number in (1, 2, 3)
    )


def test_mixed_one_and_two_line_records(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """One-line and two-line records may be mixed when blocks are unambiguous."""
    data = b"192.0.2.1 alpha\n\n192.0.2.2\nbeta\n"
    code, stdout, _ = run_intake(capsys, tmp_path / "workspace", write_input(tmp_path, data))
    assert code == 0
    assert "parsed_mappings: 2" in stdout


def test_existing_exact_mapping_reported_existing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """An exact existing mapping does not plan a new host."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "Alpha")
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.1 alpha\n")
    )
    assert code == 0
    assert "status=existing host_id=H01" in stdout
    assert "new_mappings: 0" in stdout


def test_existing_hosts_then_deterministic_assignment(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """New assignment starts after the highest existing host."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    data = b"192.0.2.1 alpha\n\n192.0.2.2 beta\n"
    code, stdout, _ = run_intake(capsys, workspace, write_input(tmp_path, data))
    assert code == 0
    assert "status=existing host_id=H01" in stdout
    assert "status=create host_id=H02" in stdout


def test_existing_gaps_are_not_reused(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Assignment follows the maximum ID rather than filling a gap."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    create_host(capsys, workspace, "H03", "192.0.2.3", "gamma")
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.2 beta\n")
    )
    assert code == 0
    assert "status=create host_id=H04" in stdout
    assert "host_id=H02" not in stdout


def test_assignment_after_h99(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Canonical assignment grows from H99 to H100."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H99", "192.0.2.99", "ninety-nine")
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.100 hundred\n")
    )
    assert code == 0
    assert "status=create host_id=H100" in stdout


def test_ipv6_canonicalization(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """IPv6 input and existing comparisons use canonical ipaddress semantics."""
    input_path = write_input(tmp_path, b"2001:0db8:0000::0001 v6host\n")
    code, stdout, _ = run_intake(capsys, tmp_path / "workspace", input_path)
    assert code == 0
    assert "ip=2001:db8::1" in stdout


def test_repeated_identical_mapping_collapsed(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Repeated semantic identity is planned once with first display form."""
    data = b"192.0.2.1 Alpha\n\n192.0.2.1 alpha\n"
    code, stdout, _ = run_intake(capsys, tmp_path / "workspace", write_input(tmp_path, data))
    assert code == 0
    assert "parsed_mappings: 1" in stdout
    assert stdout.count("mapping: status=") == 1
    assert "label=Alpha" in stdout


def test_same_ip_conflicting_labels(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """One input IP cannot map to different labels."""
    data = b"192.0.2.1 alpha\n\n192.0.2.1 beta\n"
    workspace = tmp_path / "workspace"
    code, _, stderr = run_intake(capsys, workspace, write_input(tmp_path, data))
    assert code != 0
    assert "conflicts" in stderr
    assert not workspace.exists()


def test_same_label_conflicting_ips(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """One case-insensitive input label cannot map to different IPs."""
    data = b"192.0.2.1 Alpha\n\n192.0.2.2 alpha\n"
    code, _, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert "conflicts" in stderr


def test_multiple_ips_in_one_record_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A record with multiple addresses is outside the exact grammar."""
    data = b"192.0.2.1 192.0.2.2 alpha\n"
    code, _, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert "supported one-line" in stderr


def test_conflict_against_existing_ip(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """An existing IP cannot be rebound to a different label."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    before = snapshot(workspace)
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.1 beta\n"), "--apply"
    )
    assert code != 0
    assert "existing IP" in stderr
    assert snapshot(workspace) == before


def test_conflict_against_existing_label(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """An existing label cannot be rebound to a different IP."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "Alpha")
    before = snapshot(workspace)
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.2 alpha\n"), "--apply"
    )
    assert code != 0
    assert "existing label" in stderr
    assert snapshot(workspace) == before


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"192.0.2.1\n", "one-line"),
        (b"alpha\n", "one-line"),
        (b"192.0.2.1\nalpha\nextra\n", "more than two"),
    ],
)
def test_incomplete_or_oversized_blocks_rejected(
    data: bytes,
    message: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Incomplete mappings and blocks beyond the grammar fail closed."""
    code, _, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert message in stderr


@pytest.mark.parametrize(
    "data",
    [
        b"Nmap scan report for 192.0.2.1\nHost is up\n80/tcp open http\n",
        b"username: synthetic\npassword: synthetic-secret\n",
        b"https://synthetic.invalid/path\n",
    ],
    ids=["scanner", "credential", "url"],
)
def test_unsupported_data_classes_rejected(
    data: bytes,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Scanner, credential, and URL inputs are not guessed into host mappings."""
    code, stdout, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert stdout == ""
    assert "error:" in stderr


@pytest.mark.parametrize("data", [b"192.0.2.1\x00alpha\n", b"192.0.2.1\talpha\n"])
def test_control_characters_rejected(
    data: bytes,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """NUL and other non-line ASCII controls are rejected."""
    code, _, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert "control character" in stderr


def test_boundary_whitespace_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Boundary whitespace is never silently persisted in a label."""
    code, _, stderr = run_intake(
        capsys,
        tmp_path / "workspace",
        write_input(tmp_path, b"192.0.2.1\n alpha\n"),
    )
    assert code != 0
    assert "boundary whitespace" in stderr


def test_invalid_utf8_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Malformed UTF-8 fails before workspace mutation."""
    workspace = tmp_path / "workspace"
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.1 alpha\xff\n")
    )
    assert code != 0
    assert "valid UTF-8" in stderr
    assert not workspace.exists()


def test_oversized_input_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """The documented conservative byte limit is enforced before decoding."""
    data = b"a" * (MAX_INPUT_BYTES + 1)
    code, _, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code != 0
    assert "byte limit" in stderr


def test_symlink_input_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Input symlinks are rejected even when they point to a regular file."""
    target = write_input(tmp_path, b"192.0.2.1 alpha\n", "target.txt")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    code, _, stderr = run_intake(capsys, tmp_path / "workspace", link)
    assert code != 0
    assert "symlink" in stderr


def test_symlink_intake_directory_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Apply rejects an existing symlink at inbox/operator before mutation."""
    workspace = tmp_path / "workspace"
    (workspace / "inbox").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "inbox" / "operator").symlink_to(outside, target_is_directory=True)
    before = snapshot(workspace)
    code, _, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, b"192.0.2.1 alpha\n"),
        "--apply",
    )
    assert code != 0
    assert "non-symlink directory" in stderr
    assert snapshot(workspace) == before


def test_symlink_workspace_component_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A symlink anywhere in the supplied workspace path fails closed."""
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    code, _, stderr = run_intake(
        capsys,
        linked_parent / "workspace",
        write_input(tmp_path, b"192.0.2.1 alpha\n"),
        "--apply",
    )
    assert code != 0
    assert "components must not be symlinks" in stderr
    assert not (real_parent / "workspace").exists()


def test_malformed_existing_host_record_fails_closed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Missing canonical identity fields block planning."""
    workspace = tmp_path / "workspace"
    (workspace / "hosts").mkdir(parents=True)
    (workspace / "hosts" / "H01.md").write_text("# malformed\n", encoding="utf-8")
    before = snapshot(workspace)
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.2 beta\n"), "--apply"
    )
    assert code != 0
    assert "malformed identity" in stderr
    assert snapshot(workspace) == before


def test_duplicate_existing_identity_fails_closed(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Two canonical records cannot claim the same identity."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    create_host(capsys, workspace, "H02", "192.0.2.1", "alpha")
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.3 gamma\n")
    )
    assert code != 0
    assert "duplicate existing" in stderr


def test_preview_is_byte_for_byte_read_only(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Preview does not create, rewrite, chmod, or preserve anything."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    before = snapshot(workspace)
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.2 beta\n")
    )
    assert code == 0
    assert "mode: preview" in stdout
    assert snapshot(workspace) == before


def test_apply_preserves_exact_raw_bytes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Successful apply preserves the original bytes without newline normalization."""
    workspace = tmp_path / "workspace"
    data = b"192.0.2.1\r\nalpha\r\n"
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, data), "--apply"
    )
    assert code == 0, stderr
    intake_path = workspace / "inbox" / "operator" / "INTAKE-20260731T123456123456Z.txt"
    assert intake_path.read_bytes() == data
    assert "preserved_input: inbox/operator/INTAKE-20260731T123456123456Z.txt" in stdout


def test_applied_intake_permissions_are_restrictive(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The private intake directory and file use 0700 and 0600 permissions."""
    workspace = tmp_path / "workspace"
    code, _, _ = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, b"192.0.2.1 alpha\n"),
        "--apply",
    )
    assert code == 0
    directory = workspace / "inbox" / "operator"
    intake_path = directory / "INTAKE-20260731T123456123456Z.txt"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(intake_path.stat().st_mode) == 0o600


def test_apply_creates_expected_canonical_hosts(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Apply routes every new mapping through canonical host bootstrap."""
    workspace = tmp_path / "workspace"
    code, _, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, EXAMPLE), "--apply"
    )
    assert code == 0, stderr
    for host_id, ip, label in (
        ("H01", "192.0.2.20", "Gitlab"),
        ("H02", "192.0.2.22", "WORKSTATION-B"),
        ("H03", "192.0.2.21", "WORKSTATION-A"),
    ):
        text = (workspace / "hosts" / f"{host_id}.md").read_text(encoding="utf-8")
        assert f"- Host ID: `{host_id}`" in text
        assert f"- IP address: `{ip}`" in text
        assert f"- Hostname: `{label}`" in text
        assert (workspace / "report" / f"{host_id}.md").is_file()
        assert (workspace / "inbox" / host_id).is_dir()
        assert (workspace / "evidence" / host_id).is_dir()


def test_apply_creates_preflighted_missing_workspace_parent_chain(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A nested new workspace is created only after its nearest parent preflight."""
    workspace = tmp_path / "missing-parent" / "workspace"
    code, _, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, b"192.0.2.10 nested-host\n"),
        "--apply",
    )
    assert code == 0, stderr
    assert (workspace / "hosts" / "H01.md").is_file()


def test_apply_all_existing_is_no_op(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """All-existing apply creates no duplicate intake and changes no bytes or modes."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    before = snapshot(workspace)
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.1 ALPHA\n"), "--apply"
    )
    assert code == 0
    assert "new_mappings: 0" in stdout
    assert "preserved_input: (none)" in stdout
    assert snapshot(workspace) == before


def test_conflict_causes_no_partial_creation(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """A late conflicting mapping prevents every host and intake write."""
    workspace = tmp_path / "workspace"
    data = b"192.0.2.1 alpha\n\n192.0.2.2 beta\n\n192.0.2.1 gamma\n"
    code, _, _ = run_intake(
        capsys, workspace, write_input(tmp_path, data), "--apply"
    )
    assert code != 0
    assert not workspace.exists()


def test_raw_input_is_not_echoed(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Neither successful nor rejected execution echoes the complete raw input."""
    data = b"192.0.2.1 alpha\n\n192.0.2.2 beta\n"
    code, stdout, stderr = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code == 0
    decoded = data.decode()
    assert decoded not in stdout
    assert decoded not in stderr

    secret_marker = b"synthetic-password-marker: value\n"
    code, stdout, stderr = run_intake(
        capsys,
        tmp_path / "other-workspace",
        write_input(tmp_path, secret_marker, "rejected.txt"),
    )
    assert code != 0
    assert secret_marker.decode().strip() not in stdout + stderr


def test_input_sha256_reported(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Preview reports the exact input byte hash."""
    data = b"192.0.2.1 alpha\n"
    code, stdout, _ = run_intake(
        capsys, tmp_path / "workspace", write_input(tmp_path, data)
    )
    assert code == 0
    assert f"input_sha256: {hashlib.sha256(data).hexdigest()}" in stdout


def test_preview_and_apply_modes_are_exclusive_and_required(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Argparse enforces exactly one explicit mode."""
    input_path = write_input(tmp_path, b"192.0.2.1 alpha\n")
    base = ["--workspace", str(tmp_path / "workspace"), "--input-file", str(input_path)]
    for args in (base, [*base, "--preview", "--apply"]):
        with pytest.raises(SystemExit):
            main(args, now=FIXED_NOW)
        assert capsys.readouterr().err


def test_planned_host_path_collision_fails_before_write(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Unexpected state at a planned Hxx destination blocks the entire plan."""
    workspace = tmp_path / "workspace"
    (workspace / "report").mkdir(parents=True)
    (workspace / "report" / "H01.md").write_text("unexpected\n", encoding="utf-8")
    before = snapshot(workspace)
    code, _, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, b"192.0.2.1 alpha\n"),
        "--apply",
    )
    assert code != 0
    assert "destination already exists" in stderr
    assert snapshot(workspace) == before


def test_noncanonical_existing_ipv6_compares_semantically(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Existing textual IPv6 variants compare through ipaddress semantics."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "2001:0db8:0000::0001", "v6host")
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"2001:db8::1 V6HOST\n")
    )
    assert code == 0
    assert "status=existing host_id=H01 ip=2001:db8::1" in stdout


def test_existing_unknown_host_advances_assignment(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A canonical unknown-identity record still reserves its host number."""
    workspace = tmp_path / "workspace"
    code = new_host_main(["--workspace", str(workspace), "--host-id", "H03"])
    assert code == 0
    capsys.readouterr()
    code, stdout, _ = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.4 delta\n")
    )
    assert code == 0
    assert "status=create host_id=H04" in stdout


def test_new_host_cli_behavior_remains_available_after_refactor(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The original CLI still creates and reports one canonical host."""
    workspace = tmp_path / "workspace"
    code = new_host_main(
        [
            "--workspace",
            str(workspace),
            "--host-id",
            "H01",
            "--ip",
            "192.0.2.1",
            "--hostname",
            "alpha",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Initialized workspace:" in captured.out
    assert "Created host H01:" in captured.out
    assert captured.err == ""


def test_preview_rejects_report_regular_file_without_mutation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Preview and apply agree that the common report path must be a directory."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "report").write_bytes(b"wrong-type")
    before = snapshot(workspace)

    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.10 alpha\n")
    )

    assert code != 0
    assert stdout == ""
    assert "report path" in stderr
    assert "mode: preview" not in stdout
    assert snapshot(workspace) == before


def test_preview_rejects_symlinked_common_component_without_mutation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Preview rejects a common-directory symlink before printing a plan."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside-evidence"
    outside.mkdir()
    (workspace / "evidence").symlink_to(outside, target_is_directory=True)
    before = snapshot(workspace)

    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, b"192.0.2.10 alpha\n")
    )

    assert code != 0
    assert stdout == ""
    assert "non-symlink directory" in stderr
    assert snapshot(workspace) == before


@pytest.mark.parametrize(
    "relative_directory",
    ["hosts", "report", "inbox", "evidence", "inbox/operator"],
    ids=["hosts", "report", "inbox", "evidence", "operator-intake"],
)
def test_apply_permission_failure_precedes_every_persistent_write(
    relative_directory: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Effective mode-0500 failures leave intake and H02 entirely absent."""
    if os.geteuid() == 0:
        pytest.skip("effective permission fixture requires a non-root test user")
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    target = workspace / relative_directory
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.chmod(0o500)
    before = snapshot(workspace)

    try:
        code, _, stderr = run_intake(
            capsys,
            workspace,
            write_input(tmp_path, b"192.0.2.2 beta\n"),
            "--apply",
        )
        assert code != 0
        assert "not writable and searchable" in stderr
        assert snapshot(workspace) == before
        assert not (workspace / "hosts" / "H02.md").exists()
        assert not (workspace / "report" / "H02.md").exists()
        assert not (workspace / "inbox" / "H02").exists()
        assert not (workspace / "evidence" / "H02").exists()
        assert list((workspace / "inbox" / "operator").glob("INTAKE-*.txt")) == []
    finally:
        target.chmod(0o700)


def test_all_existing_apply_ignores_unneeded_unwritable_creation_paths(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A true no-op does not demand write access to unrelated common paths."""
    if os.geteuid() == 0:
        pytest.skip("effective permission fixture requires a non-root test user")
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    targets = [workspace / "report", workspace / "queries", workspace / "checkpoints"]
    for target in targets:
        target.chmod(0o500)
    before = snapshot(workspace)

    try:
        code, stdout, stderr = run_intake(
            capsys,
            workspace,
            write_input(tmp_path, b"192.0.2.1 ALPHA\n"),
            "--apply",
        )
        assert code == 0, stderr
        assert "new_mappings: 0" in stdout
        assert "preserved_input: (none)" in stdout
        assert snapshot(workspace) == before
    finally:
        for target in targets:
            target.chmod(0o700)


def test_unexpected_post_write_failure_rolls_back_only_apply_created_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A fault after writes removes the intake and H02 but preserves H01."""
    workspace = tmp_path / "workspace"
    create_host(capsys, workspace, "H01", "192.0.2.1", "alpha")
    before = snapshot(workspace)
    original_apply = operator_intake.apply_bootstrap_plan

    def fail_after_bootstrap(
        plan: operator_intake.BootstrapPlan,
        tracker: operator_intake.CreationTracker,
    ) -> list[str]:
        original_apply(plan, tracker)
        raise OSError("synthetic post-write failure")

    monkeypatch.setattr(operator_intake, "apply_bootstrap_plan", fail_after_bootstrap)
    code, _, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, b"192.0.2.2 beta\n"),
        "--apply",
    )

    assert code != 0
    assert "filesystem operation failed: synthetic post-write failure" in stderr
    assert "192.0.2.2 beta" not in stderr
    assert "alpha" not in stderr
    assert "Traceback" not in stderr
    assert stderr.count("\n") == 1
    assert snapshot(workspace) == before
    assert (workspace / "hosts" / "H01.md").is_file()
    assert not (workspace / "hosts" / "H02.md").exists()
    assert not (workspace / "report" / "H02.md").exists()
    assert not (workspace / "inbox" / "operator").exists()


def test_filesystem_error_normalization_replaces_controls_and_is_bounded() -> None:
    """Only one bounded safe detail survives multiline and control-heavy text."""
    error = OSError(
        "unsafe-prefix\n\x00\x1b synthetic post-write failure\r\n"
        + "attacker-controlled-suffix" * 100
    )
    message = operator_intake._normalize_filesystem_error(error)

    assert message == "filesystem operation failed: synthetic post-write failure"
    assert "\n" not in message
    assert "\r" not in message
    assert "\x00" not in message
    assert "\x1b" not in message
    assert len(message) <= operator_intake.MAX_FILESYSTEM_ERROR_MESSAGE


def test_filesystem_error_normalization_does_not_expose_path_or_secret(
    tmp_path: Path,
) -> None:
    """Untrusted exception text falls back rather than exposing path or content."""
    controlled_path = tmp_path / "fictional-token-value" / "operator-input.txt"
    raw_content = "fictional-password-value 198.51.100.77 private-label"
    error = OSError(f"write failed at {controlled_path}: {raw_content}")
    message = operator_intake._normalize_filesystem_error(error)

    assert message == "filesystem operation failed"
    assert str(controlled_path) not in message
    assert "fictional-token-value" not in message
    assert "fictional-password-value" not in message
    assert "198.51.100.77" not in message
    assert "private-label" not in message


@pytest.mark.parametrize("error", [OSError(), OSError("attacker-controlled-only")])
def test_filesystem_error_normalization_uses_generic_fallback(error: OSError) -> None:
    """Empty or unrecognized arbitrary exception text is never echoed."""
    assert operator_intake._normalize_filesystem_error(error) == "filesystem operation failed"


def test_filesystem_error_normalization_preserves_permission_meaning(
    tmp_path: Path,
) -> None:
    """A recognized errno preserves system meaning while omitting its filename."""
    controlled_path = tmp_path / "fictional-secret-path"
    error = OSError(errno.EACCES, "attacker-controlled strerror", controlled_path)
    message = operator_intake._normalize_filesystem_error(error)

    assert message == "filesystem operation failed: permission denied"
    assert str(controlled_path) not in message
    assert "fictional-secret-path" not in message
    assert "attacker-controlled" not in message


def test_normal_validation_error_text_remains_unchanged(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The OSError normalizer does not alter existing IntakeError messages."""
    code, stdout, stderr = run_intake(
        capsys,
        tmp_path / "workspace",
        write_input(tmp_path, b"192.0.2.1 alpha\xff\n"),
    )

    assert code != 0
    assert stdout == ""
    assert stderr == "error: input must be valid UTF-8\n"


@pytest.mark.parametrize(
    ("data", "expected_count", "positions"),
    [
        (
            (
                b"192.0.2.1 alpha\n\n"
                b"192.0.2.1 beta\n\n"
                b"192.0.2.3 gamma\n\n"
                b"192.0.2.4 gamma\n"
            ),
            2,
            (2, 4),
        ),
        (
            (
                b"192.0.2.1 alpha\n\n"
                b"192.0.2.1 beta\n\n"
                b"192.0.2.3 gamma\n\n"
                b"192.0.2.4 gamma\n\n"
                b"192.0.2.5 delta\n\n"
                b"192.0.2.5 epsilon\n"
            ),
            3,
            (2, 4, 6),
        ),
    ],
    ids=["two-independent", "three-independent"],
)
def test_independent_input_conflicts_are_all_reported_deterministically(
    data: bytes,
    expected_count: int,
    positions: tuple[int, ...],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Later valid records still establish comparison state after an earlier conflict."""
    workspace = tmp_path / "workspace"
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, data), "--apply"
    )

    assert code != 0
    assert stdout == ""
    assert f"input conflicts detected ({expected_count})" in stderr
    offsets = [stderr.index(f"record {position}") for position in positions]
    assert offsets == sorted(offsets)
    assert "alpha" not in stderr
    assert "gamma" not in stderr
    assert not workspace.exists()
