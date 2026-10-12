"""Tests for bounded private credential intake."""

import hashlib
import json
import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import credential_intake, host_state
from scripts.build_brief import main as build_brief_main
from scripts.build_query_appendix import main as build_query_appendix_main
from scripts.credential_intake import CREDENTIAL_FIELDS, MAX_INPUT_BYTES, main
from scripts.log_query import main as log_query_main
from scripts.new_host import main as new_host_main
from scripts.workspace_status import main as workspace_status_main

FIXED_NOW = datetime(2026, 7, 31, 12, 34, 56, 123456, tzinfo=UTC)
LATER_NOW = FIXED_NOW + timedelta(seconds=1)
FICTIONAL_SENTINEL_A = f"Fictional-{chr(65)}!"
FICTIONAL_SENTINEL_B = f"Fictional-{chr(66)}!"
FICTIONAL_SENTINEL_C = f"Fictional-{chr(67)}!"
ALL_SENTINELS = (FICTIONAL_SENTINEL_A, FICTIONAL_SENTINEL_B, FICTIONAL_SENTINEL_C)


def run_intake(
    capsys: pytest.CaptureFixture[str],
    workspace: Path,
    input_path: Path,
    mode: str = "--preview",
    now: datetime = FIXED_NOW,
) -> tuple[int, str, str]:
    """Run credential intake in-process and capture its public streams."""
    try:
        code = main(
            [
                "--workspace",
                str(workspace),
                "--input-file",
                str(input_path),
                mode,
            ],
            now=now,
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def create_workspace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, *, second_host: bool = False
) -> Path:
    """Create a fictional canonical workspace through the supported host CLI."""
    workspace = tmp_path / "workspace"
    assert (
        new_host_main(
            [
                "--workspace",
                str(workspace),
                "--host-id",
                "H01",
                "--ip",
                "192.0.2.10",
                "--hostname",
                "alpha.synthetic.test",
            ]
        )
        == 0
    )
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n",
        encoding="utf-8",
    )
    if second_host:
        assert (
            new_host_main(
                [
                    "--workspace",
                    str(workspace),
                    "--host-id",
                    "H02",
                    "--ip",
                    "192.0.2.20",
                    "--hostname",
                    "beta.synthetic.test",
                ]
            )
            == 0
        )
    capsys.readouterr()
    return workspace


def write_input(tmp_path: Path, raw: bytes, name: str = "credentials.txt") -> Path:
    """Write one synthetic credential input outside the target workspace."""
    path = tmp_path / name
    path.write_bytes(raw)
    return path


def password_input(
    secret: str = FICTIONAL_SENTINEL_A,
    *,
    selector: str = "host: H01",
    service: str = "service: synthetic-login",
) -> bytes:
    """Return one short fictional password block."""
    return (
        f"{selector}\nusername: fictional-user\n{service}\npassword: {secret}\n"
    ).encode()


def token_input(
    secret: str = FICTIONAL_SENTINEL_B,
    *,
    selector: str = "host: H01",
    username: bool = False,
) -> bytes:
    """Return one short fictional token block."""
    user = "username: fictional-user\n" if username else ""
    return (
        f"{selector}\n{user}service: synthetic-api\ntoken: {secret}\n"
    ).encode()


def ledger_path(workspace: Path) -> Path:
    """Return the canonical private ledger path."""
    return workspace / "private" / "credentials" / "credentials.jsonl"


def intake_paths(workspace: Path) -> list[Path]:
    """Return sorted preserved raw intake paths."""
    path = workspace / "private" / "credentials" / "intake"
    return sorted(path.glob("INTAKE-*.txt")) if path.is_dir() else []


def load_ledger(workspace: Path) -> list[dict[str, object]]:
    """Load test-only canonical ledger records."""
    return [json.loads(line) for line in ledger_path(workspace).read_text().splitlines()]


def snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    """Capture identities, metadata, and bytes for zero-mutation assertions."""
    if not root.exists() and not root.is_symlink():
        return {}
    result: dict[str, tuple[object, ...]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result[relative] = (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            content,
        )
    return result


def fd_count() -> int:
    """Return the current Linux process descriptor count."""
    return len(os.listdir("/proc/self/fd"))


def transaction_entries(root: Path) -> list[Path]:
    """Return every preserved private quarantine entry below a test workspace."""
    if not root.exists():
        return []
    return sorted(
        path
        for path in root.rglob(f"{credential_intake.QUARANTINE_PREFIX}*")
    )


def assert_redacted(*streams: str) -> None:
    """Assert all explicit fictional secret sentinels remain absent."""
    combined = "\n".join(streams)
    for sentinel in ALL_SENTINELS:
        assert sentinel not in combined
        assert hashlib.sha256(sentinel.encode()).hexdigest() not in combined


@pytest.mark.parametrize(
    ("selector", "expected_host"),
    [
        ("host: H01", "H01"),
        ("ip: 192.0.2.10", "H01"),
        ("hostname: ALPHA.SYNTHETIC.TEST", "H01"),
        ("H01", "H01"),
        ("192.0.2.10", "H01"),
        ("Alpha.Synthetic.Test", "H01"),
    ],
)
def test_host_selector_forms(
    selector: str,
    expected_host: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Canonical ID, IP, and case-insensitive label selectors resolve."""
    workspace = create_workspace(capsys, tmp_path)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input(selector=selector))
    )
    assert code == 0, stderr
    assert f"host_id={expected_host}" in stdout
    assert_redacted(stdout, stderr)


def test_matching_multiple_selectors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Multiple different selectors are allowed when all identify one host."""
    workspace = create_workspace(capsys, tmp_path)
    raw = (
        b"host: H01\nip: 192.0.2.10\nhostname: Alpha.Synthetic.Test\n"
        + f"username: fictional-user\npassword: {FICTIONAL_SENTINEL_A}\n".encode()
    )
    code, stdout, stderr = run_intake(capsys, workspace, write_input(tmp_path, raw))
    assert code == 0, stderr
    assert "host_id=H01" in stdout
    assert_redacted(stdout, stderr)


def test_conflicting_selectors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Selectors resolving to different canonical hosts fail closed."""
    workspace = create_workspace(capsys, tmp_path, second_host=True)
    raw = password_input(selector="host: H01\nip: 192.0.2.20")
    before = snapshot(workspace)
    code, stdout, stderr = run_intake(capsys, workspace, write_input(tmp_path, raw))
    assert code != 0
    assert not stdout
    assert "conflict" in stderr
    assert snapshot(workspace) == before
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    "selector",
    ["host: H03", "ip: 192.0.2.99", "hostname: unknown.synthetic.test"],
)
def test_unknown_host(
    selector: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Unknown canonical identities instruct the operator to use host intake."""
    workspace = create_workspace(capsys, tmp_path)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input(selector=selector))
    )
    assert code != 0
    assert "host intake" in stderr
    assert not (workspace / "private").exists()
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    ("raw", "secret_type", "username"),
    [
        (password_input(), "password", "fictional-user"),
        (token_input(), "token", None),
        (token_input(username=True), "token", "fictional-user"),
        (
            f"host: H01\nservice: synthetic-api\napi_key: {FICTIONAL_SENTINEL_C}\n".encode(),
            "api_key",
            None,
        ),
    ],
)
def test_supported_secret_forms_apply(
    raw: bytes,
    secret_type: str,
    username: str | None,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Password, token, and API-key forms produce canonical private records."""
    workspace = create_workspace(capsys, tmp_path)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    record = load_ledger(workspace)[0]
    assert record["secret_type"] == secret_type
    assert record["username"] == username
    assert record["status"] == "unverified"
    assert record["source"] == "operator"
    assert tuple(record) == CREDENTIAL_FIELDS
    assert_redacted(stdout, stderr)


def test_optional_metadata_and_canonical_url(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Optional metadata is stored and HTTP(S) URLs are normalized."""
    workspace = create_workspace(capsys, tmp_path)
    raw = (
        b"host: H01\nusername: fictional-user\nservice: Synthetic Login\n"
        b"url: HTTPS://ALPHA.SYNTHETIC.TEST:443/path?q=1\nrealm: local\n"
        + (
            "note: fictional operator note\n"
            f"password: {FICTIONAL_SENTINEL_A}\n"
        ).encode()
    )
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    record = load_ledger(workspace)[0]
    assert record["service"] == "Synthetic Login"
    assert record["url"] == "https://alpha.synthetic.test/path?q=1"
    assert record["realm"] == "local"
    assert record["note"] == "fictional operator note"
    assert "fictional operator note" not in stdout
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://alpha.synthetic.test/a",
        "https:///missing-host",
        "https://user:pass@alpha.synthetic.test/a",
        "https://alpha.synthetic.test/a#fragment",
        "https://alpha.synthetic.test:bad/a",
    ],
)
def test_invalid_urls_rejected(
    url: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Unsupported or unsafe URLs fail without private mutations."""
    workspace = create_workspace(capsys, tmp_path)
    raw = password_input(service=f"url: {url}")
    code, stdout, stderr = run_intake(capsys, workspace, write_input(tmp_path, raw))
    assert code != 0
    assert not (workspace / "private").exists()
    assert_redacted(stdout, stderr)


def test_multiple_blocks_preserve_new_record_order(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Multiple blank-line-separated records append in original order."""
    workspace = create_workspace(capsys, tmp_path)
    raw = password_input() + b"\n" + token_input()
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    records = load_ledger(workspace)
    assert [record["secret_type"] for record in records] == ["password", "token"]
    assert records[0]["credential_id"] < records[1]["credential_id"]
    assert "parsed_credentials: 2" in stdout
    assert_redacted(stdout, stderr)


def test_exact_duplicate_and_all_existing_apply_are_noop(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An all-existing apply changes no bytes, modes, timestamps, or intake paths."""
    workspace = create_workspace(capsys, tmp_path)
    input_path = write_input(tmp_path, password_input())
    first = run_intake(capsys, workspace, input_path, "--apply")
    assert first[0] == 0, first[2]
    before = snapshot(workspace)
    ledger_before = ledger_path(workspace).stat()
    ledger_bytes = ledger_path(workspace).read_bytes()
    count = len(intake_paths(workspace))
    names = [path.name for path in intake_paths(workspace)]
    code, stdout, stderr = run_intake(
        capsys, workspace, input_path, "--apply", now=LATER_NOW
    )
    assert code == 0, stderr
    assert "existing_credentials: 1" in stdout
    assert "new_credentials: 0" in stdout
    assert "preserved_input: (none)" in stdout
    assert len(intake_paths(workspace)) == count
    assert [path.name for path in intake_paths(workspace)] == names
    ledger_after = ledger_path(workspace).stat()
    assert ledger_path(workspace).read_bytes() == ledger_bytes
    assert ledger_after.st_ino == ledger_before.st_ino
    assert ledger_after.st_mtime_ns == ledger_before.st_mtime_ns
    assert stat.S_IMODE(ledger_after.st_mode) == stat.S_IMODE(ledger_before.st_mode)
    assert snapshot(workspace) == before
    credentials = ledger_path(workspace).parent
    assert [path.name for path in credentials.glob(".*.tmp")] == []
    assert (credentials / ".credentials.lock").is_file()
    assert_redacted(*first[1:], stdout, stderr)


def test_duplicate_inside_one_batch_appends_once(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Repeated exact blocks in one input are deduplicated in input order."""
    workspace = create_workspace(capsys, tmp_path)
    raw = password_input() + b"\n" + password_input()
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    assert len(load_ledger(workspace)) == 1
    assert "existing_credentials: 1" in stdout
    assert_redacted(stdout, stderr)


def test_changed_secret_warns_and_appends(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A changed value for the same identity is appended with a bounded warning."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "a.txt"), "--apply"
    )[0] == 0
    old = ledger_path(workspace).read_bytes()
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, password_input(FICTIONAL_SENTINEL_C), "c.txt"),
        "--apply",
        now=LATER_NOW,
    )
    assert code == 0, stderr
    assert "warning_count: 1" in stdout
    assert "warning=yes" in stdout
    assert ledger_path(workspace).read_bytes().startswith(old)
    assert len(load_ledger(workspace)) == 2
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    "raw",
    [
        (
            "host: H01\nusername: fictional-user\n"
            f"password: {FICTIONAL_SENTINEL_A}\n"
            f"token: {FICTIONAL_SENTINEL_B}\n"
        ).encode(),
        f"host: H01\npassword: {FICTIONAL_SENTINEL_A}\n".encode(),
        b"host: H01\nusername: fictional-user\npassword:\n",
        (
            f"host: H01\nusername: fictional-user\npassword: {FICTIONAL_SENTINEL_A}"
            "\x00\n"
        ).encode(),
        (
            f"host: H01\nusername: fictional-user\npassword: {FICTIONAL_SENTINEL_A}\n"
            "continued\n"
        ).encode(),
        (
            "host: H01\nusername: fictional-user\nunknown: value\n"
            f"password: {FICTIONAL_SENTINEL_A}\n"
        ).encode(),
        (
            "host: H01\nhost: H01\nusername: fictional-user\n"
            f"password: {FICTIONAL_SENTINEL_A}\n"
        ).encode(),
        f"host: H01\nservice: trailing \ntoken: {FICTIONAL_SENTINEL_B}\n".encode(),
    ],
)
def test_malformed_inputs_are_redacted_and_read_only(
    raw: bytes, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Known grammar, secret, control, and duplicate-field failures are safe."""
    workspace = create_workspace(capsys, tmp_path)
    before = snapshot(workspace)
    code, stdout, stderr = run_intake(capsys, workspace, write_input(tmp_path, raw))
    assert code != 0
    assert not stdout
    assert stderr.startswith("error:")
    assert snapshot(workspace) == before
    assert_redacted(stdout, stderr)


def test_secret_spaces_preserved_without_normalization(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Secret punctuation and spaces beyond the syntax separator remain exact."""
    workspace = create_workspace(capsys, tmp_path)
    secret = f" {FICTIONAL_SENTINEL_A} with spaces "
    raw = password_input(secret)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    assert load_ledger(workspace)[0]["secret"] == secret
    assert_redacted(stdout, stderr)


def test_invalid_utf8_and_oversized_input(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Invalid UTF-8 and over-limit files fail before parsing or mutation."""
    workspace = create_workspace(capsys, tmp_path)
    for name, raw in (("bad.txt", b"\xff\xfe"), ("large.txt", b"x" * (MAX_INPUT_BYTES + 1))):
        code, stdout, stderr = run_intake(
            capsys, workspace, write_input(tmp_path, raw, name)
        )
        assert code != 0
        assert not (workspace / "private").exists()
        assert_redacted(stdout, stderr)


def test_preview_is_read_only_and_discloses_no_secret_properties(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Preview emits only bounded routing data and creates no files."""
    workspace = create_workspace(capsys, tmp_path)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input())
    )
    assert code == 0, stderr
    assert "mode: preview" in stdout
    assert "new_credentials: 1" in stdout
    assert "username_present=yes" in stdout
    assert "length" not in stdout.casefold()
    assert "credential_key" not in stdout
    assert not (workspace / "private").exists()
    assert_redacted(stdout, stderr)


def test_apply_preserves_exact_input_and_permissions(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Apply preserves original bytes and creates exact 0700/0600 private modes."""
    workspace = create_workspace(capsys, tmp_path)
    raw = password_input() + b"\r\n"
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    paths = intake_paths(workspace)
    assert len(paths) == 1
    assert paths[0].read_bytes() == raw
    for path in (
        workspace / "private",
        workspace / "private" / "credentials",
        workspace / "private" / "credentials" / "intake",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(ledger_path(workspace).stat().st_mode) == 0o600
    lock = ledger_path(workspace).parent / ".credentials.lock"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    "mutation",
    [
        "invalid_utf8",
        "invalid_json",
        "array",
        "string",
        "number",
        "truncated",
        "blank_line",
        "missing_newline",
        "extra_field",
        "wrong_required_type",
        "wrong_nullable_type",
        "malformed_id",
        "timestamp_mismatch",
        "invalid_host",
        "invalid_secret_type",
        "password_without_username",
        "invalid_url",
        "noncanonical_url",
        "invalid_status",
        "invalid_source",
        "wrong_key",
        *[f"missing:{field}" for field in CREDENTIAL_FIELDS],
    ],
)
def test_malformed_existing_ledger_fails_closed(
    mutation: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Every malformed existing-ledger class fails before mutation."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    path = ledger_path(workspace)
    record = load_ledger(workspace)[0]
    raw: bytes
    if mutation == "invalid_utf8":
        raw = b"\xff\n"
    elif mutation == "invalid_json":
        raw = b"{invalid}\n"
    elif mutation == "array":
        raw = b"[]\n"
    elif mutation == "string":
        raw = b'"record"\n'
    elif mutation == "number":
        raw = b"7\n"
    elif mutation == "truncated":
        raw = b'{"credential_id":'
    elif mutation == "blank_line":
        raw = b"\n"
    elif mutation == "missing_newline":
        raw = json.dumps(record, separators=(",", ":")).encode()
    else:
        if mutation.startswith("missing:"):
            record.pop(mutation.split(":", 1)[1])
        elif mutation == "extra_field":
            record["extra"] = "value"
        elif mutation == "wrong_required_type":
            record["secret"] = 7
        elif mutation == "wrong_nullable_type":
            record["realm"] = 7
        elif mutation == "malformed_id":
            record["credential_id"] = "CRED-invalid"
        elif mutation == "timestamp_mismatch":
            record["created_at_utc"] = "2026-07-31T12:34:57.123456Z"
        elif mutation == "invalid_host":
            record["host_id"] = "H99"
        elif mutation == "invalid_secret_type":
            record["secret_type"] = "certificate"
        elif mutation == "password_without_username":
            record["username"] = None
        elif mutation == "invalid_url":
            record["url"] = "ftp://alpha.synthetic.test/"
        elif mutation == "noncanonical_url":
            record["url"] = "HTTPS://ALPHA.SYNTHETIC.TEST/"
        elif mutation == "invalid_status":
            record["status"] = "verified"
        elif mutation == "invalid_source":
            record["source"] = "import"
        else:
            record["credential_key"] = "0" * 64
        raw = (json.dumps(record, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    before = snapshot(workspace / "private")
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, token_input(), "next.txt"), "--apply", LATER_NOW
    )
    assert code != 0
    assert snapshot(workspace / "private") == before
    assert len(intake_paths(workspace)) == 1
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("duplicate_field", ["credential_id", "credential_key"])
def test_duplicate_ledger_identifiers_fail_closed(
    duplicate_field: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Duplicate private ledger IDs and exact keys are malformed state."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    record = load_ledger(workspace)[0]
    second = dict(record)
    if duplicate_field == "credential_id":
        second["secret"] = FICTIONAL_SENTINEL_C
        second["credential_key"] = credential_intake._credential_key(second)
    else:
        second["credential_id"] = "CRED-20260731T123457123456Z"
        second["created_at_utc"] = "2026-07-31T12:34:57.123456Z"
    path = ledger_path(workspace)
    path.write_text(
        "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in (record, second))
    )
    before = path.read_bytes()
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, token_input(), "next.txt"), "--apply", LATER_NOW
    )
    assert code != 0
    expected = f"duplicate credential {duplicate_field.removeprefix('credential_')}"
    assert expected in stderr.casefold()
    assert path.read_bytes() == before
    assert_redacted(stdout, stderr)


def test_symlink_input_rejected(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """Input symlinks are never followed."""
    workspace = create_workspace(capsys, tmp_path)
    target = write_input(tmp_path, password_input(), "target.txt")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    code, stdout, stderr = run_intake(capsys, workspace, link)
    assert code != 0
    assert "symlink" in stderr
    assert not (workspace / "private").exists()
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize(
    "component", ["private", "credentials", "intake", "ledger", "lock"]
)
def test_private_symlink_components_rejected(
    component: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Every canonical private component rejects symlink redirection."""
    workspace = create_workspace(capsys, tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    private = workspace / "private"
    credentials = private / "credentials"
    intake = credentials / "intake"
    if component == "private":
        private.symlink_to(external, target_is_directory=True)
    else:
        private.mkdir(mode=0o700)
        if component == "credentials":
            credentials.symlink_to(external, target_is_directory=True)
        else:
            credentials.mkdir(mode=0o700)
            if component == "intake":
                intake.symlink_to(external, target_is_directory=True)
            elif component == "ledger":
                intake.mkdir(mode=0o700)
                (credentials / "credentials.jsonl").symlink_to(external / "sentinel")
            else:
                (credentials / ".credentials.lock").symlink_to(external / "sentinel")
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input())
    )
    assert code != 0
    assert "symlink" in stderr
    assert not any(external.iterdir())
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("component", ["workspace", "private", "credentials", "intake"])
@pytest.mark.parametrize("substitution", ["directory", "symlink"])
def test_directory_components_reject_preopen_substitution(
    component: str,
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Every retained directory boundary rejects a deterministic pre-open swap."""
    workspace = create_workspace(capsys, tmp_path)
    private = workspace / "private"
    credentials = private / "credentials"
    intake = credentials / "intake"
    if component != "workspace":
        private.mkdir(mode=0o700)
    if component in {"credentials", "intake"}:
        credentials.mkdir(mode=0o700)
    if component == "intake":
        intake.mkdir(mode=0o700)
    targets = {
        "workspace": (workspace, "workspace"),
        "private": (private, "private"),
        "credentials": (credentials, "credentials"),
        "intake": (intake, "intake"),
    }
    target, label = targets[component]
    saved = target.with_name(f"{target.name}.validated")
    external = tmp_path / f"external-{component}-{substitution}"
    external.mkdir()
    sentinel = external / "sentinel"
    sentinel.write_bytes(b"unchanged-external-object")
    input_path = write_input(tmp_path, password_input())
    baseline = fd_count()
    acted = False

    def substitute(event: str, **details: object) -> None:
        nonlocal acted
        if (
            acted
            or event != "directory_after_stat"
            or details.get("label") != label
            or details.get("name") != target.name
        ):
            return
        acted = True
        target.rename(saved)
        if substitution == "directory":
            external.rename(target)
        else:
            target.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    code, stdout, stderr = run_intake(capsys, workspace, input_path, "--preview")
    assert acted
    assert code != 0
    assert fd_count() == baseline
    sentinel_after = target / "sentinel" if substitution == "directory" else sentinel
    assert sentinel_after.read_bytes() == b"unchanged-external-object"
    assert list(tmp_path.rglob("credentials.jsonl")) == []
    assert list(tmp_path.rglob("INTAKE-*.txt")) == []
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("component", ["private", "ledger", "lock"])
def test_wrong_private_path_types_rejected(
    component: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A file for private/ or directory for the ledger fails safely."""
    workspace = create_workspace(capsys, tmp_path)
    private = workspace / "private"
    if component == "private":
        private.write_text("not a directory")
    else:
        credentials = private / "credentials"
        credentials.mkdir(parents=True, mode=0o700)
        os.chmod(private, 0o700)
        os.chmod(credentials, 0o700)
        name = "credentials.jsonl" if component == "ledger" else ".credentials.lock"
        (credentials / name).mkdir()
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input())
    )
    assert code != 0
    assert_redacted(stdout, stderr)


def test_permission_preflight_causes_zero_mutation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A deterministic permission failure occurs before the first write."""
    workspace = create_workspace(capsys, tmp_path)
    before = snapshot(workspace)
    monkeypatch.setattr(credential_intake, "_has_write_search", lambda _path: False)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--apply"
    )
    assert code != 0
    assert "writable" in stderr
    assert snapshot(workspace) == before
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("component", ["workspace", "private", "credentials", "intake"])
def test_real_mode_0500_private_paths_fail_without_mutation(
    component: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Real non-root mode restrictions fail before credential mutation."""
    if os.geteuid() == 0:
        pytest.skip("requires the effective non-root test user")
    workspace = create_workspace(capsys, tmp_path)
    private = workspace / "private"
    credentials = private / "credentials"
    intake = credentials / "intake"
    restricted: Path
    if component == "workspace":
        restricted = workspace
    else:
        private.mkdir(mode=0o700)
        restricted = private
        if component in {"credentials", "intake"}:
            credentials.mkdir(mode=0o700)
            restricted = credentials
        if component == "intake":
            intake.mkdir(mode=0o700)
            restricted = intake
    os.chmod(restricted, 0o500)
    before = snapshot(workspace)
    try:
        code, stdout, stderr = run_intake(
            capsys,
            workspace,
            write_input(tmp_path, password_input()),
            "--apply",
        )
        assert code != 0
        assert snapshot(workspace) == before
        assert not ledger_path(workspace).exists()
        assert intake_paths(workspace) == []
        assert_redacted(stdout, stderr)
    finally:
        os.chmod(restricted, 0o700)


@pytest.mark.parametrize(
    "operation",
    [
        "directory_path_fstat",
        "directory_at_fstat",
        "ensure_directory_fstat",
        "write_initial_fstat",
        "lock_fchmod",
        "lock_fstat",
        "verified_file_fstat",
    ],
)
def test_descriptor_acquisition_failures_return_to_baseline(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Every injected post-open failure closes its newly owned descriptor."""
    root = tmp_path / "descriptor-audit"
    root.mkdir(mode=0o700)
    child = root / "child"
    child.mkdir(mode=0o700)
    regular = root / "regular"
    regular.write_bytes(b"bounded-test-data")
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    baseline = fd_count()
    target_events = {
        "directory_path_fstat": "directory_after_open",
        "directory_at_fstat": "directory_after_open",
        "ensure_directory_fstat": "ensure_directory_before_fstat",
        "write_initial_fstat": "write_after_open",
        "lock_fchmod": "lock_after_create",
        "lock_fstat": "lock_before_fstat",
        "verified_file_fstat": "verified_read_after_open",
    }
    target_event = target_events[operation]
    acted = False

    def fail(event: str, **details: object) -> None:
        nonlocal acted
        if acted or event != target_event:
            return
        if operation == "directory_path_fstat" and details.get("name") != child.name:
            return
        acted = True
        raise OSError("synthetic descriptor validation failure")

    monkeypatch.setattr(credential_intake, "_fault_point", fail)
    if operation == "lock_fstat":
        lock = root / credential_intake.LOCK_NAME
        lock.touch(mode=0o600)
        os.chmod(lock, 0o600)
    try:
        with pytest.raises((OSError, credential_intake.CredentialIntakeError)):
            if operation == "directory_path_fstat":
                credential_intake._open_directory_path(str(child), "descriptor audit")
            elif operation == "directory_at_fstat":
                credential_intake._open_dir_at(parent_fd, child.name, "descriptor audit")
            elif operation == "ensure_directory_fstat":
                credential_intake._ensure_directory_at(
                    parent_fd, "created-directory", "descriptor audit"
                )
            elif operation == "write_initial_fstat":
                credential_intake._write_exclusive_at(
                    parent_fd, "created-file", b"bounded-test-data"
                )
            elif operation in {"lock_fchmod", "lock_fstat"}:
                credential_intake._acquire_lock(parent_fd)
            else:
                credential_intake._verified_read_at(
                    parent_fd,
                    regular.name,
                    limit=1024,
                    label="descriptor audit file",
                )
        assert acted
        assert fd_count() == baseline
        assert not (root / "created-directory").exists()
        assert not (root / "created-file").exists()
        if operation == "lock_fchmod":
            assert not (root / credential_intake.LOCK_NAME).exists()
        assert regular.read_bytes() == b"bounded-test-data"
    finally:
        os.close(parent_fd)


def test_secure_unique_sidecar_ignores_predictable_symlink(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A predictable sidecar symlink cannot redirect the secure ledger write."""
    workspace = create_workspace(capsys, tmp_path)
    credentials = workspace / "private" / "credentials"
    credentials.mkdir(parents=True, mode=0o700)
    os.chmod(workspace / "private", 0o700)
    os.chmod(credentials, 0o700)
    external = tmp_path / "external-sentinel"
    external.write_text("unchanged")
    (credentials / ".credentials.jsonl.tmp").symlink_to(external)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--apply"
    )
    assert code == 0, stderr
    assert external.read_text() == "unchanged"
    assert_redacted(stdout, stderr)


def test_failed_existing_replacement_preserves_ledger_and_rolls_back_intake(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A publication failure preserves the old ledger byte-for-byte."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    before = ledger_path(workspace).read_bytes()
    before_intakes = intake_paths(workspace)

    def fail_after_exchange(event: str, **_details: object) -> None:
        if event == "before_ledger_commit":
            raise OSError("synthetic post-exchange failure")

    monkeypatch.setattr(credential_intake, "_fault_point", fail_after_exchange)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, token_input(), "second.txt"),
        "--apply",
        LATER_NOW,
    )
    assert code != 0
    assert ledger_path(workspace).read_bytes() == before
    assert intake_paths(workspace) == before_intakes
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("target_kind", ["input", "host", "ledger"])
@pytest.mark.parametrize("replacement_kind", ["regular", "symlink"])
def test_verified_reads_reject_inode_and_symlink_substitution(
    target_kind: str,
    replacement_kind: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Every sensitive read rejects a deterministic pre-open substitution."""
    workspace = create_workspace(capsys, tmp_path)
    input_path = write_input(tmp_path, password_input(), "candidate.txt")
    if target_kind == "ledger":
        assert run_intake(capsys, workspace, input_path, "--apply")[0] == 0
        input_path = write_input(tmp_path, token_input(), "next.txt")
        target = ledger_path(workspace)
        label = "credential ledger"
    elif target_kind == "host":
        target = workspace / "hosts" / "H01.md"
        label = "canonical host record"
    else:
        target = input_path
        label = "input file"
    original = target.read_bytes()
    external = tmp_path / f"{target_kind}-external"
    external.write_bytes(original)
    acted = False

    def substitute(event: str, **details: object) -> None:
        nonlocal acted
        if acted or event != "verified_read_after_stat" or details.get("label") != label:
            return
        acted = True
        if replacement_kind == "regular":
            replacement = target.parent / f".{target.name}.replacement"
            replacement.write_bytes(original)
            os.replace(replacement, target)
        else:
            target.unlink()
            target.symlink_to(external)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    mode = "--apply" if target_kind == "ledger" else "--preview"
    code, stdout, stderr = run_intake(capsys, workspace, input_path, mode, LATER_NOW)
    assert acted
    assert code != 0
    assert "changed" in stderr or "safely" in stderr
    assert_redacted(stdout, stderr)


def test_concurrent_new_ledger_creation_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """No-overwrite publication rejects and preserves a concurrent new ledger."""
    workspace = create_workspace(capsys, tmp_path)

    def create_concurrent(event: str, **details: object) -> None:
        if event != "before_new_ledger_publish":
            return
        directory_fd = int(details["credentials_fd"])
        descriptor = os.open(
            credential_intake.LEDGER_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        os.close(descriptor)

    monkeypatch.setattr(credential_intake, "_fault_point", create_concurrent)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, password_input()),
        "--apply",
    )
    assert code != 0
    assert ledger_path(workspace).read_bytes() == b""
    assert intake_paths(workspace) == []
    assert list(ledger_path(workspace).parent.glob(".*.tmp")) == []
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("substitution", ["invalid_regular", "valid_regular", "symlink"])
def test_existing_ledger_substitution_is_detected_restored_and_preserved(
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Atomic displaced-object verification restores original and preserves the swap."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    original = ledger_path(workspace).read_bytes()
    before_intakes = intake_paths(workspace)
    unexpected = original if substitution == "valid_regular" else b"unexpected-state\n"
    external = tmp_path / "external-ledger"
    external.write_bytes(unexpected)

    def substitute(event: str, **_details: object) -> None:
        if event != "before_ledger_exchange":
            return
        if substitution == "symlink":
            ledger_path(workspace).unlink()
            ledger_path(workspace).symlink_to(external)
        else:
            os.replace(external, ledger_path(workspace))

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, token_input(), "next.txt"),
        "--apply",
        LATER_NOW,
    )
    assert code != 0
    assert ledger_path(workspace).read_bytes() == original
    preserved = list(
        ledger_path(workspace).parent.glob(
            f"{credential_intake.QUARANTINE_PREFIX}*"
        )
    )
    assert len(preserved) == 1
    if substitution == "symlink":
        assert preserved[0].is_symlink()
        assert external.read_bytes() == unexpected
    else:
        assert preserved[0].read_bytes() == unexpected
    assert intake_paths(workspace) == before_intakes
    assert list(ledger_path(workspace).parent.glob(".*.tmp")) == []
    assert_redacted(stdout, stderr)


def test_rollback_refuses_replaced_intake_inode_and_cleans_temporary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Identity-aware rollback leaves a substituted intake object untouched."""
    workspace = create_workspace(capsys, tmp_path)
    replacement = tmp_path / "replacement-intake"
    replacement.write_bytes(b"external-object")

    def replace_and_block(event: str, **details: object) -> None:
        if event != "before_new_ledger_publish":
            return
        preserved = intake_paths(workspace)
        assert len(preserved) == 1
        os.replace(replacement, preserved[0])
        descriptor = os.open(
            credential_intake.LEDGER_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=int(details["credentials_fd"]),
        )
        os.close(descriptor)

    monkeypatch.setattr(credential_intake, "_fault_point", replace_and_block)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, password_input()),
        "--apply",
    )
    assert code != 0
    preserved = [
        path
        for path in (workspace / "private" / "credentials").rglob("*")
        if path.is_file() and path.read_bytes() == b"external-object"
    ]
    assert len(preserved) == 1
    assert list(ledger_path(workspace).parent.glob(".*.tmp")) == []
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("object_type", ["file", "directory"])
@pytest.mark.parametrize("substitution", ["real", "symlink"])
def test_atomic_quarantine_preserves_precleanup_substitution(
    object_type: str,
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Atomic cleanup moves and preserves an object substituted before rename."""
    parent = tmp_path / "quarantine-parent"
    parent.mkdir(mode=0o700)
    candidate = parent / "assessment_team"
    if object_type == "directory":
        candidate.mkdir()
    else:
        candidate.write_bytes(b"apply-created-object")
    expected = candidate.lstat()
    saved = tmp_path / "expected-object"
    external = tmp_path / "external-object"
    if substitution == "real":
        if object_type == "directory":
            external.mkdir()
            (external / "sentinel").write_bytes(b"unchanged-external-object")
        else:
            external.write_bytes(b"unchanged-external-object")
    else:
        external.mkdir()
        (external / "sentinel").write_bytes(b"unchanged-external-object")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def substitute(event: str, **details: object) -> None:
        if event != "before_quarantine" or details.get("name") != candidate.name:
            return
        candidate.rename(saved)
        if substitution == "real":
            external.rename(candidate)
        else:
            candidate.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    try:
        with pytest.raises(credential_intake.CredentialIntakeError):
            credential_intake._atomic_remove_at(
                parent_fd,
                candidate.name,
                expected,
                directory=object_type == "directory",
                label="synthetic cleanup candidate",
            )
    finally:
        os.close(parent_fd)
    assert saved.exists()
    preserved = transaction_entries(parent)
    assert len(preserved) == 1
    if substitution == "symlink":
        assert preserved[0].is_symlink()
        assert (external / "sentinel").read_bytes() == b"unchanged-external-object"
    elif object_type == "directory":
        assert (preserved[0] / "sentinel").read_bytes() == b"unchanged-external-object"
    else:
        assert preserved[0].read_bytes() == b"unchanged-external-object"


def test_atomic_quarantine_collision_preserves_candidate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A no-overwrite quarantine collision fails without moving either object."""
    parent = tmp_path / "collision-parent"
    parent.mkdir(mode=0o700)
    candidate = parent / "assessment_team"
    candidate.write_bytes(b"apply-created-object")
    expected = candidate.stat()
    quarantine = parent / f"{credential_intake.QUARANTINE_PREFIX}collision"
    quarantine.write_bytes(b"unrelated-object")
    monkeypatch.setattr(
        credential_intake,
        "_quarantine_name",
        lambda: quarantine.name,
    )
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(credential_intake.CredentialIntakeError, match="collision"):
            credential_intake._atomic_remove_at(
                parent_fd, candidate.name, expected, label="synthetic candidate"
            )
    finally:
        os.close(parent_fd)
    assert candidate.read_bytes() == b"apply-created-object"
    assert quarantine.read_bytes() == b"unrelated-object"


def test_atomic_quarantine_candidate_disappears_without_deletion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A candidate moved away before quarantine fails without touching it."""
    parent = tmp_path / "missing-parent"
    parent.mkdir(mode=0o700)
    candidate = parent / "assessment_team"
    candidate.write_bytes(b"apply-created-object")
    expected = candidate.stat()
    saved = tmp_path / "moved-candidate"

    def disappear(event: str, **_details: object) -> None:
        if event == "before_quarantine":
            candidate.rename(saved)

    monkeypatch.setattr(credential_intake, "_fault_point", disappear)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(credential_intake.CredentialIntakeError, match="disappeared"):
            credential_intake._atomic_remove_at(
                parent_fd, candidate.name, expected, label="synthetic candidate"
            )
    finally:
        os.close(parent_fd)
    assert saved.read_bytes() == b"apply-created-object"


def test_atomic_quarantine_leaves_new_original_name_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An object appearing after quarantine is never a cleanup target."""
    parent = tmp_path / "new-original-parent"
    parent.mkdir(mode=0o700)
    candidate = parent / "assessment_team"
    candidate.write_bytes(b"apply-created-object")
    expected = candidate.stat()

    def appear(event: str, **_details: object) -> None:
        if event == "quarantine_after_move":
            candidate.write_bytes(b"unrelated-object")

    monkeypatch.setattr(credential_intake, "_fault_point", appear)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        assert credential_intake._atomic_remove_at(
            parent_fd, candidate.name, expected, label="synthetic candidate"
        )
    finally:
        os.close(parent_fd)
    assert candidate.read_bytes() == b"unrelated-object"
    assert transaction_entries(parent) == []


@pytest.mark.parametrize("substitution", ["regular", "symlink"])
def test_failed_new_publication_preserves_replaced_temporary(
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A substituted prepared ledger is quarantined and never deleted."""
    workspace = create_workspace(capsys, tmp_path)
    credentials = workspace / "private" / "credentials"
    external = tmp_path / "temporary-external"
    if substitution == "regular":
        external.write_bytes(b"unrelated-object")
    else:
        external.mkdir()
        (external / "sentinel").write_bytes(b"unchanged-external-object")
    acted = False

    def substitute(event: str, **details: object) -> None:
        nonlocal acted
        if (
            acted
            or event != "before_quarantine"
            or details.get("label") != "ledger replacement"
        ):
            return
        acted = True
        candidate = credentials / str(details["name"])
        candidate.unlink()
        if substitution == "regular":
            external.rename(candidate)
        else:
            candidate.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--apply"
    )
    assert acted
    assert code != 0
    assert not ledger_path(workspace).exists()
    assert intake_paths(workspace) == []
    preserved = transaction_entries(credentials)
    assert preserved
    if substitution == "symlink":
        assert any(path.is_symlink() for path in preserved)
        assert (external / "sentinel").read_bytes() == b"unchanged-external-object"
    else:
        assert any(
            path.is_file() and path.read_bytes() == b"unrelated-object"
            for path in preserved
        )
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("substitution", ["regular", "symlink"])
def test_failed_apply_preserves_replaced_intake_during_rollback(
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Rollback quarantines a substituted intake without deleting its target."""
    workspace = create_workspace(capsys, tmp_path)
    external = tmp_path / "intake-external"
    if substitution == "regular":
        external.write_bytes(b"unrelated-object")
    else:
        external.mkdir()
        (external / "sentinel").write_bytes(b"unchanged-external-object")
    acted = False

    def substitute_and_fail(event: str, **details: object) -> None:
        nonlocal acted
        if event == "before_new_ledger_publish":
            descriptor = os.open(
                credential_intake.LEDGER_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=int(details["credentials_fd"]),
            )
            os.close(descriptor)
        elif (
            not acted
            and event == "before_quarantine"
            and str(details.get("name", "")).startswith("INTAKE-")
        ):
            acted = True
            intake = intake_paths(workspace)[0]
            intake.unlink()
            if substitution == "regular":
                external.rename(intake)
            else:
                intake.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute_and_fail)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--apply"
    )
    assert acted
    assert code != 0
    assert ledger_path(workspace).read_bytes() == b""
    preserved = transaction_entries(workspace / "private" / "credentials")
    assert preserved
    if substitution == "symlink":
        assert any(path.is_symlink() for path in preserved)
        assert (external / "sentinel").read_bytes() == b"unchanged-external-object"
    else:
        assert any(
            path.is_file() and path.read_bytes() == b"unrelated-object"
            for path in preserved
        )
    assert_redacted(stdout, stderr)


def test_displaced_original_substitution_is_quarantined_before_commit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Commit cleanup restores the original and preserves a displaced substitute."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    original = ledger_path(workspace).read_bytes()
    external = tmp_path / "displaced-external"
    external.write_bytes(b"unrelated-object")
    acted = False

    def substitute(event: str, **details: object) -> None:
        nonlocal acted
        if (
            acted
            or event != "before_quarantine"
            or details.get("label") != "displaced credential ledger"
        ):
            return
        acted = True
        candidate = ledger_path(workspace).parent / str(details["name"])
        candidate.unlink()
        external.rename(candidate)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, token_input(), "next.txt"),
        "--apply",
        LATER_NOW,
    )
    assert acted
    assert code != 0
    assert ledger_path(workspace).read_bytes() == original
    assert any(
        path.is_file() and path.read_bytes() == b"unrelated-object"
        for path in transaction_entries(ledger_path(workspace).parent)
    )
    assert_redacted(stdout, stderr)


@pytest.mark.parametrize("substitution", ["directory", "symlink"])
def test_apply_created_directory_substitution_is_quarantined(
    substitution: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Directory rollback never recursively deletes a substituted entry."""
    workspace = create_workspace(capsys, tmp_path)
    credentials = workspace / "private" / "credentials"
    external = tmp_path / "directory-external"
    external.mkdir()
    (external / "sentinel").write_bytes(b"unchanged-external-object")
    saved = tmp_path / "expected-intake-directory"
    acted = False

    def substitute_and_fail(event: str, **details: object) -> None:
        nonlocal acted
        if event == "before_new_ledger_publish":
            descriptor = os.open(
                credential_intake.LEDGER_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=int(details["credentials_fd"]),
            )
            os.close(descriptor)
        elif (
            not acted
            and event == "before_quarantine"
            and details.get("name") == "intake"
        ):
            acted = True
            intake = credentials / "intake"
            intake.rename(saved)
            if substitution == "directory":
                external.rename(intake)
            else:
                intake.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(credential_intake, "_fault_point", substitute_and_fail)
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--apply"
    )
    assert acted
    assert code != 0
    assert saved.is_dir()
    preserved = transaction_entries(credentials)
    assert len(preserved) == 1
    if substitution == "symlink":
        assert preserved[0].is_symlink()
        assert (external / "sentinel").read_bytes() == b"unchanged-external-object"
    else:
        assert (preserved[0] / "sentinel").read_bytes() == b"unchanged-external-object"
    assert ledger_path(workspace).read_bytes() == b""
    assert_redacted(stdout, stderr)


def test_unavailable_exchange_fails_closed_and_cleans_temporary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Existing-ledger update never falls back when atomic exchange is unavailable."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input(), "first.txt"), "--apply"
    )[0] == 0
    original = ledger_path(workspace).read_bytes()
    before_intakes = intake_paths(workspace)

    def unavailable(_directory_fd: int, _left: str, _right: str) -> None:
        raise credential_intake._error("secure atomic ledger exchange is unavailable")

    monkeypatch.setattr(credential_intake, "_rename_exchange", unavailable)
    code, stdout, stderr = run_intake(
        capsys,
        workspace,
        write_input(tmp_path, token_input(), "second.txt"),
        "--apply",
        LATER_NOW,
    )
    assert code != 0
    assert "unavailable" in stderr
    assert ledger_path(workspace).read_bytes() == original
    assert intake_paths(workspace) == before_intakes
    assert list(ledger_path(workspace).parent.glob(".*.tmp")) == []
    assert list(ledger_path(workspace).parent.glob(".*.original")) == []
    assert_redacted(stdout, stderr)


def test_transaction_lock_serializes_two_apply_operations(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Two cooperating apply calls re-plan serially under the canonical lock."""
    workspace = create_workspace(capsys, tmp_path)
    first_input = write_input(tmp_path, password_input(), "first.txt")
    second_input = write_input(tmp_path, token_input(), "second.txt")
    first_locked = threading.Event()
    release_first = threading.Event()
    second_locked = threading.Event()
    results: dict[str, int] = {}

    def coordinate(event: str, **_details: object) -> None:
        if event != "lock_acquired":
            return
        if threading.current_thread().name == "first-apply":
            first_locked.set()
            assert release_first.wait(5)
        elif threading.current_thread().name == "second-apply":
            second_locked.set()

    monkeypatch.setattr(credential_intake, "_fault_point", coordinate)

    def apply(name: str, input_path: Path, now: datetime) -> None:
        results[name] = main(
            [
                "--workspace",
                str(workspace),
                "--input-file",
                str(input_path),
                "--apply",
            ],
            now=now,
        )

    first = threading.Thread(
        target=apply, args=("first", first_input, FIXED_NOW), name="first-apply"
    )
    second = threading.Thread(
        target=apply, args=("second", second_input, LATER_NOW), name="second-apply"
    )
    first.start()
    assert first_locked.wait(5)
    second.start()
    assert not second_locked.wait(0.2)
    release_first.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive() and not second.is_alive()
    assert results == {"first": 0, "second": 0}
    assert len(load_ledger(workspace)) == 2
    captured = capsys.readouterr()
    assert_redacted(captured.out, captured.err)


def test_preview_creates_no_transaction_lock(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Preview remains strictly read-only and does not create its advisory lock."""
    workspace = create_workspace(capsys, tmp_path)
    assert run_intake(
        capsys, workspace, write_input(tmp_path, password_input()), "--preview"
    )[0] == 0
    assert not (workspace / "private").exists()


def test_private_store_excluded_from_brief_status_and_query_appendix(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Existing bounded context and report tools never inspect private credentials."""
    workspace = create_workspace(capsys, tmp_path)
    raw = (
        password_input()
        + b"\n"
        + token_input()
        + (
            f"\nhost: H01\nservice: synthetic-third\napi_key: {FICTIONAL_SENTINEL_C}\n"
        ).encode()
    )
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, raw), "--apply"
    )
    assert code == 0, stderr
    assert_redacted(stdout, stderr)

    prompt = write_input(tmp_path, b"Review fictional host state.", "prompt.txt")
    assert (
        log_query_main(
            [
                "--workspace",
                str(workspace),
                "--purpose",
                "Synthetic context exclusion check",
                "--host-id",
                "H01",
                "--prompt-file",
                str(prompt),
            ],
            now=FIXED_NOW,
        )
        == 0
    )
    query_streams = capsys.readouterr()

    brief = tmp_path / "brief.md"
    assert (
        build_brief_main(
            [
                "--workspace",
                str(workspace),
                "--host-id",
                "H01",
                "--output",
                str(brief),
            ],
            now=FIXED_NOW,
        )
        == 0
    )
    brief_streams = capsys.readouterr()
    assert workspace_status_main(["--workspace", str(workspace)], now=FIXED_NOW) == 0
    status_streams = capsys.readouterr()
    assert build_query_appendix_main(["--workspace", str(workspace)], now=FIXED_NOW) == 0
    appendix_streams = capsys.readouterr()
    appendix = workspace / "report" / "AI_QUERY_APPENDIX.md"
    generated = [
        brief,
        appendix,
        workspace / "observations.jsonl",
        workspace / "attempts.jsonl",
        workspace / "hosts" / "H01.md",
        workspace / "report" / "H01.md",
        *sorted((workspace / "queries").glob("*")),
    ]
    generated_text = [path.read_text() for path in generated if path.is_file()]
    repository = Path(__file__).resolve().parents[1]
    reusable = [
        repository / "AGENTS.md",
        repository / ".gitignore",
        repository / "pyproject.toml",
        repository / ".github" / "copilot-instructions.md",
        repository / "scripts" / "credential_intake.py",
        repository / "tests" / "test_credential_intake.py",
    ]
    for root_name in ("docs", "scripts", "tests", "templates"):
        root = repository / root_name
        if not root.is_dir():
            continue
        reusable.extend(
            path
            for path in root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    stage_report = repository / "development" / "STAGE_REPORT.txt"
    if stage_report.exists():
        reusable.append(stage_report)
    reusable = sorted(set(reusable))
    secret_bytes = tuple(sentinel.encode() for sentinel in ALL_SENTINELS)
    secret_hashes = tuple(
        hashlib.sha256(sentinel).hexdigest().encode() for sentinel in secret_bytes
    )
    for path in reusable:
        content = path.read_bytes()
        assert all(sentinel not in content for sentinel in secret_bytes)
        assert all(secret_hash not in content for secret_hash in secret_hashes)
    assert_redacted(
        *generated_text,
        brief.read_text(),
        brief_streams.out,
        brief_streams.err,
        status_streams.out,
        status_streams.err,
        appendix.read_text(),
        appendix_streams.out,
        appendix_streams.err,
        query_streams.out,
        query_streams.err,
        "sentinel A; sentinel B; sentinel C test summary",
    )


def test_existing_host_intake_still_resolves_canonical_state(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Credential intake refreshes metadata without changing manual host notes."""
    workspace = create_workspace(capsys, tmp_path)
    host_path = workspace / "hosts" / "H01.md"
    host_before = host_path.read_text(encoding="utf-8")
    code, stdout, stderr = run_intake(
        capsys, workspace, write_input(tmp_path, token_input()), "--apply"
    )
    assert code == 0, stderr
    host_after = host_path.read_text(encoding="utf-8")
    before_manual = (
        host_before[: host_before.index(host_state.HOST_START)]
        + host_before[host_before.index(host_state.HOST_END) + len(host_state.HOST_END) :]
    )
    after_manual = (
        host_after[: host_after.index(host_state.HOST_START)]
        + host_after[host_after.index(host_state.HOST_END) + len(host_state.HOST_END) :]
    )
    credential = json.loads(
        (workspace / "private/credentials/credentials.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert after_manual == before_manual
    assert credential["credential_id"] in host_after
    assert FICTIONAL_SENTINEL_B not in host_after
    assert_redacted(stdout, stderr)
