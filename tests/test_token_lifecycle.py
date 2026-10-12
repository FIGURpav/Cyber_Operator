"""Tests for the secure ephemeral session-token lifecycle."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import token_lifecycle
from scripts.create_checkpoint import main as checkpoint_main
from scripts.new_host import main as new_host_main
from scripts.screenshot_workflow import report_main
from scripts.token_lifecycle import main as token_main

NOW = datetime(2026, 8, 9, 18, 0, 0, 123456, tzinfo=UTC)
LATER = NOW + timedelta(seconds=1)
SECRET = "Synthetic.Session.Token.Value-12345"
EVIDENCE_ID = "EVD-20260809T175959123456Z"
ATTEMPT_ID = "ATT-20260809T175959223456Z"


def run_token(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    now: datetime = NOW,
    secret: str | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> tuple[int, str, str]:
    if secret is not None:
        assert monkeypatch is not None
        monkeypatch.setattr(
            sys,
            "stdin",
            SimpleNamespace(buffer=io.BytesIO((secret + "\n").encode("utf-8"))),
        )
    try:
        code = token_main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_report(
    capsys: pytest.CaptureFixture[str], workspace: Path
) -> tuple[int, str, str]:
    try:
        code = report_main(
            ["check", "--workspace", str(workspace), "--barrier", "manual"]
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_checkpoint(
    capsys: pytest.CaptureFixture[str], workspace: Path, destination: Path
) -> tuple[int, str, str]:
    try:
        code = checkpoint_main(
            ["--workspace", str(workspace), "--destination", str(destination)],
            now=NOW,
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Path:
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
                "target.synthetic.test",
            ]
        )
        == 0
    )
    capsys.readouterr()
    artifact = workspace / "evidence/H01" / f"{EVIDENCE_ID}.txt"
    artifact.write_text("sanitized synthetic response\n", encoding="utf-8")
    metadata = {
        "schema_version": "1.0",
        "evidence_id": EVIDENCE_ID,
        "timestamp_utc": "2026-08-09T17:59:59.123456Z",
        "host_id": "H01",
        "kind": "synthetic",
        "label": "Synthetic token provenance",
        "artifact_path": f"evidence/H01/{EVIDENCE_ID}.txt",
        "size_bytes": artifact.stat().st_size,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    (workspace / "evidence/H01" / f"{EVIDENCE_ID}.json").write_text(
        json.dumps(metadata) + "\n", encoding="utf-8"
    )
    attempt = {
        "schema_version": "1.0",
        "attempt_id": ATTEMPT_ID,
        "timestamp_utc": "2026-08-09T17:59:59.223456Z",
        "host_id": "H01",
        "action": "Synthetic bounded token validation",
        "status": "success",
        "result_sha256": "1" * 64,
        "result_text": "Synthetic authentication succeeded.\n",
        "evidence_refs": [f"evidence/H01/{EVIDENCE_ID}.txt"],
        "next_step": "Record the lifecycle result.",
    }
    (workspace / "attempts.jsonl").write_text(
        json.dumps(attempt, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    return workspace


def set_profile(workspace: Path, profile: str) -> None:
    (workspace / "TASK_CONTEXT.md").write_text(
        f"- Current task: synthetic\n- Operational profile: {profile}\n",
        encoding="utf-8",
    )


def capture_args(workspace: Path, **changes: str) -> list[str]:
    values = {
        "host_id": "H01",
        "service": "synthetic-web",
        "principal": "synthetic-user",
        "token_kind": "session",
        "source_evidence_id": EVIDENCE_ID,
    }
    values.update(changes)
    args = [
        "capture",
        "--workspace",
        str(workspace),
        "--host-id",
        values["host_id"],
        "--service",
        values["service"],
        "--principal",
        values["principal"],
        "--token-kind",
        values["token_kind"],
        "--source-evidence-id",
        values["source_evidence_id"],
        "--secret-stdin",
    ]
    if "expires_at" in values:
        args.extend(["--expires-at", values["expires_at"]])
    return args


def capture(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    workspace: Path,
    *,
    secret: str = SECRET,
    now: datetime = NOW,
    **changes: str,
) -> str:
    code, stdout, stderr = run_token(
        capsys,
        *capture_args(workspace, **changes),
        now=now,
        secret=secret,
        monkeypatch=monkeypatch,
    )
    assert code == 0, stderr
    assert secret not in stdout + stderr
    return next(
        line.split(": ", 1)[1]
        for line in stdout.splitlines()
        if line.startswith("token_id:")
    )


def validate(
    capsys: pytest.CaptureFixture[str], workspace: Path, token_id: str
) -> None:
    code, stdout, stderr = run_token(
        capsys,
        "validate",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--result",
        "valid",
        "--evidence-id",
        EVIDENCE_ID,
        "--attempt-id",
        ATTEMPT_ID,
        now=LATER,
    )
    assert code == 0, stderr
    assert "result: valid" in stdout


def events(workspace: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (workspace / "private/session_tokens/events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]


def test_capture_is_ephemeral_private_and_secret_free_in_metadata(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    secret_path = workspace / f"private/session_tokens/active/{token_id}.secret"
    assert secret_path.read_text(encoding="utf-8") == SECRET
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_path.parent.stat().st_mode) == 0o700
    ledger = workspace / "private/session_tokens/events.jsonl"
    index = workspace / "report/TOKEN_INDEX.md"
    assert SECRET not in ledger.read_text(encoding="utf-8")
    assert SECRET not in index.read_text(encoding="utf-8")
    record = events(workspace)[0]
    assert record["fingerprint"].startswith("hmac-sha256:")
    assert record["fingerprint"] != "hmac-sha256:" + hashlib.sha256(
        SECRET.encode()
    ).hexdigest()


def test_active_token_blocks_report_and_checkpoint(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    code, stdout, stderr = run_report(capsys, workspace)
    assert code == 1, stderr
    assert "report_ready: no" in stdout
    assert f"blocking_token_ids: {token_id}" in stdout
    destination = tmp_path / "checkpoints"
    code, _, stderr = run_checkpoint(capsys, workspace, destination)
    assert code == 1
    assert token_id in stderr
    assert not destination.exists()


def test_controlled_engagement_blocks_unresolved_tokens_and_checkpoint(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    set_profile(workspace, "controlled-engagement")
    token_id = capture(capsys, monkeypatch, workspace)
    code, stdout, stderr = run_token(capsys, "closure-check", "--workspace", str(workspace))
    assert code == 1, stderr
    assert "closure_ready: no" in stdout
    assert "blocking_tokens: 1" in stdout
    assert token_id in stdout
    code, stdout, stderr = run_report(capsys, workspace)
    assert code == 1, stderr
    assert "report_contract: engagement" in stdout
    assert "blocking_tokens: 1" in stdout
    destination = tmp_path / "checkpoints"
    code, stdout, stderr = run_checkpoint(capsys, workspace, destination)
    assert code == 1
    assert token_id in stderr
    assert not destination.exists()


def test_manual_cleanup_resolves_report_and_allows_checkpoint_without_secret(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    code, stdout, stderr = run_token(
        capsys,
        "cleanup",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        "Synthetic token is reproducible and no longer needed",
        now=LATER,
    )
    assert code == 0, stderr
    assert "ephemeral_copy: removed" in stdout
    assert not (workspace / f"private/session_tokens/active/{token_id}.secret").exists()
    assert run_report(capsys, workspace)[0] == 0
    destination = tmp_path / "checkpoints"
    code, stdout, stderr = run_checkpoint(capsys, workspace, destination)
    assert code == 0, stderr
    checkpoint = Path(stdout.splitlines()[1]) / "workspace"
    assert not list(checkpoint.rglob("*.secret"))


@pytest.mark.parametrize("command", ["expire", "revoke"])
def test_expire_and_revoke_remove_ephemeral_value(
    command: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    code, _, stderr = run_token(
        capsys,
        command,
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        f"Synthetic {command} decision",
        now=LATER,
    )
    assert code == 0, stderr
    assert events(workspace)[-2]["event"] == command + "d"
    assert events(workspace)[-1]["event"] == "cleaned"
    assert not (workspace / f"private/session_tokens/active/{token_id}.secret").exists()


def test_auto_cleanup_removes_expired_token(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    expiry = (NOW - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    token_id = capture(
        capsys, monkeypatch, workspace, expires_at=expiry
    )
    code, stdout, stderr = run_token(
        capsys,
        "cleanup",
        "--workspace",
        str(workspace),
        "--auto",
        now=NOW,
    )
    assert code == 0, stderr
    assert "cleaned_tokens: 1" in stdout
    assert token_id in stdout
    assert run_report(capsys, workspace)[0] == 0


def test_validated_token_promotes_once_and_removes_ephemeral_copy(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    validate(capsys, workspace, token_id)
    code, stdout, stderr = run_token(
        capsys,
        "promote",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        "Synthetic token retained for continued authorized testing",
        now=LATER + timedelta(seconds=1),
    )
    assert code == 0, stderr
    assert SECRET not in stdout + stderr
    credential_id = next(
        line.split(": ", 1)[1]
        for line in stdout.splitlines()
        if line.startswith("credential_id:")
    )
    ledger = workspace / "private/credentials/credentials.jsonl"
    credentials = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert len(credentials) == 1
    assert credentials[0]["credential_id"] == credential_id
    assert credentials[0]["secret"] == SECRET
    assert not (workspace / f"private/session_tokens/active/{token_id}.secret").exists()
    assert SECRET not in (workspace / "private/session_tokens/events.jsonl").read_text()
    assert SECRET not in (workspace / "report/TOKEN_INDEX.md").read_text()
    assert credential_id in (workspace / "report/TOKEN_INDEX.md").read_text()
    assert run_report(capsys, workspace)[0] == 0


def test_same_promoted_value_does_not_duplicate_canonical_credential(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    for offset in (0, 10):
        token_id = capture(
            capsys,
            monkeypatch,
            workspace,
            now=NOW + timedelta(seconds=offset),
        )
        validate(capsys, workspace, token_id)
        assert (
            run_token(
                capsys,
                "promote",
                "--workspace",
                str(workspace),
                "--token-id",
                token_id,
                now=LATER + timedelta(seconds=offset + 1),
            )[0]
            == 0
        )
    records = [
        json.loads(line)
        for line in (workspace / "private/credentials/credentials.jsonl")
        .read_text()
        .splitlines()
    ]
    assert len(records) == 1


def test_unvalidated_token_cannot_be_promoted(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    code, _, stderr = run_token(
        capsys,
        "promote",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        now=LATER,
    )
    assert code == 1
    assert "validated" in stderr
    assert SECRET not in stderr


def test_secret_value_is_rejected_from_persistent_reason(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    before = (workspace / "private/session_tokens/events.jsonl").read_bytes()
    code, stdout, stderr = run_token(
        capsys,
        "cleanup",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        f"Do not persist {SECRET}",
        now=LATER,
    )
    assert code == 1
    assert SECRET not in stdout + stderr
    assert (workspace / "private/session_tokens/events.jsonl").read_bytes() == before
    assert (
        workspace / f"private/session_tokens/active/{token_id}.secret"
    ).is_file()


def test_historical_not_retained_has_no_secret_or_fingerprint_key(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, stdout, stderr = run_token(
        capsys,
        "record-not-retained",
        "--workspace",
        str(workspace),
        "--host-id",
        "H01",
        "--service",
        "synthetic-web",
        "--principal",
        "synthetic-user",
        "--source-evidence-id",
        EVIDENCE_ID,
        "--source-attempt-id",
        ATTEMPT_ID,
        "--reason",
        "Value was removed before lifecycle tracking existed",
    )
    assert code == 0, stderr
    assert "secret_present: no" in stdout
    assert events(workspace)[0]["event"] == "not_retained"
    assert not (workspace / "private/session_tokens/.fingerprint-key").exists()
    assert not list((workspace / "private/session_tokens/active").iterdir())
    assert run_report(capsys, workspace)[0] == 0


def test_legacy_status_and_report_are_lazy_and_non_mutating(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_root = workspace / "private/session_tokens"
    before = sorted(path.relative_to(workspace) for path in workspace.rglob("*"))
    assert run_token(capsys, "status", "--workspace", str(workspace))[0] == 0
    assert run_token(capsys, "closure-check", "--workspace", str(workspace))[0] == 0
    assert run_report(capsys, workspace)[0] == 0
    after = sorted(path.relative_to(workspace) for path in workspace.rglob("*"))
    assert before == after
    assert not token_root.exists()


def test_private_symlink_is_rejected_without_touching_external_target(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (workspace / "private").symlink_to(external, target_is_directory=True)
    code, _, stderr = run_token(
        capsys,
        *capture_args(workspace),
        secret=SECRET,
        monkeypatch=monkeypatch,
    )
    assert code == 1
    assert "non-symlink" in stderr
    assert not list(external.iterdir())


def test_secret_symlink_substitution_fails_closed(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    external = tmp_path / "external-secret"
    external.write_text("external sentinel", encoding="utf-8")
    token_path = workspace / f"private/session_tokens/active/{token_id}.secret"
    triggered = False

    def substitute(event: str, **_details: object) -> None:
        nonlocal triggered
        if event == "before_secret_open" and not triggered:
            triggered = True
            token_path.unlink()
            token_path.symlink_to(external)

    monkeypatch.setattr(token_lifecycle, "_fault_point", substitute)
    code, _, stderr = run_token(
        capsys,
        "cleanup",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        "Synthetic discard",
        now=LATER,
    )
    assert code == 1
    assert external.read_text() == "external sentinel"
    assert "safely" in stderr or "mode 0600" in stderr


@pytest.mark.parametrize("replace_inode", [True, False])
def test_quarantine_substitution_preserves_unexpected_object(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    replace_inode: bool,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    token_path = workspace / f"private/session_tokens/active/{token_id}.secret"
    triggered = False

    def substitute(event: str, **_details: object) -> None:
        nonlocal triggered
        if event == "before_quarantine" and not triggered:
            triggered = True
            if replace_inode:
                token_path.unlink()
            token_path.write_text("unexpected object", encoding="utf-8")
            token_path.chmod(0o600)

    monkeypatch.setattr(token_lifecycle, "_fault_point", substitute)
    code, _, stderr = run_token(
        capsys,
        "cleanup",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        "Synthetic discard",
        now=LATER,
    )
    assert code == 1
    assert "adjudication" in stderr
    quarantine = list(token_path.parent.glob(".token-quarantine-*"))
    assert len(quarantine) == 1
    assert quarantine[0].read_text() == "unexpected object"


def test_capture_failure_removes_exact_ephemeral_file(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)

    def fail_append(*_args: object, **_kwargs: object) -> None:
        raise token_lifecycle.TokenLifecycleError("synthetic append failure")

    monkeypatch.setattr(token_lifecycle, "_append_event", fail_append)
    code, stdout, stderr = run_token(
        capsys,
        *capture_args(workspace),
        secret=SECRET,
        monkeypatch=monkeypatch,
    )
    assert code == 1
    assert SECRET not in stdout + stderr
    assert not list((workspace / "private/session_tokens/active").iterdir())


def test_promotion_retry_after_credential_commit_is_idempotent(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    validate(capsys, workspace, token_id)
    original_append = token_lifecycle._append_event
    failed = False

    def fail_promoted(
        layout: token_lifecycle.TokenLayout, record: dict[str, object]
    ) -> None:
        nonlocal failed
        if record["event"] == "promoted" and not failed:
            failed = True
            raise token_lifecycle.TokenLifecycleError(
                "synthetic post-credential failure"
            )
        original_append(layout, record)

    monkeypatch.setattr(token_lifecycle, "_append_event", fail_promoted)
    code, _, stderr = run_token(
        capsys,
        "promote",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        now=LATER + timedelta(seconds=1),
    )
    assert code == 1
    assert "post-credential" in stderr
    assert (
        workspace / f"private/session_tokens/active/{token_id}.secret"
    ).is_file()
    credential_ledger = workspace / "private/credentials/credentials.jsonl"
    assert len(credential_ledger.read_text().splitlines()) == 1

    monkeypatch.setattr(token_lifecycle, "_append_event", original_append)
    code, _, stderr = run_token(
        capsys,
        "promote",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        now=LATER + timedelta(seconds=2),
    )
    assert code == 0, stderr
    assert len(credential_ledger.read_text().splitlines()) == 1
    assert run_report(capsys, workspace)[0] == 0


def test_cleanup_retry_closes_event_after_secret_was_already_removed(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    token_id = capture(capsys, monkeypatch, workspace)
    original_append = token_lifecycle._append_event
    failed = False

    def fail_cleaned(
        layout: token_lifecycle.TokenLayout, record: dict[str, object]
    ) -> None:
        nonlocal failed
        if record["event"] == "cleaned" and not failed:
            failed = True
            raise token_lifecycle.TokenLifecycleError(
                "synthetic post-cleanup failure"
            )
        original_append(layout, record)

    monkeypatch.setattr(token_lifecycle, "_append_event", fail_cleaned)
    cleanup_args = [
        "cleanup",
        "--workspace",
        str(workspace),
        "--token-id",
        token_id,
        "--reason",
        "Synthetic discard",
    ]
    code, _, stderr = run_token(capsys, *cleanup_args, now=LATER)
    assert code == 1
    assert "post-cleanup" in stderr
    assert events(workspace)[-1]["event"] == "discarded"
    assert not (workspace / f"private/session_tokens/active/{token_id}.secret").exists()
    assert run_report(capsys, workspace)[0] == 1

    monkeypatch.setattr(token_lifecycle, "_append_event", original_append)
    code, _, stderr = run_token(
        capsys, *cleanup_args, now=LATER + timedelta(seconds=1)
    )
    assert code == 0, stderr
    assert events(workspace)[-1]["event"] == "cleaned"
    assert run_report(capsys, workspace)[0] == 0


def test_secret_command_line_option_is_rejected_without_echoing_value(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, stdout, stderr = run_token(
        capsys,
        "capture",
        "--workspace",
        str(workspace),
        "--secret",
        SECRET,
    )
    assert code == 1
    assert SECRET not in stdout + stderr
    assert "stdin" in stderr

    code, stdout, stderr = run_token(
        capsys,
        "capture",
        "--workspace",
        str(workspace),
        "--unexpected",
        SECRET,
    )
    assert code == 1
    assert SECRET not in stdout + stderr
    assert "invalid command-line" in stderr


def test_missing_provenance_rejected_before_lazy_creation(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    args = capture_args(workspace)
    index = args.index("--source-evidence-id")
    del args[index : index + 2]
    code, _, stderr = run_token(
        capsys,
        *args,
        secret=SECRET,
        monkeypatch=monkeypatch,
    )
    assert code == 1
    assert "source" in stderr
    assert not (workspace / "private/session_tokens").exists()


def test_wrapper_is_executable() -> None:
    mode = (Path(__file__).parents[1] / "scripts/cyber-token").stat().st_mode
    assert mode & stat.S_IXUSR
