"""Tests for operator-driven screenshot requests and report coverage."""

import binascii
import hashlib
import json
import os
import struct
import threading
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from policy_support import synthetic_configuration

from scripts import credential_intake, engagement_policy, screenshot_workflow
from scripts.new_host import main as new_host_main
from scripts.screenshot_workflow import report_main, screenshot_main

NOW = datetime(2026, 8, 9, 16, 0, 0, 123456, tzinfo=UTC)
LATER = NOW + timedelta(seconds=1)
SECRET = "Synthetic-Credential-Value!"
CREDENTIAL_ID = "CRED-20260809T155959123456Z"
AUTHORIZATION_ID = "AUTH-20260809T155959123456Z"
ALTERNATIVE_EVIDENCE_ID = "EVD-20260809T155959123456Z"


def run_screenshot(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    now: datetime = NOW,
) -> tuple[int, str, str]:
    try:
        code = screenshot_main(list(args), now=now)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_report(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    arguments = list(args)
    if arguments and arguments[0] == "check" and "--barrier" not in arguments:
        arguments.extend(("--barrier", "manual"))
    try:
        code = report_main(arguments)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_workspace(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, host_id: str = "H01"
) -> Path:
    workspace = tmp_path / "workspace"
    assert (
        new_host_main(
            [
                "--workspace",
                str(workspace),
                "--host-id",
                host_id,
                "--ip",
                "192.0.2.10",
                "--hostname",
                "target.synthetic.test",
            ]
        )
        == 0
    )
    capsys.readouterr()
    return workspace


def add_second_host(
    capsys: pytest.CaptureFixture[str], workspace: Path
) -> None:
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
                "other.synthetic.test",
            ]
        )
        == 0
    )
    capsys.readouterr()


def request_args(workspace: Path, **changes: object) -> list[str]:
    values: dict[str, object] = {
        "host_id": "H01",
        "stage": "discovery",
        "priority": "required",
        "reason": "Show synthetic tool enumeration",
        "interface": "application",
        "protocol": "local",
        "endpoint": "VS Code Tools panel",
        "slug": "mcp-tools",
    }
    values.update(changes)
    args = [
        "request",
        "--workspace",
        str(workspace),
        "--host-id",
        str(values["host_id"]),
        "--stage",
        str(values["stage"]),
        "--priority",
        str(values["priority"]),
        "--reason",
        str(values["reason"]),
        "--interface",
        str(values["interface"]),
        "--protocol",
        str(values["protocol"]),
        "--endpoint",
        str(values["endpoint"]),
        "--slug",
        str(values["slug"]),
        "--step",
        "Open the synthetic tool panel",
        "--must-include",
        "target context and tool names",
        "--must-exclude",
        "unrelated credentials",
    ]
    if values.get("url"):
        args.extend(["--url", str(values["url"])])
    if values.get("port"):
        args.extend(["--port", str(values["port"])])
    if values.get("service"):
        args.extend(["--service", str(values["service"])])
    if values.get("credential_id"):
        args.extend(["--credential-id", str(values["credential_id"])])
    if values.get("login_authorized"):
        args.append("--login-authorized")
    if values.get("contains_secrets"):
        args.append("--contains-secrets")
    if values.get("command"):
        args.extend(["--command", str(values["command"])])
    return args


def enable_secret_display(workspace: Path) -> None:
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n- Operational profile: controlled-engagement\n",
        encoding="utf-8",
    )
    _, policy = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Synthetic screenshot secret-display policy",
        now=NOW - timedelta(seconds=2),
    )
    engagement_policy.apply_activation(workspace, policy)
    engagement_policy.set_secret_display(
        workspace=workspace,
        enabled=True,
        reason="Synthetic engagement screenshot requirement",
        acknowledged=True,
        apply=True,
        now=NOW - timedelta(seconds=1),
    )


def png(width: int = 2, height: int = 2, red: int = 0) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        )

    raw_rows = b"".join(
        b"\x00" + bytes((red, 0, 0, 255)) * width for _ in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw_rows))
        + chunk(b"IEND", b"")
    )


def oversized_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 8000, 5001, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b""))
        + chunk(b"IEND", b"")
    )


def pending_path(workspace: Path, operator_id: str = "S001") -> Path:
    events = [
        json.loads(line)
        for line in (workspace / "screenshot_requests.jsonl").read_text().splitlines()
    ]
    request = next(item for item in events if item["operator_id"] == operator_id)
    return workspace / request["pending_path"]


def write_credential(workspace: Path) -> None:
    directory = workspace / "private" / "credentials"
    directory.mkdir(parents=True, mode=0o700)
    (workspace / "private").chmod(0o700)
    directory.chmod(0o700)
    record = {
        "credential_id": CREDENTIAL_ID,
        "created_at_utc": "2026-08-09T15:59:59.123456Z",
        "host_id": "H01",
        "secret_type": "password",
        "username": "synthetic-user",
        "service": "ssh",
        "url": None,
        "realm": None,
        "note": None,
        "secret": SECRET,
        "status": "unverified",
        "source": "operator",
        "credential_key": credential_intake._credential_key(
            {
                "host_id": "H01",
                "secret_type": "password",
                "username": "synthetic-user",
                "service": "ssh",
                "url": None,
                "realm": None,
                "secret": SECRET,
            }
        ),
    }
    ledger = directory / "credentials.jsonl"
    ledger.write_text(json.dumps(record, separators=(",", ":")) + "\n")
    ledger.chmod(0o600)


def write_waiver_provenance(
    workspace: Path,
    *,
    authorization_host: str = "H01",
    evidence_host: str = "H01",
) -> None:
    authorization = {
        "schema_version": "1.0",
        "authorization_id": AUTHORIZATION_ID,
        "created_at_utc": "2026-08-09T15:59:59.123456Z",
        "host_ids": [authorization_host],
        "categories": ["other"],
        "maximum_impact": "low",
        "techniques": ["screenshot-waiver"],
        "exclusions": [],
        "source": "operator",
        "summary": "Synthetic screenshot waiver authorization",
    }
    with (workspace / "authorizations.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(authorization, separators=(",", ":")) + "\n")
    evidence_dir = workspace / "evidence" / evidence_host
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / f"{ALTERNATIVE_EVIDENCE_ID}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "evidence_id": ALTERNATIVE_EVIDENCE_ID,
                "host_id": evidence_host,
                "description": "Synthetic alternative evidence",
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("interface", "protocol", "endpoint", "url", "port"),
    [
        ("url", "https", "https://192.0.2.10/login", "https://192.0.2.10/login", 443),
        ("rdp", "rdp", "192.0.2.10:3389", None, 3389),
        ("ssh", "ssh", "192.0.2.10:22", None, 22),
        ("terminal", "local", "operator terminal", None, None),
        ("application", "local", "synthetic application", None, None),
        ("api", "https", "https://192.0.2.10/api", "https://192.0.2.10/api", 443),
    ],
)
def test_request_renders_all_interface_classes(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    interface: str,
    protocol: str,
    endpoint: str,
    url: str | None,
    port: int | None,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    args = request_args(
        workspace,
        interface=interface,
        protocol=protocol,
        endpoint=endpoint,
        url=url,
        port=port,
    )
    code, stdout, stderr = run_screenshot(capsys, *args)
    assert code == 0, stderr
    assert "SCREENSHOT NOW — S001 [REQUIRED]" in stdout
    assert "192.0.2.10" in stdout
    assert str(workspace / "inbox/screenshots/pending/S001_H01_mcp-tools.png") in stdout


def test_sequential_ids_do_not_reuse_gaps(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    assert (
        run_screenshot(
            capsys,
            *request_args(workspace, slug="second-view", reason="Second view"),
            now=LATER,
        )[0]
        == 0
    )
    ledger = (workspace / "screenshot_requests.jsonl").read_text()
    assert '"operator_id":"S001"' in ledger
    assert '"operator_id":"S002"' in ledger


@pytest.mark.parametrize(
    "payload",
    [
        b'{"event":"requested","value":NaN}\n',
        b'{"event":"requested","nested":{"value":1,"value":2}}\n',
    ],
)
def test_screenshot_ledger_reader_rejects_non_rfc_json(
    tmp_path: Path,
    payload: bytes,
) -> None:
    ledger = tmp_path / "screenshot_requests.jsonl"
    ledger.write_bytes(payload)

    with pytest.raises(screenshot_workflow.ScreenshotError, match="invalid JSON"):
        screenshot_workflow._read_jsonl(ledger)

    assert ledger.read_bytes() == payload


def test_review_rejects_unterminated_ledger_before_binary_side_effects(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    pending = pending_path(workspace)
    raw_png = png(red=92)
    pending.write_bytes(raw_png)
    ledger = workspace / "screenshot_requests.jsonl"
    unterminated = ledger.read_bytes()[:-1]
    ledger.write_bytes(unterminated)
    evidence_before = set((workspace / "evidence/H01").iterdir())

    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--caption",
        "Synthetic tool enumeration",
        now=LATER,
    )

    assert code == 1
    assert "missing its final newline" in stderr
    assert ledger.read_bytes() == unterminated
    assert pending.read_bytes() == raw_png
    assert set((workspace / "evidence/H01").iterdir()) == evidence_before
    assert not list((workspace / "inbox/screenshots/processed").iterdir())


def test_concurrent_requests_allocate_under_lock_and_leave_current_index(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    first_in_allocator = threading.Event()
    release_first = threading.Event()
    second_at_lock = threading.Event()
    second_in_allocator = threading.Event()
    outcomes: dict[str, dict[str, object] | str] = {}

    original_next = screenshot_workflow._next_operator_id
    original_flock = screenshot_workflow.fcntl.flock

    def delayed_next(events: list[dict[str, object]]) -> str:
        if threading.current_thread().name == "screenshot-first":
            first_in_allocator.set()
            assert release_first.wait(timeout=5)
        elif threading.current_thread().name == "screenshot-second":
            second_in_allocator.set()
        return original_next(events)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "screenshot-second"
            and operation == screenshot_workflow.fcntl.LOCK_EX
        ):
            second_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(screenshot_workflow, "_next_operator_id", delayed_next)
    monkeypatch.setattr(screenshot_workflow.fcntl, "flock", observed_flock)

    first_args = screenshot_workflow.screenshot_parser().parse_args(
        request_args(workspace, slug="first-view", reason="First view")
    )
    second_args = screenshot_workflow.screenshot_parser().parse_args(
        request_args(workspace, slug="second-view", reason="Second view")
    )

    def invoke(label: str, args: object) -> None:
        try:
            outcomes[label] = screenshot_workflow.request_screenshot(args, NOW)
        except screenshot_workflow.ScreenshotError as exc:
            outcomes[label] = str(exc)

    first = threading.Thread(
        target=invoke,
        args=("first", first_args),
        name="screenshot-first",
    )
    second = threading.Thread(
        target=invoke,
        args=("second", second_args),
        name="screenshot-second",
    )
    first.start()
    assert first_in_allocator.wait(timeout=5)
    second.start()
    try:
        assert second_at_lock.wait(timeout=5)
        assert not second_in_allocator.is_set()
    finally:
        release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert isinstance(outcomes["first"], dict)
    assert isinstance(outcomes["second"], dict)
    events = screenshot_workflow._load_events(
        workspace / "screenshot_requests.jsonl"
    )
    assert [event["operator_id"] for event in events] == ["S001", "S002"]
    assert [event["screenshot_id"] for event in events] == [
        "SCR-20260809T160000123456Z",
        "SCR-20260809T160000123457Z",
    ]
    index = (workspace / "report/SCREENSHOT_INDEX.md").read_text(encoding="utf-8")
    assert "| S001 |" in index
    assert "| S002 |" in index


def test_concurrent_accept_serializes_waiver_before_binary_side_effects(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    raw = png(red=91)
    pending = pending_path(workspace)
    pending.write_bytes(raw)
    write_waiver_provenance(workspace)

    accept_inside_lock = threading.Event()
    release_accept = threading.Event()
    waiver_at_lock = threading.Event()
    waiver_finished = threading.Event()
    outcomes: dict[str, dict[str, object] | str] = {}
    original_read_pending = screenshot_workflow._read_pending_png
    original_flock = screenshot_workflow.fcntl.flock

    def delayed_read_pending(path: Path) -> tuple[bytes, int, int]:
        if threading.current_thread().name == "screenshot-accept":
            accept_inside_lock.set()
            assert release_accept.wait(timeout=5)
        return original_read_pending(path)

    def observed_flock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "screenshot-waive"
            and operation == screenshot_workflow.fcntl.LOCK_EX
        ):
            waiver_at_lock.set()
        original_flock(descriptor, operation)

    monkeypatch.setattr(
        screenshot_workflow,
        "_read_pending_png",
        delayed_read_pending,
    )
    monkeypatch.setattr(screenshot_workflow.fcntl, "flock", observed_flock)

    accept_args = screenshot_workflow.screenshot_parser().parse_args(
        [
            "review",
            "--workspace",
            str(workspace),
            "--screenshot-id",
            "S001",
            "--accept",
            "--visual-reviewed",
            "--caption",
            "Synthetic accepted view",
        ]
    )
    waive_args = screenshot_workflow.screenshot_parser().parse_args(
        [
            "waive",
            "--workspace",
            str(workspace),
            "--screenshot-id",
            "S001",
            "--reason",
            "Concurrent synthetic waiver",
            "--authorization-id",
            AUTHORIZATION_ID,
            "--alternative-evidence-id",
            ALTERNATIVE_EVIDENCE_ID,
        ]
    )

    def accept() -> None:
        try:
            outcomes["accept"] = screenshot_workflow.review_screenshot(
                accept_args,
                LATER,
            )
        except screenshot_workflow.ScreenshotError as exc:
            outcomes["accept"] = str(exc)

    def waive() -> None:
        try:
            outcomes["waive"] = screenshot_workflow.waive_screenshot(
                waive_args,
                LATER + timedelta(microseconds=1),
            )
        except screenshot_workflow.ScreenshotError as exc:
            outcomes["waive"] = str(exc)
        finally:
            waiver_finished.set()

    accept_thread = threading.Thread(target=accept, name="screenshot-accept")
    waive_thread = threading.Thread(target=waive, name="screenshot-waive")
    accept_thread.start()
    assert accept_inside_lock.wait(timeout=5)
    waive_thread.start()
    try:
        assert waiver_at_lock.wait(timeout=5)
        assert not waiver_finished.is_set()
        assert pending.is_file()
        assert not list((workspace / "inbox/screenshots/processed").glob("*.png"))
    finally:
        release_accept.set()
    accept_thread.join(timeout=5)
    waive_thread.join(timeout=5)

    assert not accept_thread.is_alive()
    assert not waive_thread.is_alive()
    assert isinstance(outcomes["accept"], dict)
    assert "already closed" in str(outcomes["waive"])
    events = screenshot_workflow._load_events(
        workspace / "screenshot_requests.jsonl"
    )
    assert [event["event"] for event in events] == ["requested", "captured"]
    captured = outcomes["accept"]
    evidence_id = str(captured["screenshot_evidence_id"])
    assert (workspace / "evidence/H01" / f"{evidence_id}.png").read_bytes() == raw
    assert (workspace / "evidence/H01" / f"{evidence_id}.json").is_file()
    assert not pending.exists()
    assert (
        workspace / "inbox/screenshots/processed/S001_H01_mcp-tools.png"
    ).read_bytes() == raw


def test_authorized_exact_credential_is_revealed_only_in_instruction(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    write_credential(workspace)
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(
            workspace,
            interface="ssh",
            protocol="ssh",
            endpoint="192.0.2.10:22",
            port=22,
            service="ssh",
            credential_id=CREDENTIAL_ID,
            login_authorized=True,
        ),
    )
    assert code == 0, stderr
    assert f"Secret value: {SECRET}" in stdout
    assert "ssh synthetic-user@192.0.2.10" in stdout
    persisted = "\n".join(
        [
            (workspace / "screenshot_requests.jsonl").read_text(),
            (workspace / "report/SCREENSHOT_INDEX.md").read_text(),
        ]
    )
    assert SECRET not in persisted
    assert CREDENTIAL_ID in persisted


def test_credential_without_login_authorization_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    write_credential(workspace)
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(workspace, credential_id=CREDENTIAL_ID, service="ssh"),
    )
    assert code == 1
    assert stdout == ""
    assert "login-authorized" in stderr
    assert SECRET not in stderr


def test_authorized_login_requires_exact_service_scope(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    write_credential(workspace)
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(
            workspace,
            interface="ssh",
            protocol="ssh",
            endpoint="192.0.2.10:22",
            port=22,
            login_authorized=True,
        ),
    )
    assert code == 1
    assert stdout == ""
    assert "service is required" in stderr
    assert SECRET not in stderr


def test_multiple_credentials_show_metadata_without_secrets(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    write_credential(workspace)
    ledger = workspace / "private/credentials/credentials.jsonl"
    second = json.loads(ledger.read_text())
    second["credential_id"] = "CRED-20260809T155958123456Z"
    second["created_at_utc"] = "2026-08-09T15:59:58.123456Z"
    second["username"] = "other-synthetic-user"
    second["secret"] = "Second-Synthetic-Value!"
    second["credential_key"] = credential_intake._credential_key(
        {
            "host_id": "H01",
            "secret_type": "password",
            "username": second["username"],
            "service": "ssh",
            "url": None,
            "realm": None,
            "secret": second["secret"],
        }
    )
    ledger.write_text(ledger.read_text() + json.dumps(second) + "\n")
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(
            workspace,
            interface="ssh",
            protocol="ssh",
            endpoint="192.0.2.10:22",
            port=22,
            service="ssh",
            login_authorized=True,
        ),
    )
    assert code == 1
    assert stdout == ""
    assert CREDENTIAL_ID in stderr
    assert "other-synthetic-user" in stderr
    assert SECRET not in stderr
    assert second["secret"] not in stderr


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@192.0.2.10/",
        "https://192.0.2.10/?token=synthetic",
        "https://192.0.2.10/#secret",
    ],
)
def test_secret_bearing_urls_are_not_persisted(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, url: str
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, _, stderr = run_screenshot(
        capsys,
        *request_args(workspace, interface="url", protocol="https", url=url),
    )
    assert code == 1
    assert "url" in stderr.lower()
    assert (workspace / "screenshot_requests.jsonl").read_bytes() == b""


def test_secret_bearing_request_requires_active_controlled_engagement_switch(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(workspace, contains_secrets=True),
    )
    assert code == 1
    assert stdout == ""
    assert "secret-display switch" in stderr
    assert (workspace / "screenshot_requests.jsonl").read_bytes() == b""


def test_secret_bearing_capture_requires_scope_review_and_is_classified(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    enable_secret_display(workspace)
    code, stdout, stderr = run_screenshot(
        capsys,
        *request_args(workspace, contains_secrets=True),
    )
    assert code == 0, stderr
    assert "SENSITIVE CAPTURE" in stdout
    request = json.loads((workspace / "screenshot_requests.jsonl").read_text())
    assert request["contains_secrets"] is True
    assert SECRET not in json.dumps(request)

    pending_path(workspace).write_bytes(png(red=77))
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--caption",
        "Synthetic in-scope credential proof",
        now=LATER,
    )
    assert code == 1
    assert "secret-scope-reviewed" in stderr
    assert pending_path(workspace).is_file()

    code, stdout, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--secret-scope-reviewed",
        "--caption",
        "Synthetic in-scope credential proof",
        now=LATER,
    )
    assert code == 0, stderr
    evidence_id = next(
        line.split(": ", 1)[1]
        for line in stdout.splitlines()
        if line.startswith("evidence_id:")
    )
    metadata = json.loads(
        (workspace / "evidence/H01" / f"{evidence_id}.json").read_text()
    )
    assert metadata["contains_secrets"] is True
    assert metadata["sensitivity"] == "engagement-secret-bearing"
    events = [
        json.loads(line)
        for line in (workspace / "screenshot_requests.jsonl").read_text().splitlines()
    ]
    assert events[-1]["contains_secrets"] is True
    report = (workspace / "report/H01.md").read_text()
    assert "SENSITIVE CAPTURE" in report
    assert SECRET not in report
    code, stdout, stderr = run_report(
        capsys,
        "check",
        "--workspace",
        str(workspace),
        "--contract",
        "operational",
    )
    assert code == 0, stderr
    assert "report_ready: yes" in stdout


def test_secret_bearing_capture_fails_if_switch_is_disabled_before_review(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    enable_secret_display(workspace)
    assert (
        run_screenshot(
            capsys, *request_args(workspace, contains_secrets=True)
        )[0]
        == 0
    )
    pending_path(workspace).write_bytes(png(red=88))
    engagement_policy.set_secret_display(
        workspace=workspace,
        enabled=False,
        reason="Synthetic disable before review",
        acknowledged=False,
        apply=True,
        now=NOW + timedelta(microseconds=1),
    )
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--secret-scope-reviewed",
        "--caption",
        "Synthetic in-scope credential proof",
        now=LATER,
    )
    assert code == 1
    assert "not active" in stderr
    assert pending_path(workspace).is_file()


def test_required_pending_blocks_report_readiness(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    code, stdout, stderr = run_report(capsys, "check", "--workspace", str(workspace))
    assert code == 1, stderr
    assert "report_ready: no" in stdout
    assert "blocking_ids: S001" in stdout


def test_controlled_engagement_does_not_relax_required_screenshot_gate(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n- Operational profile: controlled-engagement\n",
        encoding="utf-8",
    )
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    code, stdout, stderr = run_report(capsys, "check", "--workspace", str(workspace))
    assert code == 1, stderr
    assert "operational_profile: controlled-engagement" in stdout
    assert "report_ready: no" in stdout
    assert "blocking_ids: S001" in stdout


def test_accept_requires_visual_review(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    pending_path(workspace).write_bytes(png())
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--caption",
        "Synthetic tool enumeration",
        now=LATER,
    )
    assert code == 1
    assert "visual-reviewed" in stderr
    assert pending_path(workspace).is_file()


def test_accept_preserves_exact_bytes_hash_and_manual_report_text(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    report = workspace / "report/H01.md"
    report.write_text(report.read_text() + "\nManual operator paragraph.\n")
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    raw = png(red=17)
    pending_path(workspace).write_bytes(raw)
    code, stdout, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--accept",
        "--visual-reviewed",
        "--caption",
        "Synthetic tool enumeration",
        now=LATER,
    )
    assert code == 0, stderr
    evidence_id = next(
        line.split(": ", 1)[1]
        for line in stdout.splitlines()
        if line.startswith("evidence_id:")
    )
    artifact = workspace / "evidence/H01" / f"{evidence_id}.png"
    metadata = json.loads(
        (workspace / "evidence/H01" / f"{evidence_id}.json").read_text()
    )
    assert artifact.read_bytes() == raw
    assert metadata["sha256"] == hashlib.sha256(raw).hexdigest()
    assert not pending_path(workspace).exists()
    assert (
        workspace / "inbox/screenshots/processed/S001_H01_mcp-tools.png"
    ).read_bytes() == raw
    report_text = report.read_text()
    assert "Manual operator paragraph." in report_text
    assert report_text.count("<!-- CYBER:SCREENSHOTS:START -->") == 1
    assert evidence_id in report_text
    assert SECRET not in report_text
    code, ready, _ = run_report(capsys, "check", "--workspace", str(workspace))
    assert code == 0
    assert "report_ready: yes" in ready


def test_identical_second_capture_is_not_accepted_twice(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    raw = png(red=55)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    pending_path(workspace).write_bytes(raw)
    assert (
        run_screenshot(
            capsys,
            "review",
            "--workspace",
            str(workspace),
            "--screenshot-id",
            "S001",
            "--accept",
            "--visual-reviewed",
            "--caption",
            "First synthetic view",
            now=LATER,
        )[0]
        == 0
    )
    assert (
        run_screenshot(
            capsys,
            *request_args(workspace, slug="second-view", reason="Second view"),
            now=LATER + timedelta(seconds=1),
        )[0]
        == 0
    )
    pending_path(workspace, "S002").write_bytes(raw)
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S002",
        "--accept",
        "--visual-reviewed",
        "--caption",
        "Duplicate synthetic view",
        now=LATER + timedelta(seconds=2),
    )
    assert code == 1
    assert "identical screenshot" in stderr


def test_wrong_or_ambiguous_filename_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    pending = workspace / "inbox/screenshots/pending"
    wrong = pending / "S001_H01_wrong.png"
    wrong.write_bytes(png())
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Wrong filename",
        now=LATER,
    )
    assert code == 1
    assert "expected S001_H01_mcp-tools.png" in stderr
    pending_path(workspace).write_bytes(png(red=1))
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Ambiguous files",
        now=LATER,
    )
    assert code == 1
    assert "ambiguous" in stderr


def test_invalid_capture_moves_to_archive_and_remains_blocking(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    raw = png(red=33)
    pending_path(workspace).write_bytes(raw)
    code, stdout, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Tool names are not readable",
        now=LATER,
    )
    assert code == 0, stderr
    assert "status: needs_recapture" in stdout
    archived = list((workspace / "inbox/screenshots/invalid").glob("*.png"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == raw
    assert not pending_path(workspace).exists()
    code, ready, _ = run_report(capsys, "check", "--workspace", str(workspace))
    assert code == 1
    assert "blocking_ids: S001" in ready


def test_waiver_closes_readiness_with_visible_risk(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    code, _, stderr = run_screenshot(
        capsys,
        "waive",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reason",
        "Moment cannot be reproduced",
        now=LATER,
    )
    assert code == 1
    assert "required waiver needs" in stderr

    write_waiver_provenance(workspace)
    code, _, stderr = run_screenshot(
        capsys,
        "waive",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reason",
        "Moment cannot be reproduced",
        "--authorization-id",
        AUTHORIZATION_ID,
        "--alternative-evidence-id",
        ALTERNATIVE_EVIDENCE_ID,
        now=LATER,
    )
    assert code == 0, stderr
    code, stdout, _ = run_report(capsys, "check", "--workspace", str(workspace))
    assert code == 0
    assert "waived_risk_ids: S001" in stdout


@pytest.mark.parametrize(
    ("authorization_host", "evidence_host", "error"),
    [
        ("H02", "H01", "authorization does not cover"),
        ("H01", "H02", "evidence belongs to an unrelated host"),
    ],
)
def test_waiver_provenance_must_belong_to_request_host(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    authorization_host: str,
    evidence_host: str,
    error: str,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    write_waiver_provenance(
        workspace,
        authorization_host=authorization_host,
        evidence_host=evidence_host,
    )
    code, _, stderr = run_screenshot(
        capsys,
        "waive",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reason",
        "Moment cannot be reproduced",
        "--authorization-id",
        AUTHORIZATION_ID,
        "--alternative-evidence-id",
        ALTERNATIVE_EVIDENCE_ID,
        now=LATER,
    )
    assert code == 1
    assert error in stderr


def test_public_request_cannot_claim_a_derived_coverage_key(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, _, stderr = run_screenshot(
        capsys,
        *request_args(workspace),
        "--coverage-key",
        "step:H01-ST-01:objective",
    )
    assert code == 2
    assert "unrecognized arguments" in stderr


def test_screenshot_request_rejects_cross_host_evidence(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    add_second_host(capsys, workspace)
    evidence_id = "EVD-20260809T155959223456Z"
    (workspace / "evidence/H02" / f"{evidence_id}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "evidence_id": evidence_id,
                "host_id": "H02",
                "description": "Synthetic evidence from another host",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code, _, stderr = run_screenshot(
        capsys,
        *request_args(workspace),
        "--evidence-id",
        evidence_id,
    )
    assert code == 1
    assert "evidence reference belongs to an unrelated host" in stderr


@pytest.mark.parametrize(
    "key_header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_screenshot_request_rejects_private_key_variants(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_header: str
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    code, _, stderr = run_screenshot(
        capsys,
        *request_args(workspace, reason=f"Display {key_header}"),
    )
    assert code == 1
    assert "private-key" in stderr


@pytest.mark.parametrize(
    ("modifier", "error"),
    [
        (lambda path: path.write_bytes(b"not png"), "not a PNG"),
        (lambda path: path.write_bytes(oversized_png()), "40 megapixel"),
    ],
)
def test_png_validation(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    modifier: object,
    error: str,
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    modifier(pending_path(workspace))  # type: ignore[operator]
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Invalid image",
        now=LATER,
    )
    assert code == 1
    assert error in stderr


def test_symlink_pending_file_is_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    outside = tmp_path / "outside.png"
    outside.write_bytes(png())
    pending_path(workspace).symlink_to(outside)
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Invalid image",
        now=LATER,
    )
    assert code == 1
    assert "non-symlink regular file" in stderr
    assert outside.is_file()


def test_special_and_oversized_pending_files_are_rejected(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    assert run_screenshot(capsys, *request_args(workspace))[0] == 0
    pending = pending_path(workspace)
    os.mkfifo(pending)
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Special file",
        now=LATER,
    )
    assert code == 1
    assert "regular file" in stderr
    pending.unlink()
    with pending.open("wb") as handle:
        handle.truncate(25 * 1024 * 1024 + 1)
    code, _, stderr = run_screenshot(
        capsys,
        "review",
        "--workspace",
        str(workspace),
        "--screenshot-id",
        "S001",
        "--reject",
        "--reason",
        "Oversized file",
        now=LATER,
    )
    assert code == 1
    assert "size limit" in stderr


def test_h100_is_supported_end_to_end(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path, host_id="H100")
    code, stdout, stderr = run_screenshot(
        capsys, *request_args(workspace, host_id="H100")
    )
    assert code == 0, stderr
    assert "Host: H100" in stdout
    assert "S001_H100_mcp-tools.png" in stdout


def test_active_collection_is_resolved(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    module = make_workspace(capsys, collection)
    module.rename(collection / "module-a")
    (collection / "ACTIVE_TASK").write_text("module-a\n")
    code, stdout, stderr = run_screenshot(
        capsys, *request_args(collection, host_id="H01")
    )
    assert code == 0, stderr
    assert str(collection / "module-a/inbox/screenshots/pending") in stdout


def test_legacy_workspace_lazy_creation(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workspace = make_workspace(capsys, tmp_path)
    (workspace / "screenshot_requests.jsonl").unlink()
    (workspace / "report/SCREENSHOT_INDEX.md").unlink()
    for name in ("pending", "processed", "invalid"):
        (workspace / "inbox/screenshots" / name).rmdir()
    (workspace / "inbox/screenshots").rmdir()
    code, _, stderr = run_screenshot(capsys, *request_args(workspace))
    assert code == 0, stderr
    assert (workspace / "inbox/screenshots/pending").is_dir()
    assert (workspace / "screenshot_requests.jsonl").is_file()
    assert (workspace / "report/SCREENSHOT_INDEX.md").is_file()
