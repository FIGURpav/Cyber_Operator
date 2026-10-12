"""Synthetic tests for bounded plaintext-secret report exports."""

from __future__ import annotations

import base64
import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from policy_support import synthetic_configuration

from scripts import (
    credential_intake,
    engagement_policy,
    new_host,
    sensitive_report_export,
)

NOW = datetime(2026, 8, 25, 12, 0, 0, 123450, tzinfo=UTC)
SECRET = "Synthetic report secret with spaces!"


def make_workspace(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.bootstrap_host(
        workspace,
        script_dir,
        "H01",
        "192.0.2.10",
        "target.synthetic.test",
    )
    (workspace / "TASK_CONTEXT.md").write_text(
        "- Current task: synthetic\n"
        "- Active source task: none\n"
        "- Operational profile: controlled-engagement\n"
        "- Intake mode: chat\n",
        encoding="utf-8",
    )
    _, standing = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.20/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Synthetic report-export authorization",
        now=NOW,
    )
    engagement_policy.apply_activation(workspace, standing)
    engagement_policy.set_secret_display(
        workspace=workspace,
        enabled=True,
        reason="Synthetic secret display",
        acknowledged=True,
        apply=True,
        now=NOW + timedelta(microseconds=1),
    )
    result = credential_intake.store_credential_bytes(
        workspace,
        (
            "host: H01\n"
            "username: synthetic-user\n"
            "service: synthetic-ssh\n"
            f"password: {SECRET}\n"
        ).encode(),
        now=NOW + timedelta(microseconds=2),
    )
    return workspace, result.credential_ids[0]


def enable_policy(workspace: Path, destination: Path) -> None:
    sensitive_report_export.set_policy(
        workspace=workspace,
        enabled=True,
        destination_root=str(destination),
        reason="Synthetic Cyber-Operator private report export",
        acknowledged_plaintext=True,
        acknowledged_duplication=True,
        acknowledged_retention=True,
        apply=True,
        now=NOW + timedelta(microseconds=3),
    )


def test_policy_preview_is_read_only_and_apply_requires_acknowledgements(
    tmp_path: Path,
) -> None:
    workspace, _ = make_workspace(tmp_path)
    destination = tmp_path / "private-exports"
    _, record, created = sensitive_report_export.set_policy(
        workspace=workspace,
        enabled=True,
        destination_root=str(destination),
        reason="Synthetic preview",
        acknowledged_plaintext=False,
        acknowledged_duplication=False,
        acknowledged_retention=False,
        apply=False,
        now=NOW + timedelta(microseconds=3),
    )
    assert record["event"] == "enabled"
    assert created is False
    assert not destination.exists()
    assert (workspace / sensitive_report_export.POLICY_LEDGER).read_bytes() == b""

    with pytest.raises(
        sensitive_report_export.SensitiveReportError,
        match="ack-plaintext-report",
    ):
        sensitive_report_export.set_policy(
            workspace=workspace,
            enabled=True,
            destination_root=str(destination),
            reason="Synthetic apply",
            acknowledged_plaintext=False,
            acknowledged_duplication=False,
            acknowledged_retention=False,
            apply=True,
            now=NOW + timedelta(microseconds=3),
        )
    assert not destination.exists()


def test_render_materializes_plaintext_only_in_sensitive_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, credential_id = make_workspace(tmp_path)
    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    template = workspace / "report" / "sensitive-template.md"
    template.write_text(
        "# Steps to Reproduction\n\n"
        "```bash\n"
        "curl -H {{CRED:"
        + credential_id
        + ":secret:shell}} https://target.synthetic.test/\n"
        "ssh {{CRED:"
        + credential_id
        + ":username:shell}}@target.synthetic.test\n"
        "```\n",
        encoding="utf-8",
    )
    payload_dir = workspace / "workbench"
    payload_dir.mkdir()
    payload = payload_dir / "payload.py"
    payload.write_bytes(b"print('synthetic payload')\n")

    code = sensitive_report_export.main(
        [
            "render",
            "--workspace",
            str(workspace),
            "--template",
            str(template),
            "--title",
            "Synthetic private report",
            "--payload",
            str(payload),
            "--preview",
        ],
        now=NOW + timedelta(microseconds=4),
    )
    preview = capsys.readouterr()
    assert code == 0
    assert SECRET not in preview.out + preview.err
    assert not list(destination.iterdir())

    code = sensitive_report_export.main(
        [
            "render",
            "--workspace",
            str(workspace),
            "--template",
            str(template),
            "--title",
            "Synthetic private report",
            "--payload",
            str(payload),
            "--apply",
        ],
        now=NOW + timedelta(microseconds=4),
    )
    output = capsys.readouterr()
    assert code == 0
    assert SECRET not in output.out + output.err
    export_id = "SRX-20260825T120000123454Z"
    bundle = destination / export_id
    report = bundle / sensitive_report_export.REPORT_NAME
    assert SECRET in report.read_text(encoding="utf-8")
    assert "'Synthetic report secret with spaces!'" in report.read_text(
        encoding="utf-8"
    )
    assert (bundle / "payloads" / payload.name).read_bytes() == payload.read_bytes()
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    assert stat.S_IMODE(report.stat().st_mode) == 0o600

    manifest = (bundle / sensitive_report_export.MANIFEST_NAME).read_text(
        encoding="utf-8"
    )
    policy_ledger = (workspace / sensitive_report_export.POLICY_LEDGER).read_text()
    export_ledger = (workspace / sensitive_report_export.EXPORT_LEDGER).read_text()
    assert SECRET not in manifest + policy_ledger + export_ledger
    assert credential_id in manifest
    verified_path, _ = sensitive_report_export.verify_bundle(workspace, export_id)
    assert verified_path == bundle


def test_base64_raw_renderer_materializes_multiline_key(tmp_path: Path) -> None:
    workspace, _ = make_workspace(tmp_path)
    key = "-----BEGIN TEST KEY-----\nline-one\n-----END TEST KEY-----\n"
    encoded = base64.b64encode(key.encode()).decode()
    result = credential_intake.store_credential_bytes(
        workspace,
        (
            "host: H01\n"
            "username: key-user\n"
            "service: ssh-key\n"
            f"token: {encoded}\n"
        ).encode(),
        now=NOW + timedelta(microseconds=5),
    )
    credential_id = result.credential_ids[0]
    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    template = workspace / "report" / "key-template.md"
    template.write_text(
        "```bash\n"
        "install -m 600 /dev/stdin ./id_key <<'CYBER_KEY_EOF'\n"
        f"{{{{CRED:{credential_id}:secret:base64-raw}}}}\n"
        "CYBER_KEY_EOF\n"
        "```\n",
        encoding="utf-8",
    )
    export_id, bundle, _, _, _ = sensitive_report_export.render_bundle(
        workspace=workspace,
        template_file=str(template),
        title="Synthetic key report",
        payload_files=[],
        apply=True,
        now=NOW + timedelta(microseconds=6),
    )
    assert export_id == "SRX-20260825T120000123456Z"
    assert bundle is not None
    assert key in (bundle / sensitive_report_export.REPORT_NAME).read_text()


def test_template_with_existing_plaintext_secret_is_rejected(tmp_path: Path) -> None:
    workspace, credential_id = make_workspace(tmp_path)
    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    template = workspace / "report" / "unsafe-template.md"
    template.write_text(
        f"Already copied: {SECRET}\n"
        f"{{{{CRED:{credential_id}:secret:shell}}}}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        sensitive_report_export.SensitiveReportError,
        match="credential value",
    ):
        sensitive_report_export.render_bundle(
            workspace=workspace,
            template_file=str(template),
            title="Unsafe template",
            payload_files=[],
            apply=False,
            now=NOW + timedelta(microseconds=4),
        )


def test_git_destination_and_disabled_policy_fail_closed(tmp_path: Path) -> None:
    workspace, credential_id = make_workspace(tmp_path)
    git_root = tmp_path / "git-root"
    git_root.mkdir(mode=0o700)
    (git_root / ".git").mkdir()
    with pytest.raises(
        sensitive_report_export.SensitiveReportError, match="Git work tree"
    ):
        enable_policy(workspace, git_root / "private-exports")

    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    sensitive_report_export.set_policy(
        workspace=workspace,
        enabled=False,
        destination_root=None,
        reason="Synthetic policy closure",
        acknowledged_plaintext=False,
        acknowledged_duplication=False,
        acknowledged_retention=False,
        apply=True,
        now=NOW + timedelta(microseconds=4),
    )
    template = workspace / "report" / "disabled-template.md"
    template.write_text(
        f"{{{{CRED:{credential_id}:secret:shell}}}}\n", encoding="utf-8"
    )
    with pytest.raises(
        sensitive_report_export.SensitiveReportError,
        match="not active",
    ):
        sensitive_report_export.render_bundle(
            workspace=workspace,
            template_file=str(template),
            title="Disabled export",
            payload_files=[],
            apply=False,
            now=NOW + timedelta(microseconds=5),
        )


def test_manifest_is_valid_json_and_contains_no_secret(tmp_path: Path) -> None:
    workspace, credential_id = make_workspace(tmp_path)
    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    template = workspace / "report" / "manifest-template.md"
    template.write_text(
        f"{{{{CRED:{credential_id}:secret:json}}}}\n", encoding="utf-8"
    )
    export_id, bundle, digest, ids, loot_ids = sensitive_report_export.render_bundle(
        workspace=workspace,
        template_file=str(template),
        title="Manifest test",
        payload_files=[],
        apply=True,
        now=NOW + timedelta(microseconds=7),
    )
    assert bundle is not None
    manifest = json.loads(
        (bundle / sensitive_report_export.MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert manifest["export_id"] == export_id
    assert manifest["report"]["sha256"] == digest
    assert manifest["credential_ids"] == ids
    assert loot_ids == []
    assert SECRET not in json.dumps(manifest)


def test_loot_placeholder_materializes_proof_only_in_bundle(tmp_path: Path) -> None:
    workspace, _ = make_workspace(tmp_path)
    value = "Cyber-Operator{synthetic-private-proof}"
    moment = NOW + timedelta(microseconds=8)
    loot_id = moment.strftime("LOOT-%Y%m%dT%H%M%S%fZ")
    record = {
        "schema_version": "1.0",
        "loot_id": loot_id,
        "timestamp_utc": moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "host_id": "H01",
        "category": "objective-proof",
        "label": "secondary-objective-proof",
        "source": "synthetic test",
        "username": "synthetic-user",
        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "value_text": value,
    }
    with (workspace / "loot.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    destination = tmp_path / "private-exports"
    enable_policy(workspace, destination)
    template = workspace / "report" / "loot-template.md"
    template.write_text(
        f"Proof: {{{{LOOT:{loot_id}:value_text:raw}}}}\n", encoding="utf-8"
    )
    export_id, bundle, _, credential_ids, loot_ids = (
        sensitive_report_export.render_bundle(
            workspace=workspace,
            template_file=str(template),
            title="Synthetic loot report",
            payload_files=[],
            apply=True,
            now=NOW + timedelta(microseconds=9),
        )
    )
    assert bundle is not None
    assert value in (bundle / sensitive_report_export.REPORT_NAME).read_text()
    assert credential_ids == []
    assert loot_ids == [loot_id]
    manifest = (bundle / sensitive_report_export.MANIFEST_NAME).read_text()
    assert loot_id in manifest
    assert value not in manifest
    assert export_id == "SRX-20260825T120000123459Z"
