"""Synthetic tests for controlled-engagement standing authorization."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from policy_support import synthetic_configuration

from scripts import artifact_handling, engagement_policy, new_host
from scripts.engagement_policy import EngagementPolicyError
from scripts.operational_trace import load_authorizations

BASE_TIME = datetime(2026, 8, 10, 15, 0, 0, tzinfo=UTC)


def make_workspace(tmp_path: Path, profile: str = "controlled-engagement") -> Path:
    workspace = tmp_path / "workspace"
    script_dir = Path(__file__).parents[1] / "scripts"
    new_host.initialize_workspace(workspace, script_dir)
    (workspace / "TASK_CONTEXT.md").write_text(
        f"- Current task: synthetic\n- Operational profile: {profile}\n",
        encoding="utf-8",
    )
    return workspace


def synthetic_activation(workspace: Path, *, now: datetime = BASE_TIME) -> dict[str, object]:
    _, record = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4400-4500"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Synthetic operator-approved explicit policy",
        now=now,
    )
    engagement_policy.apply_activation(workspace, record)
    return record


def test_bootstrap_creates_private_empty_standing_ledger(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    ledger = workspace / engagement_policy.STANDING_AUTHORIZATION_LEDGER
    assert ledger.read_bytes() == b""
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600


def test_strict_profile_keeps_explicit_policy_and_secret_controls_separate(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, "strict")
    record = synthetic_activation(workspace)
    assert record["preset"] == "custom"
    assert not engagement_policy.secret_display_enabled(workspace, BASE_TIME)


def test_malformed_artifact_handling_blocks_activation_and_permit(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "synthetic-host",
    )
    context = workspace / "TASK_CONTEXT.md"
    context.write_text(
        context.read_text(encoding="utf-8")
        + "- Artifact handling: corrupted\n",
        encoding="utf-8",
    )

    with pytest.raises(EngagementPolicyError, match="artifact handling must be one of"):
        engagement_policy.build_activation(
            workspace=workspace,
            preset="custom", configuration=synthetic_configuration(),
            host_scope="canonical-current-and-future",
            callback_cidrs=["192.0.2.10/32"],
            callback_port_ranges=["4444"],
            expires_at_utc=None,
            source="operator-cli",
            summary="Must fail before policy planning",
            now=BASE_TIME + timedelta(seconds=1),
        )

    with pytest.raises(EngagementPolicyError, match="artifact handling must be one of"):
        engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
            workspace=workspace,
            host_ids=["H01"],
            category="filesystem",
            impact_level="low",
            technique_family="filesystem-data",
            technique="read-only listing",
            callback=None,
            summary="Must fail before permit planning",
            apply=False,
            now=BASE_TIME + timedelta(seconds=1),
        )


def test_missing_task_context_blocks_activation_and_permit(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "synthetic-host",
    )
    (workspace / "TASK_CONTEXT.md").unlink()

    with pytest.raises(EngagementPolicyError, match="TASK_CONTEXT.md is missing"):
        engagement_policy.build_activation(
            workspace=workspace,
            preset="custom", configuration=synthetic_configuration(),
            host_scope="canonical-current-and-future",
            callback_cidrs=["192.0.2.10/32"],
            callback_port_ranges=["4444"],
            expires_at_utc=None,
            source="operator-cli",
            summary="Missing context must fail closed",
            now=BASE_TIME + timedelta(seconds=1),
        )

    with pytest.raises(EngagementPolicyError, match="TASK_CONTEXT.md is missing"):
        engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
            workspace=workspace,
            host_ids=["H01"],
            category="filesystem",
            impact_level="low",
            technique_family="filesystem-data",
            technique="read-only listing",
            callback=None,
            summary="Missing context must fail closed",
            apply=False,
            now=BASE_TIME + timedelta(seconds=1),
        )


def test_no_download_does_not_expand_or_block_valid_authorization(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    context = workspace / "TASK_CONTEXT.md"
    context.write_text(
        context.read_text(encoding="utf-8")
        + "- Artifact handling: no-download\n",
        encoding="utf-8",
    )
    synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "synthetic-host",
    )
    _, authorization, _ = engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
        workspace=workspace,
        host_ids=["H01"],
        category="filesystem",
        impact_level="low",
        technique_family="filesystem-data",
        technique="read-only listing",
        callback=None,
        summary="Independent artifact storage mode",
        apply=False,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert authorization is None


def test_artifact_mode_switch_preserves_active_standing_authorization(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    activation = synthetic_activation(workspace)
    context = workspace / "TASK_CONTEXT.md"
    before_ledger = (workspace / engagement_policy.STANDING_AUTHORIZATION_LEDGER).read_bytes()

    for mode in (artifact_handling.NO_DOWNLOAD, artifact_handling.STANDARD):
        context.write_text(
            artifact_handling.render_mode_text(
                context.read_text(encoding="utf-8"),
                mode,
            ),
            encoding="utf-8",
        )
        active = engagement_policy.active_standing_authorization(workspace, BASE_TIME)
        assert active is not None
        assert (
            active["standing_authorization_id"]
            == activation["standing_authorization_id"]
        )

    assert (workspace / engagement_policy.STANDING_AUTHORIZATION_LEDGER).read_bytes() == before_ledger


def test_preview_displays_matrix_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    code = engagement_policy.main(
        [
            "activate",
            "--workspace",
            str(workspace),
            "--preset",
            "custom",
            "--maximum-impact", "critical",
            "--technique-family", "filesystem-data",
            "--category", "filesystem",
            "--credential-operations", "none",
            "--persistence-mode", "none",
            "--allow-security-control-changes",
            "--allow-destructive",
            "--allow-bulk-data",
            "--callback-cidr",
            "192.0.2.10/32",
            "--callback-port-range",
            "4444",
            "--summary",
            "Synthetic preview",
        ],
        now=BASE_TIME,
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "mode: PREVIEW" in output
    assert "allow_destructive: ON" in output
    assert "denial_of_service: OFF" in output
    assert (workspace / engagement_policy.STANDING_AUTHORIZATION_LEDGER).read_bytes() == b""


def test_full_apply_requires_every_impact_acknowledgement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    code = engagement_policy.main(
        [
            "activate",
            "--workspace",
            str(workspace),
            "--preset",
            "custom",
            "--maximum-impact", "critical",
            "--technique-family", "filesystem-data",
            "--category", "filesystem",
            "--credential-operations", "none",
            "--persistence-mode", "none",
            "--allow-security-control-changes",
            "--allow-destructive",
            "--allow-bulk-data",
            "--callback-cidr",
            "192.0.2.10/32",
            "--callback-port-range",
            "4444",
            "--summary",
            "Synthetic apply",
            "--apply",
        ],
        now=BASE_TIME,
    )
    assert code == 1
    assert "--ack-critical-impact" in capsys.readouterr().err
    assert engagement_policy.active_standing_authorization(workspace, BASE_TIME) is None


def test_full_apply_with_all_acknowledgements_activates_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    code = engagement_policy.main(
        [
            "activate",
            "--workspace",
            str(workspace),
            "--preset",
            "custom",
            "--maximum-impact", "critical",
            "--technique-family", "filesystem-data",
            "--category", "filesystem",
            "--credential-operations", "none",
            "--persistence-mode", "none",
            "--allow-security-control-changes",
            "--allow-destructive",
            "--allow-bulk-data",
            "--callback-cidr",
            "192.0.2.10/32",
            "--callback-port-range",
            "4444",
            "--summary",
            "Synthetic approved activation",
            "--ack-critical-impact",
            "--ack-security-control-changes",
            "--ack-destructive",
            "--ack-bulk-data",
            "--apply",
        ],
        now=BASE_TIME,
    )
    assert code == 0
    assert "mode: APPLY" in capsys.readouterr().out
    assert engagement_policy.active_standing_authorization(
        workspace, BASE_TIME
    ) is not None


def test_future_canonical_host_is_permitted_and_creates_v2_authorization(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    policy = synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "future-host",
    )

    _, authorization, _ = engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
        workspace=workspace,
        host_ids=["H01"],
        category="persistence",
        impact_level="high",
        technique_family="persistence",
        technique="authorized_keys",
        callback=None,
        summary="Establish one durable access channel",
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )

    assert authorization is not None
    assert authorization["schema_version"] == "2.0"
    assert authorization["standing_authorization_id"] == policy["standing_authorization_id"]
    assert load_authorizations(workspace)[0] == authorization


@pytest.mark.parametrize(
    ("category", "family", "callback", "message"),
    [
        ("denial-of-service", "persistence", None, "DoS"),
        ("persistence", "persistence", None, "registered canonical"),
        ("external-callback", "pivot-tunnel", "203.0.113.50:4444", "allowlist"),
    ],
)
def test_permit_rejects_dos_unknown_host_and_callback_outside_allowlist(
    tmp_path: Path,
    category: str,
    family: str,
    callback: str | None,
    message: str,
) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    host_ids = ["192.0.2.99"] if category == "persistence" else ["H01"]
    if host_ids == ["H01"]:
        new_host.bootstrap_host(
            workspace,
            Path(__file__).parents[1] / "scripts",
            "H01",
            "198.51.100.10",
            "entry",
        )
    with pytest.raises(EngagementPolicyError, match=message):
        engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
            workspace=workspace,
            host_ids=host_ids,
            category=category,
            impact_level="high",
            technique_family=family,
            technique="synthetic technique",
            callback=callback,
            summary="Synthetic permit",
            apply=False,
            now=BASE_TIME + timedelta(seconds=1),
        )


def test_allowlisted_callback_is_permitted(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "entry",
    )
    _, authorization, _ = engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
        workspace=workspace,
        host_ids=["H01"],
        category="external-callback",
        impact_level="high",
        technique_family="pivot-tunnel",
        technique="reverse tunnel",
        callback="192.0.2.10:4444",
        summary="Operator-controlled callback",
        apply=False,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert authorization is None


def test_revoke_blocks_new_permits_but_preserves_v2_history(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    new_host.bootstrap_host(
        workspace,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "198.51.100.10",
        "entry",
    )
    engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
        workspace=workspace,
        host_ids=["H01"],
        category="persistence",
        impact_level="high",
        technique_family="persistence",
        technique="local admin account",
        callback=None,
        summary="Synthetic durable access",
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    engagement_policy.end_policy(
        workspace=workspace,
        event="revoked",
        note="Synthetic operator revocation",
        apply=True,
        now=BASE_TIME + timedelta(seconds=2),
    )

    assert engagement_policy.active_standing_authorization(
        workspace, BASE_TIME + timedelta(seconds=3)
    ) is None
    assert len(load_authorizations(workspace)) == 1
    with pytest.raises(EngagementPolicyError, match="no active"):
        engagement_policy.permit_operation(
            review_reference="REVIEW-SYNTHETIC",
            workspace=workspace,
            host_ids=["H01"],
            category="persistence",
            impact_level="high",
            technique_family="persistence",
            technique="another account",
            callback=None,
            summary="Must be rejected",
            apply=False,
            now=BASE_TIME + timedelta(seconds=3),
        )


def test_expired_policy_allows_a_new_activation(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    _, first = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=(BASE_TIME + timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        source="operator-cli",
        summary="Short synthetic authorization",
        now=BASE_TIME,
    )
    engagement_policy.apply_activation(workspace, first)
    _, second = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Replacement synthetic authorization",
        now=BASE_TIME + timedelta(seconds=2),
    )
    engagement_policy.apply_activation(workspace, second)
    assert engagement_policy.active_standing_authorization(
        workspace, BASE_TIME + timedelta(seconds=2)
    )["standing_authorization_id"] == second["standing_authorization_id"]


def test_duplicate_activation_apply_is_rejected_under_locked_recheck(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    _, record = engagement_policy.build_activation(
        workspace=workspace,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=None,
        source="operator-cli",
        summary="Synthetic activation",
        now=BASE_TIME,
    )
    engagement_policy.apply_activation(workspace, record)
    with pytest.raises(EngagementPolicyError, match="already has an active"):
        engagement_policy.apply_activation(workspace, record)


def test_malformed_or_symlinked_standing_ledger_fails_closed(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    ledger = workspace / engagement_policy.STANDING_AUTHORIZATION_LEDGER
    ledger.write_text("{}\n", encoding="utf-8")
    with pytest.raises(EngagementPolicyError, match="missing"):
        engagement_policy.load_standing_authorizations(workspace)

    ledger.unlink()
    outside = tmp_path / "outside"
    outside.write_text("", encoding="utf-8")
    ledger.symlink_to(outside)
    with pytest.raises(EngagementPolicyError, match="non-symlink"):
        engagement_policy.load_standing_authorizations(workspace)


def test_secret_display_preview_is_read_only_and_visible_in_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    code = engagement_policy.main(
        [
            "secret-display",
            "enable",
            "--workspace",
            str(workspace),
            "--reason",
            "Synthetic engagement reporting requirement",
        ],
        now=BASE_TIME + timedelta(seconds=1),
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "mode: PREVIEW" in output
    assert "allow_secret_display: ON" in output
    assert not (workspace / engagement_policy.SECRET_DISPLAY_LEDGER).exists()
    assert not engagement_policy.secret_display_enabled(
        workspace, BASE_TIME + timedelta(seconds=1)
    )

    assert (
        engagement_policy.main(
            ["status", "--workspace", str(workspace)],
            now=BASE_TIME + timedelta(seconds=1),
        )
        == 0
    )
    status = capsys.readouterr().out
    assert "artifact_handling: standard" in status
    assert "allow_secret_display: OFF" in status
    assert "secret_display_surfaces: none" in status


def test_status_exposes_no_download_and_rejects_malformed_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    context = workspace / "TASK_CONTEXT.md"
    context.write_text(
        context.read_text(encoding="utf-8")
        + "- Artifact handling: no-download\n",
        encoding="utf-8",
    )

    assert engagement_policy.main(
        ["status", "--workspace", str(workspace)], now=BASE_TIME
    ) == 0
    assert "artifact_handling: no-download" in capsys.readouterr().out

    context.write_text(
        context.read_text(encoding="utf-8")
        + "- Artifact handling: standard\n",
        encoding="utf-8",
    )
    assert engagement_policy.main(
        ["status", "--workspace", str(workspace)], now=BASE_TIME
    ) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "duplicate artifact handling entries" in captured.err


def test_secret_display_enable_requires_ack_and_uses_private_ledger(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    arguments = [
        "secret-display",
        "enable",
        "--workspace",
        str(workspace),
        "--reason",
        "Synthetic engagement reporting requirement",
        "--apply",
    ]
    assert engagement_policy.main(arguments, now=BASE_TIME + timedelta(seconds=1)) == 1
    assert "--ack-secret-display" in capsys.readouterr().err
    assert not (workspace / engagement_policy.SECRET_DISPLAY_LEDGER).exists()

    arguments.insert(-1, "--ack-secret-display")
    assert engagement_policy.main(arguments, now=BASE_TIME + timedelta(seconds=1)) == 0
    output = capsys.readouterr().out
    assert "allow_secret_display: ON" in output
    ledger = workspace / engagement_policy.SECRET_DISPLAY_LEDGER
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600
    assert engagement_policy.secret_display_enabled(
        workspace, BASE_TIME + timedelta(seconds=1)
    )
    assert engagement_policy.load_secret_display_events(workspace)[0]["surfaces"] == [
        "chat",
        "screenshot",
        "private-report",
    ]


def test_secret_display_disable_and_standing_expiry_fail_closed(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    engagement_policy.set_secret_display(
        workspace=workspace,
        enabled=True,
        reason="Synthetic enable",
        acknowledged=True,
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    engagement_policy.set_secret_display(
        workspace=workspace,
        enabled=False,
        reason="Synthetic disable",
        acknowledged=False,
        apply=True,
        now=BASE_TIME + timedelta(seconds=2),
    )
    assert not engagement_policy.secret_display_enabled(
        workspace, BASE_TIME + timedelta(seconds=3)
    )

    second = make_workspace(tmp_path / "expiring")
    _, policy = engagement_policy.build_activation(
        workspace=second,
        preset="custom", configuration=synthetic_configuration(),
        host_scope="canonical-current-and-future",
        callback_cidrs=["192.0.2.10/32"],
        callback_port_ranges=["4444"],
        expires_at_utc=(BASE_TIME + timedelta(seconds=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        source="operator-cli",
        summary="Synthetic expiring policy",
        now=BASE_TIME,
    )
    engagement_policy.apply_activation(second, policy)
    engagement_policy.set_secret_display(
        workspace=second,
        enabled=True,
        reason="Synthetic enable",
        acknowledged=True,
        apply=True,
        now=BASE_TIME + timedelta(seconds=1),
    )
    assert not engagement_policy.secret_display_enabled(
        second, BASE_TIME + timedelta(seconds=3)
    )


def test_secret_display_rejects_secret_bearing_reason(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    with pytest.raises(EngagementPolicyError, match="secret"):
        engagement_policy.set_secret_display(
            workspace=workspace,
            enabled=True,
            reason="token=synthetic-value",
            acknowledged=True,
            apply=False,
            now=BASE_TIME + timedelta(seconds=1),
        )


def test_malformed_or_symlinked_secret_display_ledger_fails_closed(
    tmp_path: Path,
) -> None:
    workspace = make_workspace(tmp_path)
    synthetic_activation(workspace)
    ledger = workspace / engagement_policy.SECRET_DISPLAY_LEDGER
    ledger.write_text("{}\n", encoding="utf-8")
    ledger.chmod(0o600)
    with pytest.raises(EngagementPolicyError, match="missing"):
        engagement_policy.load_secret_display_events(workspace)

    ledger.unlink()
    outside = tmp_path / "outside-secret-display"
    outside.write_text("", encoding="utf-8")
    ledger.symlink_to(outside)
    with pytest.raises(EngagementPolicyError, match="non-symlink"):
        engagement_policy.load_secret_display_events(workspace)

    ledger.unlink()
    ledger.symlink_to(tmp_path / "missing-secret-display-target")
    with pytest.raises(EngagementPolicyError, match="non-symlink"):
        engagement_policy.load_secret_display_events(workspace)
