"""Synthetic coverage for fail-closed legacy evidence self-collision recovery."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import host_identity, new_host, operational_trace

EVIDENCE_ID = "EVD-20260901T120000123456Z"
NOW = datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC)


def legacy_record(payload: bytes) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "evidence_id": EVIDENCE_ID,
        "timestamp_utc": "2026-09-01T12:00:00.123456Z",
        "host_id": "H01",
        "kind": "synthetic",
        "label": "synthetic legacy self-collision",
        "artifact_path": f"evidence/H01/{EVIDENCE_ID}.json",
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def write_legacy_pair(root: Path, payload: bytes) -> tuple[Path, Path, dict[str, object]]:
    directory = root / "evidence" / "H01"
    directory.mkdir(parents=True, exist_ok=True)
    metadata = directory / f"{EVIDENCE_ID}.json"
    artifact = directory / f"{EVIDENCE_ID}.legacy"
    record = legacy_record(payload)
    metadata.write_text(json.dumps(record) + "\n", encoding="utf-8")
    artifact.write_bytes(payload)
    return metadata, artifact, record


def test_hash_verified_legacy_sibling_preserves_metadata_bytes(tmp_path: Path) -> None:
    payload = b'{"synthetic":"retained result"}\n'
    metadata, artifact, record = write_legacy_pair(tmp_path, payload)
    before = metadata.read_bytes()

    assert host_identity.locate_evidence_artifact(metadata, record) == artifact
    assert metadata.read_bytes() == before


@pytest.mark.parametrize("condition", ["missing", "wrong-hash", "symlink"])
def test_legacy_recovery_fails_closed(condition: str, tmp_path: Path) -> None:
    payload = b"synthetic retained result\n"
    metadata, artifact, record = write_legacy_pair(tmp_path, payload)
    if condition == "missing":
        artifact.unlink()
    elif condition == "wrong-hash":
        artifact.write_bytes(b"different bytes\n")
    else:
        artifact.unlink()
        artifact.symlink_to(tmp_path / "outside")

    with pytest.raises(host_identity.HostIdentityError):
        host_identity.locate_evidence_artifact(metadata, record)


def test_operational_change_validation_accepts_recovered_legacy_artifact(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    new_host.bootstrap_host(workspace, scripts, "H01", "192.0.2.10", "synthetic")
    payload = b'{"synthetic":"retained result"}\n'
    metadata, artifact, record = write_legacy_pair(workspace, payload)
    assert metadata.is_file() and artifact.is_file() and record["host_id"] == "H01"
    _, authorization = operational_trace.log_authorization(
        workspace=workspace,
        host_ids=["H01"],
        categories=["configuration"],
        maximum_impact="moderate",
        techniques=["package install"],
        exclusions=["destructive action"],
        source="operator-chat",
        summary="Synthetic authorization",
        now=NOW,
    )

    _, change = operational_trace.log_change(
        workspace=workspace,
        event="planned",
        authorization_id=authorization["authorization_id"],
        host_id="H01",
        category="configuration",
        impact_level="moderate",
        technique="package install",
        target="synthetic package state",
        description="Synthetic package installation",
        reversibility="reversible",
        before_state="package absent",
        rollback_steps=["remove synthetic package"],
        validation_steps=["verify synthetic version"],
        evidence_ids=[],
        now=NOW.replace(second=1),
    )

    assert change["event"] == "planned"
    assert change["host_id"] == "H01"
