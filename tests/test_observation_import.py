"""Synthetic tests for atomic normalized JSON and Nmap XML observation intake."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import capture_evidence, host_state, observation_import
from scripts.new_host import bootstrap_host

NOW = datetime(2026, 9, 9, 21, 0, 0, 123456, tzinfo=UTC)


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    bootstrap_host(
        root,
        Path(__file__).parents[1] / "scripts",
        "H01",
        "192.0.2.10",
        "alpha.test",
    )
    return root


def write_json_input(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def evidence(root: Path, tmp_path: Path) -> str:
    source = tmp_path / "scanner-output.txt"
    source.write_bytes(b"synthetic immutable scanner output\n")
    _, _, record = capture_evidence.capture_evidence(
        str(root),
        "H01",
        "scanner",
        "Synthetic scanner evidence",
        "txt",
        str(source),
        now=NOW,
    )
    return record["evidence_id"]


def normalized_items() -> list[dict[str, object]]:
    return [
        {
            "kind": "service",
            "state": "observed",
            "source_tool": "synthetic-batch",
            "note": "TLS service",
            "evidence_ids": [],
            "transport": "tcp",
            "port": 443,
            "service": "https",
        },
        {
            "kind": "endpoint",
            "state": "confirmed",
            "source_tool": "synthetic-batch",
            "note": "Health endpoint",
            "evidence_ids": [],
            "transport": "tcp",
            "port": 443,
            "service": "https",
            "endpoint": "/health",
        },
    ]


def records(root: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (root / "observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_batch_requires_immutable_scanner_evidence(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    input_path = write_json_input(tmp_path, normalized_items())
    before = (root / "observations.jsonl").read_bytes()
    with pytest.raises(observation_import.ObservationImportError, match="evidence"):
        observation_import.import_observations(
            workspace=str(root),
            host_id="H01",
            input_path=input_path,
            input_format="normalized-json",
            evidence_ids=[],
            apply=True,
            now=NOW,
        )
    assert (root / "observations.jsonl").read_bytes() == before


def test_normalized_preview_is_read_only_and_apply_is_deduplicated(
    tmp_path: Path,
) -> None:
    root = workspace(tmp_path)
    input_path = write_json_input(tmp_path, normalized_items())
    evidence_id = evidence(root, tmp_path)
    ledger = root / "observations.jsonl"
    before = ledger.read_bytes()

    preview = observation_import.import_observations(
        workspace=str(root),
        host_id="H01",
        input_path=input_path,
        input_format="normalized-json",
        evidence_ids=[evidence_id],
        apply=False,
        now=NOW,
    )
    assert preview["planned"] == 2
    assert ledger.read_bytes() == before

    applied = observation_import.import_observations(
        workspace=str(root),
        host_id="H01",
        input_path=input_path,
        input_format="normalized-json",
        evidence_ids=[evidence_id],
        apply=True,
        now=NOW,
    )
    assert applied["planned"] == 2
    assert len(records(root)) == 2
    retained = ledger.read_bytes()

    duplicate = observation_import.import_observations(
        workspace=str(root),
        host_id="H01",
        input_path=input_path,
        input_format="normalized-json",
        evidence_ids=[evidence_id],
        apply=True,
        now=NOW,
    )
    assert duplicate["planned"] == 0
    assert duplicate["duplicates"] == 2
    assert ledger.read_bytes() == retained


def test_normalized_batch_is_all_or_none(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    values = normalized_items()
    values.append(
        {
            "kind": "service",
            "state": "observed",
            "source_tool": "synthetic-batch",
            "note": "Invalid late record",
            "evidence_ids": [],
            "transport": "tcp",
            "port": 70000,
            "service": "invalid",
        }
    )
    input_path = write_json_input(tmp_path, values)
    evidence_id = evidence(root, tmp_path)
    ledger = root / "observations.jsonl"
    before = ledger.read_bytes()

    with pytest.raises(observation_import.ObservationImportError, match="observation 3"):
        observation_import.import_observations(
            workspace=str(root),
            host_id="H01",
            input_path=input_path,
            input_format="normalized-json",
            evidence_ids=[evidence_id],
            apply=True,
            now=NOW,
        )
    assert ledger.read_bytes() == before


def test_nmap_xml_selects_the_canonical_interface(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    source = tmp_path / "scan.xml"
    source.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host><address addr="198.51.100.8" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="9999"><state state="open"/></port>
  </ports></host>
  <host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.9"/></port>
    <port protocol="tcp" portid="80"><state state="closed"/></port>
  </ports></host>
</nmaprun>
""",
        encoding="utf-8",
    )
    evidence_id = evidence(root, tmp_path)
    result = observation_import.import_observations(
        workspace=str(root),
        host_id="H01",
        input_path=source,
        input_format="nmap-xml",
        evidence_ids=[evidence_id],
        apply=True,
        now=NOW,
    )
    assert result["planned"] == 1
    [record] = records(root)
    assert record["port"] == 22
    assert record["service"] == "ssh OpenSSH 9.9"


def test_nmap_rejects_declaration_anywhere_without_writing(tmp_path: Path) -> None:
    root = workspace(tmp_path)
    source = tmp_path / "scan.xml"
    source.write_bytes(
        b" " * 5000
        + b'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        + b"<nmaprun/>"
    )
    evidence_id = evidence(root, tmp_path)
    before = (root / "observations.jsonl").read_bytes()
    with pytest.raises(observation_import.ObservationImportError, match="entities"):
        observation_import.import_observations(
            workspace=str(root),
            host_id="H01",
            input_path=source,
            input_format="nmap-xml",
            evidence_ids=[evidence_id],
            apply=True,
            now=NOW,
        )
    assert (root / "observations.jsonl").read_bytes() == before


def test_refresh_failure_does_not_roll_back_canonical_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = workspace(tmp_path)
    input_path = write_json_input(tmp_path, normalized_items())
    evidence_id = evidence(root, tmp_path)

    def fail_refresh(*_args: object, **_kwargs: object) -> None:
        raise host_state.HostStateError("synthetic publication conflict")

    monkeypatch.setattr(host_state, "refresh", fail_refresh)
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = observation_import.main(
            [
                "import",
                "--workspace",
                str(root),
                "--host-id",
                "H01",
                "--input",
                str(input_path),
                "--format",
                "normalized-json",
                "--evidence",
                evidence_id,
                "--apply",
            ]
        )
    assert code == 0
    assert "host_view: stale" in stdout.getvalue()
    assert "host_view_stale" in stderr.getvalue()
    assert len(records(root)) == 2
