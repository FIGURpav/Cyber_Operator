"""Batch-import normalized JSON or bounded Nmap XML into observations.jsonl."""

from __future__ import annotations

import argparse
import stat
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

if __package__:
    from . import host_identity, host_state, ledger_io, log_observation
else:
    import host_identity  # type: ignore[no-redef]
    import host_state  # type: ignore[no-redef]
    import ledger_io  # type: ignore[no-redef]
    import log_observation  # type: ignore[no-redef]

FORMATS = ("normalized-json", "nmap-xml")
MAX_INPUT = 16 * 1024 * 1024
MAX_ITEMS = 4096
NORMALIZED_FIELDS = {
    "kind", "state", "source_tool", "note", "evidence_ids", "transport",
    "port", "service", "url", "endpoint", "http_status",
}


class ObservationImportError(ValueError):
    """A deterministic batch observation import failure."""


def _read_input(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObservationImportError("input file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
        raise ObservationImportError("input must be a bounded real regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT:
        raise ObservationImportError("input exceeds its size limit")
    return raw


def _normalized(raw: bytes, evidence_ids: list[str]) -> list[dict[str, Any]]:
    try:
        value = ledger_io.loads_json(raw)
    except ledger_io.LedgerIOError as exc:
        raise ObservationImportError("normalized JSON is invalid") from exc
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise ObservationImportError("normalized JSON must contain 1..4096 observations")
    result: list[dict[str, Any]] = []
    for number, item in enumerate(value, start=1):
        if not isinstance(item, dict) or not set(item).issubset(NORMALIZED_FIELDS):
            raise ObservationImportError(f"normalized observation {number} has unsupported fields")
        merged = dict(item)
        supplied = merged.get("evidence_ids", [])
        if not isinstance(supplied, list) or any(not isinstance(entry, str) for entry in supplied):
            raise ObservationImportError(f"normalized observation {number} has invalid evidence_ids")
        merged["evidence_ids"] = sorted({*evidence_ids, *supplied})
        result.append(merged)
    return result


def _nmap(raw: bytes, root: Path, host_id: str, evidence_ids: list[str]) -> list[dict[str, Any]]:
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ObservationImportError("Nmap XML declarations and entities are not accepted")
    try:
        document = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ObservationImportError("Nmap XML is malformed") from exc
    if document.tag != "nmaprun":
        raise ObservationImportError("input is not an Nmap XML document")
    endpoints = set(host_identity.host_endpoints(root, host_id))
    matches = []
    for host in document.findall("host"):
        addresses = {
            item.get("addr") for item in host.findall("address")
            if item.get("addrtype") in {"ipv4", "ipv6"} and item.get("addr")
        }
        if addresses & endpoints:
            matches.append(host)
    if len(matches) != 1:
        raise ObservationImportError(
            "Nmap XML must contain exactly one host matching a canonical interface"
        )
    result: list[dict[str, Any]] = []
    for port in matches[0].findall("./ports/port"):
        protocol, port_text = port.get("protocol"), port.get("portid")
        if protocol not in {"tcp", "udp"} or not port_text or not port_text.isdecimal():
            continue
        state_element = port.find("state")
        port_state = state_element.get("state") if state_element is not None else "unknown"
        if port_state not in {"open", "open|filtered"}:
            continue
        service_element = port.find("service")
        pieces: list[str] = []
        if service_element is not None:
            for field in ("name", "product", "version", "extrainfo"):
                value = service_element.get(field)
                if value:
                    pieces.append(value)
        service = " ".join(pieces)[: log_observation.SERVICE_MAX_LEN] or None
        note = f"Nmap reported port state {port_state}"
        result.append({
            "kind": "service", "state": "observed", "source_tool": "nmap-xml",
            "note": note, "evidence_ids": list(evidence_ids), "transport": protocol,
            "port": int(port_text), "service": service, "url": None, "endpoint": None,
            "http_status": None,
        })
    if not result:
        raise ObservationImportError("Nmap XML has no open services for the selected host")
    if len(result) > MAX_ITEMS:
        raise ObservationImportError("Nmap XML yields too many observations")
    return result


def _normalize_batch(
    workspace: str, host_id: str, candidates: list[dict[str, Any]]
) -> tuple[Path, Path, list[dict[str, Any]]]:
    normalized: list[dict[str, Any]] = []
    root: Path | None = None
    ledger: Path | None = None
    for number, item in enumerate(candidates, start=1):
        missing = [name for name in ("kind", "state", "source_tool", "note", "evidence_ids") if name not in item]
        if missing:
            raise ObservationImportError(
                f"observation {number} is missing: {', '.join(missing)}"
            )
        try:
            current_root, current_ledger, data = log_observation.normalize_observation(
                workspace=workspace, host_id=host_id, kind=item["kind"], state=item["state"],
                source_tool=item["source_tool"], note=item["note"], evidence_ids=item["evidence_ids"],
                transport=item.get("transport"), port=item.get("port"), service=item.get("service"),
                url=item.get("url"), endpoint=item.get("endpoint"), http_status=item.get("http_status"),
            )
        except SystemExit as exc:
            raise ObservationImportError(f"observation {number} failed canonical validation") from exc
        if root is not None and (root, ledger) != (current_root, current_ledger):
            raise ObservationImportError("batch observations resolve to different ledgers")
        root, ledger = current_root, current_ledger
        normalized.append(data)
    assert root is not None and ledger is not None
    return root, ledger, normalized


def _records(
    ledger: Path, normalized: list[dict[str, Any]], moment: datetime
) -> tuple[list[dict[str, Any]], int]:
    try:
        existing = log_observation._read_existing_records(ledger)
    except SystemExit as exc:
        raise ObservationImportError("existing observations ledger is invalid") from exc
    known_keys = {item["observation_key"] for item in existing}
    known_ids = {item["observation_id"] for item in existing}
    result: list[dict[str, Any]] = []
    duplicates = 0
    for data in normalized:
        key = log_observation.build_observation_key(data)
        if key in known_keys:
            duplicates += 1
            continue
        allocated = None
        for offset in range(MAX_ITEMS + 1):
            candidate = moment + timedelta(microseconds=len(result) + offset)
            identifier = log_observation.build_observation_id(candidate)
            if identifier not in known_ids:
                allocated = candidate
                break
        if allocated is None:
            raise ObservationImportError("could not allocate a unique observation ID")
        identifier = log_observation.build_observation_id(allocated)
        record = {
            "observation_id": identifier,
            "created_at_utc": allocated.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            **data,
            "observation_key": key,
        }
        result.append({field: record[field] for field in log_observation.FIELD_ORDER})
        known_keys.add(key)
        known_ids.add(identifier)
    return result, duplicates


def import_observations(
    *, workspace: str, host_id: str, input_path: Path, input_format: str,
    evidence_ids: list[str], apply: bool, now: datetime | None = None,
) -> dict[str, Any]:
    if input_format not in FORMATS:
        raise ObservationImportError("unsupported observation import format")
    if not evidence_ids:
        raise ObservationImportError(
            "batch observation import requires immutable scanner evidence"
        )
    raw = _read_input(input_path)
    root = log_observation.validate_workspace(workspace, host_id)[0]
    candidates = (
        _normalized(raw, evidence_ids)
        if input_format == "normalized-json"
        else _nmap(raw, root, host_id, evidence_ids)
    )
    root, ledger, normalized = _normalize_batch(workspace, host_id, candidates)
    moment = now or datetime.now(UTC)
    records, duplicates = _records(ledger, normalized, moment)
    if apply:
        try:
            with ledger_io.exclusive_ledger_lock(ledger):
                re_root, re_ledger, re_normalized = _normalize_batch(workspace, host_id, candidates)
                if (re_root, re_ledger) != (root, ledger):
                    raise ObservationImportError("observation destination changed after preview")
                records, duplicates = _records(ledger, re_normalized, moment)
                ledger_io.append_json_records(
                    ledger, records, create=True, maximum_record_bytes=64 * 1024,
                    maximum_total_bytes=16 * 1024 * 1024,
                )
        except ledger_io.LedgerIOError as exc:
            raise ObservationImportError(str(exc)) from exc
    return {
        "workspace": root, "host_id": host_id, "planned": len(records),
        "duplicates": duplicates, "mode": "APPLY" if apply else "PREVIEW",
    }


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyber-observe")
    sub = parser.add_subparsers(dest="command", required=True)
    importing = sub.add_parser("import")
    importing.add_argument("--workspace", required=True)
    importing.add_argument("--host-id", required=True)
    importing.add_argument("--input", type=Path, required=True)
    importing.add_argument("--format", choices=FORMATS, required=True)
    importing.add_argument("--evidence", action="append", default=[])
    importing.add_argument("--no-refresh", action="store_true")
    importing.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = import_observations(
            workspace=args.workspace, host_id=args.host_id, input_path=args.input,
            input_format=args.format, evidence_ids=args.evidence, apply=args.apply,
        )
        print(f"mode: {result['mode']}")
        print(f"host_id: {result['host_id']}")
        print(f"observations: {result['planned']}")
        print(f"duplicates: {result['duplicates']}")
        if args.apply and not args.no_refresh:
            if host_state.best_effort_refresh(result["workspace"], [args.host_id]):
                print("host_view: current")
            else:
                print("warning: host_view_stale", file=sys.stderr)
                print("host_view: stale")
        elif args.apply:
            print("host_view: not-requested")
        else:
            print("host_view: planned")
        return 0
    except (ObservationImportError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
