"""Materialize secret-free current-state projections into host and global Markdown."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import (
        credential_intake,
        execution_provenance,
        host_identity,
        operational_trace,
        report_contract,
        restore_checkpoint,
        structured_state,
        token_lifecycle,
        workspace_status,
        workspace_transaction,
    )
else:
    import credential_intake  # type: ignore[no-redef]
    import execution_provenance  # type: ignore[no-redef]
    import host_identity  # type: ignore[no-redef]
    import operational_trace  # type: ignore[no-redef]
    import report_contract  # type: ignore[no-redef]
    import restore_checkpoint  # type: ignore[no-redef]
    import structured_state  # type: ignore[no-redef]
    import token_lifecycle  # type: ignore[no-redef]
    import workspace_status  # type: ignore[no-redef]
    import workspace_transaction  # type: ignore[no-redef]

HOST_START = "<!-- CYBER:HOST-STATE:START -->"
HOST_END = "<!-- CYBER:HOST-STATE:END -->"
GLOBAL_START = "<!-- CYBER:GLOBAL-STATE:START -->"
GLOBAL_END = "<!-- CYBER:GLOBAL-STATE:END -->"
DIGEST_RE = re.compile(r"^- Source digest: `([0-9a-f]{64})`$", re.MULTILINE)
MAX_MARKDOWN = 4 * 1024 * 1024
MAX_ROWS = 40
RENAME_EXCHANGE = 2


class HostStateError(ValueError):
    """A deterministic projection or publication failure."""


def _safe(value: Any, maximum: int = 180) -> str:
    if value is None:
        return "none"
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split()).replace("|", "\\|").replace("`", "'")
    return text[:maximum] if text else "none"


def _read_markdown(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise HostStateError(f"cannot open {path.name}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_MARKDOWN:
            raise HostStateError(f"{path.name} must be a bounded dedicated regular file")
        raw = handle.read(MAX_MARKDOWN + 1)
        after = os.fstat(handle.fileno())
    if len(raw) > MAX_MARKDOWN or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise HostStateError(f"{path.name} changed while being read")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HostStateError(f"{path.name} must be UTF-8") from exc
    return raw, before


def _replace_block(original: str, start: str, end: str, block: str) -> str:
    start_count, end_count = original.count(start), original.count(end)
    if start_count != end_count or start_count > 1:
        raise HostStateError("managed state markers are malformed")
    if start_count:
        left = original.index(start)
        right = original.index(end, left) + len(end)
        updated = original[:left] + block + original[right:]
    else:
        separator = "" if original.endswith("\n\n") else ("\n" if original.endswith("\n") else "\n\n")
        updated = original + separator + block + "\n"
    return updated if updated.endswith("\n") else updated + "\n"


def _rename_exchange(directory_fd: int, left: str, right: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        raise HostStateError("atomic compare-and-swap requires Linux renameat2")
    result = function(directory_fd, left.encode(), directory_fd, right.encode(), RENAME_EXCHANGE)
    if result != 0:
        code = ctypes.get_errno()
        if code in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
            raise HostStateError("atomic compare-and-swap is unavailable")
        raise OSError(code, os.strerror(code))


def _cas_replace(path: Path, expected: bytes, expected_info: os.stat_result, replacement: bytes) -> None:
    restore_checkpoint.require_path_instance(path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp_name: str | None = None
    old_descriptor = -1
    try:
        old_descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        opened = os.fstat(old_descriptor)
        if (opened.st_dev, opened.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise HostStateError(f"{path.name} changed after preview")
        current = os.read(old_descriptor, len(expected) + 1)
        if current != expected:
            raise HostStateError(f"{path.name} changed after preview")
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.state.")
        temp_name = Path(temporary).name
        try:
            os.fchmod(descriptor, stat.S_IMODE(opened.st_mode))
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(replacement)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        current_path = path.lstat()
        if (current_path.st_dev, current_path.st_ino) != (opened.st_dev, opened.st_ino):
            raise HostStateError(f"{path.name} changed before publication")
        _rename_exchange(directory_fd, temp_name, path.name)
        displaced = os.stat(temp_name, dir_fd=directory_fd, follow_symlinks=False)
        if (displaced.st_dev, displaced.st_ino) != (opened.st_dev, opened.st_ino):
            try:
                _rename_exchange(directory_fd, temp_name, path.name)
            except (HostStateError, OSError):
                pass
            raise HostStateError(f"{path.name} compare-and-swap detected a conflicting edit")
        final = path.read_bytes()
        if final != replacement:
            try:
                _rename_exchange(directory_fd, temp_name, path.name)
            except (HostStateError, OSError):
                pass
            raise HostStateError(f"{path.name} publication verification failed")
        os.unlink(temp_name, dir_fd=directory_fd)
        temp_name = None
        os.fsync(directory_fd)
    finally:
        if old_descriptor >= 0:
            os.close(old_descriptor)
        if temp_name is not None:
            # This is either our unpublished replacement or a deliberately preserved
            # conflicting object. Remove only a file still containing our replacement.
            try:
                candidate = path.parent / temp_name
                if candidate.read_bytes() == replacement:
                    candidate.unlink()
            except OSError:
                pass
        os.close(directory_fd)


def _credential_records(
    root: Path, known_host_ids: set[str]
) -> list[dict[str, Any]]:
    handles = credential_intake._open_workspace(str(root))
    try:
        snapshot = credential_intake._read_ledger(
            handles.credentials_fd,
            known_host_ids,
        )
        return list(snapshot.records)
    except credential_intake.CredentialIntakeError as exc:
        raise HostStateError(str(exc)) from exc
    finally:
        handles.close()


def _source_snapshot(root: Path) -> dict[str, Any]:
    try:
        records = host_identity.discover_hosts(root)
        hosts = [record.host_id for record in records]
        host_set = set(hosts)
        merges = host_identity.applied_merges(root)
        raw_aliases = host_identity._resolved_aliases(root)
        history = {record.host_id: record.host_id for record in records}
        history.update(
            (item.source_host_id, item.destination_host_id) for item in merges
        )
        known_host_ids = set(history)
        endpoints = {record.host_id: [record.ip] for record in records}
        merged_ids = {record.host_id: [] for record in records}
        for item in merges:
            if item.source_ip not in endpoints[item.destination_host_id]:
                endpoints[item.destination_host_id].append(item.source_ip)
            merged_ids[item.destination_host_id].append(item.source_host_id)
        aliases = {host: set(raw_aliases.get(host, set())) for host in hosts}
        for source, values in raw_aliases.items():
            canonical_source = history.get(source)
            if canonical_source in aliases:
                aliases[canonical_source].update(values)
        attempts = workspace_status.parse_attempts(root, host_set, host_history=history)
        loot = workspace_status.parse_loot(root, host_set, host_history=history)
        observations = workspace_status.parse_observations(root, host_set, host_history=history)
        evidence = {host: [] for host in hosts}
        evidence_roots = [
            (record.host_id, root / "evidence" / record.storage_key)
            for record in records
        ]
        evidence_roots.extend(
            (
                item.source_host_id,
                root / "evidence" / item.source_storage_key,
            )
            for item in merges
        )
        for owner, directory in evidence_roots:
            canonical_owner = history[owner]
            if not directory.is_dir() or directory.is_symlink():
                continue
            for metadata in sorted(directory.iterdir()):
                if metadata.is_file() and workspace_status.EVIDENCE_FILE_RE.match(
                    metadata.name
                ):
                    evidence[canonical_owner].append(
                        metadata.relative_to(root).as_posix()
                    )
        changes = operational_trace.load_changes(root)
        paths = operational_trace.load_attack_paths(root)
        report_context = report_contract.ValidationContext(root)
        _, all_steps = report_contract.load_steps(root, context=report_context)
        steps = report_contract._effective_step_states(all_steps)
        runs = execution_provenance._load_runs_with_context(
            root, all_steps, report_context, verify_artifacts=False
        )
        claims = execution_provenance._load_claims_with_context(
            root, all_steps, runs, report_context
        )
        known_reference_ids = {
            item["attempt_id"]
            for grouped in attempts.values()
            for item in grouped
        }
        for paths_for_host in evidence.values():
            for relative in paths_for_host:
                match = re.search(r"EVD-\d{8}T\d{12}Z", Path(relative).name)
                if match:
                    known_reference_ids.add(match.group(0))
        known_reference_ids.update(claims)
        findings = structured_state.finding_states(
            root,
            known_host_ids=known_host_ids,
            known_reference_ids=known_reference_ids,
        )
        work_items = structured_state.work_item_states(
            root,
            known_host_ids=known_host_ids,
            known_reference_ids=known_reference_ids,
        )
        local_artifacts = structured_state.local_artifact_states(
            root, known_host_ids=known_host_ids
        )
        credentials = _credential_records(root, known_host_ids)
        token_events = token_lifecycle._load_events(root)
        tokens = token_lifecycle._effective(token_events)
        manifest = report_contract.load_manifest(root, required=False)
    except SystemExit as exc:
        raise HostStateError("canonical host-state source is malformed") from exc
    except (
        host_identity.HostIdentityError,
        operational_trace.TraceError,
        structured_state.StructuredStateError,
        token_lifecycle.TokenLifecycleError,
        report_contract.ReportContractError,
        execution_provenance.ProvenanceError,
    ) as exc:
        raise HostStateError(str(exc)) from exc

    def canonical(value: str) -> str | None:
        return history.get(value)

    changes_by_host = {host: [] for host in hosts}
    for item in changes:
        host = canonical(item["host_id"])
        if host in changes_by_host:
            changes_by_host[host].append(item)
    paths_by_host = {host: [] for host in hosts}
    for item in paths:
        related = {canonical(item["source_host_id"]), canonical(item["destination_host_id"])}
        for host in related & host_set:
            paths_by_host[host].append(item)
    findings_by_host = {host: [] for host in hosts}
    for item in findings.values():
        for host in {canonical(value) for value in item["host_ids"]} & host_set:
            findings_by_host[host].append(item)
    work_by_host = {host: [] for host in hosts}
    for item in work_items.values():
        for host in {canonical(value) for value in item["host_ids"]} & host_set:
            work_by_host[host].append(item)
    credentials_by_host = {host: [] for host in hosts}
    for item in credentials:
        host = canonical(item["host_id"])
        if host in credentials_by_host:
            credentials_by_host[host].append(item)
    tokens_by_host = {host: [] for host in hosts}
    for item in tokens.values():
        host = canonical(item["host_id"])
        if host in tokens_by_host:
            tokens_by_host[host].append(item)
    artifacts_by_host = {host: [] for host in hosts}
    for item in local_artifacts.values():
        for host in {canonical(value) for value in item["host_ids"]} & host_set:
            artifacts_by_host[host].append(item)
    steps_by_host = {host: [] for host in hosts}
    for item in steps.values():
        host = canonical(item["plan"]["host_id"])
        if host in steps_by_host:
            steps_by_host[host].append(item)
    generations_by_host = {host: [] for host in hosts}
    for item in runs.values():
        host = canonical(item["host_id"])
        if host in generations_by_host and item.get("source_generation"):
            generations_by_host[host].append((item["started_at_utc"], item["source_generation"]))
    proof_ids: set[str] = set()
    proofs_by_host = {host: [] for host in hosts}
    if manifest:
        for item in manifest["assessment_objectives"]:
            if item["objective_loot_id"]:
                proof_ids.add(item["objective_loot_id"])
                host = canonical(item["host_id"])
                if host in proofs_by_host:
                    proofs_by_host[host].append({"loot_id": item["objective_loot_id"], "name": item["objective_name"]})
    return {
        "root": root,
        "records": {record.host_id: record for record in records}, "hosts": hosts,
        "history": history,
        "endpoints": {host: tuple(values) for host, values in endpoints.items()},
        "merged_ids": {host: tuple(values) for host, values in merged_ids.items()},
        "aliases": {host: tuple(sorted(values)) for host, values in aliases.items()},
        "attempts": attempts, "loot": loot, "observations": observations,
        "evidence": evidence, "changes": changes_by_host, "paths": paths_by_host,
        "findings": findings_by_host, "work": work_by_host, "credentials": credentials_by_host,
        "tokens": tokens_by_host, "artifacts": artifacts_by_host, "steps": steps_by_host,
        "generations": generations_by_host, "proofs": proofs_by_host, "proof_ids": proof_ids,
        "all_findings": findings, "all_work": work_items, "all_artifacts": local_artifacts,
    }


def _sanitized_host_source(index: dict[str, Any], host: str) -> dict[str, Any]:
    record = index["records"][host]
    observations = [{key: item.get(key) for key in (
        "observation_id", "state", "kind", "transport", "port", "service", "url", "endpoint", "http_status", "evidence_ids"
    )} for item in index["observations"][host]]
    attempts = [{key: item.get(key) for key in ("attempt_id", "status", "action", "next_step", "evidence_refs")} for item in index["attempts"][host]]
    loot = [{key: item.get(key) for key in ("loot_id", "category", "label", "source", "username")} for item in index["loot"][host]]
    credentials = [{key: item.get(key) for key in (
        "credential_id", "secret_type", "username", "service", "url", "realm", "status"
    )} for item in index["credentials"][host]]
    tokens = [{key: item.get(key) for key in (
        "token_id", "service", "principal", "token_kind", "event", "validation_status", "credential_id"
    )} for item in index["tokens"][host]]
    changes = [{key: item.get(key) for key in ("change_id", "event", "category", "target", "description")} for item in index["changes"][host]]
    paths = [{key: item.get(key) for key in (
        "path_event_id", "transition", "status", "source_host_id", "source_identity", "destination_host_id", "destination_identity", "service"
    )} for item in index["paths"][host]]
    findings = [{key: item.get(key) for key in ("finding_id", "state", "severity", "title", "service", "endpoint", "references")} for item in index["findings"][host]]
    work = [{key: item.get(key) for key in ("work_item_id", "kind", "external_ref", "state", "summary", "references")} for item in index["work"][host]]
    artifacts = [{key: item.get(key) for key in ("local_artifact_id", "state", "artifact_class", "purpose", "size_bytes", "sha256")} for item in index["artifacts"][host]]
    return {
        "identity": {"host_id": host, "ip": record.ip, "hostname": record.hostname,
                     "endpoints": index["endpoints"][host],
                     "merged_ids": index["merged_ids"][host],
                     "aliases": index["aliases"][host]},
        "observations": observations, "attempts": attempts, "loot": loot,
        "credentials": credentials, "tokens": tokens, "changes": changes, "paths": paths,
        "findings": findings, "work": work, "artifacts": artifacts,
        "evidence": index["evidence"][host], "proofs": index["proofs"][host],
        "generations": index["generations"][host],
        "steps": [{"step_id": item["plan"]["step_id"], "event": item["transition"]["event"] if item["transition"] else "planned"} for item in index["steps"][host]],
    }


def host_digest(index: dict[str, Any], host: str) -> str:
    return hashlib.sha256(json.dumps(_sanitized_host_source(index, host), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def global_digest(index: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps({host: host_digest(index, host) for host in index["hosts"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _active_changes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    histories = operational_trace.change_histories(items)
    return [history[-1] for history in histories.values() if operational_trace.change_is_active(history)]


def _access(index: dict[str, Any], host: str) -> tuple[str, str]:
    successes = [item for item in index["paths"][host] if item["status"] == "success" and item["destination_host_id"] in {host, *index["merged_ids"][host]}]
    if not successes:
        return "none", "none"
    privilege = [item for item in successes if item["transition"] == "privilege_escalation"]
    selected = (privilege or successes)[-1]
    return _safe(selected["destination_identity"]), _safe(selected["transition"])


def render_host(index: dict[str, Any], host: str, moment: datetime) -> tuple[str, str]:
    digest = host_digest(index, host)
    record = index["records"][host]
    services: dict[tuple[Any, ...], dict[str, Any]] = {}
    endpoints: list[dict[str, Any]] = []
    for item in index["observations"][host]:
        if item["kind"] == "service":
            services[(item["transport"], item["port"], item.get("service"))] = item
        elif item["kind"] in {"endpoint", "http"}:
            endpoints.append(item)
    access, access_kind = _access(index, host)
    active_changes = _active_changes(index["changes"][host])
    negative = [item for item in index["attempts"][host] if item["status"] in {"failed", "blocked", "partial"}]
    successful_paths = [
        item for item in index["paths"][host] if item["status"] == "success"
    ]
    generations = sorted(index["generations"][host])
    lines = [HOST_START, "## Managed current state", "",
        f"- Generated UTC: `{moment.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}`",
        f"- Source digest: `{digest}`", f"- Canonical host: `{host}`",
        f"- Resolved hostname: `{_safe(record.hostname)}`",
        f"- Aliases: `{', '.join(index['aliases'][host]) or 'none'}`",
        f"- Interfaces: `{', '.join(index['endpoints'][host])}`",
        f"- Target generation: `{_safe(generations[-1][1]) if generations else 'not recorded'}`",
        f"- Current access: `{access}` via `{access_kind}`", "", "### Ports and services", ""]
    if services:
        lines.extend(["| Transport | Port | Service | State | Observation |", "|---|---:|---|---|---|"])
        for item in list(services.values())[-MAX_ROWS:]:
            lines.append(f"| {_safe(item['transport'])} | {item['port']} | {_safe(item.get('service'))} | {_safe(item['state'])} | `{item['observation_id']}` |")
    else:
        lines.append("- No structured service observations recorded.")
    lines.extend(["", "### Web and application endpoints", ""])
    if endpoints:
        for item in endpoints[-MAX_ROWS:]:
            location = item.get("url") or item.get("endpoint")
            status = f" status={item['http_status']}" if item.get("http_status") else ""
            lines.append(f"- `{item['observation_id']}` — {_safe(location, 300)}{status} ({_safe(item['state'])})")
    else:
        lines.append("- None recorded.")
    lines.extend(["", "### Access and attack path", ""])
    if successful_paths:
        for item in successful_paths[-MAX_ROWS:]:
            lines.append(
                f"- `{item['path_event_id']}` — {_safe(item['transition'])}: "
                f"{_safe(item['source_host_id'])}/{_safe(item['source_identity'])} -> "
                f"{_safe(item['destination_host_id'])}/{_safe(item['destination_identity'])}; "
                f"service={_safe(item['service'])}"
            )
    else:
        lines.append("- No successful access, privilege, lateral, or pivot events recorded.")
    lines.extend(["", "### High-value outcomes", "",
        f"- Findings: {len(index['findings'][host])}; confirmed: {sum(item['state'] == 'confirmed' for item in index['findings'][host])}",
        f"- Credentials: {len(index['credentials'][host])}; session tokens: {len(index['tokens'][host])}; loot items: {len(index['loot'][host])}",
        f"- Objective proofs: {len(index['proofs'][host])}; report steps: {len(index['steps'][host])}",
        f"- Evidence items: {len(index['evidence'][host])}", ""])
    for item in index["findings"][host][-MAX_ROWS:]:
        lines.append(f"- `{item['finding_id']}` — {_safe(item['severity'])} / {_safe(item['state'])}: {_safe(item['title'], 240)}")
    for item in index["credentials"][host][-MAX_ROWS:]:
        lines.append(f"- `{item['credential_id']}` — {_safe(item['secret_type'])}; principal={_safe(item.get('username'))}; service={_safe(item.get('service'))}; status={_safe(item['status'])}")
    for item in index["tokens"][host][-MAX_ROWS:]:
        lines.append(f"- `{item['token_id']}` — {_safe(item['token_kind'])}; service={_safe(item['service'])}; state={_safe(item['event'])}")
    for item in index["proofs"][host]:
        lines.append(f"- `{item['loot_id']}` — objective proof recorded: {_safe(item['name'])}")
    lines.extend(["", "### Work and recon", ""])
    if index["work"][host]:
        for item in index["work"][host][-MAX_ROWS:]:
            lines.append(f"- `{item['work_item_id']}` — {_safe(item['kind'])} `{_safe(item['external_ref'])}`: {_safe(item['state'])} — {_safe(item['summary'], 240)}")
    else:
        lines.append("- No structured work or recon items recorded.")
    lines.extend(["", "### Persistence, cleanup, and local processing", "",
        f"- Active/retained target changes: {len(active_changes)}", f"- Managed local artifacts: {len(index['artifacts'][host])}"])
    for item in active_changes[-MAX_ROWS:]:
        lines.append(f"- `{item['change_id']}` — {_safe(item['event'])}: {_safe(item['description'], 240)}")
    for item in index["artifacts"][host][-MAX_ROWS:]:
        lines.append(f"- `{item['local_artifact_id']}` — {_safe(item['artifact_class'])}: {_safe(item['state'])}; {_safe(item['purpose'], 240)}")
    lines.extend(["", "### Attempts and material negative results", "",
        f"- Attempts: {len(index['attempts'][host])}; negative/partial: {len(negative)}"])
    for item in negative[-10:]:
        lines.append(f"- `{item['attempt_id']}` — {_safe(item['status'])}: {_safe(item['action'], 240)}; next={_safe(item['next_step'], 240)}")
    lines.extend(["", "### Evidence references", ""])
    for relative in index["evidence"][host][-20:]:
        label = Path(relative).name
        lines.append(f"- [{_safe(label, 240)}](../{relative})")
    if not index["evidence"][host]:
        lines.append("- None recorded.")
    lines.extend(["", HOST_END])
    content = "\n".join(lines)
    try:
        operational_trace._reject_secret_content(record.path.parents[1], [content])
    except operational_trace.TraceError as exc:
        raise HostStateError(str(exc)) from exc
    return content, digest


def render_global(index: dict[str, Any], moment: datetime) -> tuple[str, str]:
    digest = global_digest(index)
    work = list(index["all_work"].values())
    findings = list(index["all_findings"].values())
    artifacts = list(index["all_artifacts"].values())
    active_changes = sum(len(_active_changes(index["changes"][host])) for host in index["hosts"])
    compromised = 0
    pe_hosts = 0
    rows: list[str] = []
    for host in index["hosts"]:
        access, access_kind = _access(index, host)
        if access != "none":
            compromised += 1
        if access_kind == "privilege_escalation":
            pe_hosts += 1
        services = sorted({f"{item['port']}/{item['transport']}:{_safe(item.get('service'), 32)}" for item in index["observations"][host] if item["kind"] == "service"})
        rows.append(f"| `{host}` | {_safe(', '.join(index['endpoints'][host]), 120)} | {_safe(', '.join(services[:8]), 180)} | {_safe(access)} | {len(index['findings'][host])} | {len(index['credentials'][host]) + len(index['tokens'][host])} | {len(_active_changes(index['changes'][host]))} |")
    recon = [item for item in work if item["kind"] == "recon"]
    lines = [GLOBAL_START, "## Managed assessment status", "",
        f"- Generated UTC: `{moment.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}`",
        f"- Source digest: `{digest}`", f"- Hosts: {len(index['hosts'])}; compromised: {compromised}; PE hosts: {pe_hosts}",
        f"- Findings: {len(findings)}; confirmed: {sum(item['state'] == 'confirmed' for item in findings)}",
        f"- Tasks locally complete: {sum(item['kind'] == 'assessment-task' and item['state'] == 'locally_complete' for item in work)}; reviewed: {sum(item['kind'] == 'assessment-task' and item['state'] == 'reviewed' for item in work)}",
        f"- Recon items: {len(recon)}; open/blocked: {sum(item['state'] not in {'locally_complete', 'reviewed'} for item in recon)}",
        f"- Credentials/tokens: {sum(len(index['credentials'][host]) + len(index['tokens'][host]) for host in index['hosts'])}",
        f"- Objective proofs: {sum(len(index['proofs'][host]) for host in index['hosts'])}",
        f"- Active/retained changes: {active_changes}; managed local artifacts: {len(artifacts)}", "",
        "| Host | Interfaces | Confirmed/observed services | Highest access | Findings | Credentials/tokens | Active changes |",
        "|---|---|---|---|---:|---:|---:|", *rows, "", "### Immediate gaps and priorities", ""]
    for item in [item for item in work if item["state"] in {"identified", "in_progress", "blocked"}][-MAX_ROWS:]:
        lines.append(f"- `{item['work_item_id']}` — {_safe(item['kind'])} `{_safe(item['external_ref'])}`: {_safe(item['state'])} — {_safe(item['summary'], 240)}")
    if not any(item["state"] in {"identified", "in_progress", "blocked"} for item in work):
        lines.append("- No structured open work items.")
    lines.extend(["", GLOBAL_END])
    content = "\n".join(lines)
    try:
        operational_trace._reject_secret_content(index["root"], [content])
    except operational_trace.TraceError as exc:
        raise HostStateError(str(exc)) from exc
    return content, digest


def view_status(workspace: str | Path, *, index: dict[str, Any] | None = None) -> dict[str, str]:
    root = operational_trace.validate_workspace(workspace)
    source = index or _source_snapshot(root)
    result: dict[str, str] = {}
    for host in source["hosts"]:
        path = source["records"][host].path
        raw, _ = _read_markdown(path)
        text = raw.decode()
        if text.count(HOST_START) != 1 or text.count(HOST_END) != 1:
            result[host] = "malformed" if HOST_START in text or HOST_END in text else "stale"
            continue
        match = DIGEST_RE.search(text[text.index(HOST_START):text.index(HOST_END)])
        result[host] = "current" if match and match.group(1) == host_digest(source, host) else "stale"
    raw, _ = _read_markdown(root / "global.md")
    text = raw.decode()
    if text.count(GLOBAL_START) != 1 or text.count(GLOBAL_END) != 1:
        result["global"] = "malformed" if GLOBAL_START in text or GLOBAL_END in text else "stale"
    else:
        match = DIGEST_RE.search(text[text.index(GLOBAL_START):text.index(GLOBAL_END)])
        result["global"] = "current" if match and match.group(1) == global_digest(source) else "stale"
    return result


def _refresh_once(
    root: Path,
    *,
    host_id: str | None,
    refresh_all: bool,
    apply: bool,
    now: datetime | None,
) -> dict[str, Any]:
    index = _source_snapshot(root)
    if refresh_all == (host_id is not None):
        raise HostStateError("select exactly one of --host-id or --all")
    if host_id is not None:
        if host_identity.HOST_ID_RE.fullmatch(host_id) is None:
            raise HostStateError("invalid canonical host ID")
        host_id = index["history"].get(host_id)
        if host_id not in index["records"]:
            raise HostStateError("host selector does not match a registered host")
        selected = [host_id]
    else:
        selected = list(index["hosts"])
    moment = now or datetime.now(UTC)
    plans: list[tuple[Path, bytes, os.stat_result, bytes, str]] = []
    for host in selected:
        path = index["records"][host].path
        raw, info = _read_markdown(path)
        block, digest = render_host(index, host, moment)
        updated = _replace_block(raw.decode(), HOST_START, HOST_END, block).encode()
        plans.append((path, raw, info, updated, digest))
    global_path = root / "global.md"
    raw, info = _read_markdown(global_path)
    block, digest = render_global(index, moment)
    plans.append(
        (
            global_path,
            raw,
            info,
            _replace_block(raw.decode(), GLOBAL_START, GLOBAL_END, block).encode(),
            digest,
        )
    )
    if apply:
        lock_path = root / ".host_state.lock"
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            for path, expected, expected_info, replacement, _ in plans:
                _cas_replace(path, expected, expected_info, replacement)
        finally:
            os.close(descriptor)
    return {
        "hosts": selected,
        "global": True,
        "mode": "APPLY" if apply else "PREVIEW",
        "digests": {path.name: digest for path, _, _, _, digest in plans},
    }


def refresh(
    workspace: str | Path,
    *,
    host_id: str | None,
    refresh_all: bool,
    apply: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    root = operational_trace.validate_workspace(workspace)
    if apply:
        # Hold the canonical writer lease before the one command-local source read.
        # Cooperating appenders cannot change a ledger until publication completes;
        # CAS still protects manual Markdown bytes outside that coordination plane.
        with workspace_transaction.write_guard(root):
            return _refresh_once(
                root,
                host_id=host_id,
                refresh_all=refresh_all,
                apply=True,
                now=now,
            )
    return _refresh_once(
        root,
        host_id=host_id,
        refresh_all=refresh_all,
        apply=False,
        now=now,
    )


def best_effort_refresh(
    workspace: str | Path,
    host_ids: list[str] | tuple[str, ...] | set[str],
) -> bool:
    """Refresh affected projections without changing the canonical write outcome."""
    selected = sorted(set(host_ids))
    if not selected:
        return True
    try:
        if len(selected) == 1:
            refresh(
                workspace,
                host_id=selected[0],
                refresh_all=False,
                apply=True,
            )
        else:
            refresh(workspace, host_id=None, refresh_all=True, apply=True)
    except Exception:  # noqa: BLE001 - projection failure must not roll back source state
        return False
    return True


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyber-host-state")
    parser.add_argument("--workspace", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host-id")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = refresh(args.workspace, host_id=args.host_id, refresh_all=args.all, apply=args.apply)
        print(f"mode: {result['mode']}")
        print(f"hosts: {','.join(result['hosts'])}")
        print("global: refreshed" if args.apply else "global: planned")
        return 0
    except (
        HostStateError, operational_trace.TraceError, workspace_transaction.TransactionError,
        restore_checkpoint.RestoreError, OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
