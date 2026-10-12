"""Validate operator-supplied engagement metadata and initialize a blank workspace."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

if __package__:
    from . import (
        engagement_config,
        operational_profile,
        remote_storage,
        task_collection,
    )
else:
    import engagement_config
    import operational_profile
    import remote_storage
    import task_collection

FIELDS = {
    "name", "team_id", "operator_id", "reviewer_id", "scope_reference",
    "in_scope", "excluded", "starts_at", "ends_at", "maximum_risk",
    "stop_conditions", "classification", "retention_days", "callback_cidrs",
    "callback_ports", "profile", "artifact_handling", "remote_storage",
    "remote_location", "remote_approval",
}


def validate(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("intake must contain exactly the documented fields")
    for key in FIELDS - {"in_scope", "excluded", "retention_days", "callback_cidrs", "callback_ports", "scope_reference"}:
        text = value[key]
        if not isinstance(text, str) or not text.strip() or len(text) > 2048 or any(ord(c) < 32 for c in text):
            raise ValueError(f"{key} must be bounded single-line text")
    task_collection.validate_module_name(value["name"])
    operational_profile.validate_profile(value["profile"])
    if value["artifact_handling"] not in {"standard", "no-download"}:
        raise ValueError("artifact_handling must be standard or no-download")
    if value["maximum_risk"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("maximum_risk must be low, medium, high or critical")
    if value["classification"] not in {"internal", "confidential", "restricted"}:
        raise ValueError("classification must be internal, confidential or restricted")
    if type(value["retention_days"]) is not int or not 1 <= value["retention_days"] <= 3650:
        raise ValueError("retention_days must be between 1 and 3650")
    for key in ("in_scope", "excluded", "callback_cidrs"):
        items = value[key]
        if not isinstance(items, list) or len(items) > 1000 or any(not isinstance(x, str) or not x.strip() or len(x) > 1024 or any(ord(c) < 32 for c in x) for x in items):
            raise ValueError(f"{key} must be a bounded list of non-empty strings")
    if not value["in_scope"]:
        raise ValueError("in_scope must not be empty")
    starts = datetime.fromisoformat(value["starts_at"])
    ends = datetime.fromisoformat(value["ends_at"])
    if starts.utcoffset() is None or ends.utcoffset() is None or ends <= starts:
        raise ValueError("time window requires timezone-aware dates in ascending order")
    for cidr in value["callback_cidrs"]:
        ipaddress.ip_network(cidr, strict=True)
    ports = value["callback_ports"]
    if not isinstance(ports, list) or len(ports) > 65535 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("callback_ports must be a list of ports from 1 to 65535")
    if bool(value["callback_cidrs"]) != bool(ports):
        raise ValueError("callback CIDRs and ports must both be specified or both empty")
    remote_storage.Settings(value["remote_storage"], value["remote_location"], value["remote_approval"]).validate()
    return {**value, "scope_reference": engagement_config.optional_reference(value["scope_reference"], "scope_reference")}


def normalize(intake: object, template_id: str = "standard-assessment") -> dict:
    if isinstance(intake, dict) and "schema_version" in intake:
        return engagement_config.validate(intake)
    if isinstance(intake, dict) and set(intake) == FIELDS:
        legacy = validate(intake)
        facts = {key: value for key, value in legacy.items() if key not in {"profile", "maximum_risk"}}
        facts["maximum_impact"] = legacy["maximum_risk"]
        facts["report_contract"] = "engagement" if legacy["profile"] == "controlled-engagement" or template_id == "pentest-web-app-standard" else "operational"
        return engagement_config.draft(legacy["name"], template_id, facts)
    if isinstance(intake, dict) and "name" in intake:
        return engagement_config.draft(intake["name"], template_id, intake)
    raise ValueError("intake requires a named draft or a complete engagement definition")


def initialize(root: Path, intake: object, *, apply: bool = False, template_id: str = "standard-assessment") -> Path:
    value = normalize(intake, template_id)
    repository = Path(__file__).resolve().parent.parent
    resolved = root.expanduser().resolve()
    if resolved == repository or repository in resolved.parents:
        raise ValueError("private workspace collection must be outside the repository")
    remote = remote_storage.Settings(value["remote_storage"], value["remote_location"], value["remote_approval"])
    # The collection must be explicitly prepared by the operator; preview creates nothing.
    plan = task_collection.build_module_plan(resolved, value["name"], "strict", "chat", value["artifact_handling"], remote)
    engagement_config.render_context(task_collection.render_task_context(value["name"], "strict", "chat", value["artifact_handling"], resolved, remote), value)
    if plan.exists:
        raise ValueError("intake only initializes a new workspace; existing records are never overwritten")
    if apply:
        # Publish metadata as part of the same staging-and-rename bootstrap as context.
        task_collection.apply_module_plan(plan, Path(__file__).resolve().parent, engagement_definition=value)
    return plan.destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--input", required=True, help="operator-reviewed JSON intake; no secrets")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--template", choices=engagement_config.TEMPLATES, default="standard-assessment")
    args = parser.parse_args(argv)
    try:
        path = Path(args.input)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
            raise ValueError("intake input must be a regular bounded JSON file")
        value = normalize(engagement_config.read_input(path), args.template)
        destination = initialize(Path(args.root), value, apply=args.apply)
        print(json.dumps({"mode": "APPLY" if args.apply else "PREVIEW", "workspace": str(destination), "definition": value, "missing": engagement_config.missing(value), "configuration_approved": False}, indent=2))
        return 0
    except (ValueError, OSError, task_collection.CollectionError, operational_profile.OperationalProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
