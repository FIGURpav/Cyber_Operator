"""Build bounded, provenance-rich principal candidates without authenticating."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Any

PLATFORM_CANDIDATES: dict[str, tuple[tuple[str, int, str], ...]] = {
    "linux": (
        ("root", 50, "generic Linux administrative principal"),
        ("admin", 45, "generic Linux administrative principal"),
        ("sysadmin", 40, "generic Linux administrative principal"),
    ),
    "windows": (
        ("Administrator", 55, "built-in Windows administrator principal"),
        ("Admin", 40, "common local Windows administrator alias"),
        ("localadmin", 40, "common local Windows administrator alias"),
        ("cloudbase-init", 35, "common cloudbase-init service principal"),
    ),
    "cloud-linux": (
        ("ec2-user", 65, "common RPM-family cloud image default"),
        ("ubuntu", 65, "Ubuntu cloud image default"),
        ("admin", 60, "Debian cloud image default"),
        ("debian", 60, "Debian cloud image default"),
        ("centos", 55, "CentOS cloud image default"),
        ("rocky", 55, "Rocky Linux cloud image default"),
        ("cloud-user", 55, "RHEL-compatible cloud image default"),
        ("fedora", 50, "Fedora cloud image default"),
        ("opc", 45, "Oracle Cloud Linux image default"),
        ("azureuser", 40, "common configured Azure administrator name"),
    ),
    "aws-linux": (
        ("ec2-user", 75, "common Amazon Linux or RHEL-family AMI default"),
        ("ubuntu", 75, "Ubuntu AMI default"),
        ("admin", 70, "Debian AMI default"),
        ("debian", 70, "Debian AMI default"),
        ("centos", 65, "CentOS AMI default"),
        ("rocky", 65, "Rocky Linux AMI default"),
        ("cloud-user", 65, "RHEL-compatible AMI default"),
        ("fedora", 60, "Fedora AMI default"),
    ),
    "aws-amazon-linux": (
        ("ec2-user", 90, "Amazon Linux AMI default"),
    ),
    "aws-ubuntu": (("ubuntu", 90, "Ubuntu AMI default"),),
    "aws-debian": (
        ("admin", 90, "Debian AMI default"),
        ("debian", 80, "alternate Debian image default"),
    ),
    "aws-rhel": (
        ("ec2-user", 85, "common RHEL AMI default"),
        ("cloud-user", 75, "alternate RHEL cloud image default"),
    ),
    "aws-centos": (
        ("centos", 90, "CentOS AMI default"),
        ("ec2-user", 65, "alternate RPM-family AMI default"),
    ),
    "aws-rocky": (
        ("rocky", 90, "Rocky Linux AMI default"),
        ("ec2-user", 65, "alternate RPM-family AMI default"),
    ),
    "aws-fedora": (("fedora", 90, "Fedora AMI default"),),
    "azure-linux": (("azureuser", 60, "common configured Azure admin name"),),
    "oracle-linux": (("opc", 90, "Oracle Cloud Linux image default"),),
    # GCP has no safe universal SSH username: metadata or OS Login is authoritative.
    "gcp-linux": (),
}


ROLE_CANDIDATES: dict[str, tuple[str, ...]] = {
    "pypi": (
        "pypi",
        "pypiserver",
        "publisher",
        "upload",
        "packages",
        "repo",
        "deploy",
        "builder",
        "build",
        "runner",
        "ci",
        "svc-pypi",
        "svc_pypi",
        "ai-engineering",
    ),
    "ci": (
        "jenkins",
        "gitlab-runner",
        "runner",
        "build",
        "builder",
        "deploy",
        "ci",
        "cicd",
        "svc-ci",
        "svc_ci",
    ),
    "fileserver": (
        "fileserver",
        "fileadmin",
        "backup",
        "svc-files",
        "svc_files",
    ),
    "database": (
        "postgres",
        "mysql",
        "mssql",
        "oracle",
        "dbadmin",
        "svc-db",
        "svc_db",
    ),
    "workstation": ("Administrator", "admin", "localadmin", "support"),
    "model": (
        "ml",
        "mlops",
        "inference",
        "model",
        "ai-engineering",
        "svc-ml",
        "svc_ml",
    ),
    "package-builder": (
        "builder",
        "build",
        "deploy",
        "runner",
        "ci",
        "cicd",
    ),
}


TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PrincipalCandidateError(ValueError):
    """A deterministic principal-candidate input failure."""


@dataclass(frozen=True)
class Candidate:
    """One ranked principal candidate and all reasons it was selected."""

    principal: str
    state: str
    confidence: int
    sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "state": self.state,
            "confidence": self.confidence,
            "sources": list(self.sources),
        }


def _validate_principal(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 256:
        raise PrincipalCandidateError(f"{label} must be nonempty and at most 256 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise PrincipalCandidateError(f"{label} must not contain control characters")
    return normalized


def _validate_token(value: str) -> str:
    normalized = value.strip()
    if TOKEN_RE.fullmatch(normalized) is None:
        raise PrincipalCandidateError(
            "service token must contain only letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _state_rank(state: str) -> int:
    return {"observed": 3, "declared": 2, "inferred": 1}[state]


def build_candidates(
    *,
    observed: tuple[str, ...] = (),
    declared: tuple[str, ...] = (),
    platforms: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
    service_tokens: tuple[str, ...] = (),
    domain: str | None = None,
    upn_suffix: str | None = None,
    include_domain_variants: bool = False,
    maximum: int = 100,
) -> tuple[Candidate, ...]:
    """Return deterministic candidates; this function performs no authentication."""
    if maximum < 1 or maximum > 1000:
        raise PrincipalCandidateError("maximum must be between 1 and 1000")
    unsupported_platforms = sorted(set(platforms) - set(PLATFORM_CANDIDATES))
    unsupported_roles = sorted(set(roles) - set(ROLE_CANDIDATES))
    if unsupported_platforms:
        raise PrincipalCandidateError(
            f"unsupported platform: {', '.join(unsupported_platforms)}"
        )
    if unsupported_roles:
        raise PrincipalCandidateError(f"unsupported role: {', '.join(unsupported_roles)}")
    if domain is not None:
        domain = _validate_principal(domain, "domain")
    if upn_suffix is not None:
        upn_suffix = _validate_principal(upn_suffix, "UPN suffix")
    if include_domain_variants and not (domain or upn_suffix):
        raise PrincipalCandidateError(
            "domain variants require --domain or --upn-suffix"
        )

    entries: dict[str, Candidate] = {}
    order: dict[str, int] = {}

    def add(principal: str, state: str, confidence: int, source: str) -> None:
        principal = _validate_principal(principal, "principal")
        existing = entries.get(principal)
        if existing is None:
            order[principal] = len(order)
            entries[principal] = Candidate(principal, state, confidence, (source,))
            return
        chosen_state = (
            state if _state_rank(state) > _state_rank(existing.state) else existing.state
        )
        entries[principal] = Candidate(
            principal,
            chosen_state,
            max(confidence, existing.confidence),
            tuple(dict.fromkeys((*existing.sources, source))),
        )

    for principal in observed:
        add(principal, "observed", 100, "observed principal")
    for principal in declared:
        add(principal, "declared", 95, "infrastructure or service declaration")
    for platform in platforms:
        for principal, confidence, detail in PLATFORM_CANDIDATES[platform]:
            add(principal, "inferred", confidence, f"platform:{platform}: {detail}")
    for role in roles:
        for principal in ROLE_CANDIDATES[role]:
            add(principal, "inferred", 65, f"role:{role}")
    for raw_token in service_tokens:
        token = _validate_token(raw_token)
        for principal in (token, f"svc-{token}", f"svc_{token}", f"{token}-admin"):
            add(principal, "inferred", 50, f"service-derived:{token}")

    if not entries:
        raise PrincipalCandidateError(
            "at least one observed, declared, platform, role, or service-token input is required"
        )

    if include_domain_variants:
        base_candidates = tuple(entries.values())
        for candidate in base_candidates:
            if "\\" in candidate.principal or "@" in candidate.principal:
                continue
            if domain:
                add(
                    f"{domain}\\{candidate.principal}",
                    candidate.state,
                    candidate.confidence,
                    f"domain-format:{domain}",
                )
            if upn_suffix:
                add(
                    f"{candidate.principal}@{upn_suffix}",
                    candidate.state,
                    candidate.confidence,
                    f"upn-format:{upn_suffix}",
                )

    ranked = sorted(
        entries.values(),
        key=lambda candidate: (-candidate.confidence, order[candidate.principal]),
    )
    return tuple(ranked[:maximum])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate bounded principal candidates with provenance. This command "
            "does not authenticate and grants no authorization."
        )
    )
    parser.add_argument("--observed", action="append", default=[], metavar="PRINCIPAL")
    parser.add_argument("--declared", action="append", default=[], metavar="PRINCIPAL")
    parser.add_argument(
        "--platform",
        action="append",
        default=[],
        choices=sorted(PLATFORM_CANDIDATES),
    )
    parser.add_argument("--role", action="append", default=[], choices=sorted(ROLE_CANDIDATES))
    parser.add_argument("--service-token", action="append", default=[], metavar="TOKEN")
    parser.add_argument("--domain")
    parser.add_argument("--upn-suffix")
    parser.add_argument("--include-domain-variants", action="store_true")
    parser.add_argument("--max-candidates", type=int, default=100)
    parser.add_argument("--format", choices=("table", "json", "lines"), default="table")
    return parser


def _render(candidates: tuple[Candidate, ...], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "schema_version": "1.0",
                "authorization": "not-granted",
                "candidates": [candidate.as_dict() for candidate in candidates],
            },
            indent=2,
            sort_keys=True,
        )
    if output_format == "lines":
        return "\n".join(candidate.principal for candidate in candidates)
    rows = ["confidence\tstate\tprincipal\tprovenance"]
    rows.extend(
        f"{candidate.confidence}\t{candidate.state}\t{candidate.principal}\t"
        f"{' | '.join(candidate.sources)}"
        for candidate in candidates
    )
    rows.append("AUTHORIZATION\tnot-granted\tcandidate generation only")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        candidates = build_candidates(
            observed=tuple(args.observed),
            declared=tuple(args.declared),
            platforms=tuple(args.platform),
            roles=tuple(args.role),
            service_tokens=tuple(args.service_token),
            domain=args.domain,
            upn_suffix=args.upn_suffix,
            include_domain_variants=args.include_domain_variants,
            maximum=args.max_candidates,
        )
    except PrincipalCandidateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render(candidates, args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
