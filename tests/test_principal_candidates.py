"""Synthetic tests for bounded context-aware principal expansion."""

from __future__ import annotations

import json

import pytest

from scripts import principal_candidates
from scripts.principal_candidates import PrincipalCandidateError


def by_name(
    candidates: tuple[principal_candidates.Candidate, ...],
) -> dict[str, principal_candidates.Candidate]:
    return {candidate.principal: candidate for candidate in candidates}


def test_observed_and_declared_principals_rank_before_inferences() -> None:
    candidates = principal_candidates.build_candidates(
        observed=("known.user",),
        declared=("deploy-user",),
        platforms=("aws-linux",),
        roles=("pypi",),
    )

    assert [candidate.principal for candidate in candidates[:2]] == [
        "known.user",
        "deploy-user",
    ]
    assert candidates[0].state == "observed"
    assert candidates[1].state == "declared"
    assert by_name(candidates)["ec2-user"].state == "inferred"
    assert by_name(candidates)["pypiserver"].state == "inferred"


def test_exact_image_family_produces_small_high_confidence_set() -> None:
    candidates = principal_candidates.build_candidates(platforms=("aws-debian",))

    assert [(item.principal, item.confidence) for item in candidates] == [
        ("admin", 90),
        ("debian", 80),
    ]


def test_duplicate_candidate_merges_provenance_and_keeps_best_state() -> None:
    candidates = principal_candidates.build_candidates(
        declared=("builder",),
        roles=("pypi", "package-builder"),
    )
    candidate = by_name(candidates)["builder"]

    assert candidate.state == "declared"
    assert candidate.confidence == 95
    assert candidate.sources == (
        "infrastructure or service declaration",
        "role:pypi",
        "role:package-builder",
    )


def test_service_token_derives_bounded_role_forms() -> None:
    candidates = principal_candidates.build_candidates(service_tokens=("artifact",))

    assert [candidate.principal for candidate in candidates] == [
        "artifact",
        "svc-artifact",
        "svc_artifact",
        "artifact-admin",
    ]


def test_domain_variants_are_explicit_and_retain_state() -> None:
    candidates = principal_candidates.build_candidates(
        observed=("test.user",),
        domain="EXAMPLE",
        upn_suffix="example.test",
        include_domain_variants=True,
    )
    indexed = by_name(candidates)

    assert indexed["EXAMPLE\\test.user"].state == "observed"
    assert indexed["test.user@example.test"].state == "observed"


def test_gcp_does_not_invent_a_universal_default_user() -> None:
    with pytest.raises(PrincipalCandidateError, match="at least one"):
        principal_candidates.build_candidates(platforms=("gcp-linux",))


def test_invalid_service_token_and_missing_domain_are_rejected() -> None:
    with pytest.raises(PrincipalCandidateError, match="service token"):
        principal_candidates.build_candidates(service_tokens=("bad token",))
    with pytest.raises(PrincipalCandidateError, match="domain variants"):
        principal_candidates.build_candidates(
            observed=("operator",), include_domain_variants=True
        )


def test_maximum_caps_ranked_output() -> None:
    candidates = principal_candidates.build_candidates(
        observed=("known.user",), platforms=("aws-linux",), maximum=3
    )

    assert len(candidates) == 3
    assert candidates[0].principal == "known.user"


def test_cli_json_is_machine_readable_and_explicitly_non_authorizing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = principal_candidates.main(
        ["--platform", "aws-amazon-linux", "--role", "pypi", "--format", "json"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["authorization"] == "not-granted"
    assert payload["candidates"][0]["principal"] == "ec2-user"


def test_cli_returns_error_without_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    code = principal_candidates.main([])

    assert code == 1
    assert "at least one" in capsys.readouterr().err
