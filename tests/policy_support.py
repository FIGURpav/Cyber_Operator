"""Synthetic policy metadata for validating bounds; never executes target actions."""

from scripts import engagement_policy


def synthetic_configuration():
    families = sorted(engagement_policy.TECHNIQUE_FAMILY_CATEGORIES)
    return {
        "maximum_impact": "critical",
        "technique_families": families,
        "categories": sorted({category for family in families for category in engagement_policy.TECHNIQUE_FAMILY_CATEGORIES[family]}),
        "credential_operations": "dump-reuse-spray",
        "persistence_mode": "risk-adaptive",
        "allow_security_control_changes": True,
        "allow_destructive": True,
        "allow_bulk_data": True,
    }
