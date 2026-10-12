# Reporting contract

Managed configurations specify `report_contract` explicitly. The web template
requires `engagement`; report readiness cannot be weakened with an ad hoc CLI override.
Operational profiles remain a legacy fallback only. Configuration objectives record
assessment intent; report-manifest objectives bind evidence to hosts. This release
does not automatically synchronize or redesign report-manifest objectives.

`engagement_manifest.json` uses schema `2.0`. Its top-level fields are:

| Field | Meaning |
|---|---|
| `schema_version` | Literal `2.0` |
| `report_id` | Canonical `RPT-...` identifier |
| `assessment_team` | `team_id` and display `name` |
| `engagement` | `engagement_date`, `scope_version`, credential-free HTTPS `scope_url`, UTC `approved_at_utc` |
| `chains` | Optional groupings with `chain_id`, `entry_host_id`, `host_ids` |
| `assessment_objectives` | Non-empty objective list tied to canonical hosts |

Each objective contains `host_id`, nullable `chain_id`, `category` (`application`,
`infrastructure` or `identity`), `objective_name` and nullable `objective_loot_id`.
The proof reference uses the existing canonical record identifier; its host and
label must match the declared objective. There are no points, scoring table or
candidate identifier. One objective record per host is supported in this version.

Completed objective steps retain `resulting_objective_loot_id`. Evidence, attempts,
queries, receipts and atomic claims retain their canonical identifiers and integrity
checks. Readiness requires objective coverage, matching proof, supported claims,
reviewed screenshots where required and complete query provenance. Missing proof
remains a blocker; it is never synthesized by the model.

Findings separately record severity, impact, remediation, references and state.
Reports should present scope, limitations, confirmed findings, business impact,
remediation and retest disposition. Unverified assertions stay explicitly unsupported.
Sensitive values are excluded from ordinary reporting; explicit private export is
separately controlled.

The report schema changed in 0.2.0 and remains 2.0 in 0.3.0. Private archives are not
automatically rewritten. Configuration adoption requires explicit preview and does
not migrate older report schemas or promote historical authorization records.
