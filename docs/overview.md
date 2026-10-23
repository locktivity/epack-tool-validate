# Overview

`epack-tool-validate` is an epack tool that validates evidence packs against compliance profile YAML files. It evaluates whether the artifacts in a pack satisfy the requirements defined in a profile.

## How It Works

The tool performs validation in several stages:

1. **Profile Resolution**: Determines which profile to use from tool configuration
2. **Profile Loading**: Loads the base profile and any overlay files
3. **Overlay Application**: Merges overlays into the base profile (modify, skip, add)
4. **Profile Compilation**: Validates and compiles the profile into an executable form
5. **Pack Indexing**: Indexes artifacts by their schema for efficient lookup
6. **Validation**: Evaluates each requirement against the indexed artifacts

Run without a pack, the tool stops after compilation and lints the profile instead. See [Linting a Profile](configuration.md#linting-a-profile).

## Profile Structure

Profiles are YAML files that define compliance requirements:

```yaml
id: my-compliance-profile
name: My Compliance Profile
version: "1.0.0"
description: A compliance profile for validation

requirements:
  - id: REQ-001
    name: MFA Required
    control: CC6.2
    category: Access Control
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.policy.mfa_required
                op: eq
                value: true
```

### Requirement Modes

Requirements can use two clause modes:

- **any_of**: Requirement passes if ANY clause passes. Without a pass, an unknown clause leaves the requirement unknown, then the first clause that matched with a severity sets the failure's severity, and otherwise the requirement fails at high
- **all_of**: Requirement passes if ALL clauses match

### Conditions

Conditions use JSONPath expressions to evaluate artifact metadata:

| Operator | Description |
|----------|-------------|
| `eq` | Equals |
| `neq` | Not equals |
| `gt` | Greater than |
| `gte` | Greater than or equal |
| `lt` | Less than |
| `lte` | Less than or equal |
| `exists` | Value exists (not null) |
| `not_exists` | Value does not exist (null) |
| `max_age_days` | ISO date or RFC3339 timestamp is no older than `value` days (date-only values may be up to one day in the future to absorb timezone differences) |

### Cardinality for Multi-Value Paths

When using JSONPath expressions that return multiple values (e.g., `$.accounts[*].iam.root_mfa_enabled`), you must specify how to evaluate them:

```yaml
metadata_conditions:
  all:
    - path: $.accounts[*].iam.root_mfa_enabled
      op: eq
      value: true
      cardinality: all  # ALL values must satisfy the condition
```

| Cardinality | Description |
|-------------|-------------|
| (empty) | Default. Path must return exactly one value |
| `all` | Every value must satisfy the condition |
| `any` | At least one value must satisfy the condition |
| `none` | No value should satisfy the condition |

### Graduated Severity

Clauses can specify a severity level for graded compliance:

```yaml
satisfied_by:
  any_of:
    # No severity = full pass
    - type: evidencepack/idp-posture@v1
      metadata_conditions:
        all:
          - path: $.user_security.mfa_coverage_pct
            op: gte
            value: 100

    # Severity = graded failure
    - type: evidencepack/idp-posture@v1
      severity: low
      metadata_conditions:
        all:
          - path: $.user_security.mfa_coverage_pct
            op: gte
            value: 90
```

### Freshness Checks

Clauses can require artifacts to be recent:

```yaml
- type: evidencepack/vuln-scan@v1
  freshness:
    max_age_days: 30
  metadata_conditions:
    all:
      - path: $.critical_count
        op: eq
        value: 0
```

Use `max_age_days` when the date to check is inside the artifact body rather than the artifact's manifest timestamp:

```yaml
- type: evidencepack/pentest-report@v1
  metadata_conditions:
    all:
      - path: $.metadata.test_date
        op: max_age_days
        value: 365
```

### Applies When

A clause can say when it applies with `applicable_when`. Its conditions take the same `path`, `op`, `value`, and `cardinality` as `metadata_conditions`:

```yaml
- type: evidencepack/cloud-posture@v1
  applicable_when:
    all:
      - path: $.provider
        op: eq
        value: aws
  metadata_conditions:
    all:
      - path: $.accounts[*].iam.root_mfa_enabled
        op: eq
        value: true
        cardinality: all
```

When the conditions are false for an artifact, the clause doesn't apply to it and the artifact is set aside. A clause that applies to none of its type's artifacts reads `not_applicable`. When a value the conditions need is absent, the clause reads `unknown` instead, so missing evidence never makes a clause not applicable. Artifacts too old for the clause's `freshness` are skipped before `applicable_when` is decided.

A clause with `applicable_when` and no `metadata_conditions` passes whenever it applies.

**Each element of a list.** A condition with `cardinality: each` is decided for each element of the list before its `[*]`. Elements it rules out are skipped, and the clause's conditions on that list grade only the elements left:

```yaml
- type: evidencepack/cloud-posture@v1
  applicable_when:
    all:
      - path: $.accounts[*].iam.user_count
        op: gte
        value: 1
        cardinality: each
  metadata_conditions:
    all:
      - path: $.accounts[*].iam.mfa_coverage_pct
        op: gte
        value: 100
        cardinality: all
```

Here an account with no IAM users is skipped. An account whose `user_count` is absent is graded anyway, so it passes only if its own percentage does. When every account is skipped, the clause is not applicable. When the list is absent or empty, the clause is unknown.

**Another artifact type.** With `type`, the conditions read a different artifact type than the clause:

```yaml
- type: evidencepack/mfa-settings-capture@v1
  applicable_when:
    type: evidencepack/cloud-posture@v1
    all:
      - path: $.workforce_sign_in.in_use
        op: eq
        value: true
  metadata_conditions:
    all:
      - path: $.metadata.captured_on
        op: max_age_days
        value: 365
```

The clause applies when the conditions hold on any artifact of that type. It is unknown when they hold on none and are unknown on one, and it doesn't apply when they are false on all of them. A pack with no artifact of that type makes the clause `missing`. The clause's `freshness` doesn't apply to those artifacts.

**Combining.** Clauses that don't apply are set aside before a requirement combines the rest. A requirement where no clause applies reads `not_applicable`. Like a manual requirement, it counts under its own `summary.not_applicable`, never changes the overall status, and is never in `key_failures`.

See [Configuration](configuration.md#applies-when) for the rules a profile has to follow and the `applicable_when` details each check reports.

## Unknown Outcomes

Evaluation is three-valued. A value that is absent from an artifact (a missing
field, an explicit null, an array element without the field, or an empty
result set) cannot pass or fail a comparison: the condition, its clause, and
the requirement score as `unknown` with `failure_kind:
"insufficient_evidence"`, never as a pass or a graded failure. The presence
operators (`exists`, `not_exists`) stay two-valued, since absence is exactly
what they test.

Combination follows the evidence: in `any_of`, a definite pass wins and any
unknown clause otherwise blocks a verdict; in `all_of`, a definite miss fails
the requirement even when other clauses are unknown. In `all_of`, a failed
condition, a stale artifact, or a missing timestamp decides before an artifact
type the pack doesn't have, so missing evidence never hides a failed
comparison. The overall status rolls up as fail over unknown over pass, and
`summary.unknown` counts the requirements that could not be scored. Unknown
requirements never appear in `key_failures`.

## Manual Requirements and Asserted Support

Not every requirement is machine-checkable. A written policy or a signed
agreement has no artifact field to compare, so a requirement can declare
`manual: true` instead of `satisfied_by`. Manual requirements report `status:
"manual"`, count under `summary.manual`, and never affect the overall status;
they are answered by asserted support and human review.

Asserted support comes from control mapping artifacts
(`evidencepack/control-mapping@v1`) sealed into the pack by its publisher.
Each entry maps a requirement to a piece of evidence: an artifact (optionally
a JSON pointer into it) or an indexed document (optionally a quoted passage in
its extracted text). The tool joins entries to the profile's requirements,
resolves each reference against the pack, and reports the results in the
`asserted_support` output section. Any requirement can receive entries, so a
machine-checked requirement shows its computed result and its mapped evidence
side by side.

Mappings are assertions, not verification results. A broken or stale mapping
produces warnings (`MAPPING_UNRESOLVED`, `MAPPING_PROFILE_MISMATCH`,
`INVALID_MAPPING_ENTRY`, `MANUAL_UNSUPPORTED`), never a failure. See
[Configuration](configuration.md#control-mappings) for the join rules,
resolution states, and output shape.

## Output

The tool outputs a `validation.json` file containing:

```json
{
  "status": "pass",
  "profile": {
    "id": "my-compliance-profile",
    "name": "My Compliance Profile",
    "version": "1.0.0",
    "digest": "sha256:abc123..."
  },
  "validated_at": "2024-06-15T12:00:00Z",
  "validated_at_label": "just now",
  "pack_digest": "sha256:def456...",
  "summary": {
    "total": 5,
    "passed": 5,
    "failed": 0,
    "missing": 0,
    "warnings": 0
  },
  "requirements": [
    {
      "id": "REQ-001",
      "name": "MFA Required",
      "control": "CC6.2",
      "category": "Access Control",
      "status": "pass",
      "artifact": "artifacts/idp-posture.json",
      "path": "$.enabled",
      "expected": {"op": "eq", "value": true},
      "actual": true,
      "checks": [
        {
          "clause_index": 0,
          "schema": "evidencepack/idp-posture@v1",
          "status": "pass",
          "artifact": "artifacts/idp-posture.json",
          "conditions": [
            {
              "path": "$.enabled",
              "expected": {"op": "eq", "value": true},
              "actual": true,
              "passed": true
            }
          ]
        }
      ]
    }
  ],
  "by_category": {
    "Access Control": {"passed": 3, "failed": 0, "missing": 0},
    "System Operations": {"passed": 2, "failed": 0, "missing": 0}
  }
}
```

## Overlays

Overlays allow customizing profiles without modifying the original:

```yaml
id: my-overlay
name: Production Overlay

# Modify existing requirements
modify:
  - id: REQ-001
    name: Stricter MFA Requirement
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100

# Skip requirements
skip:
  - REQ-003
  - REQ-004

# Add new requirements
add:
  - id: REQ-NEW
    name: New Requirement
    satisfied_by:
      any_of:
        - type: evidencepack/custom@v1
```

Overlays are applied in order, with last-write-wins semantics.

## Limitations

- **Single Profile (MVP)**: Currently supports one profile per validation run
- **Local Profiles Only**: Profiles must be local files (no remote fetch)
