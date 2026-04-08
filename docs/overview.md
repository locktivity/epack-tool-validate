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
              - path: $.mfa_enabled
                op: eq
                value: true
```

### Requirement Modes

Requirements can use two clause modes:

- **any_of**: Requirement passes if ANY clause matches (first match wins)
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

### Cardinality for Multi-Value Paths

When using JSONPath expressions that return multiple values (e.g., `$.accounts[*].mfa_enabled`), you must specify how to evaluate them:

```yaml
metadata_conditions:
  all:
    - path: $.accounts[*].mfa_enabled
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
          - path: $.mfa_coverage
            op: gte
            value: 100

    # Severity = graded failure
    - type: evidencepack/idp-posture@v1
      severity: low
      metadata_conditions:
        all:
          - path: $.mfa_coverage
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
              - path: $.mfa_coverage
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
