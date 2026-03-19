# Configuration

`epack-tool-validate` requires a compliance profile to validate against. The profile path is specified in the tool configuration.

## Tool Requirements

| Requirement | Value |
|-------------|-------|
| Requires Pack | Yes |
| Network Access | No |

## Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `profile` | string | Yes* | Path to a single profile YAML file |
| `profiles` | []string | Yes* | List of profile paths (MVP: only one supported) |
| `overlays` | []string | No | List of overlay YAML files to apply |

*Either `profile` or `profiles` must be specified. If both are provided, `profiles` takes precedence.

## Usage

### Via epack Build

Add to your build configuration:

```yaml
# epack.yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config:
      profile: profiles/security-policy.yaml
```

### With Overlays

Apply environment-specific customizations:

```yaml
# epack.yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config:
      profile: profiles/security-policy.yaml
      overlays:
        - profiles/overlays/production.yaml
        - profiles/overlays/us-region.yaml
```

## Profile File Format

Profiles are YAML files with the following structure:

```yaml
id: my-security-profile           # Unique identifier
name: My Security Profile         # Human-readable name
version: "1.0.0"                  # Semantic version
description: Example profile      # Optional description

requirements:
  - id: REQ-001                   # Unique requirement ID
    name: Access Control Policy   # Requirement name
    control: CC6.1                # Optional control reference
    category: Access Control      # Optional category for grouping
    satisfied_by:
      any_of:                     # OR: any clause can satisfy
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:                  # AND: all conditions must match
              - path: $.has_access_policy
                op: eq
                value: true
```

### Clause Options

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Required. Artifact schema to match (e.g., `evidencepack/idp-posture@v1`) |
| `severity` | string | Optional. Failure severity: `critical`, `high`, `medium`, `low` |
| `freshness.max_age_days` | int | Optional. Maximum age of artifact in days |
| `metadata_conditions.all` | []Condition | Optional. Conditions that must all be true |

### Condition Options

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | JSONPath expression (e.g., `$.mfa_coverage`) |
| `op` | string | Operator: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `exists`, `not_exists` |
| `value` | any | Expected value (not required for `exists`/`not_exists`) |
| `cardinality` | string | For multi-value paths: `all`, `any`, `none` (empty = single value required) |

### Supported JSONPath Syntax

The following JSONPath patterns are supported:

| Pattern | Example | Description |
|---------|---------|-------------|
| Root field | `$.field` | Access top-level field |
| Nested field | `$.nested.field` | Access nested field |
| Array index | `$.array[0]` | Access specific array element |
| Last element | `$.array[-1]` | Access last array element |
| Wildcard | `$.array[*].field` | Access field in all array elements (requires `cardinality`) |
| Recursive descent | `$..field` | Access field at any depth (requires `cardinality`) |

**Note**: Multi-value patterns (wildcards, recursive descent) require a `cardinality` field to specify how multiple results are evaluated. See [Cardinality](#cardinality-for-multi-value-paths).

### Cardinality for Multi-Value Paths

When a JSONPath expression can return multiple values, you must specify how to evaluate them:

```yaml
metadata_conditions:
  all:
    - path: $.accounts[*].mfa_enabled
      op: eq
      value: true
      cardinality: all  # ALL accounts must have MFA enabled
```

| Cardinality | Description |
|-------------|-------------|
| (empty) | Default. Path must return exactly one value |
| `all` | Every value must satisfy the condition |
| `any` | At least one value must satisfy the condition |
| `none` | No value should satisfy the condition |

**Examples**:

```yaml
# All accounts must have MFA enabled
- path: $.accounts[*].mfa_enabled
  op: eq
  value: true
  cardinality: all

# At least one environment must be production
- path: $.deployments[*].environment
  op: eq
  value: production
  cardinality: any

# No user should have admin role
- path: $.users[*].role
  op: eq
  value: admin
  cardinality: none
```

**Partial presence detection**: For `cardinality: all`, the validator checks that ALL array elements have the field. If some elements are missing the field entirely, validation fails. For example, `$.accounts[*].mfa_enabled` with `cardinality: all` will fail if 2 out of 3 accounts have `mfa_enabled: true` but the third account has no `mfa_enabled` field - the result will show "2 of 3 elements have field".

**Note**: Partial presence detection requires a simple wildcard path (e.g., `$.accounts[*].field`). Recursive descent paths (`$..field`) cannot detect partial presence since there's no single base array to count.

## Overlay File Format

Overlays customize profiles without modifying the original:

```yaml
id: production-overlay            # Optional identifier
name: Production Overlay          # Optional name

# Modify existing requirements (replaces entire requirement)
modify:
  - id: REQ-001
    name: Stricter Access Control
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.has_access_policy
                op: eq
                value: true
              - path: $.policy_reviewed_days
                op: lte
                value: 90

# Skip requirements entirely
skip:
  - REQ-003
  - REQ-004

# Add new requirements
add:
  - id: REQ-PROD-001
    name: Production-Specific Check
    category: Production
    satisfied_by:
      any_of:
        - type: evidencepack/deploy-info@v1
          metadata_conditions:
            all:
              - path: $.environment
                op: eq
                value: production
```

### Overlay Application Order

1. Overlays are applied in the order specified
2. `modify` replaces the entire requirement (last-write-wins)
3. `skip` removes requirements from evaluation
4. `add` appends new requirements (ID must be unique)

## Configuration Examples

### Basic Single Profile

```yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config:
      profile: profiles/compliance.yaml
```

### Profile with Multiple Overlays

```yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config:
      profile: profiles/security-policy.yaml
      overlays:
        - profiles/overlays/skip-manual.yaml
        - profiles/overlays/environment-prod.yaml
```

### Environment-Specific Configuration

Use environment variables in overlay paths:

```yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config:
      profile: profiles/security-baseline.yaml
      overlays:
        - profiles/overlays/${ENVIRONMENT}.yaml
```

### Shared Configuration with YAML Anchors

Use YAML anchors to share configuration between multiple tool instances:

```yaml
tools:
  validate:
    source: locktivity/epack-tool-validate@v1
    config: &base-validate
      profile: profiles/security-baseline.yaml

  validate-strict:
    source: locktivity/epack-tool-validate@v1
    config:
      <<: *base-validate
      overlays:
        - profiles/overlays/strict.yaml
```

## Output Files

| File | Description |
|------|-------------|
| `validation.json` | JSON file containing validation results |

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Validation completed (check `validation.json` for pass/fail) |
| 1 | Operational error (profile not found, invalid YAML, etc.) |

Note: A failing validation (requirements not met) still exits with code 0. Check the `status` field in `validation.json` to determine pass/fail.
