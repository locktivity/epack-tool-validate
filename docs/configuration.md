# Configuration

`epack-tool-validate` requires a compliance profile to validate against. The profile path is specified in the tool configuration.

## Tool Requirements

| Requirement | Value |
|-------------|-------|
| Requires Pack | No. With a pack it validates; without one it lints the profile |
| Network Access | No |

## Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `profile` | string | Yes* | Path to a single profile YAML file |
| `profiles` | []string | Yes* | List of profile paths (MVP: only one supported) |
| `overlays` | []string | No | List of overlay YAML files to apply |
| `schemas` | map | No | Artifact type to JSON Schema path, used by lint. Adds types the tool does not bundle and replaces bundled schemas for the types it names |

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

### Linting a Profile

Run the tool without a pack to lint a profile before it ever meets evidence:

```bash
epack tool validate profiles/security-policy.yaml
```

With no arguments, lint reads `profile`, `overlays` and `schemas` from the tool configuration. Arguments replace them:

```bash
epack tool validate profiles/draft.yaml --overlay profiles/overlays/production.yaml --schema acme/thing@v1=schemas/thing.json
```

Lint reports every problem it finds, not just the first. Findings print to stderr and are written to `lint.json`. Errors mean the profile will not evaluate as written. Warnings mean it will, but probably not as intended.

| Code | Severity | Meaning |
|------|----------|---------|
| `UNKNOWN_PATH` | error | The path names a field the artifact's schema does not declare. Includes the declared fields at that level and the closest declared paths |
| `PATH_SHAPE` | error | The path indexes something that is not an array, or reads a field of something that is not an object |
| `OPERATOR_TYPE_MISMATCH` | error | A numeric operator on a non-numeric field, or `max_age_days` on a field that is not a date string |
| `NEVER_MATCHES` | error | `eq` against a value the field can never hold: the wrong type, a value outside its allowed values, or a whole object. Also a numeric operator given a non-numeric value |
| `MISSING_VALUE` | error | A comparison with no `value` |
| `MISSING_FIELD` | error | The profile has no version, or a requirement has no `id` or `name` |
| `ALWAYS_MATCHES` | warning | `neq` against a value the field can never hold |
| `VACUOUS_PASS` | warning | A condition that passes when there is nothing to test: `cardinality: none` over an empty list, `exists` with `none`, `not_exists` with `all`, or a single `not_exists`, which also passes when the field was never collected |
| `FRESHNESS_IGNORED` | warning | `freshness.max_age_days` below 1, which is ignored |
| `TYPE_UNCHECKED` | warning | No schema is known for the clause's type, so its paths were not checked. Pass one under `schemas` |
| `PATH_UNCHECKED` | warning | The path uses recursive descent, a filter or a union, which cannot be checked statically |

Compiler errors such as `INVALID_OPERATOR` and `INVALID_CARDINALITY` are reported too, every one of them in a single run.

The tool bundles schemas for `evidencepack/idp-posture@v1`, `cloud-posture@v1`, `vcs-posture@v1`, `email-dns@v1` and `tls@v1`. Any other type needs a schema under `schemas` before its paths are checked.

## Profile File Format

Profiles are YAML files with the following structure:

```yaml
id: my-security-profile           # Unique identifier
name: My Security Profile         # Human-readable name
version: "1.0.0"                  # Semantic version
description: Example profile      # Optional description

requirements:
  - id: REQ-001                   # Unique requirement ID
    name: MFA is enforced for every user  # The statement a reviewer reads
    control: CC6.1                # Optional control reference
    category: Access Control      # Optional category for grouping
    description: >                # Optional prose: what satisfies this
      Every active user is enrolled in multi-factor authentication.
    satisfied_by:
      any_of:                     # OR: any clause can satisfy
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:                  # AND: all conditions must match
              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100
```

### Editor and Agent Support

`schema/profile.schema.json` and `schema/overlay.schema.json` describe the profile and overlay grammar as JSON Schema. Point an editor at them from the top of the file for completion and inline errors:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/locktivity/epack-tool-validate/main/schema/profile.schema.json
id: my-security-profile
```

The JSON Schema checks the grammar. Lint goes further: it checks each path against the schema of the artifact it reads.

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
| `path` | string | JSONPath expression (e.g., `$.user_security.mfa_coverage_pct`) |
| `op` | string | Operator: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `exists`, `not_exists`, `max_age_days` |
| `value` | any | Expected value (not required for `exists`/`not_exists`) |
| `cardinality` | string | For multi-value paths: `all`, `any`, `none` (empty = single value required) |

`max_age_days` expects `value` to be a non-negative number of days (validated at profile compile time) and the JSONPath value to be an ISO date (`YYYY-MM-DD`) or RFC3339 timestamp. It passes when the date is no older than the configured number of days and not in the future. Date-only values carry no timezone, so they are allowed up to one day in the future; RFC3339 timestamps must not be in the future at all.

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
    - path: $.accounts[*].iam.root_mfa_enabled
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
- path: $.accounts[*].iam.root_mfa_enabled
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

**Partial presence detection**: For `cardinality: all`, the validator checks that ALL array elements have the field. If some elements are missing the field entirely, validation fails. For example, `$.accounts[*].iam.root_mfa_enabled` with `cardinality: all` will fail if 2 out of 3 accounts have `mfa_enabled: true` but the third account has no `mfa_enabled` field - the result will show "2 of 3 elements have field".

**Note**: Partial presence detection requires a simple wildcard path (e.g., `$.accounts[*].field`). Recursive descent paths (`$..field`) cannot detect partial presence since there's no single base array to count.

### Manual Requirements

A requirement with `manual: true` declares that no machine check answers it. It is answered by asserted support (control mapping entries, see [Control Mappings](#control-mappings)) and human review.

```yaml
requirements:
  - id: REQ-POLICY
    name: Information Security Policy
    control: PL-01
    category: Governance
    description: Current version, stating review cadence of at least annually.
    manual: true
```

The optional `description` carries what would satisfy the requirement, in prose. It is echoed on each requirement in `validation.json`, so a reviewer sees the acceptance criteria beside the outcome and any asserted support.

Rules:

- A requirement must have exactly one of `any_of`, `all_of`, or `manual: true`.
- A manual requirement must carry `id` or `control`; without either it could never receive asserted support.
- Manual requirements are never scored. They report `status: "manual"`, count under `summary.manual`, and never affect the overall status. `summary.total` minus `summary.manual` is the machine-checked denominator.
- A manual requirement with no asserted support entries produces a `MANUAL_UNSUPPORTED` warning.

## Overlay File Format

Overlays customize profiles without modifying the original:

```yaml
id: production-overlay            # Optional identifier
name: Production Overlay          # Optional name

# Modify existing requirements (replaces entire requirement)
modify:
  - id: REQ-001
    name: MFA is enforced and phishing-resistant
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.user_security.mfa_coverage_pct
                op: gte
                value: 100
              - path: $.user_security.mfa_phishing_resistant_pct
                op: gte
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

## Control Mappings

When the pack contains control mapping artifacts (schema `evidencepack/control-mapping@v1`), the tool reports their entries as asserted support beside its computed results. Mappings are publisher assertions: they never change any requirement outcome or the overall status. No configuration is needed; mapping support is automatic.

Each mapping entry references one requirement of the validated profile and one piece of evidence in the pack. The tool joins entries to requirements:

| Entry field | Joins to |
|-------------|----------|
| `requirement` | The requirement with that `id` |
| `control` | The first requirement with that `control` value |
| `type` | The single requirement whose clauses use that artifact schema (ambiguous types match nothing) |

Mappings whose `profile.id` names a different profile are ignored. A mapping whose `profile.digest` differs from the validated profile's digest is still reported, with each entry marked `"stale": true` and a `MAPPING_PROFILE_MISMATCH` warning.

Evidence references resolve best-effort against the pack:

- `artifact` resolves against the pack's artifact paths. An RFC 6901 `pointer` resolves into the artifact's JSON content; when it names a scalar, the entry carries the cited value in `value`.
- `document_id` resolves through a document index artifact (schema `evidencepack/document-index@v1`). A `quote` anchor is searched in the document's extracted text; a `table` anchor resolves at document level, since packs carry no tabular extraction yet.

Each reported entry carries a `resolution` state:

| State | Meaning |
|-------|---------|
| `resolved` | Target (and anchor, where an extraction exists) found |
| `document_only` | Document found, but the anchor's extraction is absent |
| `unresolved` | Target or anchor not found in the pack |

The `asserted_support` output section is keyed by profile ID:

```json
"asserted_support": {
  "my-security-profile": [
    {
      "requirement": "REQ-001",
      "requirement_id": "REQ-001",
      "evidence": {"artifact": "artifacts/idp-posture.json", "pointer": "/user_security/mfa_coverage_pct"},
      "label": "MFA coverage from the IdP export",
      "resolution": "resolved",
      "value": 100,
      "source": "artifacts/control-mappings.json"
    }
  ]
}
```

`requirement`, `control`, or `type` echoes the join the entry claimed; `requirement_id` is the joined requirement's id in this profile and is absent when the claim matched nothing.

Mapping issues surface as warnings, in the `warnings` array of `validation.json` and in the run's `result.json`. They are never errors and never affect `status`:

| Code | Meaning |
|------|---------|
| `INVALID_MAPPING_ENTRY` | Entry violates the mapping schema's constraints; the entry is reported in the warning and skipped |
| `MAPPING_UNRESOLVED` | Entry cites an artifact, document, pointer, or quote not found in the pack, or references a requirement not present in the profile |
| `MAPPING_PROFILE_MISMATCH` | Mapping's profile digest differs from the profile validated |
| `MANUAL_UNSUPPORTED` | A `manual: true` requirement has no asserted support entries |

## Output Files

| File | Description |
|------|-------------|
| `validation.json` | Validation results, written when the tool runs with a pack |
| `lint.json` | Lint findings, written when the tool runs without a pack. `status` is `pass` when there are no errors |

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Validation completed (check `validation.json` for pass/fail) |
| 1 | Operational error (profile not found, invalid YAML, etc.) |

Note: A failing validation (requirements not met) still exits with code 0. Check the `status` field in `validation.json`: `pass`, `fail`, or `unknown` (evidence absent for at least one requirement, none failing).
