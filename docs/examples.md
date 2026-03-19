# Examples

## Basic Usage

Run validation on an evidence pack:

```bash
epack tool validate --pack ./my-evidence.epack
```

## Interpreting Results

### Passing Validation

```json
{
  "status": "pass",
  "profile": {
    "id": "security-baseline",
    "name": "Security Baseline",
    "version": "1.0.0"
  },
  "validated_at": "2024-06-15T12:00:00Z",
  "pack_digest": "sha256:abc123...",
  "summary": {
    "total": 5,
    "passed": 5,
    "failed": 0,
    "warnings": 0
  },
  "requirements": [
    {
      "id": "REQ-001",
      "name": "MFA Enabled",
      "status": "pass",
      "artifact": "artifacts/idp-posture.json"
    }
  ]
}
```

All requirements are satisfied.

### Failing Validation

```json
{
  "status": "fail",
  "profile": {
    "id": "security-baseline",
    "name": "Security Baseline",
    "version": "1.0.0"
  },
  "summary": {
    "total": 5,
    "passed": 3,
    "failed": 2,
    "warnings": 0
  },
  "requirements": [
    {
      "id": "REQ-001",
      "name": "MFA Coverage",
      "status": "fail",
      "severity": "high",
      "expected": {
        "op": "gte",
        "value": 100
      },
      "actual": 85,
      "delta": -15,
      "message": "conditions not satisfied",
      "artifact": "artifacts/idp-posture.json",
      "path": "$.mfa_coverage"
    },
    {
      "id": "REQ-002",
      "name": "Vulnerability Scan",
      "status": "fail",
      "severity": "high",
      "message": "no artifact with schema evidencepack/vuln-scan@v1"
    }
  ],
  "key_failures": [
    {"id": "REQ-001", "name": "MFA Coverage", "severity": "high"},
    {"id": "REQ-002", "name": "Vulnerability Scan", "severity": "high"}
  ]
}
```

The `key_failures` array highlights critical and high severity failures.

**Output fields for failed requirements**:

| Field | Description |
|-------|-------------|
| `expected` | The condition that needed to be satisfied (`op` and `value`) |
| `actual` | The actual value found in the artifact |
| `delta` | Numeric difference from expected (for numeric comparisons) |
| `path` | JSONPath that was evaluated |
| `artifact` | Path to the artifact that was checked |

## Example Profiles

### Basic Access Control Profile

```yaml
id: access-control-basic
name: Basic Access Control Profile
version: "1.0.0"

requirements:
  - id: AC-001
    name: MFA Enabled
    control: AC-1
    category: Access Control
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.mfa_enabled
                op: eq
                value: true

  - id: AC-002
    name: Password Policy
    control: AC-2
    category: Access Control
    satisfied_by:
      any_of:
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.password_policy.min_length
                op: gte
                value: 12
              - path: $.password_policy.require_special
                op: eq
                value: true
```

### Graduated Compliance Profile

This profile uses graduated severity for MFA coverage thresholds:

```yaml
id: mfa-graduated
name: MFA Coverage with Graduated Compliance
version: "1.0.0"

requirements:
  - id: MFA-001
    name: MFA Coverage
    control: CC6.2
    category: Access Control
    satisfied_by:
      any_of:
        # Full compliance (100%) - no severity = PASS
        - type: evidencepack/idp-posture@v1
          metadata_conditions:
            all:
              - path: $.mfa_coverage
                op: gte
                value: 100

        # 90%+ coverage - low severity
        - type: evidencepack/idp-posture@v1
          severity: low
          metadata_conditions:
            all:
              - path: $.mfa_coverage
                op: gte
                value: 90

        # 75%+ coverage - medium severity
        - type: evidencepack/idp-posture@v1
          severity: medium
          metadata_conditions:
            all:
              - path: $.mfa_coverage
                op: gte
                value: 75

        # Anything less - high severity
        - type: evidencepack/idp-posture@v1
          severity: high
          metadata_conditions:
            all:
              - path: $.mfa_coverage
                op: gte
                value: 0
```

| MFA Coverage | Result | Severity |
|--------------|--------|----------|
| 100% | Pass | - |
| 95% | Fail | low |
| 80% | Fail | medium |
| 50% | Fail | high |

### Profile with Freshness Requirements

```yaml
id: vuln-scan-fresh
name: Vulnerability Scanning Profile
version: "1.0.0"

requirements:
  - id: VS-001
    name: Recent Vulnerability Scan
    control: CC7.1
    category: System Operations
    satisfied_by:
      any_of:
        - type: evidencepack/vuln-scan@v1
          freshness:
            max_age_days: 7
          metadata_conditions:
            all:
              - path: $.critical_count
                op: eq
                value: 0

  - id: VS-002
    name: No High Vulnerabilities
    control: CC7.2
    category: System Operations
    satisfied_by:
      any_of:
        - type: evidencepack/vuln-scan@v1
          freshness:
            max_age_days: 30
          metadata_conditions:
            all:
              - path: $.high_count
                op: lte
                value: 5
```

### All-Of Mode Example

This requirement needs ALL clauses to be satisfied:

```yaml
requirements:
  - id: DEPLOY-001
    name: Production Deployment Checks
    category: Deployment
    satisfied_by:
      all_of:
        - type: evidencepack/deploy-info@v1
          metadata_conditions:
            all:
              - path: $.environment
                op: eq
                value: production

        - type: evidencepack/approval@v1
          metadata_conditions:
            all:
              - path: $.approved
                op: eq
                value: true

        - type: evidencepack/test-results@v1
          metadata_conditions:
            all:
              - path: $.all_passed
                op: eq
                value: true
```

### Multi-Value JSONPath with Cardinality

Use cardinality when checking conditions across arrays:

```yaml
requirements:
  - id: CLOUD-001
    name: Root MFA Enabled (All Accounts)
    category: Identity
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              # Check ALL accounts have root MFA enabled
              - path: $.accounts[*].iam.root_mfa_enabled
                op: eq
                value: true
                cardinality: all

  - id: CLOUD-002
    name: At Least One High-Availability Region
    category: Infrastructure
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              # At least one region has HA enabled
              - path: $.regions[*].high_availability
                op: eq
                value: true
                cardinality: any

  - id: CLOUD-003
    name: No Public S3 Buckets
    category: Data Protection
    satisfied_by:
      any_of:
        - type: evidencepack/cloud-posture@v1
          metadata_conditions:
            all:
              # NO bucket should be public
              - path: $.s3_buckets[*].public_access
                op: eq
                value: true
                cardinality: none
```

| Cardinality | Use Case |
|-------------|----------|
| `all` | Every item must satisfy (e.g., all accounts have MFA) |
| `any` | At least one item must satisfy (e.g., one region has HA) |
| `none` | No item should satisfy (e.g., no public buckets) |

## Example Overlays

### Skip Manual Requirements

```yaml
id: skip-manual
name: Skip Manual Review Requirements

skip:
  - MANUAL-001
  - MANUAL-002
  - MANUAL-003
```

### Environment-Specific Overlay

```yaml
id: production-overlay
name: Production Environment Overlay

modify:
  - id: VS-001
    name: Strict Vulnerability Scan (Production)
    satisfied_by:
      any_of:
        - type: evidencepack/vuln-scan@v1
          freshness:
            max_age_days: 1  # Daily scans in production
          metadata_conditions:
            all:
              - path: $.critical_count
                op: eq
                value: 0
              - path: $.high_count
                op: eq
                value: 0

add:
  - id: PROD-001
    name: Production Monitoring Active
    category: Production
    satisfied_by:
      any_of:
        - type: evidencepack/monitoring@v1
          metadata_conditions:
            all:
              - path: $.active
                op: eq
                value: true
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Compliance Check

on:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          go install github.com/locktivity/epack/cmd/epack@latest

      - name: Build evidence pack
        run: epack collect -o evidence.epack

      - name: Validate compliance
        run: |
          epack tool validate --pack evidence.epack

          # Check validation result
          STATUS=$(jq -r '.status' validation.json)
          if [ "$STATUS" != "pass" ]; then
            echo "Compliance check failed"
            jq '.key_failures' validation.json
            exit 1
          fi

          echo "Compliance check passed"
```

### GitLab CI Example

```yaml
compliance:
  stage: test
  script:
    - epack collect -o evidence.epack
    - epack tool validate --pack evidence.epack
    - |
      if [ "$(jq -r '.status' validation.json)" != "pass" ]; then
        echo "Compliance failures:"
        jq '.requirements[] | select(.status == "fail")' validation.json
        exit 1
      fi
  artifacts:
    paths:
      - validation.json
    when: always
```

## Debugging Validation Failures

### Check Artifact Schema

Ensure your artifacts have the expected schema:

```bash
# List artifact schemas in pack
epack inspect --pack evidence.epack | jq '.artifacts[].schema'
```

### Verify JSONPath

Test your JSONPath expressions against artifact content:

```bash
# Extract artifact and test JSONPath
unzip -p evidence.epack artifacts/idp-posture.json | jq '$.mfa_coverage'
```

### Profile Compilation Errors

If profile compilation fails, check:

1. All requirement IDs are unique
2. Each requirement has either `any_of` or `all_of` (not both)
3. Each clause has a `type` field
4. Severity values are valid: `critical`, `high`, `medium`, `low`
5. Multi-value JSONPath expressions (wildcards, `..`) have a `cardinality` field
6. Cardinality values are valid: `all`, `any`, `none`
