# Test Data

This directory contains test fixtures for epack-tool-validate.

## Directory Structure

```
testdata/
├── profiles/           # Test compliance profiles
├── overlays/           # Test overlay files
└── packs/              # Test evidence packs (directory format)
```

## Profiles

| File | Description |
|------|-------------|
| `test-profile.yaml` | Minimal valid profile for unit tests |
| `security-baseline.yaml` | Baseline security profile (MFA, vuln scan, access policies) |
| `all-of-example.yaml` | Demonstrates `all_of` clause mode |
| `invalid-missing-id.yaml` | Invalid: missing required `id` field |
| `invalid-both-modes.yaml` | Invalid: has both `any_of` and `all_of` |
| `invalid-duplicate-id.yaml` | Invalid: duplicate requirement IDs |

## Overlays

| File | Description |
|------|-------------|
| `skip-vuln-scan.yaml` | Skips vulnerability scan requirement (REQ-003) |
| `stricter-mfa.yaml` | Modifies MFA requirement to be stricter |
| `add-production.yaml` | Adds production-specific requirements |
| `combined.yaml` | Demonstrates all overlay operations (skip, modify, add) |

## Packs

Test packs are directory-based (not `.epack` files) for easier inspection and modification.

| Pack | Description |
|------|-------------|
| `passing-pack/` | All artifacts present with passing values |
| `failing-pack/` | Artifacts present but with failing values (MFA disabled, critical vulns) |
| `partial-pack/` | Missing vuln-scan artifact (tests missing schema behavior) |

### Pack Structure

Each pack directory contains:
```
{pack-name}/
├── manifest.json       # Pack manifest with artifact metadata
└── artifacts/
    ├── idp-posture.json    # IDP posture evidence
    └── vuln-scan.json      # Vulnerability scan results (optional)
```

## Using Test Data

### In Unit Tests

```go
import "path/filepath"

func TestWithFixtures(t *testing.T) {
    profilePath := filepath.Join("testdata", "profiles", "security-baseline.yaml")
    packPath := filepath.Join("testdata", "packs", "passing-pack")
    // ...
}
```

### With SDK Commands

```bash
# Build and test
go build -o epack-tool-validate .
epack sdk test ./epack-tool-validate

# Manual run with test data
epack sdk run ./epack-tool-validate \
  --pack ./testdata/packs/passing-pack \
  --config '{"profile": "testdata/profiles/security-baseline.yaml"}'
```

## Adding New Fixtures

### New Profile
1. Create YAML file in `profiles/`
2. Follow existing profile structure
3. Add entry to this README

### New Overlay
1. Create YAML file in `overlays/`
2. Reference requirement IDs from an existing profile
3. Add entry to this README

### New Pack
1. Create directory in `packs/`
2. Add `manifest.json` with artifact references
3. Add artifact files in `artifacts/`
4. Ensure schemas match profiles you want to test against
5. Add entry to this README
