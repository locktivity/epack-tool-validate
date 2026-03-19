# epack-tool-validate

An epack tool that validates evidence packs against compliance profile YAML files.

Built with the [Component SDK](https://github.com/locktivity/epack).

See [docs/](docs/) for detailed documentation.

## Features

- **Profile-Based Validation**: Validates pack contents against declarative compliance profiles
- **JSONPath Conditions**: Evaluate artifact metadata using JSONPath expressions
- **Multi-Value Cardinality**: Check conditions across arrays with `all`, `any`, or `none` semantics
- **Graduated Severity**: Clauses can specify severity levels for graded compliance reporting
- **Freshness Checks**: Ensure artifacts are recent enough to satisfy requirements
- **Overlay Support**: Customize profiles with overlays (modify, skip, add requirements)
- **Digest Verification**: Optionally verify profile integrity against manifest digests

## Development

### Prerequisites

- Go 1.21+
- epack CLI (`brew install locktivity/tap/epack`)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all
```

### SDK Development Workflow

Use the epack SDK commands for development:

```bash
# Run conformance tests (validates protocol compliance)
make sdk-test

# Run the tool with mock input
make sdk-run

# Or use epack directly
epack sdk test ./epack-tool-validate
epack sdk run ./epack-tool-validate
```

### Testing

```bash
make test
```

## Release

This project uses [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) builds for supply chain security.

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Action will:
1. Run tests and conformance checks
2. Build multi-platform binaries (linux/darwin, amd64/arm64)
3. Generate SLSA Level 3 provenance attestations
4. Publish to GitHub Releases with checksums

### Verifying Releases

Verify the SLSA provenance of downloaded binaries:

```bash
slsa-verifier verify-artifact epack-tool-validate-linux-amd64 \
  --provenance-path epack-tool-validate-linux-amd64.intoto.jsonl \
  --source-uri github.com/locktivity/epack-tool-validate
```

## License

Apache-2.0 - see [LICENSE](LICENSE)
