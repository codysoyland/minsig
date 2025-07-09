# Claude Code Configuration for minsig

## Project Overview
Minsig is a minimalist command-line tool for signing and verifying artifacts using Sigstore. It's an experimental alternative to Cosign, designed around the Sigstore Client Specification with a focus on simplicity and UX improvements.

**Status**: Experimental - not ready for production use

## Key Technologies
- **Language**: Go (1.24.2)
- **CLI Framework**: urfave/cli/v3
- **Primary Dependencies**: 
  - sigstore/sigstore-go (v0.7.2)
  - sigstore/sigstore (v1.9.4)
  - theupdateframework/go-tuf/v2 (v2.0.2)

## Project Structure
```
/Users/cody/s/minsig/
├── cmd/minsig/           # Main application code
│   ├── main.go          # CLI setup and main entry point
│   ├── sign.go          # Sign command implementation
│   └── verify.go        # Verify command implementation
├── go.mod               # Go module definition
├── go.sum               # Go module checksums
├── README.md            # Project documentation
└── minsig               # Built binary
```

## Build Commands
```bash
# Build the project
go build ./cmd/minsig

# Build and install
go install github.com/codysoyland/minsig/cmd/minsig@latest

# Test the project (offline tests only)
go test ./...

# Run all tests including online tests (requires internet)
go test -tags online ./...

# Run linting checks
go vet ./...
```

## Main Commands
The tool provides three main commands:

### 1. Sign Command
```bash
# Sign an artifact
minsig sign --artifact <path-to-artifact>

# Sign an attestation
minsig sign --attestation <path-to-attestation>

# Sign a container image
minsig sign --artifact <oci-image-ref> --attach
```

### 2. Verify Command
```bash
# Verify a signed artifact
minsig verify \
    --artifact <path-to-artifact> \
    --certificate-identity <expected-identity> \
    --certificate-oidc-issuer <expected-issuer>

# Verify a signed attestation
minsig verify \
    --attestation=true \
    --certificate-identity <expected-identity> \
    --certificate-oidc-issuer <expected-issuer>
```

### 3. Update TUF Command
```bash
# Update TUF cache
minsig update-tuf

# Force update with verbose output
minsig update-tuf --force --verbose
```

## Development Notes
- **Philosophy**: Unix philosophy - fewer features, more composability
- **Architecture**: Built around the Sigstore Client Specification
- **Testing**: 
  - Offline tests: Use local trusted root file (default: `go test ./...`)
  - Online tests: Use TUF and require internet access (`go test -tags online ./...`)
  - Test data available in `testdata/` directory

## Global Flags
All commands support these universal flags:
- `--tuf-url`: URL to the TUF repository (default: https://tuf-repo-cdn.sigstore.dev)
- `--tuf-root`: Path to the TUF root file
- `--tuf-cache-path`: Path to TUF repository cache (default: ~/.sigstore/tuf)
- `--tuf-cache-ttl`: Time to live for TUF cache (default: 1 hour)
- `--signing-config`: Path to signing configuration file
- `--trusted-root`: Path to trusted root file

## Contributing
Contributions are not currently accepted. For questions or feedback, reach out in #clients on Sigstore Slack.

## Key Differences from Cosign
- Fewer flags and features (many bundled into Trusted Root, Signing Config, and Sigstore Bundle)
- Several subcommands omitted in favor of alternative tools
- Legacy Sigstore OCI format not supported
- Designed for Unix philosophy principles

## Common Tasks
- **Adding new flags**: Modify the respective command files (sign.go, verify.go) and main.go for global flags
- **Extending functionality**: Follow the existing urfave/cli/v3 pattern
- **Testing changes**: Build with `go build ./cmd/minsig` and test manually
- **Debugging**: Use standard Go debugging tools and logging
- **Fetching trusted root**: Update TUF cache and copy the trusted root from `~/.sigstore/tuf/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json` to `testdata/`

## Testing Notes
- To fetch the sigstore trusted root, copy the trusted_root.json from the tuf cache (~/.sigstore/tuf) into the testdata directory