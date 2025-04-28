# sigstore-cli

A minimalist command-line tool for signing and verifying artifacts using Sigstore.

## Installation

```sh
go install github.com/codysoyland/sigstore-cli/cmd/sigstore-cli@latest
```

## Usage

### Sign an Artifact

```sh
sigstore-cli sign \
    --artifact <path-to-artifact> \
    [--signing-config <path-to-signing-config>] \
```

### Sign an attestation

```sh
sigstore-cli sign \
    --attestation <path-to-attestation> \
    [--signing-config <path-to-signing-config>] \
```

### Sign a container image

```sh
sigstore-cli sign \
    --artifact <oci-image-ref> \
    [--signing-config <path-to-signing-config>] \
    [--attach]
```

### Sign using private key

```sh
sigstore-cli sign \
    --artifact <path-to-artifact> \
    --key <path-to-private-key> \
    [--signing-config <path-to-signing-config>] \
```

### Verify a Signed Artifact

```sh
sigstore-cli verify \
    --artifact <path-to-artifact> \
    [--bundle <path-to-bundle>] \
    [--trusted-root <path-to-trusted-root>]
```


### Verify a Signed Attestation

```sh
sigstore-cli verify \
    --attestation=true \
    [--bundle <path-to-bundle>] \
    [--trusted-root <path-to-trusted-root>]
```
## Flags

### Universal flags for all commands:

| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------| 
| `--tuf-url`           | URL to the TUF repository. Default is `https://tuf-repo-cdn.sigstore.dev`   |
| `--tuf-root`          | Path to the TUF root file. Default is embedded for tuf-repo-cdn.sigstore.dev|
| `--tuf-cache-path`    | Path on disk to the TUF repository cache. Default is `~/.sigstore/tuf`      |
| `--tuf-cache-ttl`     | Time to live for the TUF cache. Default is 1 hour                           |
| `--signing-config`    | Path to the signing configuration file. Uses TUF if not specified           |
| `--trusted-root`      | Path to the trusted root file. Uses TUF if not specified                    |

### `sigstore-cli sign` flags:

| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `--artifact`           | Path to the artifact to sign. Required if attestation is not provided.     |
| `--attestation`        | Path to the attestation to sign. Required if artifact is not provided.     |
| `--key`                | Path to the private key to use for signing.                                |
| `--skip-tsa`           | Bool to indicate if the timestamp should be skipped. Default is false.     |
| `--skip-rekor`         | Bool to indicate if the Rekor entry should be skipped. Default is false.   |
| `--attach`             | Bool to indicate if the artifact is an OCI image and the signature should be attached to the image. Default is false. |
| `--output`             | Path to write the signature bundle to (defaults to [filename].sigstore.json). |
| `--id-token`           | OIDC token to send to Fulcio.                                             |

### `sigstore-cli verify` flags:
| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `--artifact`           | Path to the artifact to verify. Optional if attestation is provided.       |
| `--attestation`        | Bool to indicate if the artifact is an attestation. Default is false.      |
| `--oci`                | Bool to indicate if the artifact is an OCI image. Default is false.
| `--bundle`             | Path to the bundle file. If not provided, the bundle will be expected as `FILENAME[.sigstore.json]` in the same directory as the artifact, or as an OCI referring artifact |
