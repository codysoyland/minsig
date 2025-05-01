# minsig

A minimalist command-line tool for signing and verifying artifacts using Sigstore.

## Philosophy

The goal of this project is:

- To create an alternative to [Cosign](https://github.com/sigstore/cosign) that is redesigned around the [Sigstore Client Specification](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md).
- To experiment with UX design without the constraints of backwards compatibility.
- To inform the direction of Cosign v3+.

Non-goals include:

- To implement all of the features of Cosign.
- Code quality is not a primary focus of this project, but that may change in the future. This is vibe-driven development.

## Status

Experimental. This tool is not yet ready for production use.

## Comparison to Cosign

This is a lightweight alternative to [Cosign](https://github.com/sigstore/cosign). The purpose of this tool is to experiment with a simpler interface design compared to Cosign based on [sigstore-go](https://github.com/sigstore/sigstore-go).

Notable differences:
- Embraces the Unix philosophy: Fewer features, more composability.
- Fewer flags are offered as many are bundled into the Trusted Root, Signing Config, and Sigstore Bundle.
- Several subcommands are omitted in favor of alternative tools.
- Legacy Sigstore OCI format is not supported.

### Comparison to Cosign subcommands

| Cosign subcommand | minsig equivalent | Description |
|-------------------|-------------------------|-------------|
| `cosign sign [IMAGE]`      | `minsig sign --oci --artifact [IMAGE]`    | Sign a container image |
| `cosign verify [IMAGE]`    | `minsig verify --oci --artifact [IMAGE]`  | Verify a container image |
| `cosign sign-blob [FILE]` | `minsig sign [FILE]`    | Sign a file |
| `cosign verify-blob [FILE]` | `minsig verify [FILE]`  | Verify a file |
| `cosign attest --predicate [PREDICATE] [IMAGE]` | `minsig sign --predicate [PREDICATE] --oci --artifact [IMAGE]` |  Attest a container image |
| `cosign verify-attestation [IMAGE]` | `minsig verify --predicate-type [PREDICATE] --oci --artifact [IMAGE]` | Verify an attestation for a container image |
| `cosign attest-blob --predicate [PREDICATE] [FILE]` | `minsig sign --predicate [PREDICATE] --artifact [FILE]` | Attest a file |
| `cosign verify-blob-attestation --predicate [PREDICATE] [FILE]` | `minsig verify --predicate-type [PREDICATE] --artifact [FILE]` | Verify an attestation for a file |
| `cosign attach` | Unsupported. Use `oras attach` instead. | Attach a signature to an OCI image |
| `cosign bundle` | Unsupported. | Create a Sigstore Bundle |
| `cosign clean` | Unsupported. Use `oras blob delete`/`oras manifest delete` instead. | Delete a signature from an OCI image |
| `cosign copy` | Unsupported. Use `oras copy -r` instead. | Copy a signature from one OCI image to another |
| `cosign dockerfile` | Unsupported. | Verify images in a Dockerfile |
| `cosign download` | Unsupported. Use `oras discover`/`oras manifest get`/`oras blob get` instead. | Download a signature from an OCI image |
| `cosign env` | Unsupported. All configuration is provided with flags. | Print Cosign environment variables |
| `cosign generate` | Unsupported. | Generates (unsigned) signature payloads from the supplied container image. |
| `cosign generate-key-pair` | Unsupported. Use `openssl` instead. | Generate a key pair for signing |
| `cosign import-key-pair` | Unsupported. | Imports a PEM-encoded RSA or EC private key for signing. |
| `cosign initialize` | Unsupported. | Initializes TUF cache. |
| `cosign load` | Unsupported. | Load a signed image on disk to a remote registry. |
| `cosign login` | Unsupported. Use `docker login` instead. | Login to a registry. |
| `cosign manifest` | Unsupported. | Verify all signatures in a Kubernetes manifest. |
| `cosign public-key` | Unsupported. | Gets a public key from the key-pair. |
| `cosign save` | Unsupported. Use `oras` instead. | Save image and signature to a file. |
| `cosign tree` | Unsupported. Use `oras discover` instead. | Display supply chain security related artifacts for an image. |
| `cosign triangulate` | Unsupported as OCI referrers does not need it. | Outputs the located cosign image reference. |
| `cosign trusted-root` | Unsupported. | Create a trusted root. |
| `cosign upload` | Unsupported. | Upload to container registry. |


## Installation

```sh
go install github.com/codysoyland/minsig/cmd/minsig@latest
```

## Usage

### Sign an Artifact

```sh
minsig sign \
    --artifact <path-to-artifact> \
    [--signing-config <path-to-signing-config>] \
```

### Sign an attestation

```sh
minsig sign \
    --attestation <path-to-attestation> \
    [--signing-config <path-to-signing-config>] \
```

### Sign a container image

```sh
minsig sign \
    --artifact <oci-image-ref> \
    [--signing-config <path-to-signing-config>] \
    [--attach]
```

### Sign using private key

```sh
minsig sign \
    --artifact <path-to-artifact> \
    --key <path-to-private-key> \
    [--signing-config <path-to-signing-config>] \
```

### Verify a Signed Artifact

```sh
minsig verify \
    --artifact <path-to-artifact> \
    --certificate-identity <expected-identity> \
    --certificate-oidc-issuer <expected-issuer> \
    [--bundle <path-to-bundle>] \
    [--trusted-root <path-to-trusted-root>]
```


### Verify a Signed Attestation

```sh
minsig verify \
    --attestation=true \
    --certificate-identity <expected-identity> \
    --certificate-oidc-issuer <expected-issuer> \
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

### `minsig sign` flags:

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

### `minsig verify` flags:
| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `--artifact`           | Path to the artifact to verify. Required if attestation is not set to true. |
| `--attestation`        | Bool to indicate if the artifact is an attestation. Required if artifact path is not provided. |
| `--oci`                | Bool to indicate if the artifact is an OCI image. Default is false.         |
| `--bundle`             | Path to the bundle file. If not provided, the bundle will be expected as `FILENAME[.sigstore.json]` in the same directory as the artifact, or as an OCI referring artifact |
| `--certificate-identity` | The expected identity in the certificate subject (e.g. email address). Required if --certificate-identity-regex is not provided. |
| `--certificate-identity-regex` | A regular expression to match the identity in the certificate subject. Required if --certificate-identity is not provided. |
| `--certificate-oidc-issuer` | The expected OIDC issuer for the certificate (e.g. https://accounts.google.com). Required if --certificate-oidc-issuer-regex is not provided. |
| `--certificate-oidc-issuer-regex` | A regular expression to match the OIDC issuer for the certificate. Required if --certificate-oidc-issuer is not provided. |
