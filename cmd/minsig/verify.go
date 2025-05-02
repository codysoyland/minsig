package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	urfavecli "github.com/urfave/cli/v3"
)

// VerifyCommand returns the CLI command for verifying artifacts
func VerifyCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "verify",
		Usage: "Verify a signed artifact",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:  "artifact",
				Usage: "Path to the artifact to verify. Required if attestation is not set to true",
			},
			&urfavecli.BoolFlag{
				Name:  "attestation",
				Usage: "Bool to indicate if the artifact is an attestation. Required if artifact path is not provided",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "oci",
				Usage: "Bool to indicate if the artifact is an OCI image",
				Value: false,
			},
			&urfavecli.StringFlag{
				Name:  "bundle",
				Usage: "Path to the bundle file. If not provided, the bundle will be expected as FILENAME[.sigstore.json]",
			},
			&urfavecli.StringFlag{
				Name:  "certificate-identity",
				Usage: "The expected identity in the certificate subject (e.g. email address). Required if --certificate-identity-regex is not provided.",
			},
			&urfavecli.StringFlag{
				Name:  "certificate-identity-regex",
				Usage: "A regular expression to match the identity in the certificate subject. Required if --certificate-identity is not provided.",
			},
			&urfavecli.StringFlag{
				Name:  "certificate-oidc-issuer",
				Usage: "The expected OIDC issuer for the certificate (e.g. https://accounts.google.com). Required if --certificate-oidc-issuer-regex is not provided.",
			},
			&urfavecli.StringFlag{
				Name:  "certificate-oidc-issuer-regex",
				Usage: "A regular expression to match the OIDC issuer for the certificate. Required if --certificate-oidc-issuer is not provided.",
			},
			&urfavecli.BoolFlag{
				Name:  "require-sct",
				Usage: "Require a Signed Certificate Timestamp",
				Value: true,
			},
			&urfavecli.BoolFlag{
				Name:  "require-timestamp",
				Usage: "Require a timestamp",
				Value: true,
			},
			&urfavecli.BoolFlag{
				Name:  "require-transparency-log",
				Usage: "Require a transparency log entry (Rekor)",
				Value: true,
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			// Require either artifact path or attestation flag to be provided
			artifactPath := c.String("artifact")
			isAttestation := c.Bool("attestation")
			if artifactPath == "" && !isAttestation {
				return errors.New("either --artifact path or --attestation=true must be provided")
			}

			// Require either certificate-identity or certificate-identity-regex
			certIdentity := c.String("certificate-identity")
			certIdentityRegex := c.String("certificate-identity-regex")
			if certIdentity == "" && certIdentityRegex == "" {
				return errors.New("either --certificate-identity or --certificate-identity-regex must be provided")
			}

			// Require either certificate-oidc-issuer or certificate-oidc-issuer-regex
			certIssuer := c.String("certificate-oidc-issuer")
			certIssuerRegex := c.String("certificate-oidc-issuer-regex")
			if certIssuer == "" && certIssuerRegex == "" {
				return errors.New("either --certificate-oidc-issuer or --certificate-oidc-issuer-regex must be provided")
			}

			// Determine bundle path
			bundlePath := c.String("bundle")
			if bundlePath == "" && artifactPath != "" {
				bundlePath = artifactPath + ".sigstore.json"
			}

			// 1. Load bundle from file
			b, err := bundle.LoadJSONFromPath(bundlePath)
			if err != nil {
				return fmt.Errorf("failed to load bundle from %s: %w", bundlePath, err)
			}

			// 2. Set up verifier configuration
			verifierConfig := []verify.VerifierOption{}

			// Add SCT requirement if specified
			if c.Bool("require-sct") {
				verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))
			}

			// Add timestamp requirement if specified
			if c.Bool("require-timestamp") {
				verifierConfig = append(verifierConfig, verify.WithObserverTimestamps(1))
			}

			// Add transparency log requirement if specified
			if c.Bool("require-transparency-log") {
				verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
			}

			// 3. Configure identity verification
			certID, err := verify.NewShortCertificateIdentity(certIssuer, certIssuerRegex, certIdentity, certIdentityRegex)
			if err != nil {
				return fmt.Errorf("failed to create certificate identity: %w", err)
			}
			identityPolicies := []verify.PolicyOption{verify.WithCertificateIdentity(certID)}

			// 4. Set up trusted material
			var trustedMaterial = make(root.TrustedMaterialCollection, 0)

			// Get trusted root
			var trustedRoot *root.TrustedRoot
			trustedRootPath := c.String("trusted-root")
			if trustedRootPath != "" {
				// Use provided trusted root file
				trustedRootBytes, err := os.ReadFile(trustedRootPath)
				if err != nil {
					return fmt.Errorf("failed to read trusted root file: %w", err)
				}
				trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootBytes)
				if err != nil {
					return fmt.Errorf("failed to parse trusted root file: %w", err)
				}
			} else {
				// Get from TUF
				tufURL := c.String("tuf-url")
				tufRoot := c.String("tuf-root")
				tufCachePath := c.String("tuf-cache-path")

				// Expand ~ to home directory in cache path
				if tufCachePath[:1] == "~" {
					home, err := os.UserHomeDir()
					if err != nil {
						return fmt.Errorf("failed to get home directory: %w", err)
					}
					tufCachePath = filepath.Join(home, tufCachePath[1:])
				}

				// Setup TUF options
				tufOptions := &tuf.Options{
					RepositoryBaseURL: tufURL,
					CachePath:         tufCachePath,
				}

				// Setup TUF fetcher
				fetcher := fetcher.DefaultFetcher{}
				fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
				tufOptions.Fetcher = &fetcher

				// If custom root file provided
				if tufRoot != "" {
					rootBytes, err := os.ReadFile(tufRoot)
					if err != nil {
						return fmt.Errorf("failed to read TUF root file: %w", err)
					}
					tufOptions.Root = rootBytes
				} else {
					tufOptions.Root = tuf.DefaultRoot()
				}

				// Get TUF client
				tufClient, err := tuf.New(tufOptions)
				if err != nil {
					return fmt.Errorf("failed to create TUF client: %w", err)
				}

				trustedRoot, err = root.GetTrustedRoot(tufClient)
				if err != nil {
					return fmt.Errorf("failed to get trusted root from TUF: %w", err)
				}
			}

			trustedMaterial = append(trustedMaterial, trustedRoot)

			if len(trustedMaterial) == 0 {
				return errors.New("no trusted material provided")
			}

			// 5. Create SignedEntityVerifier
			sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
			if err != nil {
				return fmt.Errorf("failed to create signed entity verifier: %w", err)
			}

			// 6. Verify the signature against the artifact
			var artifactPolicy verify.ArtifactPolicyOption

			if artifactPath != "" {
				file, err := os.Open(artifactPath)
				if err != nil {
					return fmt.Errorf("failed to open artifact file: %w", err)
				}
				defer file.Close()
				artifactPolicy = verify.WithArtifact(file)
			} else {
				artifactPolicy = verify.WithoutArtifactUnsafe()
				fmt.Println("Warning: No artifact provided for verification")
			}

			// 7. Verify and return result
			verificationResult, err := sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}

			// Marshal and print verification result
			fmt.Println("Verification successful!")
			resultJSON, err := json.MarshalIndent(verificationResult, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal verification result: %w", err)
			}
			fmt.Println(string(resultJSON))

			return nil
		},
	}
}
