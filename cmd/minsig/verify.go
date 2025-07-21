package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
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
			&urfavecli.StringFlag{
				Name:  "public-key",
				Usage: "Path to the public key for verifying key-signed bundles. When provided, certificate identity checks are skipped and transparency log is not required",
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			// Require either artifact path or attestation flag to be provided
			artifactPath := c.String("artifact")
			isAttestation := c.Bool("attestation")
			if artifactPath == "" && !isAttestation {
				return errors.New("either --artifact path or --attestation=true must be provided")
			}

			// Check if public key verification is requested
			publicKeyPath := c.String("public-key")

			// Get certificate verification parameters
			certIdentity := c.String("certificate-identity")
			certIdentityRegex := c.String("certificate-identity-regex")
			certIssuer := c.String("certificate-oidc-issuer")
			certIssuerRegex := c.String("certificate-oidc-issuer-regex")

			// For certificate-based verification, require identity and issuer
			if publicKeyPath == "" {
				// Require either certificate-identity or certificate-identity-regex
				if certIdentity == "" && certIdentityRegex == "" {
					return errors.New("either --certificate-identity or --certificate-identity-regex must be provided (or use --public-key for key-based verification)")
				}

				// Require either certificate-oidc-issuer or certificate-oidc-issuer-regex
				if certIssuer == "" && certIssuerRegex == "" {
					return errors.New("either --certificate-oidc-issuer or --certificate-oidc-issuer-regex must be provided (or use --public-key for key-based verification)")
				}
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

			// For public key verification, expect signed timestamps from TSA
			if publicKeyPath != "" {
				// Public key verification: expect signed timestamps from TSA
				verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))

				// Only add additional requirements if explicitly set
				if c.IsSet("require-sct") && c.Bool("require-sct") {
					return errors.New("Signed Certificate Timestamps (SCT) are not applicable for public key verification")
				}
				if c.IsSet("require-transparency-log") && c.Bool("require-transparency-log") {
					verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
				}
			} else {
				// Certificate-based verification: use defaults
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
			}

			// 3. Configure identity verification
			var identityPolicies []verify.PolicyOption

			if publicKeyPath != "" {
				// Public key verification: use WithKey policy
				identityPolicies = []verify.PolicyOption{verify.WithKey()}
			} else {
				// Certificate-based verification: use certificate identity
				certID, err := verify.NewShortCertificateIdentity(certIssuer, certIssuerRegex, certIdentity, certIdentityRegex)
				if err != nil {
					return fmt.Errorf("failed to create certificate identity: %w", err)
				}
				identityPolicies = []verify.PolicyOption{verify.WithCertificateIdentity(certID)}
			}

			// 4. Set up trusted material
			var trustedMaterial = make(root.TrustedMaterialCollection, 0)

			if publicKeyPath != "" {
				// For public key verification, we still need trusted root for TSA verification
				// but we also add the public key material
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
					tufClient, err := createTUFClient(
						c.String("tuf-url"),
						c.String("tuf-root"),
						c.String("tuf-cache-path"),
						false, // verbose
					)
					if err != nil {
						return err
					}

					trustedRoot, err = root.GetTrustedRoot(tufClient)
					if err != nil {
						return fmt.Errorf("failed to get trusted root from TUF: %w", err)
					}
				}
				trustedMaterial = append(trustedMaterial, trustedRoot)

				// Create trusted public key material for signature verification
				publicKey, err := loadPublicKeyFromFile(publicKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load public key: %w", err)
				}

				// Create trusted public key material using the helper function
				trustedPublicKeyMaterial := trustedPublicKeyMaterial(publicKey)
				trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial)
			} else {
				// Get trusted root for certificate-based verification
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
					tufClient, err := createTUFClient(
						c.String("tuf-url"),
						c.String("tuf-root"),
						c.String("tuf-cache-path"),
						false, // verbose
					)
					if err != nil {
						return err
					}

					trustedRoot, err = root.GetTrustedRoot(tufClient)
					if err != nil {
						return fmt.Errorf("failed to get trusted root from TUF: %w", err)
					}
				}

				trustedMaterial = append(trustedMaterial, trustedRoot)
			}

			if len(trustedMaterial) == 0 {
				return errors.New("no trusted material provided")
			}

			// 5. Create SignedEntityVerifier
			sev, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
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

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}
