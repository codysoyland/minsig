package main

import (
	"context"
	"errors"
	"fmt"
	"log"

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
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			// Require either artifact path or attestation flag to be provided
			artifact := c.String("artifact")
			isAttestation := c.Bool("attestation")
			if artifact == "" && !isAttestation {
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

			fmt.Println("=== Verify Command Arguments ===")
			fmt.Printf("Artifact path: %s\n", artifact)
			fmt.Printf("Is attestation: %t\n", isAttestation)
			fmt.Printf("Is OCI image: %t\n", c.Bool("oci"))
			fmt.Printf("Bundle path: %s\n", c.String("bundle"))

			// Print certificate identity info
			if certIdentity != "" {
				fmt.Printf("Certificate Identity: %s\n", certIdentity)
			}
			if certIdentityRegex != "" {
				fmt.Printf("Certificate Identity Regex: %s\n", certIdentityRegex)
			}

			// Print certificate issuer info
			if certIssuer != "" {
				fmt.Printf("Certificate OIDC Issuer: %s\n", certIssuer)
			}
			if certIssuerRegex != "" {
				fmt.Printf("Certificate OIDC Issuer Regex: %s\n", certIssuerRegex)
			}

			// Global flags
			fmt.Printf("TUF URL: %s\n", c.String("tuf-url"))
			fmt.Printf("TUF Root: %s\n", c.String("tuf-root"))
			fmt.Printf("TUF Cache Path: %s\n", c.String("tuf-cache-path"))
			fmt.Printf("TUF Cache TTL: %s\n", c.Duration("tuf-cache-ttl"))
			fmt.Printf("Signing Config: %s\n", c.String("signing-config"))
			fmt.Printf("Trusted Root: %s\n", c.String("trusted-root"))

			fmt.Println("============================")

			log.Println("Verifying artifact...")
			return nil
		},
	}
}
