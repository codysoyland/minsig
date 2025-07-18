package main

import (
	"context"
	"fmt"

	"github.com/codysoyland/minsig/pkg/sign"
	"github.com/codysoyland/minsig/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/root"
	urfavecli "github.com/urfave/cli/v3"
)

// SignCommand returns the CLI command for signing artifacts
func SignCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "sign",
		Usage: "Sign an artifact",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:  "artifact",
				Usage: "Path to the artifact to sign. Required if attestation is not provided",
			},
			&urfavecli.StringFlag{
				Name:  "attestation",
				Usage: "Path to the attestation to sign. Required if artifact is not provided",
			},
			&urfavecli.StringFlag{
				Name:  "key",
				Usage: "Path to the private key to use for signing. Supports PEM-encoded PKCS#1 (RSA), PKCS#8 (RSA/ECDSA), and SEC 1 (ECDSA) formats. When provided, no certificate will be requested",
			},
			&urfavecli.BoolFlag{
				Name:  "skip-tsa",
				Usage: "Skip timestamp authority",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "skip-rekor",
				Usage: "Skip Rekor transparency log",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "attach",
				Usage: "Attach signature to OCI image",
				Value: false,
			},
			&urfavecli.StringFlag{
				Name:  "output",
				Usage: "Output path for signature bundle",
			},
			&urfavecli.StringFlag{
				Name:  "id-token",
				Usage: "OIDC ID token",
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			// 1. Get trusted materials using TUF package
			trustedRoot, signingConfig, err := getTrustedMaterials(ctx, c)
			if err != nil {
				return fmt.Errorf("failed to get trusted materials: %w", err)
			}

			// 2. Build options from CLI flags
			opts := buildSignOptions(c, trustedRoot, signingConfig)

			// 3. Create signer and sign
			signer := sign.New()
			result, err := signer.Sign(ctx, opts)
			if err != nil {
				return fmt.Errorf("signing failed: %w", err)
			}

			// 4. Display results
			displaySignResults(result)

			return nil
		},
	}
}

// getTrustedMaterials fetches trusted root and signing config using TUF
func getTrustedMaterials(ctx context.Context, c *urfavecli.Command) (*root.TrustedRoot, *root.SigningConfig, error) {
	// Create TUF client
	tufClient, err := tuf.New(tuf.Options{
		URL:       c.String("tuf-url"),
		RootPath:  c.String("tuf-root"),
		CachePath: c.String("tuf-cache-path"),
		CacheTTL:  c.Duration("tuf-cache-ttl"),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	defer tufClient.Close()

	// Get trusted root
	trustedRoot, err := tufClient.GetTrustedRoot(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	// Get signing config
	signingConfig, err := tufClient.GetSigningConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing config: %w", err)
	}

	return trustedRoot, signingConfig, nil
}

// buildSignOptions converts CLI flags to sign.Options
func buildSignOptions(c *urfavecli.Command, trustedRoot *root.TrustedRoot, signingConfig *root.SigningConfig) sign.Options {
	return sign.Options{
		ArtifactPath:    c.String("artifact"),
		AttestationPath: c.String("attestation"),
		PrivateKeyPath:  c.String("key"),
		OutputPath:      c.String("output"),
		AttachToImage:   c.Bool("attach"),
		SkipTSA:         c.Bool("skip-tsa"),
		SkipRekor:       c.Bool("skip-rekor"),
		IDToken:         c.String("id-token"),
		TrustedRoot:     trustedRoot,
		SigningConfig:   signingConfig,
	}
}

// displaySignResults shows the signing results to the user
func displaySignResults(result *sign.Result) {
	fmt.Printf("Using public key:\n\n%s\n\n", result.PublicKeyPEM)
	fmt.Printf("Successfully signed artifact\n")
	fmt.Printf("Signature bundle written to %s\n", result.BundlePath)
}