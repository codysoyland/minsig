package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	urfavecli "github.com/urfave/cli/v3"
	"google.golang.org/protobuf/encoding/protojson"
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
				Usage: "Bool to indicate if the timestamp should be skipped",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "skip-rekor",
				Usage: "Bool to indicate if the Rekor upload should be skipped",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "attach",
				Usage: "Bool to indicate if the artifact is an OCI image and the signature should be attached to the image",
				Value: false,
			},
			&urfavecli.StringFlag{
				Name:  "output",
				Usage: "Path to write the signature bundle to (defaults to [filename].sigstore.json)",
			},
			&urfavecli.StringFlag{
				Name:  "id-token",
				Usage: "OIDC token to send to Fulcio. If not provided, the web-based flow will be used",
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			// Require either artifact or attestation to be provided
			artifactPath := c.String("artifact")
			attestationPath := c.String("attestation")
			if artifactPath == "" && attestationPath == "" {
				return errors.New("either --artifact or --attestation must be provided")
			}

			// Determine the content to sign
			var content sign.Content
			var data []byte
			var err error
			var signPath string
			var outputPath string

			if artifactPath != "" {
				signPath = artifactPath
				data, err = os.ReadFile(artifactPath)
				if err != nil {
					return fmt.Errorf("failed to read artifact: %w", err)
				}
				content = &sign.PlainData{
					Data: data,
				}
			} else {
				signPath = attestationPath
				data, err = os.ReadFile(attestationPath)
				if err != nil {
					return fmt.Errorf("failed to read attestation: %w", err)
				}
				content = &sign.DSSEData{
					Data:        data,
					PayloadType: "application/vnd.in-toto+json",
				}
			}

			// Determine output path for bundle
			if c.String("output") != "" {
				outputPath = c.String("output")
			} else {
				outputPath = signPath + ".sigstore.json"
			}

			// Setup the keypair
			var keypair sign.Keypair
			keyPath := c.String("key")
			if keyPath != "" {
				// Load private key from file
				privateKey, err := loadPrivateKeyFromFile(keyPath)
				if err != nil {
					return fmt.Errorf("failed to load private key: %w", err)
				}

				// Create keypair from loaded private key
				keypair = NewPrivateKeyKeypair(privateKey)
			} else {
				// Create ephemeral keypair
				keypair, err = sign.NewEphemeralKeypair(nil)
				if err != nil {
					return fmt.Errorf("failed to create ephemeral keypair: %w", err)
				}
			}

			// Get public key
			publicKeyPem, err := keypair.GetPublicKeyPem()
			if err != nil {
				return fmt.Errorf("failed to get public key: %w", err)
			}
			fmt.Printf("Using public key:\n\n%s\n\n", publicKeyPem)

			// Configure the bundle options
			opts := sign.BundleOptions{}

			// Get signing config
			var signingConfig *root.SigningConfig
			signingConfigPath := c.String("signing-config")
			if signingConfigPath != "" {
				signingConfig, err = root.NewSigningConfigFromPath(signingConfigPath)
				if err != nil {
					return fmt.Errorf("failed to read signing config file: %w", err)
				}
			} else {
				// TODO: Add support for getting signing config from TUF
				signingConfig, err = root.NewSigningConfig(
					root.SigningConfigMediaType02,
					// Fulcio URLs
					[]root.Service{
						{
							URL:                 "https://fulcio.sigstore.dev",
							MajorAPIVersion:     1,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
					// OIDC Provider URLs
					[]root.Service{
						{
							URL:                 "https://oauth2.sigstore.dev/auth",
							MajorAPIVersion:     1,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
					// Rekor URLs
					[]root.Service{
						{
							URL:                 "https://rekor.sigstore.dev",
							MajorAPIVersion:     1,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
					root.ServiceConfiguration{
						Selector: v1.ServiceSelector_ANY,
					},
					[]root.Service{
						{
							URL:                 "https://timestamp.githubapp.com/api/v1/timestamp",
							MajorAPIVersion:     1,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
					root.ServiceConfiguration{
						Selector: v1.ServiceSelector_ANY,
					},
				)
				if err != nil {
					return fmt.Errorf("failed to create signing config: %w", err)
				}
			}

			// Only setup certificate provider if no private key is provided
			if keyPath == "" {
				var idToken = c.String("id-token")
				if idToken == "" {
					var issuer = "https://oauth2.sigstore.dev/auth"
					var clientID = "sigstore"
					token, err := oauthflow.OIDConnect(issuer, clientID, "", "", oauthflow.DefaultIDTokenGetter)
					if err != nil {
						return fmt.Errorf("failed to get OIDC token: %w", err)
					}
					idToken = token.RawString
				}
				fulcioURL, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
				if err != nil {
					log.Fatal(err)
				}
				fulcioOpts := &sign.FulcioOptions{
					BaseURL: fulcioURL,
					Timeout: time.Duration(30 * time.Second),
					Retries: 1,
				}
				opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
				opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
					IDToken: idToken,
				}
			}

			// Setup Timestamp Authority
			if !c.Bool("skip-tsa") {
				tsaURLs, err := root.SelectServices(
					signingConfig.TimestampAuthorityURLs(),
					signingConfig.TimestampAuthorityURLsConfig(),
					[]uint32{1}, time.Now(),
				)
				if err != nil {
					return fmt.Errorf("failed to select TSA URLs: %w", err)
				}

				for _, tsaURL := range tsaURLs {
					tsaOpts := &sign.TimestampAuthorityOptions{
						URL:     tsaURL,
						Timeout: 30 * time.Second,
						Retries: 1,
					}
					opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
				}
			}

			// Setup Rekor transparency log (only when using ephemeral keys with certificates)
			if !c.Bool("skip-rekor") && keyPath == "" {
				rekorURLs, err := root.SelectServices(
					signingConfig.RekorLogURLs(),
					signingConfig.RekorLogURLsConfig(),
					[]uint32{1}, time.Now(),
				)
				if err != nil {
					return fmt.Errorf("failed to select Rekor URLs: %w", err)
				}

				for _, rekorURL := range rekorURLs {
					rekorOpts := &sign.RekorOptions{
						BaseURL: rekorURL,
						Timeout: 90 * time.Second,
						Retries: 1,
					}
					opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
				}
			}

			// Create the bundle
			bundle, err := sign.Bundle(content, keypair, opts)
			if err != nil {
				return fmt.Errorf("failed to create signature bundle: %w", err)
			}

			// Marshal the bundle to JSON
			bundleJSON, err := protojson.Marshal(bundle)
			if err != nil {
				return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
			}

			// Write the bundle to file
			if err := os.WriteFile(outputPath, bundleJSON, 0644); err != nil {
				return fmt.Errorf("failed to write bundle to file: %w", err)
			}

			fmt.Printf("Successfully signed %s\n", signPath)
			fmt.Printf("Signature bundle written to %s\n", outputPath)

			// Handle attachment if necessary
			if c.Bool("attach") && artifactPath != "" {
				fmt.Println("OCI image attachment feature not yet implemented")
				// TODO: Implement OCI image attachment
			}

			return nil
		},
	}
}
