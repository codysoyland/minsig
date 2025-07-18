package sign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"google.golang.org/protobuf/encoding/protojson"
)

// Signer provides artifact signing functionality
type Signer interface {
	Sign(ctx context.Context, opts Options) (*Result, error)
}

// signer implements the Signer interface
type signer struct{}

// New creates a new Signer instance
func New() Signer {
	return &signer{}
}

// Sign signs an artifact or attestation according to the provided options
func (s *signer) Sign(ctx context.Context, opts Options) (*Result, error) {
	// 1. Validate options
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	// 2. Load content (artifact or attestation)
	content, contentPath, err := loadContent(opts)
	if err != nil {
		return nil, err
	}

	// 3. Setup keypair (private key or ephemeral based on PrivateKeyPath)
	keypair, err := setupKeypair(opts)
	if err != nil {
		return nil, err
	}

	// 4. Use provided trusted materials (no TUF fetching here)
	if opts.TrustedRoot == nil {
		return nil, errors.New("trusted root is required")
	}

	// 5. Create signer and sign
	bundle, err := createSignedBundle(ctx, content, keypair, opts)
	if err != nil {
		return nil, err
	}

	// 6. Write bundle
	outputPath := determineOutputPath(opts, contentPath)
	if err := writeBundle(bundle, outputPath); err != nil {
		return nil, err
	}

	// 7. Return result
	publicKeyPEM, err := getPublicKeyPEM(keypair)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return &Result{
		BundlePath:   outputPath,
		Bundle:       bundle,
		PublicKeyPEM: publicKeyPEM,
		KeyAlgorithm: getKeyAlgorithm(keypair),
	}, nil
}

// validateOptions validates the signing options
func validateOptions(opts Options) error {
	// Require either artifact or attestation to be provided
	if opts.ArtifactPath == "" && opts.AttestationPath == "" {
		return errors.New("either artifact path or attestation path must be provided")
	}

	// Both artifact and attestation cannot be provided at the same time
	if opts.ArtifactPath != "" && opts.AttestationPath != "" {
		return errors.New("cannot provide both artifact path and attestation path")
	}

	return nil
}

// loadContent loads the content to be signed
func loadContent(opts Options) (sign.Content, string, error) {
	var content sign.Content
	var data []byte
	var err error
	var contentPath string

	if opts.ArtifactPath != "" {
		contentPath = opts.ArtifactPath
		data, err = os.ReadFile(opts.ArtifactPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read artifact: %w", err)
		}
		content = &sign.PlainData{
			Data: data,
		}
	} else {
		contentPath = opts.AttestationPath
		data, err = os.ReadFile(opts.AttestationPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read attestation: %w", err)
		}
		content = &sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	}

	return content, contentPath, nil
}

// setupKeypair creates a keypair from the options
func setupKeypair(opts Options) (sign.Keypair, error) {
	// If PrivateKeyPath is provided, load it; otherwise create ephemeral
	if opts.PrivateKeyPath != "" {
		privateKey, err := loadPrivateKey(opts.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		return NewPrivateKeyKeypair(privateKey), nil
	}
	
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral keypair: %w", err)
	}
	return keypair, nil
}

// createSignedBundle creates a signed bundle using the provided parameters
func createSignedBundle(ctx context.Context, content sign.Content, keypair sign.Keypair, opts Options) (*protobundle.Bundle, error) {
	// Configure the bundle options
	bundleOpts := sign.BundleOptions{}

	// Only setup certificate provider if no private key is provided (ephemeral key)
	if opts.PrivateKeyPath == "" {
		var idToken = opts.IDToken
		if idToken == "" {
			// Get OIDC issuer from signing config
			oidcIssuer, err := root.SelectService(opts.SigningConfig.OIDCProviderURLs(), []uint32{1}, time.Now())
			if err != nil {
				return nil, fmt.Errorf("failed to select OIDC issuer: %w", err)
			}

			var clientID = "sigstore"
			token, err := oauthflow.OIDConnect(oidcIssuer, clientID, "", "", oauthflow.DefaultIDTokenGetter)
			if err != nil {
				return nil, fmt.Errorf("failed to get OIDC token: %w", err)
			}
			idToken = token.RawString
		}
		
		fulcioURL, err := root.SelectService(opts.SigningConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to select Fulcio URL: %w", err)
		}
		
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: fulcioURL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		bundleOpts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: idToken,
		}
	}

	// Setup Timestamp Authority
	if !opts.SkipTSA {
		tsaURLs, err := root.SelectServices(
			opts.SigningConfig.TimestampAuthorityURLs(),
			opts.SigningConfig.TimestampAuthorityURLsConfig(),
			[]uint32{1}, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to select TSA URLs: %w", err)
		}

		for _, tsaURL := range tsaURLs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL,
				Timeout: 30 * time.Second,
				Retries: 1,
			}
			bundleOpts.TimestampAuthorities = append(bundleOpts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
		}
	}

	// Setup Rekor transparency log (only when using ephemeral keys with certificates)
	if !opts.SkipRekor && opts.PrivateKeyPath == "" {
		rekorURLs, err := root.SelectServices(
			opts.SigningConfig.RekorLogURLs(),
			opts.SigningConfig.RekorLogURLsConfig(),
			[]uint32{1}, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to select Rekor URLs: %w", err)
		}

		for _, rekorURL := range rekorURLs {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: 90 * time.Second,
				Retries: 1,
			}
			bundleOpts.TransparencyLogs = append(bundleOpts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	// Create the bundle
	bundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature bundle: %w", err)
	}

	return bundle, nil
}

// determineOutputPath determines the output path for the bundle
func determineOutputPath(opts Options, contentPath string) string {
	if opts.OutputPath != "" {
		return opts.OutputPath
	}
	return contentPath + ".sigstore.json"
}

// writeBundle writes the bundle to the specified path
func writeBundle(bundle *protobundle.Bundle, outputPath string) error {
	// Marshal the bundle to JSON
	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	// Write the bundle to file
	if err := os.WriteFile(outputPath, bundleJSON, 0644); err != nil {
		return fmt.Errorf("failed to write bundle to file: %w", err)
	}

	return nil
}

// getPublicKeyPEM gets the public key in PEM format from the keypair
func getPublicKeyPEM(keypair sign.Keypair) (string, error) {
	// Check if it's our custom keypair implementation
	if privateKeypair, ok := keypair.(*PrivateKeyKeypair); ok {
		return privateKeypair.GetPublicKeyPem()
	}

	// For ephemeral keypairs, we need to use the sigstore-go method
	// This is a placeholder - we'd need to implement this properly
	return "", fmt.Errorf("cannot get public key PEM for ephemeral keypair")
}

// getKeyAlgorithm gets the key algorithm from the keypair
func getKeyAlgorithm(keypair sign.Keypair) string {
	// Check if it's our custom keypair implementation
	if privateKeypair, ok := keypair.(*PrivateKeyKeypair); ok {
		return privateKeypair.GetKeyAlgorithm()
	}

	// For ephemeral keypairs, assume ECDSA
	return "ecdsa"
}