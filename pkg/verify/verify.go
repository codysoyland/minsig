package verify

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Verifier provides artifact verification functionality
type Verifier interface {
	Verify(ctx context.Context, opts Options) (*verify.VerificationResult, error)
}

// verifier implements the Verifier interface
type verifier struct{}

// New creates a new Verifier instance
func New() Verifier {
	return &verifier{}
}

// Verify verifies a signed artifact according to the provided options
func (v *verifier) Verify(ctx context.Context, opts Options) (*verify.VerificationResult, error) {
	// 1. Validate options
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	// 2. Load bundle
	bundle, err := loadBundle(opts)
	if err != nil {
		return nil, err
	}

	// 3. Setup verifier configuration
	verifierConfig, err := setupVerifierConfig(opts)
	if err != nil {
		return nil, err
	}

	// 4. Setup identity policies
	identityPolicies, err := setupIdentityPolicies(opts)
	if err != nil {
		return nil, err
	}

	// 5. Build trusted material
	trustedMaterial, err := buildTrustedMaterial(opts)
	if err != nil {
		return nil, err
	}

	// 6. Create verifier
	sev, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed entity verifier: %w", err)
	}

	// 7. Setup artifact policy
	artifactPolicy, err := setupArtifactPolicy(opts)
	if err != nil {
		return nil, err
	}

	// 8. Verify and return result directly
	verificationResult, err := sev.Verify(bundle, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	// Return the sigstore-go verification result directly
	return verificationResult, nil
}

// validateOptions validates the verification options
func validateOptions(opts Options) error {
	// Require either artifact path or attestation flag to be provided
	if opts.ArtifactPath == "" && !opts.IsAttestation {
		return errors.New("either artifact path or attestation flag must be provided")
	}

	// Check certificate verification parameters
	publicKeyPath := opts.PublicKeyPath

	// For certificate-based verification, require identity and issuer
	if publicKeyPath == "" {
		// Require either certificate-identity or certificate-identity-regex
		if opts.CertificateIdentity == "" && opts.CertificateIdentityRegex == "" {
			return errors.New("either certificate identity or certificate identity regex must be provided (or use public key for key-based verification)")
		}

		// Require either certificate-oidc-issuer or certificate-oidc-issuer-regex
		if opts.CertificateIssuer == "" && opts.CertificateIssuerRegex == "" {
			return errors.New("either certificate issuer or certificate issuer regex must be provided (or use public key for key-based verification)")
		}
	}

	// Trusted root is required
	if opts.TrustedRoot == nil {
		return errors.New("trusted root is required")
	}

	return nil
}

// loadBundle loads the bundle from the specified path
func loadBundle(opts Options) (*bundle.Bundle, error) {
	bundlePath := opts.BundlePath
	if bundlePath == "" && opts.ArtifactPath != "" {
		bundlePath = opts.ArtifactPath + ".sigstore.json"
	}

	if bundlePath == "" {
		return nil, errors.New("bundle path must be provided")
	}

	bundle, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load bundle from %s: %w", bundlePath, err)
	}

	return bundle, nil
}

// setupVerifierConfig creates the verifier configuration
func setupVerifierConfig(opts Options) ([]verify.VerifierOption, error) {
	var verifierConfig []verify.VerifierOption

	// For public key verification, expect signed timestamps from TSA
	if opts.PublicKeyPath != "" {
		// Public key verification: expect signed timestamps from TSA
		verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))

		// Only add additional requirements if NOT ignored
		if !opts.IgnoreSCT {
			return nil, errors.New("Signed Certificate Timestamps (SCT) are not applicable for public key verification")
		}
		if !opts.IgnoreTransparencyLog {
			verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
		}
	} else {
		// Certificate-based verification: use requirements
		// Add SCT requirement if NOT ignored
		if !opts.IgnoreSCT {
			verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))
		}

		// Add timestamp requirement if NOT ignored
		if !opts.IgnoreTimestamp {
			verifierConfig = append(verifierConfig, verify.WithObserverTimestamps(1))
		}

		// Add transparency log requirement if NOT ignored
		if !opts.IgnoreTransparencyLog {
			verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
		}
	}

	return verifierConfig, nil
}

// setupIdentityPolicies creates the identity verification policies
func setupIdentityPolicies(opts Options) ([]verify.PolicyOption, error) {
	var identityPolicies []verify.PolicyOption

	if opts.PublicKeyPath != "" {
		// Public key verification: use WithKey policy
		identityPolicies = []verify.PolicyOption{verify.WithKey()}
	} else {
		// Certificate-based verification: use certificate identity
		certID, err := verify.NewShortCertificateIdentity(
			opts.CertificateIssuer,
			opts.CertificateIssuerRegex,
			opts.CertificateIdentity,
			opts.CertificateIdentityRegex,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate identity: %w", err)
		}
		identityPolicies = []verify.PolicyOption{verify.WithCertificateIdentity(certID)}
	}

	return identityPolicies, nil
}

// buildTrustedMaterial creates the trusted material collection
func buildTrustedMaterial(opts Options) (root.TrustedMaterialCollection, error) {
	var trustedMaterial = make(root.TrustedMaterialCollection, 0)

	if opts.PublicKeyPath != "" {
		// For public key verification, we need both trusted root and public key material
		trustedMaterial = append(trustedMaterial, opts.TrustedRoot)

		// Create trusted public key material for signature verification
		publicKey, err := loadPublicKey(opts.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key: %w", err)
		}

		// Create trusted public key material using the helper function
		trustedPublicKeyMaterial := trustedPublicKeyMaterial(publicKey)
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial)
	} else {
		// Certificate-based verification: use trusted root
		trustedMaterial = append(trustedMaterial, opts.TrustedRoot)
	}

	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material provided")
	}

	return trustedMaterial, nil
}

// setupArtifactPolicy creates the artifact verification policy
func setupArtifactPolicy(opts Options) (verify.ArtifactPolicyOption, error) {
	if opts.ArtifactPath != "" {
		file, err := os.Open(opts.ArtifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open artifact file: %w", err)
		}
		defer file.Close()
		return verify.WithArtifact(file), nil
	} else {
		return verify.WithoutArtifactUnsafe(), nil
	}
}