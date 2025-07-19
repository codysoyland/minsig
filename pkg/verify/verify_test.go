package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestValidateOptions(t *testing.T) {
	// Create a mock trusted root for testing
	mockTrustedRoot := &root.TrustedRoot{}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		errorMsg    string
	}{
		{
			name: "no artifact or attestation",
			opts: Options{
				TrustedRoot: mockTrustedRoot,
			},
			expectError: true,
			errorMsg:    "either artifact path or attestation flag must be provided",
		},
		{
			name: "artifact without certificate verification params",
			opts: Options{
				ArtifactPath: "test.txt",
				TrustedRoot:  mockTrustedRoot,
			},
			expectError: true,
			errorMsg:    "either certificate identity or certificate identity regex must be provided (or use public key for key-based verification)",
		},
		{
			name: "artifact with certificate identity but no issuer",
			opts: Options{
				ArtifactPath:        "test.txt",
				CertificateIdentity: "test@example.com",
				TrustedRoot:         mockTrustedRoot,
			},
			expectError: true,
			errorMsg:    "either certificate issuer or certificate issuer regex must be provided (or use public key for key-based verification)",
		},
		{
			name: "artifact with public key verification",
			opts: Options{
				ArtifactPath:  "test.txt",
				PublicKeyPath: "key.pem",
				TrustedRoot:   mockTrustedRoot,
			},
			expectError: false,
		},
		{
			name: "artifact with certificate verification",
			opts: Options{
				ArtifactPath:        "test.txt",
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
				TrustedRoot:         mockTrustedRoot,
			},
			expectError: false,
		},
		{
			name: "attestation verification",
			opts: Options{
				IsAttestation:       true,
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
				TrustedRoot:         mockTrustedRoot,
			},
			expectError: false,
		},
		{
			name: "missing trusted root",
			opts: Options{
				ArtifactPath:        "test.txt",
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
			},
			expectError: true,
			errorMsg:    "trusted root is required",
		},
		{
			name: "certificate identity regex without issuer",
			opts: Options{
				ArtifactPath:             "test.txt",
				CertificateIdentityRegex: ".*@example.com",
				TrustedRoot:              mockTrustedRoot,
			},
			expectError: true,
			errorMsg:    "either certificate issuer or certificate issuer regex must be provided (or use public key for key-based verification)",
		},
		{
			name: "certificate issuer regex without identity",
			opts: Options{
				ArtifactPath:           "test.txt",
				CertificateIssuerRegex: "https://.*\\.google\\.com",
				TrustedRoot:            mockTrustedRoot,
			},
			expectError: true,
			errorMsg:    "either certificate identity or certificate identity regex must be provided (or use public key for key-based verification)",
		},
		{
			name: "certificate verification with regex patterns",
			opts: Options{
				ArtifactPath:             "test.txt",
				CertificateIdentityRegex: ".*@example.com",
				CertificateIssuerRegex:   "https://.*\\.google\\.com",
				TrustedRoot:              mockTrustedRoot,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOptions(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLoadBundle(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test bundle file
	bundlePath := filepath.Join(tempDir, "test.sigstore.json")
	bundleData := []byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": []
			}
		},
		"messageSignature": {
			"messageDigest": {
				"algorithm": "SHA2_256",
				"digest": "dGVzdA=="
			},
			"signature": "dGVzdA=="
		}
	}`)
	if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
		t.Fatalf("Failed to create test bundle: %v", err)
	}

	// Create a test artifact
	artifactPath := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(artifactPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "explicit bundle path",
			opts: Options{
				BundlePath: bundlePath,
			},
			expectError: false,
			description: "should load bundle from explicit path",
		},
		{
			name: "implicit bundle path from artifact",
			opts: Options{
				ArtifactPath: artifactPath,
			},
			expectError: false,
			description: "should derive bundle path from artifact path",
		},
		{
			name: "non-existent bundle",
			opts: Options{
				BundlePath: filepath.Join(tempDir, "nonexistent.sigstore.json"),
			},
			expectError: true,
			description: "should fail for non-existent bundle",
		},
		{
			name: "no bundle or artifact path",
			opts: Options{
				IsAttestation: true,
			},
			expectError: true,
			description: "should fail when no bundle path can be determined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the implicit bundle path test, create the expected bundle file
			if tt.name == "implicit bundle path from artifact" {
				implicitBundlePath := artifactPath + ".sigstore.json"
				if err := os.WriteFile(implicitBundlePath, bundleData, 0644); err != nil {
					t.Fatalf("Failed to create implicit bundle: %v", err)
				}
			}

			bundle, err := loadBundle(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if bundle == nil {
				t.Errorf("Bundle is nil for %s", tt.description)
			}
		})
	}
}

func TestSetupVerifierConfig(t *testing.T) {
	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "public key verification",
			opts: Options{
				PublicKeyPath: "key.pem",
				IgnoreSCT:     true, // SCT is not applicable for public key verification
			},
			expectError: false,
			description: "should setup config for public key verification",
		},
		{
			name: "certificate verification with all requirements",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
			},
			expectError: false,
			description: "should setup config for certificate verification",
		},
		{
			name: "certificate verification ignoring SCT",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
				IgnoreSCT:           true,
			},
			expectError: false,
			description: "should setup config ignoring SCT",
		},
		{
			name: "certificate verification ignoring timestamp",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
				IgnoreTimestamp:     true,
			},
			expectError: false,
			description: "should setup config ignoring timestamp",
		},
		{
			name: "certificate verification ignoring transparency log",
			opts: Options{
				CertificateIdentity:   "test@example.com",
				CertificateIssuer:     "https://accounts.google.com",
				IgnoreTransparencyLog: true,
			},
			expectError: false,
			description: "should setup config ignoring transparency log",
		},
		{
			name: "public key verification with SCT should error",
			opts: Options{
				PublicKeyPath: "key.pem",
				IgnoreSCT:     false,
			},
			expectError: true,
			description: "should error when trying to use SCT with public key verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := setupVerifierConfig(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if config == nil {
				t.Errorf("Config is nil for %s", tt.description)
			}
		})
	}
}

func TestSetupIdentityPolicies(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test public key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	publicKey := &ecdsaKey.PublicKey
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})

	keyPath := filepath.Join(tempDir, "test_key.pem")
	if err := os.WriteFile(keyPath, keyPem, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "public key verification",
			opts: Options{
				PublicKeyPath: keyPath,
			},
			expectError: false,
			description: "should setup policy for public key verification",
		},
		{
			name: "certificate verification with identity and issuer",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
			},
			expectError: false,
			description: "should setup policy for certificate verification",
		},
		{
			name: "certificate verification with regex patterns",
			opts: Options{
				CertificateIdentityRegex: ".*@example.com",
				CertificateIssuerRegex:   "https://.*\\.google\\.com",
			},
			expectError: false,
			description: "should setup policy for certificate verification with regex",
		},
		{
			name: "certificate verification with mixed identity types",
			opts: Options{
				CertificateIdentity:      "test@example.com",
				CertificateIssuerRegex:   "https://.*\\.google\\.com",
			},
			expectError: false,
			description: "should setup policy for certificate verification with mixed identity types",
		},
		{
			name: "non-existent public key",
			opts: Options{
				PublicKeyPath: filepath.Join(tempDir, "nonexistent.pem"),
			},
			expectError: false, // setupIdentityPolicies doesn't load the key, just sets up the policy
			description: "should setup policy even for non-existent public key (key loading happens later)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := setupIdentityPolicies(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if policies == nil {
				t.Errorf("Policies is nil for %s", tt.description)
			}

			if len(policies) == 0 {
				t.Errorf("No policies returned for %s", tt.description)
			}
		})
	}
}

func TestSetupArtifactPolicy(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test artifact
	artifactPath := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(artifactPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "with artifact",
			opts: Options{
				ArtifactPath: artifactPath,
			},
			expectError: false,
			description: "should setup policy with artifact",
		},
		{
			name: "without artifact (attestation)",
			opts: Options{
				IsAttestation: true,
			},
			expectError: false,
			description: "should setup policy without artifact for attestation",
		},
		{
			name: "non-existent artifact",
			opts: Options{
				ArtifactPath: filepath.Join(tempDir, "nonexistent.txt"),
			},
			expectError: true,
			description: "should fail for non-existent artifact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := setupArtifactPolicy(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if policy == nil {
				t.Errorf("Policy is nil for %s", tt.description)
			}
		})
	}
}

func TestBuildTrustedMaterial(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test public key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	publicKey := &ecdsaKey.PublicKey
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})

	keyPath := filepath.Join(tempDir, "test_key.pem")
	if err := os.WriteFile(keyPath, keyPem, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create a mock trusted root
	mockTrustedRoot := &root.TrustedRoot{}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "public key verification",
			opts: Options{
				PublicKeyPath: keyPath,
				TrustedRoot:   mockTrustedRoot,
			},
			expectError: false,
			description: "should build trusted material for public key verification",
		},
		{
			name: "certificate verification",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
				TrustedRoot:         mockTrustedRoot,
			},
			expectError: false,
			description: "should build trusted material for certificate verification",
		},
		{
			name: "no trusted root",
			opts: Options{
				CertificateIdentity: "test@example.com",
				CertificateIssuer:   "https://accounts.google.com",
			},
			expectError: false, // buildTrustedMaterial doesn't validate TrustedRoot presence, just creates collection
			description: "should create empty trusted material without trusted root",
		},
		{
			name: "non-existent public key",
			opts: Options{
				PublicKeyPath: filepath.Join(tempDir, "nonexistent.pem"),
				TrustedRoot:   mockTrustedRoot,
			},
			expectError: true,
			description: "should fail for non-existent public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material, err := buildTrustedMaterial(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if material == nil {
				t.Errorf("Material is nil for %s", tt.description)
			}

			if len(material) == 0 {
				t.Errorf("No trusted material returned for %s", tt.description)
			}
		})
	}
}

func TestVerifierInterface(t *testing.T) {
	// Test that our verifier implements the interface
	var _ Verifier = &verifier{}
	
	// Test New() function
	v := New()
	if v == nil {
		t.Error("New() returned nil verifier")
	}
	
	// Verify it's the right type
	if _, ok := v.(*verifier); !ok {
		t.Errorf("New() returned %T, expected *verifier", v)
	}
}

func TestVerifyValidationFlow(t *testing.T) {
	tempDir := t.TempDir()

	// Create test bundle
	bundlePath := filepath.Join(tempDir, "test.sigstore.json")
	bundleData := []byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": []
			}
		},
		"messageSignature": {
			"messageDigest": {
				"algorithm": "SHA2_256",
				"digest": "dGVzdA=="
			},
			"signature": "dGVzdA=="
		}
	}`)
	if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
		t.Fatalf("Failed to create test bundle: %v", err)
	}

	verifier := New()

	// Test validation errors
	invalidOpts := []Options{
		{}, // No artifact or attestation
		{
			ArtifactPath: "test.txt",
			// Missing TrustedRoot
		},
		{
			ArtifactPath: "test.txt",
			TrustedRoot:  &root.TrustedRoot{},
			// Missing certificate identity/issuer and no public key
		},
	}

	for i, opts := range invalidOpts {
		t.Run(fmt.Sprintf("invalid_opts_%d", i), func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), opts)
			if err == nil {
				t.Error("Expected validation error, but got none")
			}
		})
	}
}