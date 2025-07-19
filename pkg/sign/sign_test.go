package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name        string
		opts        Options
		expectError bool
		errorMsg    string
	}{
		{
			name:        "no artifact or attestation",
			opts:        Options{},
			expectError: true,
			errorMsg:    "either artifact path or attestation path must be provided",
		},
		{
			name: "both artifact and attestation",
			opts: Options{
				ArtifactPath:    "test.txt",
				AttestationPath: "test.json",
			},
			expectError: true,
			errorMsg:    "cannot provide both artifact path and attestation path",
		},
		{
			name: "valid artifact only",
			opts: Options{
				ArtifactPath: "test.txt",
			},
			expectError: false,
		},
		{
			name: "valid attestation only",
			opts: Options{
				AttestationPath: "test.json",
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
				} else if err.Error() != tt.errorMsg {
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

func TestLoadContent(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files
	artifactPath := filepath.Join(tempDir, "test.txt")
	artifactData := []byte("test artifact content")
	if err := os.WriteFile(artifactPath, artifactData, 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	attestationPath := filepath.Join(tempDir, "test.json")
	attestationData := []byte(`{"test": "attestation"}`)
	if err := os.WriteFile(attestationPath, attestationData, 0644); err != nil {
		t.Fatalf("Failed to create test attestation: %v", err)
	}

	tests := []struct {
		name            string
		opts            Options
		expectedPath    string
		expectedContent string
		expectError     bool
	}{
		{
			name: "load artifact",
			opts: Options{
				ArtifactPath: artifactPath,
			},
			expectedPath:    artifactPath,
			expectedContent: "test artifact content",
			expectError:     false,
		},
		{
			name: "load attestation",
			opts: Options{
				AttestationPath: attestationPath,
			},
			expectedPath:    attestationPath,
			expectedContent: `{"test": "attestation"}`,
			expectError:     false,
		},
		{
			name: "non-existent artifact",
			opts: Options{
				ArtifactPath: filepath.Join(tempDir, "nonexistent.txt"),
			},
			expectError: true,
		},
		{
			name: "non-existent attestation",
			opts: Options{
				AttestationPath: filepath.Join(tempDir, "nonexistent.json"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, contentPath, err := loadContent(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if contentPath != tt.expectedPath {
				t.Errorf("Expected path %s, got %s", tt.expectedPath, contentPath)
			}

			if content == nil {
				t.Error("Content is nil")
			}

			// Note: We can't easily test the content data directly since it's wrapped in sign.Content interface
			// But we can verify it's not nil and the path is correct
		})
	}
}

func TestSetupKeypair(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	keyPath := filepath.Join(tempDir, "test_key.pem")
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	tests := []struct {
		name        string
		opts        Options
		expectError bool
		description string
	}{
		{
			name: "with private key",
			opts: Options{
				PrivateKeyPath: keyPath,
			},
			expectError: false,
			description: "should load private key",
		},
		{
			name: "ephemeral key",
			opts: Options{
				PrivateKeyPath: "",
			},
			expectError: false,
			description: "should create ephemeral key",
		},
		{
			name: "non-existent key file",
			opts: Options{
				PrivateKeyPath: filepath.Join(tempDir, "nonexistent.pem"),
			},
			expectError: true,
			description: "should fail for non-existent key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keypair, err := setupKeypair(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tt.description, err)
			}

			if keypair == nil {
				t.Errorf("Keypair is nil for %s", tt.description)
			}
		})
	}
}

func TestDetermineOutputPath(t *testing.T) {
	tests := []struct {
		name         string
		opts         Options
		contentPath  string
		expectedPath string
	}{
		{
			name: "explicit output path",
			opts: Options{
				OutputPath: "/custom/output.sigstore.json",
			},
			contentPath:  "/input/test.txt",
			expectedPath: "/custom/output.sigstore.json",
		},
		{
			name:         "default output path",
			opts:         Options{},
			contentPath:  "/input/test.txt",
			expectedPath: "/input/test.txt.sigstore.json",
		},
		{
			name: "empty output path",
			opts: Options{
				OutputPath: "",
			},
			contentPath:  "/input/document.pdf",
			expectedPath: "/input/document.pdf.sigstore.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := determineOutputPath(tt.opts, tt.contentPath)
			if outputPath != tt.expectedPath {
				t.Errorf("Expected output path %s, got %s", tt.expectedPath, outputPath)
			}
		})
	}
}

func TestSignerInterface(t *testing.T) {
	// Test that our signer implements the interface
	var _ Signer = &signer{}
	
	// Test New() function
	s := New()
	if s == nil {
		t.Error("New() returned nil signer")
	}
	
	// Verify it's the right type
	if _, ok := s.(*signer); !ok {
		t.Errorf("New() returned %T, expected *signer", s)
	}
}

func TestSignWithoutTrustedRoot(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test artifact
	artifactPath := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(artifactPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	// Create a test private key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	keyPath := filepath.Join(tempDir, "test_key.pem")
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	signer := New()
	
	opts := Options{
		ArtifactPath:   artifactPath,
		PrivateKeyPath: keyPath,
		OutputPath:     filepath.Join(tempDir, "output.sigstore.json"),
		// TrustedRoot is nil - this should cause an error
	}

	_, err = signer.Sign(context.Background(), opts)
	if err == nil {
		t.Error("Expected error for missing trusted root, but got none")
	}

	expectedError := "trusted root is required"
	if err.Error() != expectedError {
		t.Errorf("Expected error %q, got %q", expectedError, err.Error())
	}
}


func TestSignValidationFlow(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test artifact
	artifactPath := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(artifactPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test artifact: %v", err)
	}

	signer := New()

	// Test validation errors
	invalidOpts := []Options{
		{}, // No artifact or attestation
		{
			ArtifactPath:    artifactPath,
			AttestationPath: artifactPath,
		}, // Both artifact and attestation
	}

	for i, opts := range invalidOpts {
		t.Run(fmt.Sprintf("invalid_opts_%d", i), func(t *testing.T) {
			_, err := signer.Sign(context.Background(), opts)
			if err == nil {
				t.Error("Expected validation error, but got none")
			}
		})
	}
}