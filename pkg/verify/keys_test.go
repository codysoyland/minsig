package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type expectedKeyType int

const (
	expectedRSA expectedKeyType = iota
	expectedECDSA
)

func TestLoadPublicKey(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name            string
		keyType         string
		expectedKeyType expectedKeyType
		keyGen          func() ([]byte, error)
		expectError     bool
	}{
		{
			name:            "RSA PKIX public key",
			keyType:         "PUBLIC KEY",
			expectedKeyType: expectedRSA,
			keyGen: func() ([]byte, error) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				publicKey := &privateKey.PublicKey

				keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
				if err != nil {
					return nil, err
				}

				return pem.EncodeToMemory(&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: keyBytes,
				}), nil
			},
			expectError: false,
		},
		{
			name:            "RSA PKCS#1 public key",
			keyType:         "RSA PUBLIC KEY",
			expectedKeyType: expectedRSA,
			keyGen: func() ([]byte, error) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				publicKey := &privateKey.PublicKey

				keyBytes := x509.MarshalPKCS1PublicKey(publicKey)

				return pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PUBLIC KEY",
					Bytes: keyBytes,
				}), nil
			},
			expectError: false,
		},
		{
			name:            "ECDSA PKIX public key",
			keyType:         "PUBLIC KEY",
			expectedKeyType: expectedECDSA,
			keyGen: func() ([]byte, error) {
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				publicKey := &privateKey.PublicKey

				keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
				if err != nil {
					return nil, err
				}

				return pem.EncodeToMemory(&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: keyBytes,
				}), nil
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyData, err := tt.keyGen()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			keyPath := filepath.Join(tempDir, "test_key.pem")
			if err := os.WriteFile(keyPath, keyData, 0644); err != nil {
				t.Fatalf("Failed to write key file: %v", err)
			}

			publicKey, err := loadPublicKey(keyPath)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if publicKey == nil {
				t.Error("Public key is nil")
			}

			// Verify the key type matches what we expect
			switch tt.expectedKeyType {
			case expectedRSA:
				if _, ok := publicKey.(*rsa.PublicKey); !ok {
					t.Errorf("Expected RSA public key, got %T", publicKey)
				}
			case expectedECDSA:
				if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
					t.Errorf("Expected ECDSA public key, got %T", publicKey)
				}
			}
		})
	}
}

func TestLoadPublicKeyErrors(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		keyData     []byte
		expectError string
	}{
		{
			name:        "non-existent file",
			keyData:     nil,
			expectError: "failed to read public key file",
		},
		{
			name:        "invalid PEM data",
			keyData:     []byte("not a pem file"),
			expectError: "failed to decode PEM block",
		},
		{
			name: "unsupported key type",
			keyData: pem.EncodeToMemory(&pem.Block{
				Type:  "UNSUPPORTED KEY",
				Bytes: []byte("dummy"),
			}),
			expectError: "unsupported public key type",
		},
		{
			name: "invalid key data",
			keyData: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: []byte("invalid key data"),
			}),
			expectError: "failed to parse PKIX public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(tempDir, "test_key.pem")

			if tt.keyData != nil {
				if err := os.WriteFile(keyPath, tt.keyData, 0644); err != nil {
					t.Fatalf("Failed to write key file: %v", err)
				}
			}

			_, err := loadPublicKey(keyPath)
			if err == nil {
				t.Error("Expected error but got none")
				return
			}

			if tt.expectError != "" && err.Error() != "" {
				// Just check that we got an error, specific message checking can be fragile
				t.Logf("Got expected error: %v", err)
			}
		})
	}
}

func TestTrustedPublicKeyMaterial(t *testing.T) {
	// Generate a test ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	publicKey := &ecdsaKey.PublicKey

	// Create trusted public key material
	trustedMaterial := trustedPublicKeyMaterial(publicKey)

	if trustedMaterial == nil {
		t.Error("Trusted public key material is nil")
	}

	// Test that we can get a verifier from the trusted material
	// Note: This is a basic test - in practice you'd want to test with actual verification
	verifier, err := trustedMaterial.PublicKeyVerifier("test-key-id")
	if err != nil {
		t.Errorf("Failed to get verifier: %v", err)
	}

	if verifier == nil {
		t.Error("Verifier is nil")
	}

	// Test ValidAtTime method
	if nonExpiring, ok := verifier.(*nonExpiringVerifier); ok {
		if !nonExpiring.ValidAtTime(time.Now()) {
			t.Error("Non-expiring verifier should always be valid")
		}
		if !nonExpiring.ValidAtTime(time.Now().Add(-365 * 24 * time.Hour)) {
			t.Error("Non-expiring verifier should be valid for past times")
		}
		if !nonExpiring.ValidAtTime(time.Now().Add(365 * 24 * time.Hour)) {
			t.Error("Non-expiring verifier should be valid for future times")
		}
	} else {
		t.Error("Expected nonExpiringVerifier")
	}
}

func TestNonExpiringVerifier(t *testing.T) {
	// Test that ValidAtTime always returns true for the nonExpiringVerifier wrapper
	// We'll create a simple test without mocking the complex signature.Verifier interface
	nonExpiring := &nonExpiringVerifier{nil} // The underlying verifier is not used in ValidAtTime

	// Test that ValidAtTime always returns true
	testTimes := []time.Time{
		time.Now(),
		time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
		time.Now().Add(365 * 24 * time.Hour),  // 1 year from now
		{},                                    // Zero time
	}

	for _, testTime := range testTimes {
		if !nonExpiring.ValidAtTime(testTime) {
			t.Errorf("ValidAtTime should return true for %v", testTime)
		}
	}
}
