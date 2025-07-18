package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

// loadPublicKey loads a public key from a PEM-encoded file
func loadPublicKey(keyPath string) (crypto.PublicKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from public key file")
	}

	var publicKey crypto.PublicKey

	switch block.Type {
	case "PUBLIC KEY":
		// PKIX format - supports RSA, ECDSA, Ed25519
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
	case "RSA PUBLIC KEY":
		// PKCS#1 format - RSA only
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA public key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	// Validate that we got a supported key type
	switch publicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported public key algorithm: %T", publicKey)
	}
}

// trustedPublicKeyMaterial creates trusted public key material from a public key
func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

// nonExpiringVerifier wraps a signature verifier to make it non-expiring
type nonExpiringVerifier struct {
	signature.Verifier
}

// ValidAtTime always returns true for non-expiring verifiers
func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}