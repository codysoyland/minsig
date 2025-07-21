package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// SigstoreStagingRoot contains the embedded sigstage TUF root
//
//go:embed sigstage-root.json
var SigstoreStagingRoot []byte

// loadPrivateKeyFromFile loads a private key from a PEM-encoded file
// Supports PKCS#1 (RSA), PKCS#8 (RSA/ECDSA/Ed25519), and EC private keys
func loadPrivateKeyFromFile(keyPath string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from private key file")
	}

	var privateKey crypto.PrivateKey

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format - supports RSA, ECDSA, Ed25519
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
	case "RSA PRIVATE KEY":
		// PKCS#1 format - RSA only
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key: %w", err)
		}
	case "EC PRIVATE KEY":
		// SEC 1 format - ECDSA only
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	// Validate that we got a supported key type
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return privateKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key algorithm: %T", privateKey)
	}
}

// PrivateKeyKeypair implements the sign.Keypair interface for loaded private keys
type PrivateKeyKeypair struct {
	privateKey crypto.PrivateKey
}

// NewPrivateKeyKeypair creates a new Keypair from a loaded private key
func NewPrivateKeyKeypair(privateKey crypto.PrivateKey) *PrivateKeyKeypair {
	return &PrivateKeyKeypair{privateKey: privateKey}
}

// GetHashAlgorithm returns the hash algorithm to use with this key
func (p *PrivateKeyKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

// GetHint returns a hint for the key (not used in our case)
func (p *PrivateKeyKeypair) GetHint() []byte {
	return nil
}

// GetKeyAlgorithm returns the key algorithm string
func (p *PrivateKeyKeypair) GetKeyAlgorithm() string {
	switch p.privateKey.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	default:
		return "unknown"
	}
}

// GetPublicKeyPem returns the public key in PEM format
func (p *PrivateKeyKeypair) GetPublicKeyPem() (string, error) {
	var publicKey crypto.PublicKey

	switch priv := p.privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &priv.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &priv.PublicKey
	default:
		return "", fmt.Errorf("unsupported private key type: %T", p.privateKey)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPem), nil
}

// SignData signs the provided data using the private key
func (p *PrivateKeyKeypair) SignData(ctx context.Context, data []byte) ([]byte, []byte, error) {
	// Hash the data
	hash := sha256.Sum256(data)

	var signature []byte
	var err error

	switch priv := p.privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, priv, hash[:])
	default:
		return nil, nil, fmt.Errorf("unsupported private key type for signing: %T", p.privateKey)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, hash[:], nil
}

// loadPublicKeyFromFile loads a public key from a PEM-encoded file
func loadPublicKeyFromFile(keyPath string) (crypto.PublicKey, error) {
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

// createTUFClient creates and configures a TUF client with the given options
func createTUFClient(tufURL, tufRoot, tufCachePath string, verbose bool) (*tuf.Client, error) {
	// Expand ~ to home directory in cache path
	if len(tufCachePath) > 0 && tufCachePath[:1] == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		tufCachePath = filepath.Join(home, tufCachePath[1:])
	}

	if verbose {
		fmt.Printf("TUF URL: %s\n", tufURL)
		fmt.Printf("Cache path: %s\n", tufCachePath)
	}

	// Setup TUF options using defaults
	tufOptions := tuf.DefaultOptions()
	tufOptions = tufOptions.WithRepositoryBaseURL(tufURL)
	tufOptions = tufOptions.WithCachePath(tufCachePath)

	// If custom root file provided
	if tufRoot != "" {
		if verbose {
			fmt.Printf("Using custom TUF root: %s\n", tufRoot)
		}
		rootBytes, err := os.ReadFile(tufRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to read TUF root file: %w", err)
		}
		tufOptions = tufOptions.WithRoot(rootBytes)
	} else {
		if verbose {
			fmt.Println("Using embedded sigstage TUF root")
		}
		tufOptions = tufOptions.WithRoot(SigstoreStagingRoot)
	}

	// Create TUF client
	if verbose {
		fmt.Println("Creating TUF client...")
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	return tufClient, nil
}

// GetSigningConfig fetches the public-good Sigstore signing configuration target from TUF.
// TODO: Use root.GetSigningConfig whenever sigstore-go is updated to use signing_config.v0.2.json
func GetSigningConfig(c *tuf.Client) (*root.SigningConfig, error) {
	jsonBytes, err := c.GetTarget("signing_config.v0.2.json")
	if err != nil {
		return nil, err
	}
	return root.NewSigningConfigFromJSON(jsonBytes)
}
