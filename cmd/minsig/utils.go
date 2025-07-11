package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

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

// fetchTrustedRoot creates a TUF client and fetches the trusted root
func fetchTrustedRoot(tufURL, tufRoot, tufCachePath string, verbose bool, disableLocalCache bool) (*tuf.Client, *root.TrustedRoot, error) {

	// Expand ~ to home directory in cache path
	if tufCachePath[:1] == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		tufCachePath = filepath.Join(home, tufCachePath[1:])
	}

	if verbose {
		fmt.Printf("TUF URL: %s\n", tufURL)
		fmt.Printf("Cache path: %s\n", tufCachePath)
	}

	// Setup TUF options
	tufOptions := &tuf.Options{
		RepositoryBaseURL: tufURL,
		CachePath:         tufCachePath,
	}

	// Setup TUF fetcher
	fetcher := fetcher.DefaultFetcher{}
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
	tufOptions.Fetcher = &fetcher

	// If custom root file provided
	if tufRoot != "" {
		if verbose {
			fmt.Printf("Using custom TUF root: %s\n", tufRoot)
		}
		rootBytes, err := os.ReadFile(tufRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read TUF root file: %w", err)
		}
		tufOptions.Root = rootBytes
	} else {
		if verbose {
			fmt.Println("Using default TUF root")
		}
		tufOptions.Root = tuf.DefaultRoot()
	}

	// Configure cache behavior
	if disableLocalCache {
		if verbose {
			fmt.Println("Disabling local cache for forced update")
		}
		tufOptions.DisableLocalCache = true
	}

	// Create TUF client
	if verbose {
		fmt.Println("Creating TUF client...")
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	// Fetch the trusted root
	if verbose {
		fmt.Println("Fetching trusted root...")
	}
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get trusted root from TUF: %w", err)
	}

	return tufClient, trustedRoot, nil
}