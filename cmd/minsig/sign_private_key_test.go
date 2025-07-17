//go:build !online

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateKeyFromFile(t *testing.T) {
	// Get the current working directory to construct absolute paths
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Construct paths to test data
	testDataDir := filepath.Join(cwd, "..", "..", "testdata")
	privateKeyPath := filepath.Join(testDataDir, "test-private-key.pem")

	// Check if test files exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Skipf("Private key not found at %s, skipping test", privateKeyPath)
	}

	// Test loading the private key
	privateKey, err := loadPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Loaded private key is nil")
	}

	// Test creating a keypair from the loaded key
	keypair := NewPrivateKeyKeypair(privateKey)
	if keypair == nil {
		t.Fatal("Failed to create keypair from private key")
	}

	// Test that we can get the public key
	publicKeyPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	if len(publicKeyPem) == 0 {
		t.Fatal("Public key PEM is empty")
	}

	// Test key algorithm detection
	algorithm := keypair.GetKeyAlgorithm()
	if algorithm != "ecdsa" && algorithm != "rsa" {
		t.Fatalf("Unexpected key algorithm: %s", algorithm)
	}

	t.Logf("Successfully loaded %s private key", algorithm)
	t.Logf("Public key PEM:\n%s", publicKeyPem)
}

func TestLoadPrivateKeyFromFile_InvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := loadPrivateKeyFromFile("/nonexistent/path/key.pem")
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}

	// Test with invalid PEM content
	tempFile, err := os.CreateTemp("", "invalid-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write invalid content
	if _, err := tempFile.WriteString("This is not a valid PEM file"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	_, err = loadPrivateKeyFromFile(tempFile.Name())
	if err == nil {
		t.Fatal("Expected error for invalid PEM content, got nil")
	}
	if err.Error() != "failed to decode PEM block from private key file" {
		t.Fatalf("Unexpected error message: %v", err)
	}
}