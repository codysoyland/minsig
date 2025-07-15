//go:build !online

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	urfavecli "github.com/urfave/cli/v3"
)

func TestSignCommandWithPrivateKey(t *testing.T) {
	// Get the current working directory to construct absolute paths
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Construct paths to test data
	testDataDir := filepath.Join(cwd, "..", "..", "testdata")
	artifactPath := filepath.Join(testDataDir, "test-artifact.txt")
	privateKeyPath := filepath.Join(testDataDir, "test-signing-key.pem")
	outputPath := filepath.Join(testDataDir, "test-sign-output.sigstore.json")

	// Clean up any existing output file
	defer os.Remove(outputPath)

	// Check if test files exist
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		t.Skipf("Test artifact not found at %s, skipping test", artifactPath)
	}
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Skipf("Private key not found at %s, skipping test", privateKeyPath)
	}

	// Create a full CLI app with global flags
	trustedRootPath := filepath.Join(testDataDir, "trusted_root.json")
	app := &urfavecli.Command{
		Name:  "minsig",
		Usage: "A CLI tool for signing and verifying artifacts",
		Flags: GlobalFlags(),
		Commands: []*urfavecli.Command{
			SignCommand(),
		},
	}

	// Prepare arguments for signing with private key
	args := []string{
		"minsig",
		"--trusted-root", trustedRootPath,
		"sign",
		"--artifact", artifactPath,
		"--key", privateKeyPath,
		"--output", outputPath,
		"--skip-tsa",   // Skip timestamp authority for test
		"--skip-rekor", // Skip transparency log for test
	}

	// Create a test context
	ctx := context.Background()

	// Execute the sign command
	err = app.Run(ctx, args)
	if err != nil {
		t.Fatalf("Sign command failed: %v", err)
	}

	// Verify that the output file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Expected signature bundle file was not created")
	}

	// Read and verify the signature bundle
	bundleBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read signature bundle: %v", err)
	}

	bundleContent := string(bundleBytes)

	// Verify the bundle contains expected structure
	if !strings.Contains(bundleContent, "mediaType") {
		t.Error("Bundle does not contain mediaType field")
	}
	if !strings.Contains(bundleContent, "verificationMaterial") {
		t.Error("Bundle does not contain verificationMaterial field")
	}
	if !strings.Contains(bundleContent, "messageSignature") {
		t.Error("Bundle does not contain messageSignature field")
	}
	if !strings.Contains(bundleContent, "publicKey") {
		t.Error("Bundle does not contain publicKey field")
	}

	// Verify the bundle is not using certificate-based verification (since we used private key)
	if strings.Contains(bundleContent, "certificateChain") {
		t.Error("Bundle should not contain certificateChain when using private key")
	}

	t.Logf("Successfully created signature bundle with private key")
	t.Logf("Bundle size: %d bytes", len(bundleBytes))
}

func TestSignCommandPrivateKeyValidation(t *testing.T) {
	// Test error handling for invalid private key scenarios
	tests := []struct {
		name          string
		keyPath       string
		expectError   bool
		errorContains string
	}{
		{
			name:          "non-existent key file",
			keyPath:       "/nonexistent/key.pem",
			expectError:   true,
			errorContains: "failed to load private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get test artifact path
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatalf("Failed to get current working directory: %v", err)
			}
			testDataDir := filepath.Join(cwd, "..", "..", "testdata")
			artifactPath := filepath.Join(testDataDir, "test-artifact.txt")

			// Skip if test artifact doesn't exist
			if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
				t.Skipf("Test artifact not found at %s, skipping test", artifactPath)
			}

			// Create the sign command
			signCmd := SignCommand()

			// Prepare arguments
			args := []string{
				"sign",
				"--artifact", artifactPath,
				"--key", tt.keyPath,
				"--skip-tsa",
				"--skip-rekor",
			}

			// Create a test context
			ctx := context.Background()

			// Execute the command
			err = signCmd.Run(ctx, args)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but command succeeded")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPrivateKeyKeypairIntegration(t *testing.T) {
	// Test the full keypair workflow with different key types
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	testDataDir := filepath.Join(cwd, "..", "..", "testdata")
	privateKeyPath := filepath.Join(testDataDir, "test-signing-key.pem")

	// Skip if private key doesn't exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Skipf("Private key not found at %s, skipping test", privateKeyPath)
	}

	// Load the private key
	privateKey, err := loadPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Create keypair from private key
	keypair := NewPrivateKeyKeypair(privateKey)

	// Test GetKeyAlgorithm
	algorithm := keypair.GetKeyAlgorithm()
	if algorithm != "ecdsa" && algorithm != "rsa" {
		t.Errorf("Unexpected key algorithm: %s", algorithm)
	}

	// Test GetPublicKeyPem
	publicKeyPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	if len(publicKeyPem) == 0 {
		t.Error("Public key PEM is empty")
	}

	if !strings.Contains(publicKeyPem, "BEGIN PUBLIC KEY") {
		t.Error("Public key PEM does not contain expected header")
	}

	// Test SignData
	testData := []byte("test data to sign")
	ctx := context.Background()
	signature, hash, err := keypair.SignData(ctx, testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	if len(hash) == 0 {
		t.Error("Hash is empty")
	}

	t.Logf("Successfully signed data with %s key", algorithm)
	t.Logf("Signature length: %d bytes", len(signature))
	t.Logf("Hash length: %d bytes", len(hash))
}