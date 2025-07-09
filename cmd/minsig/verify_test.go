//go:build !online

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	urfavecli "github.com/urfave/cli/v3"
)

func TestVerifyCommand(t *testing.T) {
	// Get the current working directory to construct absolute paths
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Construct paths to test data
	testDataDir := filepath.Join(cwd, "..", "..", "testdata")
	artifactPath := filepath.Join(testDataDir, "test-artifact.txt")
	bundlePath := filepath.Join(testDataDir, "test-artifact.txt.sigstore.json")
	trustedRootPath := filepath.Join(testDataDir, "trusted_root.json")

	// Check if test files exist
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		t.Skipf("Test artifact not found at %s, skipping test", artifactPath)
	}
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		t.Skipf("Test bundle not found at %s, skipping test", bundlePath)
	}
	if _, err := os.Stat(trustedRootPath); os.IsNotExist(err) {
		t.Skipf("Trusted root not found at %s, skipping test", trustedRootPath)
	}

	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name: "successful verification with trusted root",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--certificate-identity", "cody@soyland.com",
				"--certificate-oidc-issuer", "https://github.com/login/oauth",
				"--trusted-root", trustedRootPath,
			},
			expectError: false,
		},
		{
			name: "successful verification with explicit bundle path",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--bundle", bundlePath,
				"--certificate-identity", "cody@soyland.com",
				"--certificate-oidc-issuer", "https://github.com/login/oauth",
				"--trusted-root", trustedRootPath,
			},
			expectError: false,
		},
		{
			name: "missing certificate identity",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--certificate-oidc-issuer", "https://github.com/login/oauth",
				"--trusted-root", trustedRootPath,
			},
			expectError: true,
		},
		{
			name: "missing certificate issuer",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--certificate-identity", "cody@soyland.com",
				"--trusted-root", trustedRootPath,
			},
			expectError: true,
		},
		{
			name: "missing artifact and attestation",
			args: []string{
				"verify",
				"--certificate-identity", "cody@soyland.com",
				"--certificate-oidc-issuer", "https://github.com/login/oauth",
				"--trusted-root", trustedRootPath,
			},
			expectError: true,
		},
		{
			name: "wrong certificate identity",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--certificate-identity", "wrong@email.com",
				"--certificate-oidc-issuer", "https://github.com/login/oauth",
				"--trusted-root", trustedRootPath,
			},
			expectError: true,
		},
		{
			name: "wrong certificate issuer",
			args: []string{
				"verify",
				"--artifact", artifactPath,
				"--certificate-identity", "cody@soyland.com",
				"--certificate-oidc-issuer", "https://wrong.issuer.com",
				"--trusted-root", trustedRootPath,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new CLI app for each test with global flags
			app := &urfavecli.Command{
				Name:  "minsig",
				Usage: "A CLI tool for signing and verifying artifacts",
				Flags: GlobalFlags(),
				Commands: []*urfavecli.Command{
					VerifyCommand(),
				},
			}

			// Prepend "minsig" to the args to simulate the full command line
			fullArgs := append([]string{"minsig"}, tt.args...)
			
			// Run the command
			err := app.Run(context.Background(), fullArgs)

			// Check if the error expectation matches
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

