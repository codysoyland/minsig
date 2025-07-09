//go:build online

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	urfavecli "github.com/urfave/cli/v3"
)

func TestVerifyCommandWithTUF(t *testing.T) {
	// Get the current working directory to construct absolute paths
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Construct paths to test data
	testDataDir := filepath.Join(cwd, "..", "..", "testdata")
	artifactPath := filepath.Join(testDataDir, "test-artifact.txt")
	bundlePath := filepath.Join(testDataDir, "test-artifact.txt.sigstore.json")

	// Check if test files exist
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		t.Skipf("Test artifact not found at %s, skipping test", artifactPath)
	}
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		t.Skipf("Test bundle not found at %s, skipping test", bundlePath)
	}

	t.Run("successful verification with TUF", func(t *testing.T) {
		// Create a new CLI app with global flags
		app := &urfavecli.Command{
			Name:  "minsig",
			Usage: "A CLI tool for signing and verifying artifacts",
			Flags: GlobalFlags(),
			Commands: []*urfavecli.Command{
				VerifyCommand(),
			},
		}

		// Use TUF instead of trusted root file
		args := []string{
			"minsig",
			"verify",
			"--artifact", artifactPath,
			"--certificate-identity", "cody@soyland.com",
			"--certificate-oidc-issuer", "https://github.com/login/oauth",
			"--tuf-url", "https://tuf-repo-cdn.sigstore.dev",
		}

		// Run the command
		err := app.Run(context.Background(), args)
		if err != nil {
			t.Errorf("Expected no error but got: %v", err)
		}
	})

	t.Run("successful verification with custom TUF URL", func(t *testing.T) {
		// Create a new CLI app with global flags
		app := &urfavecli.Command{
			Name:  "minsig",
			Usage: "A CLI tool for signing and verifying artifacts",
			Flags: GlobalFlags(),
			Commands: []*urfavecli.Command{
				VerifyCommand(),
			},
		}

		// Use custom TUF URL
		args := []string{
			"minsig",
			"verify",
			"--artifact", artifactPath,
			"--certificate-identity", "cody@soyland.com",
			"--certificate-oidc-issuer", "https://github.com/login/oauth",
			"--tuf-url", "https://tuf-repo-cdn.sigstore.dev",
			"--tuf-cache-path", os.TempDir() + "/sigstore-test-tuf",
		}

		// Run the command
		err := app.Run(context.Background(), args)
		if err != nil {
			t.Errorf("Expected no error but got: %v", err)
		}
	})
}