package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// createTUFClient creates and configures a TUF client with the given options
func createTUFClient(tufURL, tufRoot, tufCachePath string, verbose bool, disableLocalCache bool) (*tuf.Client, error) {
	// Expand ~ to home directory in cache path
	if tufCachePath[:1] == "~" {
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

	// Setup TUF fetcher
	fetcher := fetcher.NewDefaultFetcher()
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
	tufOptions = tufOptions.WithFetcher(fetcher)

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
			fmt.Println("Using default TUF root")
		}
		tufOptions = tufOptions.WithRoot(tuf.DefaultRoot())
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
