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