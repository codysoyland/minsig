package tuf

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// Client provides TUF repository operations
type Client interface {
	Update(ctx context.Context, opts UpdateOptions) error
	GetTrustedRoot(ctx context.Context) (*root.TrustedRoot, error)
	GetSigningConfig(ctx context.Context) (*root.SigningConfig, error)
	Close() error
}

// client implements the Client interface
type client struct {
	options   Options
	tufClient *tuf.Client
}

// New creates a new TUF client
func New(opts Options) (Client, error) {
	c := &client{
		options: opts,
	}

	// Create TUF client immediately
	tufClient, err := c.createTUFClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	c.tufClient = tufClient

	return c, nil
}

// Update updates the TUF cache
func (c *client) Update(ctx context.Context, opts UpdateOptions) error {
	if opts.Verbose {
		fmt.Println("Updating TUF cache...")
	}

	if opts.Force {
		if opts.Verbose {
			fmt.Println("Force update requested, bypassing cache TTL")
		}
		// For force updates, we recreate the client with DisableLocalCache=true
		originalDisableCache := c.options.DisableLocalCache
		c.options.DisableLocalCache = true
		
		tufClient, err := c.createTUFClient()
		if err != nil {
			c.options.DisableLocalCache = originalDisableCache
			return fmt.Errorf("failed to create TUF client for force update: %w", err)
		}
		
		// Replace with new client (no close method in sigstore-go tuf client)
		c.tufClient = tufClient
		c.options.DisableLocalCache = originalDisableCache
	}

	if opts.Verbose {
		fmt.Println("Refreshing TUF metadata...")
	}

	// The TUF client automatically refreshes metadata on operations
	// We can trigger this by getting the trusted root
	_, err := c.GetTrustedRoot(ctx)
	if err != nil {
		return fmt.Errorf("failed to refresh TUF metadata: %w", err)
	}

	if opts.Verbose {
		fmt.Println("TUF cache updated successfully!")
	} else {
		fmt.Println("TUF cache updated")
	}

	return nil
}

// GetTrustedRoot gets the trusted root from TUF
func (c *client) GetTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	return root.GetTrustedRoot(c.tufClient)
}

// GetSigningConfig gets the signing configuration from TUF
func (c *client) GetSigningConfig(ctx context.Context) (*root.SigningConfig, error) {
	// Use the same logic as utils.go GetSigningConfig
	jsonBytes, err := c.tufClient.GetTarget("signing_config.v0.2.json")
	if err != nil {
		return nil, err
	}
	return root.NewSigningConfigFromJSON(jsonBytes)
}

// Close closes the TUF client
func (c *client) Close() error {
	// sigstore-go tuf client doesn't have a close method
	// Nothing to do here
	return nil
}

// createTUFClient creates and configures a TUF client with the given options
func (c *client) createTUFClient() (*tuf.Client, error) {
	// Expand ~ to home directory in cache path
	cachePath := c.options.CachePath
	if len(cachePath) > 0 && cachePath[:1] == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cachePath = filepath.Join(home, cachePath[1:])
	}

	if c.options.Verbose {
		fmt.Printf("TUF URL: %s\n", c.options.URL)
		fmt.Printf("Cache path: %s\n", cachePath)
	}

	// Setup TUF options using defaults
	tufOptions := tuf.DefaultOptions()
	tufOptions = tufOptions.WithRepositoryBaseURL(c.options.URL)
	tufOptions = tufOptions.WithCachePath(cachePath)

	// Setup TUF fetcher
	fetcher := fetcher.NewDefaultFetcher()
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
	tufOptions = tufOptions.WithFetcher(fetcher)

	// If custom root file provided
	if c.options.RootPath != "" {
		if c.options.Verbose {
			fmt.Printf("Using custom TUF root: %s\n", c.options.RootPath)
		}
		rootBytes, err := os.ReadFile(c.options.RootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TUF root file: %w", err)
		}
		tufOptions = tufOptions.WithRoot(rootBytes)
	} else {
		if c.options.Verbose {
			fmt.Println("Using embedded sigstage TUF root")
		}
		tufOptions = tufOptions.WithRoot(getSigstoreStagingRoot())
	}

	// Create TUF client
	if c.options.Verbose {
		fmt.Println("Creating TUF client...")
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	return tufClient, nil
}

// SigstoreStagingRoot contains the embedded sigstage TUF root
//
//go:embed sigstage-root.json
var SigstoreStagingRoot []byte

// getSigstoreStagingRoot returns the embedded sigstore staging root
func getSigstoreStagingRoot() []byte {
	return SigstoreStagingRoot
}