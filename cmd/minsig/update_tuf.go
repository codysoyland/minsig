package main

import (
	"context"
	"fmt"

	urfavecli "github.com/urfave/cli/v3"
)

// UpdateTufCommand returns the CLI command for updating TUF cache
func UpdateTufCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "update-tuf",
		Usage: "Update the TUF cache",
		Flags: []urfavecli.Flag{
			&urfavecli.BoolFlag{
				Name:  "force",
				Usage: "Force update even if cache is current (bypass TTL check)",
				Value: false,
			},
			&urfavecli.BoolFlag{
				Name:  "verbose",
				Usage: "Show detailed progress information",
				Value: false,
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			verbose := c.Bool("verbose")
			force := c.Bool("force")

			if verbose {
				fmt.Println("Updating TUF cache...")
			}

			if force && verbose {
				fmt.Println("Force update requested, bypassing cache TTL")
			}

			// Create TUF client and fetch trusted root
			_, _, err := fetchTrustedRoot(
				c.String("tuf-url"),
				c.String("tuf-root"),
				c.String("tuf-cache-path"),
				verbose,
				force, // disableLocalCache
			)
			if err != nil {
				return err
			}

			// The CreateTUFClient() call already performs the initial sync
			// For force updates, we set DisableLocalCache=true
			if verbose {
				fmt.Println("Refreshing TUF metadata...")
			}

			if verbose {
				fmt.Println("TUF cache updated successfully!")
			} else {
				fmt.Println("TUF cache updated")
			}
			return nil
		},
	}
}
