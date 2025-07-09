package main

import (
	"context"
	"log"
	"os"
	"time"

	urfavecli "github.com/urfave/cli/v3"
)

// GlobalFlags returns the global flags used by the minsig CLI
func GlobalFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{
			Name:  "tuf-url",
			Usage: "URL to the TUF repository",
			Value: "https://tuf-repo-cdn.sigstore.dev",
		},
		&urfavecli.StringFlag{
			Name:  "tuf-root",
			Usage: "Path to the TUF root file. Default is embedded for tuf-repo-cdn.sigstore.dev",
		},
		&urfavecli.StringFlag{
			Name:  "tuf-cache-path",
			Usage: "Path on disk to the TUF repository cache",
			Value: "~/.sigstore/tuf",
		},
		&urfavecli.DurationFlag{
			Name:  "tuf-cache-ttl",
			Usage: "Time to live for the TUF cache",
			Value: time.Hour,
		},
		&urfavecli.StringFlag{
			Name:  "signing-config",
			Usage: "Path to the signing configuration file. Uses TUF if not specified",
		},
		&urfavecli.StringFlag{
			Name:  "trusted-root",
			Usage: "Path to the trusted root file. Uses TUF if not specified",
		},
	}
}

func main() {
	app := &urfavecli.Command{
		Name:  "minsig",
		Usage: "A CLI tool for signing and verifying artifacts",
		Flags: GlobalFlags(),
		Commands: []*urfavecli.Command{
			SignCommand(),
			VerifyCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
