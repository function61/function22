package main

import (
	"context"

	"github.com/function61/gokit/app/cli"
	"github.com/spf13/cobra"
)

const (
	tagline            = "Secure Shell server"
	defaultHostKeyFile = "/etc/ssh/ssh_host_ed25519_key"
)

func main() {
	app := &cobra.Command{
		Short: tagline,
		Args:  cobra.NoArgs,
		Run: cli.WrapRun(func(ctx context.Context, _ []string) error {
			return logic(ctx)
		}),
	}

	cli.AddLogLevelControls(app.Flags())

	app.AddCommand(generateHostKeyEntrypoint())
	app.AddCommand(installEntrypoint())

	cli.Execute(app)
}
