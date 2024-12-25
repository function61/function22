package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/ScaleFT/sshkeys"
	"github.com/function61/gokit/app/cli"
	"github.com/function61/gokit/os/osutil"
	"github.com/spf13/cobra"
)

func generateHostKeyEntrypoint() *cobra.Command {
	return &cobra.Command{
		Use:   "host-key-generate",
		Short: "Generates the host key at " + defaultHostKeyFile,
		Args:  cobra.NoArgs,
		Run: cli.WrapRun(func(_ context.Context, _ []string) error {
			return generateHostKey()
		}),
	}
}

func generateHostKey() error {
	exists, err := osutil.Exists(defaultHostKeyFile)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("%s exists; refusing to continue for safety", defaultHostKeyFile)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// "-----BEGIN OPENSSH PRIVATE KEY-----" format
	// TODO: once https://github.com/golang/go/issues/37132 lands (proposal-accepted) we don't need this dependency
	privateKeyMarshaledOpenSSHFormat, err := sshkeys.Marshal(privateKey, &sshkeys.MarshalOptions{
		Format: sshkeys.FormatOpenSSHv1,
	})
	if err != nil {
		return err
	}

	return os.WriteFile(defaultHostKeyFile, privateKeyMarshaledOpenSSHFormat, 0600)
}
