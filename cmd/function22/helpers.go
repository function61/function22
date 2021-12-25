package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/function61/gokit/os/osutil"
	"github.com/function61/gokit/os/systemdinstaller"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/spf13/cobra"
)

func installEntrypoint() *cobra.Command {
	allowedUsers := ""
	interfaceName := "tailscale0"

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Make the server start on system startup",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			osutil.ExitIfError(func() error {
				hostKeyExists, err := osutil.Exists(defaultHostKeyFile)
				if err != nil {
					return err
				}

				if !hostKeyExists { // pro-tip
					return errors.New("host key doesn't exist. create it by running $ " + os.Args[0] + " host-key-generate")
				}

				if allowedUsers == "" {
					return errors.New("you need to specify allowed-users")
				}

				options := []systemdinstaller.Option{
					systemdinstaller.Docs(
						"https://github.com/function61/function22",
						"https://function61.com/"),
					systemdinstaller.Env("SSH_ALLOWED_USERS", allowedUsers),
				}

				if interfaceName != "" {
					options = append(
						options,
						systemdinstaller.Env("SSH_LISTEN_INTERFACE", interfaceName),
						systemdinstaller.WaitNetworkInterface(interfaceName))
				}

				service := systemdinstaller.Service("function22", tagline, options...)

				if err := systemdinstaller.Install(service); err != nil {
					return err
				}

				fmt.Println(systemdinstaller.EnableAndStartCommandHints(service))

				return nil
			}())
		},
	}

	cmd.Flags().StringVarP(&allowedUsers, "allowed-users", "", allowedUsers, "Users allowed for SSH access: 'user1,user2'")
	cmd.Flags().StringVarP(&interfaceName, "interface", "", interfaceName, "Network interface to listen in")

	return cmd
}

var sshSignalMap = map[gliderssh.Signal]os.Signal{
	gliderssh.SIGINT:  os.Interrupt,
	gliderssh.SIGKILL: os.Kill,
}

func setWinsize(f *os.File, w, h int) {
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func envsSpecifyTerminal(environ []string) bool {
	for _, env := range environ {
		if key, _ := osutil.ParseEnv(env); key == "TERM" {
			return true
		}
	}

	return false
}

// context-ful version of net.Listen() that optionally also uses SO_BINDTODEVICE to bind to a specific interface,
// i.e. to listen only on its network addresses. see https://linux.die.net/man/7/socket
func listenByInterfaceName(ctx context.Context, network string, address string, interfaceName string) (net.Listener, error) {
	// errors with "no such device" if *interfaceName* is not found
	listener, err := (&net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			if interfaceName == "" { // listen on all interfaces
				return nil
			}

			var err error
			if errControl := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			}); errControl != nil {
				return errControl
			}

			return err
		},
	}).Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}

	go func() { // why isn't this done by Listen(ctx, ...)?
		<-ctx.Done()
		listener.Close()
	}()

	return listener, nil
}
