package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/function61/function22/pkg/linuxuser"
	"github.com/function61/gokit/app/dynversion"
	"github.com/function61/gokit/io/bidipipe"
	"github.com/function61/gokit/log/logex"
	"github.com/function61/gokit/os/osutil"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/spf13/cobra"
)

const (
	tagline            = "Secure Shell server"
	defaultHostKeyFile = "/etc/ssh/ssh_host_ed25519_key"
)

func main() {
	app := &cobra.Command{
		Use:     os.Args[0],
		Short:   tagline,
		Version: dynversion.Version,
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, args []string) {
			rootLogger := logex.StandardLogger()

			osutil.ExitIfError(logic(
				osutil.CancelOnInterruptOrTerminate(rootLogger),
				true,
				rootLogger))
		},
	}

	app.AddCommand(generateHostKeyEntrypoint())
	app.AddCommand(installEntrypoint())

	osutil.ExitIfError(app.Execute())
}

func logic(ctx context.Context, verbose bool, logger *log.Logger) error {
	listenInterface := os.Getenv("SSH_LISTEN_INTERFACE")

	allowedUsersSerialized, err := osutil.GetenvRequired("SSH_ALLOWED_USERS") // "user1,user2"
	if err != nil {
		return err
	}

	// "user1,user2" => ["user1", "user2"]
	allowedUsers := strings.Split(allowedUsersSerialized, ",")

	// if the interface is not available & configured, this will fail and we'll "crash". that is great,
	// since our supervisor will restart us and we'll eventually be expected to succeed. systemd can
	// also be optionally set up to know about the interface dependency, so we'll be only started when
	// systemd knows the interface is available
	sshPortListener, err := listenByInterfaceName(ctx, "tcp", ":22", listenInterface)
	if err != nil {
		return err
	}
	defer sshPortListener.Close() // double close intentional

	// have to do this beforehand, because gliderssh.PasswordAuth() interface doesn't allow us to
	// pass uid/gid to the session handler, so we'd have to do one FindByUsername() per connection plus
	// once per each session, which feels weird and wrong.
	//
	// caveat of this approach: we don't notice new accounts / password changes without server restart.
	knownUsers := map[string]*linuxuser.Account{}
	for _, username := range allowedUsers {
		account, err := linuxuser.FindByUsername(username)
		if err != nil {
			return fmt.Errorf("FindByUsername: %s: %w", username, err)
		}

		knownUsers[username] = account
	}

	if err := gliderssh.Serve(sshPortListener, func(s gliderssh.Session) {
		// user now definitely exists in *knownUsers*
		if err := s.Exit(handleSSHConnection(s, *knownUsers[s.User()], verbose, logger)); err != nil {
			logger.Printf("session.Exit(): %v", err)
		}
	},
		gliderssh.HostKeyFile(defaultHostKeyFile),
		gliderssh.PasswordAuth(func(ctx gliderssh.Context, pass string) bool {
			username := ctx.User()

			account, found := knownUsers[username]
			if !found {
				logger.Printf("login attempt for unknown user: %s", username)
				return false
			}

			if err := linuxuser.ValidatePassword(pass, *account); err != nil {
				return false
			} else {
				return true
			}
		}),
		gliderssh.PublicKeyAuth(func(ctx gliderssh.Context, userKey gliderssh.PublicKey) bool {
			if _, allowed := knownUsers[ctx.User()]; !allowed {
				logger.Printf("login attempt for unknown user: %s", ctx.User())
				return false
			}

			// FIXME: path traversal vuln, but currently mitigated by SSH_ALLOWED_USERS whitelist
			authorizedKeysFile, err := os.Open(filepath.Join("/home", ctx.User(), ".ssh/authorized_keys"))
			if err != nil {
				if os.IsNotExist(err) { // user simply doesn't have them
					return false
				} else {
					logger.Printf("error reading authorized_keys: %v", err)
					return false
				}
			}
			defer authorizedKeysFile.Close()

			authorizedKeys := bufio.NewScanner(authorizedKeysFile)
			for authorizedKeys.Scan() {
				authorizedKey, _, _, _, err := gliderssh.ParseAuthorizedKey(authorizedKeys.Bytes())
				if err != nil {
					logger.Printf("ParseAuthorizedKey: %v", err)
					return false
				}

				if gliderssh.KeysEqual(userKey, authorizedKey) {
					return true
				}
			}
			if err := authorizedKeys.Err(); err != nil {
				logger.Printf("error scanning: %v", err)
				return false
			}

			return false // none of the keys matched
		}),
	); err != nil {
		select {
		case <-ctx.Done(): // error was expected due to context cancel
			return nil
		default:
			return err
		}
	}

	return nil
}

func handleSSHConnection(s gliderssh.Session, account linuxuser.Account, verbose bool, logger *log.Logger) int {
	if verbose {
		user := s.User()

		tcpAddress := s.RemoteAddr().(*net.TCPAddr)

		logger.Printf("new session for %q from %v", user, tcpAddress)
		defer logger.Printf("closing session for %q from %v", user, tcpAddress)
	}

	if subsys := s.Subsystem(); subsys != "" { // what does this do? AFAIK SCP is a subsystem but even it doesn't set it?
		logger.Printf("unsupported subsystem specified: %s", subsys)
		fmt.Fprint(s, "unsupported subsystem specified\n")
		return 1
	}

	argv := s.Command()

	userWantsDefaultShell := len(argv) == 0
	if userWantsDefaultShell {
		userDefaultShell := account.Shell // usually /bin/bash
		if userDefaultShell == "" {
			fmt.Fprint(s, "user doesn't have a shell defined\n")
			return 1
		}

		argv = []string{userDefaultShell}
	}

	sshClientEnvs := s.Environ()

	ptyReq, sshClientWindowChanged, isPty := s.Pty()

	// envsSpecifyTerminal() check just because in theory TERM could be sent via ENVs, though SSH seems
	// to pass it out-of-band explicitly in the PTY request and the server seems to be supposed to append it
	if isPty && ptyReq.Term != "" && !envsSpecifyTerminal(sshClientEnvs) {
		sshClientEnvs = append(sshClientEnvs, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	//nolint:gosec // Due to nature of SSH this is a thing we must do
	cmd := exec.CommandContext(s.Context(), argv[0], argv[1:]...)
	cmd.Env = sshClientEnvs
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    account.Uid,
			Gid:    account.GidPrimary,
			Groups: account.GidsSupplementary,
		},
	}

	sigs := make(chan gliderssh.Signal, 1)
	s.Signals(sigs)
	go func() { // signals coming from SSH client are piped to the process
		for sigStr := range sigs {
			sig, found := sshSignalMap[sigStr]
			if !found {
				panic(fmt.Errorf("sig not implemented: %s", sigStr))
			}

			if err := cmd.Process.Signal(sig); err != nil {
				panic(err)
			}
		}
	}()

	handleExit := func(err error) int {
		if err == nil {
			return 0
		}

		if errExit, is := err.(*exec.ExitError); is {
			return errExit.ExitCode()
		} else { // perhaps error finding executable?
			fmt.Fprint(s, err.Error()+"\n")
			return 1
		}
	}

	if isPty {
		terminal, err := pty.Start(cmd)
		if err != nil {
			logger.Printf("running shell: %v", err)
			return 1
		}
		defer terminal.Close()

		go func() { // window change events from SSH client (terminal resizes). https://www.austingroupbugs.net/view.php?id=1151
			for window := range sshClientWindowChanged {
				setWinsize(terminal, window.Width, window.Height)
			}
		}()

		go func() {
			// SSH is terminal's stdin and terminal's stdout is SSH.
			// this always errors upon closing connection so we'll ignore its error
			_ = bidipipe.Pipe(bidipipe.WithName("SSH", s), bidipipe.WithName("Terminal", terminal))
		}()

		return handleExit(cmd.Wait())
	} else {
		cmd.Stdin = s  // reads from session mean stdin
		cmd.Stdout = s // writes to session mean stdout
		cmd.Stderr = s.Stderr()

		return handleExit(cmd.Run())
	}
}
