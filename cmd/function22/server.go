package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/function61/function22/pkg/linuxuser"
	"github.com/function61/gokit/io/bidipipe"
	"github.com/function61/gokit/os/osutil"
	gliderssh "github.com/gliderlabs/ssh"
)

func logic(ctx context.Context) error {
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
		if err := s.Exit(handleSSHConnection(s, *knownUsers[s.User()])); err != nil {
			slog.Error("session.Exit()", "err", err)
		}
	},
		gliderssh.HostKeyFile(defaultHostKeyFile),
		gliderssh.PasswordAuth(func(ctx gliderssh.Context, pass string) bool {
			username := ctx.User()

			account, found := knownUsers[username]
			if !found {
				slog.Warn("login attempt for unknown user", "username", username)
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
				slog.Warn("login attempt for unknown user", "username", ctx.User())
				return false
			}

			// FIXME: path traversal vuln, but currently mitigated by SSH_ALLOWED_USERS whitelist
			authorizedKeysFile, err := os.Open(filepath.Join("/home", ctx.User(), ".ssh/authorized_keys"))
			if err != nil {
				if os.IsNotExist(err) { // user simply doesn't have them
					return false
				} else {
					slog.Error("error reading authorized_keys", "err", err)
					return false
				}
			}
			defer authorizedKeysFile.Close()

			authorizedKeys := bufio.NewScanner(authorizedKeysFile)
			for authorizedKeys.Scan() {
				authorizedKey, _, _, _, err := gliderssh.ParseAuthorizedKey(authorizedKeys.Bytes())
				if err != nil {
					slog.Error("ParseAuthorizedKey", "err", err)
					return false
				}

				if gliderssh.KeysEqual(userKey, authorizedKey) {
					return true
				}
			}
			if err := authorizedKeys.Err(); err != nil {
				slog.Error("scanning", "err", err)
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

func handleSSHConnection(s gliderssh.Session, account linuxuser.Account) int {
	user := s.User()

	tcpAddress := s.RemoteAddr().(*net.TCPAddr)

	slog.Debug("new session", "user", user, "tcpAddress", tcpAddress)
	defer slog.Debug("closing session", "user", user, "tcpAddress", tcpAddress)

	if subsys := s.Subsystem(); subsys != "" { // what does this do? AFAIK SCP is a subsystem but even it doesn't set it?
		slog.Error("unsupported subsystem specified", "subsys", subsys)
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

	sshClientEnvs = append(sshClientEnvs, sshConnectionEnvVars(s)...)
	if userWantsDefaultShell { // FIXME: should this be set anyway?
		sshClientEnvs = append(sshClientEnvs, loginEnvVars(account)...)
	}

	//nolint:gosec // Due to nature of SSH this is a thing we must do
	cmd := exec.CommandContext(s.Context(), argv[0], argv[1:]...)
	cmd.Dir = account.Homedir
	cmd.Env = sshClientEnvs
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    account.Uid,
			Gid:    account.GidPrimary,
			Groups: account.GidsSupplementary,
		},
	}

	if userWantsDefaultShell {
		// "bash" -> "-bash"
		// convention to tell that we want login shell (read shell config files, fill PATH etc.)
		// https://unix.stackexchange.com/a/46856
		//
		// cmd := exec.Command(name, "argv1") is internally copied to two fields:
		// - cmd.Path (which we're not mutating here)
		// - cmd.Args[0] (mutating this one, which no longer affects the actual exec'd binary)
		cmd.Args[0] = "-" + cmd.Args[0]
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
			slog.Error("starting shell", "err", err)
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
