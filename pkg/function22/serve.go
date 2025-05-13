// function22 SSH server
package function22

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/function61/function22/pkg/linuxuser"
	"github.com/function61/gokit/io/bidipipe"
	gliderssh "github.com/gliderlabs/ssh"
)

func Serve(s gliderssh.Session, account linuxuser.Account, pathFallback string) int {
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
	if isPty && ptyReq.Term != "" && !envsSpecify(sshClientEnvs, "TERM") {
		sshClientEnvs = append(sshClientEnvs, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	sshClientEnvs = append(sshClientEnvs, sshConnectionEnvVars(s)...)
	if userWantsDefaultShell { // FIXME: should this be set anyway?
		sshClientEnvs = append(sshClientEnvs, loginEnvVars(account)...)
	} else if !envsSpecify(sshClientEnvs, "PATH") && pathFallback != "" {
		sshClientEnvs = append(sshClientEnvs, "PATH="+pathFallback)
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
		cmd.Stdin = newReadCancelerForCommand(s, cmd) // reads from session mean stdin
		cmd.Stdout = s                                // writes to session mean stdout
		cmd.Stderr = s.Stderr()

		return handleExit(cmd.Run())
	}
}
