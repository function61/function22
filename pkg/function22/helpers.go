package function22

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"
	"unsafe"

	"github.com/function61/function22/pkg/linuxuser"
	"github.com/function61/gokit/os/osutil"
	gliderssh "github.com/gliderlabs/ssh"
)

var sshSignalMap = map[gliderssh.Signal]os.Signal{
	gliderssh.SIGINT:  os.Interrupt,
	gliderssh.SIGKILL: os.Kill,
}

func setWinsize(f *os.File, w, h int) {
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func envsSpecify(environ []string, key string) bool {
	for _, env := range environ {
		if keyCandidate, _ := osutil.ParseEnv(env); keyCandidate == key {
			return true
		}
	}

	return false
}

// https://unix.stackexchange.com/a/76356
func loginEnvVars(account linuxuser.Account) []string {
	staticVars := []string{
		makeEnvVarStr("HOME", account.Homedir),
		makeEnvVarStr("SHELL", account.Shell),
		makeEnvVarStr("USER", account.Username),
	}

	environmentFileVars, err := readEnvironmentFile()
	if err != nil {
		slog.Warn("loginEnvVars", "err", err)
	}

	return append(staticVars, environmentFileVars...)
}

// https://en.wikibooks.org/wiki/OpenSSH/Client_Applications#SSH_Client_Environment_Variables_--_Server_Side
func sshConnectionEnvVars(s gliderssh.Session) []string {
	clientAddress := s.RemoteAddr().(*net.TCPAddr)
	serverAddress := s.LocalAddr().(*net.TCPAddr)

	// SSH_CONNECTION=100.76.39.10 37004 100.115.75.64 22
	// SSH_CONNECTION=<clientIP> <clientPort> <serverIP> <serverPort>
	connEnv := fmt.Sprintf(
		"SSH_CONNECTION=%s %d %s %d",
		clientAddress.IP.String(),
		clientAddress.Port,
		serverAddress.IP.String(),
		serverAddress.Port)

	// SSH_CLIENT=100.76.39.10 37004 22
	// SSH_CLIENT=<clientIP> <clientPort> <serverPort>
	clientEnv := fmt.Sprintf(
		"SSH_CLIENT=%s %d %d",
		clientAddress.IP.String(),
		clientAddress.Port,
		serverAddress.Port)

	// TODO
	// ttyEnv:="SSH_TTY=/dev/pts/2"

	return []string{connEnv, clientEnv}
}

func makeEnvVarStr(key string, value string) string {
	return fmt.Sprintf("%s=%s", key, value)
}

// reads `/etc/environment` and returns all non-empty lines as a slice of strings.
// https://superuser.com/a/664237
func readEnvironmentFile() ([]string, error) {
	withErr := func(err error) ([]string, error) { return nil, fmt.Errorf("readEnvironmentFile: %w", err) }

	file, err := os.Open("/etc/environment")
	if err != nil {
		return withErr(err)
	}
	defer file.Close()

	var envs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// the dumb format has quotes so we cannot use the line format as-is for the ENV block
		keyAndValue := environmentFileValueParseRe.FindStringSubmatch(line)
		if keyAndValue == nil {
			return withErr(fmt.Errorf("failed to parse: %s", line))
		}

		// reconstruct back to `key=value` but without quotes around the value
		envs = append(envs, makeEnvVarStr(keyAndValue[1], keyAndValue[2]))
	}

	if err := scanner.Err(); err != nil {
		return withErr(err)
	}

	return envs, nil
}

// parses `key="value"`
var environmentFileValueParseRe = regexp.MustCompile(`^([^=]+)="([^"]+)"$`)

// `cmd.Wait()` (and by extension, `Run()`) doesn't return before stdin is closed.
// this is really disgusting wart as stdin content doesn't matter after if process has exited.
// but to get `Wait()` to exit we need to "close" (unblock its `Read()`) the stdin and for that we need this monstrosity.
// https://github.com/golang/go/issues/7990
func newReadCancelerForCommand(reader io.Reader, cmd *exec.Cmd) io.Reader {
	return newReadCanceler(reader, func() error {
		processExited := cmd.ProcessState != nil
		if processExited {
			return io.EOF
		} else {
			return nil
		}
	})
}

type readResult struct {
	read int
	err  error
}

type readCanceler struct {
	reader                   io.Reader
	readResult               chan readResult
	shouldCancel             func() error // function to check whether in-flight `Read()` should be canceled
	shouldCancelPollInterval *time.Ticker
}

func newReadCanceler(reader io.Reader, shouldCancel func() error) io.Reader {
	return &readCanceler{
		reader:                   reader,
		readResult:               make(chan readResult, 1),
		shouldCancel:             shouldCancel,
		shouldCancelPollInterval: time.NewTicker(500 * time.Millisecond),
	}
}

var _ io.Reader = (*readCanceler)(nil)

func (g *readCanceler) Read(p []byte) (int, error) {
	// this may block "forever", thus do it in a goroutine
	go func() {
		read, err := g.reader.Read(p)
		g.readResult <- readResult{read, err}
	}()

	for {
		select {
		case res := <-g.readResult:
			if res.err != nil { // we know the consumer will not be calling us again
				g.releaseResources()
			}
			return res.read, res.err
		case <-g.shouldCancelPollInterval.C:
			// detect if we're wanting to exit from `Wait()` soon (but just waiting for our reader to unblock)
			if err := g.shouldCancel(); err != nil {
				g.releaseResources()
				// just to unblock `Wait()` of `exec.Cmd`.
				// NOTE: we're purposefully abandoning last in-flight `Read()` here
				return 0, err
			}
		}
	}
}

func (g *readCanceler) releaseResources() {
	g.shouldCancelPollInterval.Stop()
}
