package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/function61/function22/pkg/function22"
	"github.com/function61/function22/pkg/linuxuser"
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
		user := knownUsers[s.User()]
		if err := s.Exit(function22.Serve(s, *user, "")); err != nil {
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
