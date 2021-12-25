package linuxuser

// https://en.wikipedia.org/wiki/Passwd#Shadow_file

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

type Account struct {
	username          string
	passwordHash      string
	Uid               uint32
	GidPrimary        uint32
	GidsSupplementary []uint32
	Shell             string
}

func FindByUsername(username string) (*Account, error) {
	shadowFile, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer shadowFile.Close()

	shadowLines := bufio.NewScanner(shadowFile)

	for shadowLines.Scan() {
		if shadowLines.Text() == "" { // skip empty lines
			continue
		}

		// usbmux:*:18909:0:99999:7:::
		parts := strings.Split(shadowLines.Text(), ":")

		if len(parts) < 9 {
			return nil, fmt.Errorf("/etc/shadow invalid parts number: %d", len(parts))
		}

		itemUsername := parts[0]

		if itemUsername == username {
			uid, gid, shell, err := resolveUIDAndGIDAndShellForUser(itemUsername)
			if err != nil {
				return nil, fmt.Errorf("resolveUIDAndGIDAndShellForUser: %w", err)
			}

			groups, err := resolveSupplementaryGids(itemUsername)
			if err != nil {
				return nil, fmt.Errorf("resolveSupplementaryGids: %w", err)
			}

			return &Account{
				username:          itemUsername,
				passwordHash:      parts[1],
				Uid:               uid,
				GidPrimary:        gid,
				GidsSupplementary: groups,
				Shell:             shell,
			}, nil
		}
	}
	if err := shadowLines.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("username not found: %s", username)
}

func ValidatePassword(givenPassword string, account Account) error {
	salt, err := extractSHA512CryptSalt(account)
	if err != nil {
		return err
	}

	givenPasswordHash, err := hashPassword(givenPassword, salt)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(givenPasswordHash), []byte(account.passwordHash)) != 1 {
		return errors.New("wrong password")
	}

	return nil
}

func hashPassword(givenPassword string, salt []byte) (string, error) {
	hash, err := sha512_crypt.New().Generate([]byte(givenPassword), salt)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func extractSHA512CryptSalt(account Account) ([]byte, error) {
	// $6 prefix indicates sha512_crypt
	if !strings.HasPrefix(account.passwordHash, "$6$") {
		return nil, errors.New("unexpected passwordHash type")
	}

	return []byte(account.passwordHash[:11]), nil
}

// /etc/shadow doesn't contain uid & gid, so we have to read it from a separate file
func resolveUIDAndGIDAndShellForUser(username string) (uint32, uint32, string, error) {
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return 0, 0, "", err
	}
	defer passwdFile.Close()

	passwdLines := bufio.NewScanner(passwdFile)

	for passwdLines.Scan() {
		// usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
		parts := strings.Split(passwdLines.Text(), ":")
		if len(parts) < 7 {
			return 0, 0, "", fmt.Errorf("/etc/passwd invalid parts number: %d", len(parts))
		}

		name := parts[0]
		if name == username {
			uid, err := strconv.Atoi(parts[2])
			if err != nil {
				return 0, 0, "", err
			}

			gid, err := strconv.Atoi(parts[3])
			if err != nil {
				return 0, 0, "", err
			}

			shell := parts[6]

			return uint32(uid), uint32(gid), shell, nil
		}
	}
	if err := passwdLines.Err(); err != nil {
		return 0, 0, "", err
	}

	return 0, 0, "", fmt.Errorf("user '%s' not found from /etc/passwd", username)
}

func resolveSupplementaryGids(username string) ([]uint32, error) {
	groups := []uint32{}

	groupFile, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer groupFile.Close()

	groupLines := bufio.NewScanner(groupFile)

	for groupLines.Scan() {
		// docker:x:129:joonas
		parts := strings.Split(groupLines.Text(), ":")
		if len(parts) < 4 {
			return nil, fmt.Errorf("/etc/group invalid parts number: %d", len(parts))
		}

		lineUsername := parts[3]
		if lineUsername == username {
			gid, err := strconv.Atoi(parts[2])
			if err != nil {
				return nil, err
			}

			groups = append(groups, uint32(gid))
		}
	}
	if err := groupLines.Err(); err != nil {
		return nil, err
	}

	return groups, nil
}
