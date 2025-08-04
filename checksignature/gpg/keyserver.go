package gpg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FetchKeyFromKeyserver attempts to fetch a GPG key from a list of keyservers
// and return it in ASCII-armored format. Tries each server in order until one succeeds.
func FetchKeyFromKeyserver(keyID string) (string, error) {
	keyservers := []string{
		"keys.openpgp.org",
		"keyserver.ubuntu.com",
	}

	// Try fetching the key from a list of known keyservers.
	// If one fails, try the next.
	for _, server := range keyservers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "gpg", "--keyserver", server, "--recv-keys", keyID)
		if err := cmd.Run(); err == nil {
			// If key was received, try to export it in ASCII-armored format
			exportCtx, exportCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer exportCancel()

			exportCmd := exec.CommandContext(exportCtx, "gpg", "--armor", "--export", keyID)
			output, exportErr := exportCmd.Output()
			if exportErr == nil {
				return string(output), nil
			}
		}
	}

	return "", fmt.Errorf("key not found on any keyserver")
}

// ImportKeyDirectly imports a GPG public key directly into the local keyring.
// The key must be ASCII-armored. This does not assign any trust level to the key.
func ImportKeyDirectly(publicKey string) error {
	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = strings.NewReader(publicKey)
	return cmd.Run()
}
