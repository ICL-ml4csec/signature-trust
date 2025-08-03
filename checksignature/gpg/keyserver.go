package gpg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FetchKeyFromKeyserver attempts to fetch a GPG key from keyservers
func FetchKeyFromKeyserver(keyID string) (string, error) {
	keyservers := []string{
		"keys.openpgp.org",
		"keyserver.ubuntu.com",
	}

	for _, server := range keyservers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "gpg", "--keyserver", server, "--recv-keys", keyID)
		if err := cmd.Run(); err == nil {
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

// ImportKeyDirectly imports a GPG public key directly
func ImportKeyDirectly(publicKey string) error {
	cmd := exec.Command("gpg", "--import")
	cmd.Stdin = strings.NewReader(publicKey)
	return cmd.Run()
}
