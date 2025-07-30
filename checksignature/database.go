package checksignature

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

func generateSSHKeyDatabase() error {
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}

	sshDir := filepath.Join(usr.HomeDir, ".ssh")
	keyDatabase := make(map[string]string)

	pubKeyFiles, err := filepath.Glob(filepath.Join(sshDir, "*.pub"))
	if err != nil {
		return fmt.Errorf("failed to find SSH public keys: %v", err)
	}

	for _, pubKeyFile := range pubKeyFiles {
		cmd := exec.Command("ssh-keygen", "-lf", pubKeyFile)
		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("Skipping %s: %v\n", pubKeyFile, err)
			continue
		}

		parts := strings.Fields(string(output))
		var fingerprint string
		for _, part := range parts {
			if strings.HasPrefix(part, "SHA256:") {
				fingerprint = part
				break
			}
		}

		if fingerprint == "" {
			fmt.Printf("Could not extract fingerprint from %s\n", pubKeyFile)
			continue
		}

		privKeyFile := strings.TrimSuffix(pubKeyFile, ".pub")
		stat, err := os.Stat(privKeyFile)
		if err != nil {
			fmt.Printf("Private key not found for %s: %v\n", pubKeyFile, err)
			continue
		}

		createdAt := stat.ModTime().UTC().Format(time.RFC3339)
		keyDatabase[fingerprint] = createdAt

	}

	file, err := os.Create("local_ssh_key_dates.json")
	if err != nil {
		return fmt.Errorf("failed to create key database file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(keyDatabase); err != nil {
		return fmt.Errorf("failed to write key database: %v", err)
	}

	// fmt.Printf("Generated SSH key database with %d keys\n", len(keyDatabase))
	return nil
}
