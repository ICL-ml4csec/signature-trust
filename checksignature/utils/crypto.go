package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// InterfaceToString safely converts interface{} to string for key IDs
func InterfaceToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ComputeFingerprintFlexible computes the SHA256 fingerprint from either
// a full SSH public key string (e.g., "ssh-ed25519 AAAAC3...") or a raw byte blob.
func ComputeFingerprintFlexible(input interface{}) (string, error) {
	var keyData []byte

	switch v := input.(type) {
	case string:
		// Parse from SSH key string format
		parts := strings.Fields(v)
		if len(parts) < 2 {
			return "", fmt.Errorf("invalid SSH key string format")
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode SSH key string: %v", err)
		}
		keyData = decoded

	case []byte:
		keyData = v

	default:
		return "", fmt.Errorf("unsupported input type: %T", v)
	}

	// Compute SHA256 fingerprint
	hash := sha256.Sum256(keyData)
	fp := base64.StdEncoding.EncodeToString(hash[:])
	return fmt.Sprintf("SHA256:%s", strings.TrimRight(fp, "=")), nil
}
