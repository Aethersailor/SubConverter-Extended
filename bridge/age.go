package main

import (
	"crypto/sha256"
	"fmt"
	"strings"

	mihomoage "github.com/metacubex/mihomo/component/age"
)

type ageRecipientResult struct {
	Recipient   string `json:"recipient,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Source      string `json:"source,omitempty"`
	Error       string `json:"error,omitempty"`
}

func resolveAgeRecipient(key string) (ageRecipientResult, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(strings.Fields(key)) != 1 {
		return ageRecipientResult{}, fmt.Errorf("invalid age key")
	}

	recipient := key
	source := "public"
	if err := mihomoage.VerityPublicKeys(key); err != nil {
		if err := mihomoage.VeritySecretKeys(key); err != nil {
			return ageRecipientResult{}, fmt.Errorf("invalid age key")
		}
		publicKeys, err := mihomoage.ToPublicKeys(key)
		if err != nil || len(publicKeys) != 1 {
			return ageRecipientResult{}, fmt.Errorf("invalid age secret key")
		}
		recipient = publicKeys[0]
		source = "secret"
	}

	fingerprint := sha256.Sum256([]byte(recipient))
	return ageRecipientResult{
		Recipient:   recipient,
		Fingerprint: fmt.Sprintf("%x", fingerprint[:]),
		Source:      source,
	}, nil
}

func encryptAgeArmored(data, recipient string) (string, error) {
	if err := mihomoage.VerityPublicKeys(recipient); err != nil {
		return "", fmt.Errorf("invalid age recipient")
	}
	encrypted, err := mihomoage.EncryptBytes([]byte(data), recipient)
	if err != nil {
		return "", fmt.Errorf("age encryption failed")
	}
	return string(encrypted), nil
}
