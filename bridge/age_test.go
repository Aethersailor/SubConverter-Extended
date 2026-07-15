package main

import (
	"strings"
	"testing"

	mihomoage "github.com/metacubex/mihomo/component/age"
)

func TestResolveAndEncryptAgeRecipients(t *testing.T) {
	tests := []struct {
		name     string
		generate func() (string, string, error)
	}{
		{name: "x25519", generate: mihomoage.GenX25519KeyPair},
		{name: "mlkem768-x25519", generate: mihomoage.GenHybridKeyPair},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, public, err := tt.generate()
			if err != nil {
				t.Fatalf("generate key pair: %v", err)
			}

			fromSecret, err := resolveAgeRecipient(secret)
			if err != nil {
				t.Fatalf("resolve secret: %v", err)
			}
			fromPublic, err := resolveAgeRecipient(public)
			if err != nil {
				t.Fatalf("resolve public: %v", err)
			}
			if fromSecret.Source != "secret" || fromPublic.Source != "public" {
				t.Fatalf("unexpected sources: secret=%q public=%q", fromSecret.Source, fromPublic.Source)
			}
			if fromSecret.Recipient != public || fromPublic.Recipient != public {
				t.Fatalf("recipient mismatch")
			}
			if fromSecret.Fingerprint != fromPublic.Fingerprint || len(fromSecret.Fingerprint) != 64 {
				t.Fatalf("fingerprint mismatch")
			}

			plaintext := "proxies:\n  - name: AgeSmoke\n    type: direct\n"
			armored, err := encryptAgeArmored(plaintext, fromSecret.Recipient)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if !strings.HasPrefix(armored, mihomoage.FileHeader) {
				t.Fatalf("missing Age armor header")
			}
			decrypted, err := mihomoage.DecryptBytes([]byte(armored), secret)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(decrypted) != plaintext {
				t.Fatalf("decrypted content mismatch")
			}
		})
	}
}

func TestResolveAgeRecipientRejectsInvalidOrMultipleKeys(t *testing.T) {
	if _, err := resolveAgeRecipient("not-an-age-key"); err == nil {
		t.Fatal("invalid key was accepted")
	}

	_, public, err := mihomoage.GenX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	if _, err := resolveAgeRecipient(public + "\n" + public); err == nil {
		t.Fatal("multiple keys were accepted")
	}

	officialExample := "age1xh86kh9v23vattr58yedspm3f57sxvnswu9krr6ns438amekx5gsd09uma"
	if _, err := resolveAgeRecipient(officialExample); err != nil {
		t.Fatalf("official Mihomo public-key example was rejected: %v", err)
	}
}
