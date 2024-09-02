package encrypt

import (
	"bytes"
	"testing"
)

func TestNewGpgKey(t *testing.T) {
	keys, err := NewEncrypter("name", "email@example.com")
	if err != nil {
		t.Fatal("error creating gpg key", err)
	}

	if keys.publicKey == nil || keys.privateKey == nil {
		t.Fatal("gpg keys are nil")
	}
}

func TestGpgSaveKey(t *testing.T) {
	privateKey := new(bytes.Buffer)
	keys, _ := NewEncrypter("name", "email@example.com")

	_, err := keys.WriteTo(privateKey)
	if err != nil {
		t.Fatal("error saving private key", err)
	}

	pk, err := NewEncrypterFromReader(privateKey)
	if err != nil {
		t.Fatalf("error creating gpg encrypter: %v", err)
	}

	if pk.privateKey.GetFingerprint() != keys.privateKey.GetFingerprint() {
		t.Fatalf("expected fingerprint %s, got %s", keys.privateKey.GetFingerprint(), pk.privateKey.GetFingerprint())
	}
}

func TestGpgEncrypter_Encrypt(t *testing.T) {
	var (
		data      = bytes.NewBufferString("encrypt me")
		encrypted = new(bytes.Buffer)
	)
	keys, _ := NewEncrypter("name", "email@example.com")

	err := keys.Encrypt(encrypted, data)
	if err != nil {
		t.Fatal("error encrypting data", err)
	}

	decrypted, err := keys.Decrypt(encrypted)
	if err != nil {
		t.Fatal("error decrypting data", err)
	}

	if bytes.Equal(decrypted, data.Bytes()) {
		t.Fatalf("expected %s, got %s", data.String(), decrypted)
	}
}
