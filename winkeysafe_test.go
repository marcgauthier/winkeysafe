package winkeysafe

import (
	"fmt"
	"os"
	"testing"

	"github.com/awnumar/memguard"
)

var testWordsList = []string{
	"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
	"golf", "hotel", "india", "juliet", "kilo", "lima",
	"mike", "november", "oscar", "papa", "quebec", "romeo",
	"sierra", "tango", "uniform", "victor", "whiskey", "xray",
}

// TestMain initializes memguard and provides cleanup.
func TestMain(m *testing.M) {
	memguard.CatchInterrupt()
	defer memguard.Purge()
	os.Exit(m.Run())
}

// TestGenerateAndRetrieveKey tests key generation, storage, and retrieval.
func TestGenerateAndRetrieveKey(t *testing.T) {
	// Setup
	wordsList = testWordsList
	defer func() { secureKey = nil }() // Reset secureKey after the test

	cipherFile := "test_key.dat"
	plainTextFile := "test_key.txt"

	// Ensure test files are removed after the test
	defer os.Remove(cipherFile)

	// Generate a new key
	words, err := New(cipherFile, plainTextFile)
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	fmt.Println("plain text key: ", words)

	// remove plain text file
	os.Remove(plainTextFile)

	// Load the generated key
	_, err = New(cipherFile, plainTextFile)
	if err != nil {
		t.Fatalf("Failed to load the generated key: %v", err)
	}

	// Retrieve the key
	key, err := GetKey()
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}
	if len(key) == 0 {
		t.Fatalf("Key should not be empty")
	}
}

// TestDestroyKey tests the key destruction functionality.
func TestDestroyKey(t *testing.T) {
	// Setup
	secureKey = memguard.NewBufferFromBytes([]byte("dummy-key"))

	// Destroy the key
	DestroyKey()

	if secureKey != nil {
		t.Fatalf("Expected secureKey to be nil after DestroyKey, but it is not nil")
	}
}

// TestEncryptAndDecrypt tests encryption and decryption functionality.
func TestEncryptAndDecrypt(t *testing.T) {
	// Setup
	data := []byte("test data")
	secureData := make([]byte, len(data))
	copy(secureData, data)

	// Encrypt data
	encrypted, err := encryptData(secureData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	if len(encrypted) == 0 {
		t.Fatalf("Encrypted data should not be empty")
	}

	// Decrypt data
	decrypted, err := decryptData(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Fatalf("Decrypted data does not match original. Got: %s, Want: %s", string(decrypted), string(data))
	} else {
		fmt.Println("success")
	}
}
