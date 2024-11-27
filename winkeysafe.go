// Package winkeysafe provides functions for key management using DPAPI encryption on Windows systems.
package winkeysafe

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"unsafe"

	"github.com/awnumar/memguard"
	"golang.org/x/sys/windows"
)

// SecureKey is a locked buffer holding the encryption key in memory.
var secureKey *memguard.LockedBuffer

// GetKey retrieves the key stored in memguard. Returns an error if the key is not loaded.
func GetKey() (string, error) {

	secureKey.Melt()
	defer secureKey.Freeze()

	if secureKey == nil {
		return "", errors.New("key not loaded into memory")
	}
	return secureKey.String(), nil
}

// DestroyKey securely destroys the key in memory.
func DestroyKey() {
	if secureKey != nil {
		secureKey.Destroy()
		secureKey = nil
	}
}

// AccessKey manages key initialization, validation, and encryption/decryption logic.
// Ensure that New() has been called before using this function.
func New(cipherFile, plainTextFile string) (string, error) {
	if len(wordsList) == 0 {
		return "", errors.New("wordsList is not initialized. Call New() before AccessKey()")
	}

	keyDatExists := fileExists(cipherFile)
	keyTxtExists := fileExists(plainTextFile)

	// Error if both key.dat and key.txt exist simultaneously.
	if keyDatExists && keyTxtExists {
		return "", fmt.Errorf("copy %s to a safe place and remove it from this server", plainTextFile)
	}

	if keyDatExists {
		// Decrypt and load key from key.dat.
		encryptedKey, err := os.ReadFile(cipherFile)
		if err != nil {
			return "", fmt.Errorf("failed to read key.dat: %w", err)
		}

		decryptedKey, err := decryptData(encryptedKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt key.dat: %w", err)
		}

		// Securely load the key into memguard.
		secureKey = memguard.NewBufferFromBytes(decryptedKey)

		// Securely destroy the decryptedKey slice.
		memguard.WipeBytes(decryptedKey)

		return "", nil
	}

	if keyTxtExists {
		// Validate and encrypt the key from key.txt.
		plainTextKey, err := os.ReadFile(plainTextFile)
		if err != nil {
			return "", fmt.Errorf("failed to read %s: %w", plainTextFile, err)
		}

		words := strings.Fields(string(plainTextKey))
		if len(words) != 24 || !validateWords(words) {
			return "", fmt.Errorf("%s must contain exactly 24 valid words from the word list", plainTextKey)
		}

		encryptedKey, err := encryptData([]byte(strings.Join(words, " ")))
		if err != nil {
			return "", fmt.Errorf("failed to encrypt %s: %w", plainTextKey, err)
		}

		err = os.WriteFile(cipherFile, encryptedKey, 0600)
		if err != nil {
			return "", fmt.Errorf("failed to save %s: %w", cipherFile, err)
		}

		// Securely wipe the plainTextKey from memory.
		memguard.WipeBytes(plainTextKey)

		return "", nil
	}

	// Generate a new key if no files exist.
	words := generate256BitsKey()
	err := os.WriteFile(plainTextFile, []byte(strings.Join(words, " ")), 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write %s: %w", plainTextFile, err)
	}

	plainTextKey, err := os.ReadFile(plainTextFile)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", plainTextFile, err)
	}

	encryptedKey, err := encryptData([]byte(plainTextKey))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt generated key: %w", err)
	}

	err = os.WriteFile(cipherFile, encryptedKey, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to save %s: %w", cipherFile, err)
	}

	// Securely wipe the plainTextKey from memory.
	memguard.WipeBytes(plainTextKey)

	return formatWords(words), nil
}

// selectRandomWords selects 24 random words from the given wordsList and returns them as a []string.
func selectRandomWords(wordsList []string) ([]string, error) {
	// Ensure the wordsList has enough words to pick from
	if len(wordsList) < 24 {
		return nil, fmt.Errorf("wordsList must contain at least 24 words, but only %d provided", len(wordsList))
	}

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Create a slice to hold the selected words
	selectedWords := make([]string, 0, 24)

	// Create a map to track used indices to ensure no duplicates
	usedIndices := make(map[int]struct{})

	// Randomly pick 24 words
	for len(selectedWords) < 24 {
		index := rand.Intn(len(wordsList))
		if _, used := usedIndices[index]; !used {
			selectedWords = append(selectedWords, wordsList[index])
			usedIndices[index] = struct{}{}
		}
	}

	return selectedWords, nil
}

// fileExists checks if a given file exists on the system.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// validateWords ensures all words exist in the predefined words list.
func validateWords(words []string) bool {
	wordSet := make(map[string]struct{}, len(wordsList))
	for _, word := range wordsList {
		wordSet[word] = struct{}{}
	}
	for _, word := range words {
		if _, exists := wordSet[word]; !exists {
			return false
		}
	}
	return true
}

// formatWords neatly formats a list of words into a multi-line string.
func formatWords(words []string) string {
	var builder strings.Builder
	for i, word := range words {
		builder.WriteString(word)
		if (i+1)%6 == 0 {
			builder.WriteString("\n")
		} else {
			builder.WriteString(" ")
		}
	}
	return builder.String()
}

// encryptData encrypts data using DPAPI in the machine context.
func encryptData(data []byte) ([]byte, error) {
	desc := windows.StringToUTF16Ptr("")
	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var outBlob windows.DataBlob

	err := windows.CryptProtectData(&inBlob, desc, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &outBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	encrypted := make([]byte, outBlob.Size)
	copy(encrypted, unsafe.Slice(outBlob.Data, outBlob.Size))

	// Securely wipe the input data.
	memguard.WipeBytes(data)

	return encrypted, nil
}

// decryptData decrypts data using DPAPI in the machine context.
func decryptData(data []byte) ([]byte, error) {
	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var outBlob windows.DataBlob
	var desc *uint16

	err := windows.CryptUnprotectData(&inBlob, &desc, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &outBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	decrypted := make([]byte, outBlob.Size)
	copy(decrypted, unsafe.Slice(outBlob.Data, outBlob.Size))

	// Securely wipe the input data.
	memguard.WipeBytes(data)

	return decrypted, nil
}

// generate256BitsKey generates a random 24-word key from the words list.
func generate256BitsKey() []string {
	if len(wordsList) == 0 {
		return nil
	}

	results := make([]string, 24)
	for i := 0; i < 24; i++ {
		results[i] = wordsList[rand.Intn(len(wordsList))]
	}
	return results
}
