package winkeysafe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AccessKey manages key initialization, validation, and encryption/decryption logic.
func AccessKey() ([]byte, error) {

	keyDatExists := fileExists("key.dat")
	keyTxtExists := fileExists("key.txt")

	// Error if both key.dat and key.txt exist simultaneously.
	if keyDatExists && keyTxtExists {
		return nil, errors.New("both key.dat and key.txt exist. Copy key.txt to a safe place and remove it from this server")
	}

	if keyDatExists {
		// Decrypt and load key from key.dat.
		encryptedKey, err := os.ReadFile("key.dat")
		if err != nil {
			return nil, fmt.Sprintf("failed to read key.dat: %v", err)
		}

		decryptedKey, err := decryptData(encryptedKey)
		if err != nil {
			return nil, fmt.Sprintf("failed to decrypt key.dat: %v", err)
		}

		return decryptedKey, nil
	}

	if keyTxtExists {
		// Validate and encrypt the key from key.txt.
		plainTextKey, err := os.ReadFile("key.txt")
		if err != nil {
			return nil, fmt.Sprintf("failed to read key.txt: %v", err)
		}

		encryptedKey, err := encryptData([]byte(plainTextKey))
		if err != nil {
			return nil, fmt.Sprintf("failed to encrypt key.txt: %v", err)
		}

		err = os.WriteFile("key.dat", encryptedKey, 0600)
		if err != nil {
			return nil, fmt.Sprintf("failed to save key.dat: %v", err)
		}

		return []byte(plainTextKey), errors.New("key.txt successfully encrypted to key.dat. Remove key.txt from this server and store it safely")
	}

	// Generate a new key if no files exist.
	words := generate256BitsKey()
	err := os.WriteFile("key.txt", []byte(words), 0600)
	if err != nil {
		return nil, fmt.Sprintf("failed to write key.txt: %v", err)
	}

	plainTextKey, err := os.ReadFile("key.txt")
	if err != nil {
		return nil, fmt.Sprintf("failed to read key.txt: %v", err)
	}

	encryptedKey, err := encryptData([]byte(plainTextKey))
	if err != nil {
		return nil, fmt.Sprintf("failed to encrypt generated key: %v", err)
	}

	err = os.WriteFile("key.dat", encryptedKey, 0600)
	if err != nil {
		return nil, fmt.Sprintf("failed to save key.dat: %v", err)
	}

	return []byte(plainTextKey), nil
}

// fileExists checks if a given file exists on the system.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
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
	return decrypted, nil
}

// Characters pool for the key generation
const charPool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"

// generate32BytesKey generates a random 32-byte string using the specified character pool.
func generate256BitsKey() (string, error) {
	keyLength := 32
	charPoolLength := len(charPool)
	key := make([]byte, keyLength)

	for i := 0; i < keyLength; i++ {
		randomIndex, err := secureRandomInt(charPoolLength)
		if err != nil {
			return "", fmt.Errorf("Failed to generate random index: %v", err)
		}
		key[i] = charPool[randomIndex]
	}

	return string(key)
}

// secureRandomInt generates a cryptographically secure random integer in the range [0, max).
func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}

	randomBytes := make([]byte, 1)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}

	return int(randomBytes[0]) % max, nil
}
