package winkeysafe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/awnumar/memguard"
	"golang.org/x/sys/windows"
)

// SecureKey is a locked buffer holding the encryption key in memory.
var secureKey *memguard.LockedBuffer

// GetKey retrieves the key stored in memguard. Returns an error if the key is not loaded.
func GetKey() ([]byte, error) {
	if secureKey == nil {
		return nil, errors.New("key not loaded into memory")
	}

	// Melt the buffer to make it readable
	secureKey.Melt()
	defer secureKey.Freeze() // Freeze the buffer after accessing it

	// Return the key as a string
	return secureKey.Bytes(), nil
}

// AccessKey manages key initialization, validation, and encryption/decryption logic.
func AccessKey() (bool, string) {
	keyDatExists := fileExists("key.dat")
	keyTxtExists := fileExists("key.txt")

	// Error if both key.dat and key.txt exist simultaneously.
	if keyDatExists && keyTxtExists {
		return false, "both key.dat and key.txt exist. Copy key.txt to a safe place and remove it from this server"
	}

	if keyDatExists {
		// Decrypt and load key from key.dat.
		encryptedKey, err := os.ReadFile("key.dat")
		if err != nil {
			return false, fmt.Sprintf("failed to read key.dat: %v", err)
		}

		decryptedKey, err := decryptData(encryptedKey)
		if err != nil {
			return false, fmt.Sprintf("failed to decrypt key.dat: %v", err)
		}

		secureKey = memguard.NewBufferFromBytes(decryptedKey)
		return true, "decryption key loaded"
	}

	if keyTxtExists {
		// Validate and encrypt the key from key.txt.
		plainTextKey, err := os.ReadFile("key.txt")
		if err != nil {
			return false, fmt.Sprintf("failed to read key.txt: %v", err)
		}

		encryptedKey, err := encryptData([]byte(plainTextKey))
		if err != nil {
			return false, fmt.Sprintf("failed to encrypt key.txt: %v", err)
		}

		err = os.WriteFile("key.dat", encryptedKey, 0600)
		if err != nil {
			return false, fmt.Sprintf("failed to save key.dat: %v", err)
		}

		return false, "key.txt successfully encrypted to key.dat. Remove key.txt from this server and store it safely"
	}

	// Generate a new key if no files exist.
	words := generate256BitsKey()
	err := os.WriteFile("key.txt", []byte(words), 0600)
	if err != nil {
		return false, fmt.Sprintf("failed to write key.txt: %v", err)
	}

	plainTextKey, err := os.ReadFile("key.txt")
	if err != nil {
		return false, fmt.Sprintf("failed to read key.txt: %v", err)
	}

	encryptedKey, err := encryptData([]byte(plainTextKey))
	if err != nil {
		return false, fmt.Sprintf("failed to encrypt generated key: %v", err)
	}

	err = os.WriteFile("key.dat", encryptedKey, 0600)
	if err != nil {
		return false, fmt.Sprintf("failed to save key.dat: %v", err)
	}

	log.Printf("Generated keys consists of 32 characters.\nPlease record this key, save key.txt\nthen delete the file from this server.\nIf you loose the key you loose your database!!\n")
	log.Println("---------------------------------------------------------")
	log.Println(words)
	log.Println("---------------------------------------------------------")

	return false, ""
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
func generate256BitsKey() string {
	keyLength := 32
	charPoolLength := len(charPool)
	key := make([]byte, keyLength)

	for i := 0; i < keyLength; i++ {
		randomIndex, err := secureRandomInt(charPoolLength)
		if err != nil {
			log.Fatalf("Failed to generate random index: %v", err)
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
