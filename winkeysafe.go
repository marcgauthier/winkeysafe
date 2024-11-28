// Package winkeysafe provides functions for key management using DPAPI encryption on Windows systems.
package winkeysafe

import (
	"fmt"
	"math/rand"
	"os"
	"unsafe"

	"github.com/awnumar/memguard"
	"golang.org/x/sys/windows"
)

// AccessKey manages key initialization, validation, and encryption/decryption logic.
// Ensure that New() has been called before using this function.
func Get(cipherFile, plainTextFile string) ([]byte, error) {

	keyDatExists := fileExists(cipherFile)
	keyTxtExists := fileExists(plainTextFile)

	// Error if both key.dat and key.txt exist simultaneously.
	if keyDatExists && keyTxtExists {
		return nil, fmt.Errorf("can't have both plaintext and cipher keys on your server, copy %s to a safe place and remove it from this server", plainTextFile)
	}

	// if a key is present make sure it accessible.
	if keyDatExists {
		// Decrypt and load key from key.dat.
		encryptedKey, err := os.ReadFile(cipherFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", cipherFile, err)
		}

		decryptedKey, err := decryptDataUsingDPAPI(encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %s: %w", cipherFile, err)
		}

		return decryptedKey, nil
	}

	// if only a plaintext key is present, the data was moved of the cipher file was
	// deleted by accident. Recreate the cipherFile and generate error!

	if keyTxtExists {

		// Validate and encrypt the key from key.txt.
		plainTextKey, err := os.ReadFile(plainTextFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", plainTextFile, err)
		}

		if len(plainTextKey) != 32 {
			return nil, fmt.Errorf("%s must contain a key that is 32 characters", plainTextKey)
		}

		encryptedKey, err := encryptDataUsingDPAPI(plainTextKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt %s using DPAPI: %w", plainTextKey, err)
		}

		err = os.WriteFile(cipherFile, encryptedKey, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to save %s: %w", cipherFile, err)
		}

		return nil, fmt.Errorf("can't have both plaintext and cipher keys on your server, copy %s to a safe place and remove it from this server", plainTextFile)
	}

	// if no files exist generate both cipher and plaintext files.

	// generate a new key
	plainTextKey := generate256BitsKey(32)

	// save the plaintextfile
	err := os.WriteFile(plainTextFile, []byte(plainTextKey), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", plainTextFile, err)
	}

	// encrypt plaintextkey using DPAPI
	encryptedKey, err := encryptDataUsingDPAPI([]byte(plainTextKey))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt generated key: %w", err)
	}

	// write the cipher file.
	err = os.WriteFile(cipherFile, encryptedKey, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to save %s: %w", cipherFile, err)
	}

	return []byte(plainTextKey), nil
}

// fileExists checks if a given file exists on the system.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// encryptData encrypts data using DPAPI in the machine context.
func encryptDataUsingDPAPI(data []byte) ([]byte, error) {
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
func decryptDataUsingDPAPI(data []byte) ([]byte, error) {
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

// generate256BitsKey generates a random key of the specified size (in characters).
func generate256BitsKey(size int) string {
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(){[]};:.,/?`~"
	var results []byte

	for i := 0; i < size; i++ {
		// Securely generate a random index
		x := 0
		y := len(characters) - 1
		randomIndex := rand.Intn(y-x+1) + x

		// Append the selected character
		results = append(results, characters[randomIndex])
	}

	return string(results)
}
