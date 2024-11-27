
# winkeysafe

`winkeysafe` is a Go package for managing encryption keys securely on Windows systems using the Data Protection API (DPAPI) and [memguard](https://github.com/awnumar/memguard) for secure memory management. It provides functionalities for generating, encrypting, decrypting, and securely storing encryption keys.

## Features

- **Secure Key Management:** Uses memguard to store sensitive keys securely in memory.
- **Encryption and Decryption:** Leverages Windows DPAPI for machine-specific encryption.
- **Key Generation:** Generates a 24-word key for encryption purposes.
- **Key Persistence:** Supports saving and loading encrypted keys from files.
- **Cross-Process Security:** Ensures keys remain secure and protected in memory.

## Requirements

- Windows operating system.
- Go 1.18 or higher.
- [memguard](https://github.com/awnumar/memguard) library for secure memory management.
- Permissions to read/write files in the working directory.

## Installation

To install the package, use:

```bash
go get -u github.com/yourusername/winkeysafe
```

## Usage

### Import the Package

```go
import "github.com/marcgauthier/winkeysafe"
```

### Initialize Key Management

1. Ensure the `wordsList` variable is initialized with a valid list of 24 unique words.
2. Use the `New()` function to generate or load keys:

```go
package main

import (
	"fmt"
	"github.com/marcgauthier/winkeysafe"
)

func main() {
	winkeysafe.WordsList = []string{"alpha", "bravo", "charlie", "delta", /*... other words ...*/}

	cipherFile := "key.dat"
	plainTextFile := "key.txt"

	message, err := winkeysafe.New(cipherFile, plainTextFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(message)

	key, err := winkeysafe.GetKey()
	if err != nil {
		fmt.Printf("Failed to get key: %v\n", err)
	} else {
		fmt.Printf("Secure key: %s\n", key)
	}

	// Securely destroy the key after use
	winkeysafe.DestroyKey()
}
```

### Encrypt and Decrypt Data

Use `encryptData` and `decryptData` for encryption and decryption:

```go
data := []byte("sensitive data")

// Encrypt data
encrypted, err := winkeysafe.EncryptData(data)
if err != nil {
	fmt.Printf("Encryption failed: %v\n", err)
	return
}

// Decrypt data
decrypted, err := winkeysafe.DecryptData(encrypted)
if err != nil {
	fmt.Printf("Decryption failed: %v\n", err)
	return
}

fmt.Printf("Decrypted data: %s\n", string(decrypted))
```

### Destroy Key

After completing encryption or decryption tasks, securely destroy the key in memory:

```go
winkeysafe.DestroyKey()
```

## Functions

### Key Management

- `New(cipherFile, plainTextFile string) (string, error)`
  - Initializes or loads encryption keys.
- `GetKey() (string, error)`
  - Retrieves the secure key from memory.
- `DestroyKey()`
  - Securely destroys the key in memory.

### Encryption/Decryption

- `encryptData(data []byte) ([]byte, error)`
  - Encrypts data using Windows DPAPI.
- `decryptData(data []byte) ([]byte, error)`
  - Decrypts data using Windows DPAPI.

## Security Best Practices

1. Always call `DestroyKey()` after use to ensure keys are securely wiped from memory.
2. Ensure `wordsList` contains unique, unpredictable words for generating secure keys.
3. Use secure permissions to restrict access to the `key.dat` and `key.txt` files.
4. Regularly rotate encryption keys to minimize the risk of compromise.

## Example Test File

Refer to the `winkeysafe_test.go` file for comprehensive examples of unit tests for this package.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request.

## Acknowledgments

- [memguard](https://github.com/awnumar/memguard): For secure memory management.
- Windows DPAPI: For encryption and decryption functionality.
```

Save this content in a file named `README.md` in the root directory of your project. Let me know if you need help customizing it further!
