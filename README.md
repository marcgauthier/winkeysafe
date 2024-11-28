
# winkeysafe

`winkeysafe` is a Go package for creating and storing an encryption key securely on Windows systems using the Data Protection API (DPAPI) and [memguard](https://github.com/awnumar/memguard) for secure memory management. It provides functionalities for generating, encrypting, decrypting, and securely storing encryption keys.

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
go get -u github.com/marcgauthier/winkeysafe
```

## Usage

### Import the Package

```go
import "github.com/marcgauthier/winkeysafe"
```

### Initialize Key Management

1. Use the `Get()` function to generate or load keys:

```go
package main

import (
	"fmt"
	"github.com/marcgauthier/winkeysafe"
)

func main() {
	
	cipherFile := "key.dat"
	plainTextFile := "key.txt"

	// generate key and files if require, return the plaintextkey and error if any  
	key, err := winkeysafe.Get(cipherFile, plainTextFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
}
```

## Functions

### Key Management

- `Get(cipherFile, plainTextFile string) ([]byte, error)`
  - Initializes or loads encryption keys.

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
