# Encryption and Decryption cli

## Overview

This repository contains two Go programs for file encryption and decryption:

- `encrypt.go`: Encrypts files using AES256 encryption.
- `decrypt.go`: Decrypts files encrypted by `encrypt.go`.

Both programs support the use of a user-specified password for encryption/decryption and the generation of a random AES256 key.

## Features

### `encrypt.go`

- Generates an AES256 key and saves it to a file.
- Encrypts files using AES256 encryption.
- Supports encryption of individual files or entire directories.
- Cleans up original files after encryption if specified.

### `decrypt.go`

- Decrypts files encrypted by `encrypt.go`.
- Supports decryption of individual files or entire directories.
- Cleans up encrypted files after decryption if specified.

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) (version 1.16 or later)

### Build

To build the programs, navigate to the directory containing the `.go` files and run:

```bash
go build encrypt.go
go build decrypt.go
```

This will create two executables: `encrypt` and `decrypt`.

## Usage

### `encrypt`

Encrypt a single file:

```bash
./encrypt -f <input_file>  [-kf <key_file>] [-clean]
```

Encrypt all files in a directory:

```bash
./encrypt -dir <directory> [-kf <key_file>] [-clean]
```

#### Flags

- `-f <input_file>`: Input file to encrypt.
- `-kf <key_file>`: File to read/write the encryption key. Defaults to `keyfile.key`.
- `-dir <directory>`: Directory containing files to encrypt.
- `-clean`: Clean up (delete) the original files after encryption.

### `decrypt`

Decrypt a single file:

```bash
./decrypt -f <input_file> [-kf <key_file>] [-clean]
```

Decrypt all files in a directory:

```bash
./decrypt -dir <directory> [-kf <key_file>] [-clean]
```

#### Flags

- `-f <input_file>`: Input file to decrypt.
- `-kf <key_file>`: File to read the decryption key from. Defaults to `keyfile.key`.
- `-dir <directory>`: Directory containing files to decrypt.
- `-clean`: Clean up (delete) the encrypted files after decryption.

## Deployment

To make the executables globally available, move them to a directory that is included in your system's PATH.

### Linux/macOS

```bash
sudo mv encrypt /usr/local/bin/
sudo mv decrypt /usr/local/bin/
```

### Windows

Move the `encrypt.exe` and `decrypt.exe` files to a directory included in your PATH. For example, `C:\Windows\System32`.

```cmd
move encrypt.exe C:\Windows\System32
move decrypt.exe C:\Windows\System32
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss changes.
