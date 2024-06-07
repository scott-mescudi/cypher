# File Encryption and Decryption Tools

This repository contains two Go programs for file encryption and decryption using AES256. The `encrypt` program encrypts a file, while the `decrypt` program decrypts an encrypted file. Each program needs to be built separately.

## Building the Programs

To build the `encrypt` and `decrypt` programs, follow these steps:

1. Clone the repository or download the source files.
2. Open a terminal and navigate to the directory containing the source files.
3. Build each program using the `go build` command.


go build -o encrypt encrypt.go
go build -o decrypt decrypt.go


4. Move the built executables to `/usr/bin` to use them globally, or run them locally using `./`.


sudo mv encrypt /usr/bin/encrypt
sudo mv decrypt /usr/bin/decrypt


## Usage

### Encrypt

The `encrypt` program encrypts a file using AES256 encryption. You can provide a password to derive the encryption key or generate a random key.

#### Flags

- `-i` : Input file to encrypt (required).
- `-clean` : Delete the input file after encryption (optional).
- `-p` : Password to derive the encryption key (optional).
- `-kf` : File to store/load the encryption key (optional).

#### Examples


# Encrypt a file with a password
encrypt -i plaintext.txt -p mypassword

# Encrypt a file with a random key
encrypt -i plaintext.txt

# Encrypt a file and delete the original
encrypt -i plaintext.txt -clean

# Encrypt a file and specify a key file
encrypt -i plaintext.txt -kf mykeyfile.key


### Decrypt

The `decrypt` program decrypts an encrypted file using AES256 encryption. You can provide a password to derive the decryption key or read the key from a file.

#### Flags

- `-i` : Input file to decrypt (required).
- `-o` : Output file for decrypted data (required).
- `-k` : File to read the encryption key from (optional).
- `-clean` : Delete the input and key files after decryption (optional).
- `-p` : Password to derive the decryption key (optional).

#### Examples


# Decrypt a file with a password
decrypt -i encrypted.bin -o plaintext.txt -p mypassword

# Decrypt a file with a key file
decrypt -i encrypted.bin -o plaintext.txt -k mykeyfile.key

# Decrypt a file and delete the encrypted file and key file
decrypt -i encrypted.bin -o plaintext.txt -clean -k mykeyfile.key

## Notes

- Ensure that the key file and input file exist and are accessible when running the programs.
- Handle the generated encryption keys securely and avoid sharing them publicly.
- The salt used for key derivation is stored in the ciphertext file, so the same password can be used to decrypt the file.
