package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"io"
	"os"
)

// GenerateKey generates a random AES256 key and writes it to a file.
func GenerateKey(filename string) ([]byte, error) {
	key := make([]byte, 32) // AES256 key size
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	err := os.WriteFile(filename, key, 0644)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateUserKey generates a key from a password using PBKDF2 and writes it to a file.
func GenerateUserKey(filename, password string) ([]byte, []byte, error) {
	// Generate a salt
	salt := make([]byte, 16) // Salt length should be at least 8 bytes
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
	err := os.WriteFile(filename, key, 0644)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// Encrypt encrypts a file using AES256 encryption.
func Encrypt(key []byte, salt []byte, plaintextFile string, ciphertextFile string) error {
	plaintext, err := os.ReadFile(plaintextFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext)+len(salt))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Prepend salt to ciphertext
	copy(ciphertext[aes.BlockSize:], salt)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize+len(salt):], plaintext)

	return os.WriteFile(ciphertextFile, ciphertext, 0644)
}

func main() {

	var (
		inputfile string
		cleanup   bool
		userkey   string
		keyfile   string
	)

	flag.StringVar(&inputfile, "i", "", "input file to encrypt")
	flag.BoolVar(&cleanup, "clean", false, "delete the input file after encryption")
	flag.StringVar(&userkey, "p", "", "password to derive the encryption key")
	flag.StringVar(&keyfile, "kf", "", "file to store/load the encryption key")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println("Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
        os.Exit(1)
	}

	keyFilename := "keyfile.key"

	var key []byte
	var salt []byte
	var err error

	if keyfile != "" {
		keyFilename = keyfile
	}

	if userkey != "" {
		ukey, usalt, err := GenerateUserKey(keyFilename, userkey)
		if err != nil {
			panic(err)
		} else {
			key = ukey
			salt = usalt
		}
	} else {
		key, err = GenerateKey(keyFilename)
		if err != nil {
			panic(err)
		}
	}

	err = Encrypt(key, salt, inputfile, "encrypted.bin")
	if err != nil {
		panic(err)
	}

	if cleanup {
		err = os.Remove(inputfile)
		if err != nil {
			panic(err)
		}
	}
}

