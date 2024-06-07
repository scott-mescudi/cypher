package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

// ReadKey reads the AES key from a file.
func ReadKey(filename string) ([]byte, error) {
	key, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateUserKey generates a key from a password using PBKDF2.
func GenerateUserKey(password string, salt []byte) ([]byte, error) {
	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
	return key, nil
}

// Decrypt decrypts a file using AES256 encryption.
func Decrypt(key []byte, ciphertextFile string, decryptedFile string) error {
	ciphertext, err := os.ReadFile(ciphertextFile)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize+16 {
		return errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize+16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return os.WriteFile(decryptedFile, ciphertext, 0644)
}

func main() {
	var (
		inputfile  string
		outputfile string
		keyfile    string
		cleanup    bool
		userkey    string
	)

	flag.StringVar(&inputfile, "i", "", "input file to decrypt")
	flag.StringVar(&outputfile, "o", "", "output file for decrypted data")
	flag.StringVar(&keyfile, "k", "", "file to read the encryption key from")
	flag.BoolVar(&cleanup, "clean", false, "delete the input and key files after decryption")
	flag.StringVar(&userkey, "p", "", "password to derive the decryption key")

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

	if inputfile == "" || outputfile == "" {
		flag.Usage()
		os.Exit(1)
	}

	keyFilename := "keyfile.key"
	var key []byte
	var err error

	if keyfile != "" {
		keyFilename = keyfile
	}

	if userkey != "" {
		// Read the ciphertext to extract the salt
		ciphertext, err := os.ReadFile(inputfile)
		if err != nil {
			panic(err)
		}
		if len(ciphertext) < aes.BlockSize+16 {
			panic("ciphertext too short")
		}
		salt := ciphertext[aes.BlockSize : aes.BlockSize+16]
		key, err = GenerateUserKey(userkey, salt)
		if err != nil {
			panic(err)
		}
	} else {
		key, err = ReadKey(keyFilename)
		if err != nil {
			panic(err)
		}
	}

	err = Decrypt(key, inputfile, outputfile)
	if err != nil {
		panic(err)
	}

	if cleanup {
		err = os.Remove(inputfile)
		if err != nil {
			panic(err)
		}

		err = os.Remove(keyFilename)
		if err != nil {
			panic(err)
		}
	}
}
