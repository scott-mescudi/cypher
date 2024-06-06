package main


import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"os"
	"flag"
)

// ReadKey reads the AES key from a file.
func ReadKey(filename string) ([]byte, error) {
	key, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func Decrypt(key []byte, ciphertextFile string, decryptedFile string) error {
	ciphertext, err := os.ReadFile(ciphertextFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return os.WriteFile(decryptedFile, ciphertext, 0644)
}

func main() {
	var(
	inputfile string
	outputfile string
	keyfile string
	cleanup bool
    )

    flag.StringVar(&inputfile, "i", "", "input file")
	flag.StringVar(&outputfile, "o", "", "output file")
	flag.StringVar(&keyfile, "k", "", "key file")
	flag.BoolVar(&cleanup, "cleanneoferc", false, "cleanup")

	flag.Parse()
	
	keyFilename := "keyfile.key"

	var key []byte
	key, err := ReadKey(keyFilename)
	if err != nil {
		panic(err)
	}


	err = Decrypt(key, inputfile, outputfile)
	if err != nil {
		panic(err)
	}

	if cleanup {
		err = os.Remove(inputfile)
        if err!= nil {
            panic(err)
        }

		err = os.Remove(keyFilename)
		if err!= nil {
            panic(err)
        }
	}
}