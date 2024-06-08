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
	"path/filepath"
	"strings"
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
func read_dir(dir string) ([]string, error) {

	var files []string = []string{}
 
    items, err := os.ReadDir(dir)
    if err != nil {
        fmt.Println(err)
    }

    for _, item := range items {
        if item.IsDir() {
            subitems, err := os.ReadDir(filepath.Join(dir, item.Name()))
            if err != nil {
                fmt.Printf("failed to read subdirectory %s: %v\n", item.Name(), err)
                continue
            }
            for _, subitem := range subitems {
                if !subitem.IsDir() {
                    fin := (filepath.Join(item.Name(), subitem.Name()))
					files = append(files, fin)
                }
            }
        } else {
            files = append(files, item.Name())
        }
    }
    return files, nil
}
// Decrypt decrypts a file using AES256 encryption.
// Decrypt decrypts a file using AES256 encryption.
func Decrypt(key []byte, ciphertextFile string, decryptedFile string) error {
    ciphertext, err := os.ReadFile(ciphertextFile)
    if err != nil {
        return err
    }

    // Check if the file contains enough data for IV and ciphertext
    if len(ciphertext) < aes.BlockSize {
        return errors.New("ciphertext too short")
    }

    // Extract the IV from the beginning of the file
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

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
		directory  string
	)

	flag.StringVar(&inputfile, "f", "", "input file to decrypt")
	flag.StringVar(&outputfile, "o", "", "output file for decrypted data")
	flag.StringVar(&keyfile, "k", "", "file to read the encryption key from")
	flag.BoolVar(&cleanup, "clean", false, "delete the input and key files after decryption")
	flag.StringVar(&userkey, "p", "", "password to derive the decryption key")
	flag.StringVar(&directory, "dir", "", "directory to decrypt")

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
	var err error

	if keyfile != "" {
		keyFilename = keyfile
	}

	if userkey !=  "" && directory != "" {
	fmt.Println("Error: -p flag cannot be used with -dir")
	os.Exit(3)
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
			fmt.Println(err, "140")
		}
	}

	if directory != "" {
		files, err := read_dir(directory)
		if err != nil {
			fmt.Println(err, "147")
		}
		for _, file := range files {
			ext := filepath.Ext(file)
			nameWithoutExt := strings.TrimSuffix(file, ext)
			newFileName := nameWithoutExt + ".txt"

            extE := filepath.Ext(file)
			if extE == ".bin" {
				err = Decrypt(key, filepath.Join(directory, file), filepath.Join(directory, newFileName))
				if err != nil {
					fmt.Println(err, "157")
				}
		    }else{
				fmt.Printf("file '%s' is not encrypted\n", file)
			}
		}

		if cleanup {
			for _, file := range files {
				ext := filepath.Ext(file)
				if ext == ".bin" {
					err = os.Remove(filepath.Join(directory, file))
					if err != nil {
						panic(err)
					}
				}
			}
		}

	} else {
		err := Decrypt(key, inputfile, outputfile)
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
}
