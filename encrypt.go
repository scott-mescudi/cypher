package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func generateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	err := os.WriteFile("KEYFILE.key", key, 0444)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func readKey(keyfile string) ([]byte, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptData(key []byte, filename string, clean bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)
	newFileName := nameWithoutExt + ".bin"
	outFile, err := os.Create(newFileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	buffer := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %w", err)
		}
		if n == 0 {
			break
		}

		// Get the file extension
	    ext := filepath.Ext(filename)
	

		chunk := buffer[:n]
		plaintextWithExt := append(chunk, []byte("\n"+ext)...)
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}

		ciphertext := gcm.Seal(nonce, nonce, plaintextWithExt, nil)
		if _, err := outFile.Write(ciphertext); err != nil {
			return err
		}
	}

	if clean {
		if err := os.Remove(filename); err != nil {
			return fmt.Errorf("error removing original file: %w", err)
		}
	}

	return nil
}

func encryptDirectory(key []byte, dir string, clean bool) error {
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, item := range items {
		fullPath := filepath.Join(dir, item.Name())
		if item.IsDir() {
			if err := encryptDirectory(key, fullPath, clean); err != nil {
				fmt.Println("[-]Failed to walk directory")
			}
		} else {
			ext := filepath.Ext(item.Name())
			switch ext {
			case ".bin":
				fmt.Printf("[-] %v is already encrypted\n", item.Name())
			case ".key":
				fmt.Printf("[-] Cannot encrypt keyfile %v\n", item.Name())
			default:
				if err := encryptData(key, fullPath, clean); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func main() {
	var (
		err      error
		clean    bool
		dir      string
		filename string
		help     bool
		version  bool
		key      []byte
		keyfile  string
	)

	flag.BoolVar(&clean, "clean", false, "remove original file after encryption")
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&version, "v", false, "show version")
	flag.StringVar(&dir, "dir", "", "directory to encrypt")
	flag.StringVar(&filename, "f", "", "file to encrypt")
	flag.StringVar(&keyfile, "kf", "", "encrypt using existing keyfile")

	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	if dir != "" {
		if _, err = os.Stat(dir); err != nil {
			fmt.Println("[-] Directory not found. Exiting...")
			os.Exit(6)
		}
	} else if filename != "" {
		if _, err = os.Stat(filename); err != nil {
			fmt.Println("[-] File not found. Exiting...")
			os.Exit(5)
		}
	}

	if help {
		flag.Usage()
		os.Exit(1)
	}

	if version {
		fmt.Println("[v] version == 2.0.0")
		os.Exit(2)
	}

	if keyfile != "" {
		key, err = readKey(keyfile)
		if err != nil {
			fmt.Println("[-] Keyfile not found or invalid. Exiting...")
			os.Exit(4)
		} else {
			fmt.Println("[+] Key file found. Reading keyfile...")
		}
	} else {
		if _, err = os.Stat("KEYFILE.key"); err != nil {
			fmt.Println("[-] No key file found. Generating a new keyfile...")
			key, err = generateRandomKey()
			if err != nil {
				fmt.Println("[-] Error generating keyfile: ", err)
				os.Exit(3)
			}
		} else {
			fmt.Println("[+] Default keyfile found. Reading keyfile...")
			key, err = readKey("KEYFILE.key")
			if err != nil {
				fmt.Println("[-] Default keyfile not found. Exiting...")
				os.Exit(4)
			}
		}
	}

	if filename != "" {
		err = encryptData(key, filename, clean)
		if err != nil {
			fmt.Println("[+] Error encrypting file: ", err)
		} else {
			fmt.Println("[+] File encryption complete.")
		}

		if clean {
			fmt.Println("[+] Original file removed.")
		}
	}

	if dir != "" {
		if dir == "/" || dir == "/home" {
			fmt.Println("[-] Cannot encrypt root directory. Exiting...")
			os.Exit(5)
		}

		err = encryptDirectory(key, dir, clean)
		if err != nil {
			fmt.Println("[-] Error encrypting directory: ", err)
			os.Exit(7)
		} else {
			fmt.Println("\n[+] Directory encryption complete.")
		}

		if clean {
			fmt.Println("[+] Original files in directory removed.")
		}
	}
}
