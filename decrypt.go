package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func loadKey(keyfile string) ([]byte, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key length is %d bytes, must be 16, 24, or 32 bytes", len(key))
	}
	return key, nil
}

func decryptData(key []byte, filename string, clean bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	var ciphertext []byte

	buffer := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %w", err)
		}
		if n == 0 {
			break
		}
		ciphertext = append(ciphertext, buffer[:n]...)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	content := string(plaintext)
	lines := strings.Split(content, "\n")
	newEXT := lines[len(lines)-1]

	lines = lines[:len(lines)-1]
	plaintext = []byte(strings.Join(lines, "\n"))

	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)
	newFileName := nameWithoutExt + newEXT

	err = os.WriteFile(newFileName, plaintext, 0600)
	if err != nil {
		return fmt.Errorf("error writing decrypted file: %w", err)
	}

	if clean {
		err = os.Remove(filename)
		if err != nil {
			return fmt.Errorf("error removing original file: %w", err)
		}
	}

	return nil
}

func decryptDirectory(key []byte, dir string, clean bool) error {
	items, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("error reading directory: %w", err)
	}

	for _, item := range items {
		fullPath := filepath.Join(dir, item.Name())
		if item.IsDir() {
			if err := decryptDirectory(key, fullPath, clean); err != nil {
				return err
			}
		} else {
			ext := filepath.Ext(item.Name())
			switch ext {
			case ".bin":
				err = decryptData(key, fullPath, clean)
				if err != nil {
					return err
				}
			default:
				fmt.Printf("[-] %v is not encrypted\n", item.Name())
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
		key      []byte = nil
		keyfile  string
	)

	flag.BoolVar(&clean, "clean", false, "remove original file after decryption")
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&version, "v", false, "show version")
	flag.StringVar(&dir, "dir", "", "directory to decrypt")
	flag.StringVar(&filename, "f", "", "file to decrypt")
	flag.StringVar(&keyfile, "kf", "", "decrypt using existing keyfile")

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
		key, err = loadKey(keyfile)
		if err != nil {
			fmt.Println("[-] Keyfile not found or invalid. Exiting...")
			os.Exit(4)
		}
	} else {
		fmt.Println("[+] Using default keyfile: KEYFILE.key")
		key, err = loadKey("KEYFILE.key")
		if err != nil {
			fmt.Println("[-] Keyfile not found or invalid. Exiting...")
			os.Exit(4)
		} else {
			fmt.Println("[+] Found default keyfile....")
		}
	}

	if key == nil {
		fmt.Println("[-] No valid key provided. Exiting...")
		os.Exit(3)
	}

	if filename != "" {
		err = decryptData(key, filename, clean)
		if err != nil {
			fmt.Println("[+] Error decrypting file: ", err)
		} else {
			fmt.Println("[+] File decryption complete.")
		}

		if clean {
			fmt.Println("[+] Original file removed.")
		}
	}

	if dir != "" {
		if dir == "/" || dir == "/home" {
			fmt.Println("[-] Cannot decrypt root directory. Exiting...")
			os.Exit(5)
		}

		err = decryptDirectory(key, dir, clean)
		if err != nil {
			fmt.Println("[-] Error decrypting directory: ", err)
			os.Exit(7)
		} else {
			fmt.Println("\n[+] Directory decryption complete.")
		}

		if clean {
			fmt.Println("[+] Encrypted files in directory removed.")
		}
	}
}
