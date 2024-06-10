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
	// Create a new AES cipher block
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
    
	// Write the key to a file
	err := os.WriteFile("KEYFILE.key", key, 0444)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func readKey(keyfile string) ([]byte, error) {
	// Read the key from a file
	key, err := os.ReadFile(keyfile)
    if err != nil {
        return nil, err
    }

    return key, nil
}



func encryptData(key []byte, filename string, clean bool) error {
	// Read the file content
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Get the file extension
	ext := filepath.Ext(filename)
	// Concatenate the plaintext with a newline and the file extension
	plaintextWithExt := append(plaintext, []byte("\n"+ext)...)

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt the concatenated data
	ciphertext := gcm.Seal(nonce, nonce, plaintextWithExt, nil) // Prepend nonce to ciphertext

	// Create the new filename with .bin extension
	nameWithoutExt := strings.TrimSuffix(filename, ext)
	newFileName := nameWithoutExt + ".bin"

	// Write the ciphertext to the new file
	err = os.WriteFile(newFileName, ciphertext, 0600)
	if err != nil {
		return err
	}

	// Optionally, remove the original file if the clean flag is set
	if clean {
		err := os.Remove(filename)
		if err != nil {
			return fmt.Errorf("error removing original file: %w", err)
		}
	}

	return nil
}



func encrypt_directory(key []byte, dir string, clean bool) error {
	//open directory
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}


    //loop through all items in directory
	for _, item := range items {
		if item.IsDir() {
			subitems, err := os.ReadDir(filepath.Join(dir, item.Name()))
			if err != nil {
				fmt.Printf("[-] failed to read subdirectory %s: %v\n", item.Name(), err)
				continue
			}
			for _, subitem := range subitems {
				if !subitem.IsDir() {
					sub := filepath.Join(dir, item.Name(), subitem.Name())
					ext := filepath.Ext(subitem.Name())
					//filtering files
					switch ext {

					case ".bin":
                        fmt.Printf("[-] %v is already encrypted\n", subitem.Name())
                        
					case ".key":
                        fmt.Printf("[-] Cannot encrypt keyfile: %v\n", subitem.Name())
                        
					default:
                        err = encryptData(key, sub, clean)
                        if err != nil {
                            return err
                        }
					}
				}
			}
		} else {
			//filtering files
			ext := filepath.Ext(item.Name())
			switch ext {

			case ".bin":
				fmt.Printf("[-] %v is already encrypted\n", item.Name())
			 
			case ".key":
				fmt.Printf("[-] Cannot encrypt keyfile %v\n", item.Name())
			
			default:
				err = encryptData(key, filepath.Join(dir, item.Name()), clean)
				if err != nil {
                    return err
                }
			}
		}
	}
	return nil
}

func main() {
	var(
        err error
		clean bool = false
		dir string
		filename string
		help bool
		version bool
		key []byte
		keyfile string
	)


	flag.BoolVar(&clean, "clean", false, "remove original file after encryption")
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&version, "v", false, "show version")
	flag.StringVar(&dir, "dir", "", "directory to encrypt")
	flag.StringVar(&filename, "f", "", "file to encrypt")
	flag.StringVar(&keyfile, "kf", "", "encrypt usng existing keyfile")
	
	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
        os.Exit(1)
	}

	//check for file/dir
	if dir!= "" {
		if _, err = os.Stat(dir); err!= nil {
			fmt.Println("[-] Directory not found. Exiting...")
			os.Exit(6)
		}
    }else if filename!= "" {
		if _, err = os.Stat(filename); err!= nil {
			fmt.Println("[-] File not found. Exiting...")
			os.Exit(5)
		}
	}


    
	//basic flag handling
	if help {
        flag.Usage()
        os.Exit(1)
    }

	if version {
        fmt.Println("[v] version == 2.0.0")
        os.Exit(2)
    }

	if clean{
		clean = true
	}
    

    //keyfile handling
	if _, err = os.Stat("KEYFILE.key"); err != nil {
		fmt.Println("[-] No key file found. Generating a new keyfile...")
		Genkey, err := generateRandomKey()
        if err!= nil {
            fmt.Println("[-] Error generating keyfile: ", err)
			os.Exit(3)
        }else{
			key = Genkey
		}
	}else{
		fmt.Println("[-] looking for default keyfile...")
		Readkey, err := readKey("KEYFILE.key")
		if err!= nil {
			fmt.Println("[-] Default keyfile not found. Exiting...")
			os.Exit(4)
		}else{
			fmt.Println("[+] Default keyfile found. Reading keyfile...")
			key = Readkey
		}   
	}

	if keyfile!= "" {
		Readkey, err := readKey(keyfile)
        if err!= nil {
            fmt.Println("[-] No keyfile found. Exiting...")
			os.Exit(4)
        }else{
		    fmt.Println("[+] Key file found. Reading keyfile...")
			key = Readkey
		}
	}


    //single file encryption
	if filename!= "" {
		err = encryptData(key, filename, clean)
        if err!= nil {
            fmt.Println("[+] Error encrypting file: ", err)
        }else{
			fmt.Println("[+] File encryption complete.")
		}

		if clean{
			fmt.Println("[+] Original file removed.")
		}
	}


    //directory encryption
	if dir!= "" {
		if dir == "/" || dir == "/home"{
			fmt.Println("[-] Cannot encrypt root directory. Exiting...")
            os.Exit(5)
		}

		err = encrypt_directory(key, dir, clean)
        if err!= nil {
            fmt.Println("[-] error encrypting directory: ", err)
			os.Exit(7)
        }else{
            fmt.Println("\n[+] Directory encryption complete.")
        }

        if clean{
            fmt.Println("[+] Original files in directory removed.")
        }
	}

}