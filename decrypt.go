package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"flag"

)

func loadKey(keyfile string) ([]byte, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func decryptData(key []byte, filename string, clean bool) error {
	//	read data from file
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
    
	//check aes cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	//check gcm cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	//check nonce size
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

    // read extension from file
    content := string(plaintext)
    lines := strings.Split(content, "\n")
	newEXT := lines[len(lines)-1]
	
	// remove last line
    lines = strings.Split(string(plaintext), "\n")
    if len(lines) > 0 {
        lines = lines[:len(lines)-1]
    }
	
    plaintext = []byte(strings.Join(lines, "\n"))


    //write decrypted file with new extension
	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)
	newFileName := nameWithoutExt + newEXT

	err = os.WriteFile(newFileName, plaintext, 0600)
	if err != nil { 
		return err
	}
    
	//clean up .bin files if flag is set
	if clean {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
	}

	return nil
}

func decryptdir(key []byte, dir string, clean bool) error {
	//open directory
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}


    //loop through all items in directory
	for _, item := range items {
		fullpath := filepath.Join(dir, item.Name())
		if item.IsDir() {
			if err := decryptdir(key, fullpath, clean); err!= nil {
				return err
			}
		} else {
			ext := filepath.Ext(item.Name())
			switch ext {
			case ".bin":
				err = decryptData(key,fullpath, clean)
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
	var(
        err error
		clean bool = false
		dir string
		filename string
		help bool
		version bool
		key []byte = nil
		keyfile string
	)


	flag.BoolVar(&clean, "clean", false, "remove original file after decryption")
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&version, "v", false, "show version")
	flag.StringVar(&dir, "dir", "", "directory to decrypt")
	flag.StringVar(&filename, "f", "", "file to decrypt")
	flag.StringVar(&keyfile, "kf", "", "decrypt usng existing keyfile")
	
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
	if keyfile!= "" {
        key, err = loadKey(keyfile)
        if err!= nil {
            fmt.Println("[-] Keyfile not found. Exiting...")
            os.Exit(4)
        }
    }else{
		fmt.Println("[+] Using default keyfile: KEYFILE.key")
        key, err = loadKey("KEYFILE.key")
        if err!= nil {
            fmt.Println("[-] Keyfile not found. Exiting...")
            os.Exit(4)
        }else{
			fmt.Println("[+] found default keyfile....")
		}
    }

    if key == nil {
		os.Exit(3)
	}

    //single file decryption
	if filename!= "" {
		err = decryptData(key, filename, clean)
        if err!= nil {
            fmt.Println("[+] Error encypting file: ", err)
        }else{
			fmt.Println("[+] File decryption complete.")
		}

		if clean{
			fmt.Println("[+] Original file removed.")
		}
	}


    //directory decryption
	if dir!= "" {
		if dir == "/" || dir == "/home"{
			fmt.Println("[-] Cannot decrypt root directory. Exiting...")
            os.Exit(5)
		}

		err = decryptdir(key, dir, clean)
        if err!= nil {
            fmt.Println("[-] error decrypting directory: ", err)
			os.Exit(7)
        }else{
            fmt.Println("\n[+] Directory decryption complete.")
        }

        if clean{
            fmt.Println("[+] encypted files in directory removed.")
        }
	}

}
