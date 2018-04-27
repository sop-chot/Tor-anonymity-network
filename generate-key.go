package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"./resource/encryption"
)

var DIRECTORY_NAME string = "pemDirectory"

func main() {
	args := os.Args[1:]

	if len(args) != 1 {
		fmt.Println("Usage: go run generate-key.go [filename]")
		os.Exit(1)
	}

	privateKey, err := encryption.RSAGenerateKey()
	checkError(err, "Generate RSA key")

	marshalPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshalPrivateKey,
	}

	if _, err := os.Stat(DIRECTORY_NAME); os.IsNotExist(err) {
		err = os.Mkdir("pemDirectory", os.ModeDir)
		checkError(err, "os.Mkdir")
	}

	if err := os.Chmod("pemDirectory", 0700); err != nil {
		checkError(err, "Change mode of pemDirectory")
	}

	pemFile, err := os.Create(filepath.Join(DIRECTORY_NAME, args[0]) + ".pem")
	checkError(err, "Create pem file")

	defer pemFile.Close()
	pem.Encode(pemFile, &privateKeyBlock)
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[generate-key] ERROR", msg, err)
		os.Exit(1)
	}
}
