package main

import (
	"bytes"
	"fmt"
	"os"

	"../../resource"
	"../encryption"
)

var (
	testkeyFilename = "testkey"
)

func main() {
	generateKeyTest()
}

func generateKeyTest() {
	privKey, pubKey := resource.GetKeyPair(testkeyFilename)
	msg := []byte("Hello there!")
	ciphertext, err := encryption.RSAEncrypt(pubKey, msg)
	checkError(err, "RSA encryption")

	plaintext, err := encryption.RSADecrypt(privKey, ciphertext)
	checkError(err, "RSA decryption")

	if bytes.Equal(plaintext, msg) {
		fmt.Println("[GEN KEY] Encryption using RSA key pair SUCCESS")
	} else {
		fmt.Println("[GEN KEY] Encryption using RSA key pair FAILED")
	}
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[GENERATE KEY TEST] ERROR", msg, err)
		os.Exit(1)
	}
}
