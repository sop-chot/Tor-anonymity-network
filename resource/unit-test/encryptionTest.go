package main

import (
	"bytes"

	"crypto/rsa"
	"fmt"
	"os"

	"../cells"
	"../encryption"
)

var (
	SK1 = []byte("9368616e676520bc98697320709e1375")
	SK2 = []byte("905f4f2124e9ec375e4204b3615408ee")
	SK3 = []byte("aa218ca5849c18a6afbcfe26db0bae32")

	debug = true
)

func main() {
	DHSharedKeyTest()
	RSAEncryptionTest()
	AESEncryptionTest()
}

func DHSharedKeyTest() {
	fmt.Println("\n*********************** DHSharedKeyTest ***********************")

	// Select group for Alice and Bob
	agroup, akey, err := encryption.CreateDHKey()
	checkError(err, "Create DH key for Alice")

	bgroup, bkey, err := encryption.CreateDHKey()
	checkError(err, "Create DH key for Bob")

	// Compute shared key between Alice and Bob
	asharedKey, err := encryption.ComputeSharedKey(agroup, bkey.Bytes(), akey)
	checkError(err, "Compute shared key for Alice")

	bsharedKey, err := encryption.ComputeSharedKey(bgroup, akey.Bytes(), bkey)
	checkError(err, "Compute shared key for Bob")

	if bytes.Equal(asharedKey, bsharedKey) {
		fmt.Printf("[DH] Create a shared key [%d bytes] SUCCESS\n\n", len(asharedKey))
		fmt.Printf("[%x]\n", asharedKey)
	} else {
		fmt.Println("[DH] Create a shared key FAILED")
	}
}

func RSAEncryptionTest() {
	fmt.Println("\n*********************** RSAEncryptionTest ***********************")
	DHkeyBytes, ciphertext, RSAkey := encryptDHKeyWithRSAKey()

	// Decrypt the DH key with RSA key
	plaintext, err := encryption.RSADecrypt(RSAkey, ciphertext)
	checkError(err, "Decrypt message using RSA")

	if bytes.Equal(DHkeyBytes, plaintext) {
		fmt.Println("[RSA] OAEP Encryption of DH key SUCCESS\n")
		printBeforeAndAfterEncryption("Encrypting message:", DHkeyBytes, ciphertext)
		printBeforeAndAfterEncryption("Decrypting message:", ciphertext, plaintext)
	} else {
		fmt.Println("[RSA] OAEP Encryption of DH key FAILED")
	}
}

func encryptDHKeyWithRSAKey() (DHkeyBytes, ciphertext []byte, RSAkey *rsa.PrivateKey) {
	_, DHkey, err := encryption.CreateDHKey()
	checkError(err, "Create DH key")
	DHkeyBytes = DHkey.Bytes()

	RSAkey, err = encryption.RSAGenerateKey()
	checkError(err, "Create RSA key")

	// Encrypt the DH key with RSA key
	ciphertext, err = encryption.RSAEncrypt(&RSAkey.PublicKey, DHkeyBytes)
	checkError(err, "Encrypt DH key using RSA")
	return DHkeyBytes, ciphertext, RSAkey
}

func printBeforeAndAfterEncryption(header string, before, after []byte) {
	if debug {
		fmt.Println(header)
		fmt.Printf("from [%d bytes]\n\n", len(before))
		fmt.Printf("[%x]\n\n", before)
		fmt.Printf("to [%d bytes]\n\n", len(after))
		fmt.Printf("[%x]\n\n", after)
	}
}

func AESEncryptionTest() {
	fmt.Println("\n*********************** AESEncryptionTest ***********************")
	DHkeyBytes, encryptedDHKey, RSAkey := encryptDHKeyWithRSAKey()
	extendCmd := cells.EncodeRelayCell(3, "a3e8", "123.45.6.97:8080", encryptedDHKey)
	iv := encryption.GenerateIV()

	// Nested encryptions
	encryptedCommand1 := AESEncryption(extendCmd, iv, SK1, "[AES] CTR encrypting message using SK1")
	encryptedCommand2 := AESEncryption(encryptedCommand1, iv, SK2, "[AES] CTR encrypting message using SK2")
	encryptedCommand3 := AESEncryption(encryptedCommand2, iv, SK3, "[AES] CTR encrypting message using SK3")

	// Nested decryptions
	decryptedCommand3 := AESEncryption(encryptedCommand3, iv, SK3, "[AES] CTR decrypting message using SK3")
	decryptedCommand2 := AESEncryption(decryptedCommand3, iv, SK2, "[AES] CTR decrypting message using SK2")
	decryptedCommand1 := AESEncryption(decryptedCommand2, iv, SK1, "[AES] CTR decrypting message using SK1")

	decodedCommand := cells.DecodeRelayCell(decryptedCommand1)
	fmt.Println("[AES] EXTEND command:", decodedCommand.Command)

	data := decodedCommand.Data
	plaintext, err := encryption.RSADecrypt(RSAkey, data)
	checkError(err, "Decrypt message using RSA")

	if bytes.Equal(plaintext, DHkeyBytes) {
		fmt.Println("[AES] Encryption of relay cell SUCCESS")
	} else {
		fmt.Println("[AES] Encryption of relay cell FAILED")
	}
}

func AESEncryption(data, iv, key []byte, msg string) []byte {
	ciphertext, err := encryption.AESEncryptCTR(key, data, iv)
	checkError(err, "Encrypt command using AES CTR")
	printBeforeAndAfterEncryption(msg, data, ciphertext)
	return ciphertext
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[ENCRYPTION TEST] ERROR", msg, err)
		os.Exit(1)
	}
}
