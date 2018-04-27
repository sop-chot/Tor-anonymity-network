/*
	This is a library to negotiate a shared key between two peers using Diffie-Hellman protocol,
	encrypt/decrypt a message using AES CTR and RSA OAEP protocols.

	To use this library, you must install the external DH library as followed:
		go get "github.com/monnand/dhkx"
	This will add the DH package into your $GOPATH for import.
*/

package encryption

import (
	"crypto/x509"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/monnand/dhkx"
)

var (
	RSAKeyBits = 2048
	RSAHash    = sha256.New()
	RSALabel   = []byte("")
)

// CreateDHKey ... Set values of g and p
// where p is prime and g is a primitive root modulo p
//
// Select Second Oakley Group from rfc2409:
// The generator is 2 (decimal)
// The hexadecimal value of 1024-bit prime p is:
// 		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
// 		29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
// 		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
// 		E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
// 		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
// 		FFFFFFFF FFFFFFFF
// This group is assigned id 2 and will create DH key of size 128 bytes
func CreateDHKey() (group *dhkx.DHGroup, key *dhkx.DHKey, err error) {
	group, err = dhkx.GetGroup(2)
	if err != nil {
		return nil, nil, err
	}

	// Choose secret key a and generate key = g^a mod p
	key, err = group.GeneratePrivateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	return group, key, err
}

func DHKeyToByteArray(key *dhkx.DHKey) []byte {
	return key.Bytes()
}

// ComputeSharedKey ... Compute a shared key = g^(ab) mod p
// MD5 hash function is used to reduce the size of DH key from 128 bytes to 16 bytes
// to adhere with AES key size standard of 16 bytes to select AES-128
func ComputeSharedKey(group *dhkx.DHGroup, otherkey []byte, mykey *dhkx.DHKey) (hashedKey []byte, err error) {
	otherDHKey := dhkx.NewPublicKey(otherkey)
	sharedKey, err := group.ComputeKey(otherDHKey, mykey)
	if err != nil {
		return nil, err
	}

	return HashSharedKey(sharedKey.Bytes()), nil
	// hash := md5.New()
	// hash.Write(DHKeyToByteArray(sharedKey))
	// hashedKey = hash.Sum(nil)
	// return hashedKey, nil
}

// HashSharedKey ... uses md5 to hash a shared key
func HashSharedKey(key []byte) []byte {
	hash := md5.New()
	hash.Write(key)
	return hash.Sum(nil)
}

func RSAGenerateKey() (privKey *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, RSAKeyBits)
}

func RSAKeyToString(pubKey rsa.PublicKey) (keystr string, err error) {
	MarshalPubKey, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return "", err
	}

	return string(MarshalPubKey), nil
}

func RSAEncrypt(pubKey *rsa.PublicKey, message []byte) (ciphertext []byte, err error) {
	return rsa.EncryptOAEP(RSAHash, rand.Reader, pubKey, message, RSALabel)
}

func RSADecrypt(privKey *rsa.PrivateKey, ciphertext []byte) (plaintext []byte, err error) {
	return rsa.DecryptOAEP(RSAHash, rand.Reader, privKey, ciphertext, RSALabel)
}

// GenerateIV ... Generate initialization vector with size n bytes containing all 0s
func GenerateIV() []byte {
	return make([]byte, aes.BlockSize)
}

// AESEncryptCTR ... Encrypt or decrypt message using 128-bit AES in counter (CTR) mode
// with iv of all 0 bytes. Note that encryption and decryption are symmetrical.
func AESEncryptCTR(key, plaintext, iv []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}
