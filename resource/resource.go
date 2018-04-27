package resource

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"./errorlib"

	uuid "github.com/satori/go.uuid"
)

type OnionInfo struct {
	Key     rsa.PublicKey
	Address net.Addr
}

type HeartBeats struct {
	sync.RWMutex
	// Key is address
	HeartBeatMap map[string]int64
}

// A struct that represents the format any message will be sent through
type RequestMessage struct {
	// the address of the sending node
	Address string
	// the circuitId of the sending node
	CircuitID string
	// is the encrypted data for a relay cell or control cell
	IsRelay bool
	// the encrypted data containing header and actual onion(payload)
	EncryptedData []byte
}

type ResponseMessage struct {
	CircuitID string
	IsRelay   bool
	Data      []byte
}

type ServerDirectory struct {
	Addresses []string
}

var (
	PEM_DIRECTORY   string = "pemDirectory"
	HeartBeat       uint32 = 2000
	serverDirectory        = "serverDirectory"
	// Time to refresh the circuit in seconds
	ForceRefresh             int64 = 30
	TimeoutRefreshMultiplier int64 = 4
)

// GenerateUUID creates random 16 bytes UUID versions 3 as specified in RFC 4122.
func GenerateUUID() (id string, err error) {
	u4, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	return u4.String(), nil
}

// GetKeyPair - Reads the RSA public/private key pair from a pem file
func GetKeyPair(pemFileName string) (*rsa.PrivateKey, *rsa.PublicKey) {
	pemFileBytes, err := ioutil.ReadFile(filepath.Join(PEM_DIRECTORY, pemFileName) + ".pem")
	checkError(err, "getKeyPair: Open call for pem file")

	privateKeyBlock, _ := pem.Decode(pemFileBytes)

	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		checkError(errors.New("Private key block nil or wrong type"), "getKeyPair: Block issue")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	checkError(err, "getKeyPair: Failed to parse private key")
	return privateKey, &privateKey.PublicKey
}

// GetServerDirectory - Reads a list of server addresses from a the serverDirectory json file
func GetServerDirectory() (serverAddresses []string) {
	jsonFileBytes, err := ioutil.ReadFile(filepath.Join(serverDirectory, serverDirectory) + ".json")
	if err != nil {
		fmt.Println(err)
	}

	serverDirectory := ServerDirectory{}
	err = json.Unmarshal(jsonFileBytes, &serverDirectory)
	if err != nil {
		fmt.Println(err)
	}

	return serverDirectory.Addresses
}

// ChooseRandomServer - Chooses a random server from serverDirectory json file unless all servers are unavailable
func ChooseRandomServer() (serverAddr string, err error) {
	serverAddresses := GetServerDirectory()

	numAddresses := len(serverAddresses)
	randomOrdering := rand.Perm(numAddresses)
	timeoutDuration := time.Duration(350 * time.Millisecond)

	for i := 0; i < 5; i++ { // Try 5 times to account for any an unreliable network
		for _, order := range randomOrdering {
			address := serverAddresses[order]
			_, err := net.DialTimeout("tcp", address, timeoutDuration)
			if err != nil {
				fmt.Println(err) // Server is probably offline
				continue
			} else {
				fmt.Println(address, "is reachable. Will connect to it.")
				return address, nil
			}
		}

		time.Sleep(timeoutDuration)
	}

	return serverAddr, errorlib.ServersUnavailableError("error")
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[resource] ERROR", msg, err)
		os.Exit(1)
	}
}
