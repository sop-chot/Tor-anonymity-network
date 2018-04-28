package onionlib

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"sort"
	"sync"
	"time"

	"../resource"
	"../resource/cells"
	"../resource/circuitTest"
	"../resource/encryption"
	"../resource/errorlib"
	"../resource/print"
)

// OnionRPC ... represents an OnionRPC instance for the application
type OnionRPC int

// OnionNetwork Represents an Onion network in the system
type OnionNetwork interface {
	// Sends a HTTPS request through the circuit
	// - destAddress: the string represenation of the destintion, e.g. www.google.com
	// - command: HTTP command that the client wish to perform
	// Errors:
	// - HttpError
	// - CorruptPacketError
	// - CircuitGenerationError
	// - OnionEncryptionError
	// - OnionDecryptionError
	// - RetryError
	GetRequest(srcPort int, destAddress string) ([]byte, error)

	// Closes clientNode, all open streams in the current circuit and lastly the circuit itself
	UnlinkFromNetwork()
}

// ClientNode ... Represents a client node in the system
type ClientNode struct {
	MinNodes            int
	NumRetry            int
	TimeoutRefresh      int64
	TimeoutForceRefresh int64
	ServerConn          *rpc.Client
	Address             string
}

// OnionNode ... Represents an onion node used in the circuit
type OnionNode struct {
	PubKey    rsa.PublicKey
	SharedKey []byte
	Addr      net.Addr
}

// StreamDirectory ... A directory that stores all currently opened streams
type StreamDirectory struct {
	sync.RWMutex
	//key is destinationAddress
	streamMap map[string]string
}

// CircuitRefresh ... Struct that keeps track of when the circuit was last built
type CircuitRefresh struct {
	sync.RWMutex
	timeSinceCircuitLastBuilt int64
}

// Circuit ... Struct that contains the rpc connection with entry node and
//             all the onion nodes in the current circuit
type Circuit struct {
	sync.RWMutex
	circuitConnection *rpc.Client
	//key is onion node's rank in the circuit
	circuitMap map[int]*OnionNode
}

// keeps track of the onion nodes in the most recently built circuit
var mostRecentCircuit []resource.OnionInfo

// Represents a client node singleton, used internally
var clientNode *ClientNode

// Lock for any http(s) requests (GET)
var requestLock = &sync.RWMutex{}
var circuitID string
var circuitIDLock = &sync.RWMutex{}

type HeartBeats struct {
	sync.RWMutex
	// Key is IP address
	HeartBeatMap map[string]string
}

// Global variables
var entryNodeHeartBeats = resource.HeartBeats{HeartBeatMap: make(map[string]int64)}
var senderHeartBeats = HeartBeats{HeartBeatMap: make(map[string]string)}
var currentCircuit = Circuit{circuitMap: make(map[int]*OnionNode)}
var streamDirectory = StreamDirectory{streamMap: make(map[string]string)}
var refreshStatus = CircuitRefresh{timeSinceCircuitLastBuilt: 0}

// A channel where responses propagated from entry node are received
var responseChannel chan []byte = make(chan []byte)

// A channel that receives signals to refresh the circuit
var refreshChannel = make(chan bool, 1)

// A global variable to store the topology of the circuit
// for demo purposes only
var circuitTopology string

/* ==========================    Client Application Entry Method    ========================== */
// JoinOnionNetwork ... Initialises a ClientNode instance for the client
// Errors:
// - InsufficientNumberOfOnionNodeError
func JoinOnionNetwork(privateAddr, clientAddr, serverAddr string, minNodes, numRetry int, topology string) (cn *ClientNode, err error) {
	serverConn, err := rpc.Dial("tcp", serverAddr)
	checkError(err, "JoinOnionNetwork: Dial RPC to Server")

	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	onionRPC := new(OnionRPC)
	rpc.Register(onionRPC)

	clientNode = &ClientNode{
		MinNodes:            minNodes,
		NumRetry:            numRetry,
		TimeoutRefresh:      resource.TimeoutRefreshMultiplier * int64(minNodes) * 2,
		TimeoutForceRefresh: resource.ForceRefresh * resource.TimeoutRefreshMultiplier,
		ServerConn:          serverConn,
		Address:             clientAddr}

	circuitTopology = topology
	listener, err := net.Listen("tcp", privateAddr)
	if err != nil {
		return nil, err
	}
	go rpc.Accept(listener)

	// If nodes disconnect during initial circuit creation, retry
	for i := 0; i < numRetry; i++ {
		err = establishCircuit(topology)
		if err != nil {
			print.Info(print.ONIONLIB, "JoinOnionNetwork", "Initial circuit creation failed. Retry establishing a new circuit", nil)
			continue
		}
		break
	}

	if err != nil {
		print.Info(print.ONIONLIB, "JoinOnionNetwork", "Initial circuit creation failed. Cannot join network", nil)
		return nil, err
	}

	go periodicRefreshTracker()

	return clientNode, nil
}

/* ==========================    OnionNetwork API Implementation    ========================== */
// GetRequest ... Version 1 should try to just support GET requests
// Errors:
// - HttpError
// - CorruptPacketError
// - CircuitGenerationError
// - OnionEncryptionError
// - OnionDecryptionError
// - RetryError
func (clientNode *ClientNode) GetRequest(destAddress string) (dataToReturn []byte, err error) {

	requestLock.Lock()
	print.Info(print.ONIONLIB, "GetRequest", "Getting website", destAddress)

	for i := 0; i < clientNode.NumRetry; i++ {

		msg := fmt.Sprintf("Retry Counter [%d]", i)
		print.Info(print.ONIONLIB, "GetRequest", msg, nil)

		currentCircuit.Lock()
		if len(currentCircuit.circuitMap) < clientNode.MinNodes {

			err := refreshCircuit()
			if err != nil {
				currentCircuit.Unlock()
				continue
			}
		}
		currentCircuit.Unlock()

		currentCircuit.RLock()
		dataToReturn, err = getRequestHelper(destAddress, 0)
		currentCircuit.RUnlock()
		if err == nil {
			requestLock.Unlock()
			return dataToReturn, nil
		} else {
			currentCircuit.Lock()
			emptyCircuitAndStreams()
			currentCircuit.Unlock()
			print.Debug(print.ONIONLIB, "getRequestHelper", "error was encountered", err)
		}
	}
	requestLock.Unlock()

	return nil, err
}

// UnlinkFromNetwork ... Disconnects client from the circuit, clean up
func (clinetNode *ClientNode) UnlinkFromNetwork() {
	print.Info(print.ONIONLIB, "UnlinkFromNetwork", "destroy the entire circuit", nil)
	clientNode.ServerConn.Close()
	currentCircuit.Lock()
	destroyCircuit()
	currentCircuit.Unlock()
}

/* ==========================    OnionRPC API Method    ========================== */
// OnionHeartBeat ... Sends heartbeat to entry onion node
func (t *OnionRPC) OnionHeartBeat(address string, output *bool) error {
	timeStamp := time.Now().UnixNano()
	entryNodeHeartBeats.Lock()
	//fmt.Println("[" + time.Now().Format(time.RFC3339Nano) + "]" + address + " ... pinged me\n")
	entryNodeHeartBeats.HeartBeatMap[address] = timeStamp
	entryNodeHeartBeats.Unlock()
	return nil
}

// SendResponse ... RPC method for entry onion node to contact Onionlib
func (t *OnionRPC) SendResponse(input resource.ResponseMessage, output *bool) error {
	circuitIDLock.RLock()
	isResponseForCircuit := circuitID == input.CircuitID
	circuitIDLock.RUnlock()

	if isResponseForCircuit {
		responseChannel <- input.Data
	}
	return nil
}

// SendError ... RPC method to receive TRUNCATED message from entry onion node
func (t *OnionRPC) SendError(input resource.ResponseMessage, output *bool) error {
	circuitIDLock.RLock()
	isErrorForCircuit := circuitID == input.CircuitID
	fmt.Println("CIRCUITID:", circuitID)
	fmt.Println("INPUT ID:", input.CircuitID)
	circuitIDLock.RUnlock()

	if isErrorForCircuit {
		if !input.IsRelay {
			fmt.Println("[ERROR] SendError: package received is not a relay cell")
			return nil
		}

		decryptedData, err := decryptOnionPacket(input.Data, -1, "sendResponse")
		if err != nil {
			fmt.Println("[ERROR] SendError: unable to decrypt onion packet")

			if len(refreshChannel) != 1 {
				fmt.Println("current length of refresh channel", len(refreshChannel))
				refreshChannel <- true
			}
			return nil
		}

		decodedData := cells.DecodeRelayCell(decryptedData)
		cmd := decodedData.Command

		if cmd == cells.TRUNCATED {
			print.Info(print.ONIONLIB, "SendError", "Received TRUNCATED message from onion node, onion node truncated is", decodedData.Target)
			if len(refreshChannel) != 1 {
				fmt.Println("current length of refresh channel", len(refreshChannel))
				refreshChannel <- true
			}
		} else {
			print.Info(print.ONIONLIB, "SendError", "[ERROR] SendError: error message is not TRAUNCATED", cmd)
		}
	}

	return nil
}

/* ==========================    Routines & Routines Helpers   ========================== */
// General go routine for circuit maintenance
func periodicRefreshTracker() {
	refreshInterval := time.Duration(clientNode.TimeoutForceRefresh) * time.Second

	for {
		time.Sleep(refreshInterval)
		currentTime := time.Now().UnixNano()

		if currentTime-refreshStatus.timeSinceCircuitLastBuilt > int64(refreshInterval) {
			print.Info(print.ONIONLIB, "periodicRefreshTracker", "Force refresh of circuit", nil)
			currentCircuit.Lock()
			err := refreshCircuit()
			currentCircuit.Unlock()
			print.Error(print.ONIONLIB, err, "periodicRefreshTracker")
		}
	}
}

// Helper function to refresh the circuit
func refreshCircuit() error {
	print.Info(print.ONIONLIB, "refreshCircuit", "Refreshing circuit...", nil)
	currentTime := time.Now().UnixNano()
	refreshInterval := time.Duration(clientNode.TimeoutForceRefresh) * time.Second
	isRecentlyRefresh := currentTime-refreshStatus.timeSinceCircuitLastBuilt < int64(refreshInterval/2)
	isCircuitUp := len(currentCircuit.circuitMap) == clientNode.MinNodes

	// Do not refresh the circuit if it was recently refreshed
	if isRecentlyRefresh && isCircuitUp {
		print.Info(print.ONIONLIB, "refreshCircuit", "Circuit recently refreshed", int64(refreshInterval/2))
		return nil
	}

	// Destroy current circuit
	if currentCircuit.circuitConnection != nil {
		print.Info(print.ONIONLIB, "refreshCircuit", "destroy current circuit", nil)
		destroyCircuit()
	}

	// Let circuit stabilize
	//	time.Sleep(time.Duration(clientNode.TimeoutRefresh) * time.Second)

	print.Info(print.ONIONLIB, "refreshCircuit", "create a new circuit", nil)
	// Uncomment to use global topology consistently
	err := establishCircuit(circuitTopology)
	//err := establishCircuit("")
	if err != nil {
		print.Error(print.ONIONLIB, err, "refreshCircuit")
		return err
	}

	return nil
}

// Routine to check onionlib's heartbeat with the entry node periodically
func checkEntryNodeHeartBeats(entryNode resource.OnionInfo) {
	address := entryNode.Address.String()
	heartBeatInterval := time.Duration(resource.HeartBeat) * time.Millisecond
	time.Sleep(heartBeatInterval)

	for {
		// fmt.Println("Hello Entry Node", address)
		entryNodeHeartBeats.Lock()
		oldTimeStamp, exist := entryNodeHeartBeats.HeartBeatMap[address]
		if !exist {
			entryNodeHeartBeats.Unlock()
			return
		}

		currTimeStamp := time.Now().UnixNano()

		if currTimeStamp-oldTimeStamp > int64(heartBeatInterval) {
			//fmt.Println("Goodbye ", address)
			delete(entryNodeHeartBeats.HeartBeatMap, address)
			entryNodeHeartBeats.Unlock()
			return
		}

		entryNodeHeartBeats.Unlock()
		time.Sleep(heartBeatInterval)
	}
}

// Pings the entry node by calling OnionHeartBeat rpc call periodically
func sendOnionNodeHeartBeat(nodeConnection *rpc.Client, clientNodeAddr, entryNodeAddr, heartBeatCircuitID string) {
	// Setup initial heartbeat mapping
	entryNodeHeartBeats.Lock()
	entryNodeHeartBeats.HeartBeatMap[entryNodeAddr] = time.Now().UnixNano()
	entryNodeHeartBeats.Unlock()

	heartBeatInterval := time.Duration(resource.HeartBeat) / 2
	var output bool
	for {

		circuitIDLock.RLock()
		isThisMyCircuit := circuitID == heartBeatCircuitID
		circuitIDLock.RUnlock()

		if isThisMyCircuit {
			entryNodeHeartBeats.RLock()
			if _, ok := entryNodeHeartBeats.HeartBeatMap[entryNodeAddr]; ok {
				// Send heartbeat to entry node
				entryNodeHeartBeats.RUnlock()
				//fmt.Println("["+time.Now().Format(time.RFC3339Nano)+"]"+"Pinging ...", entryNodeAddr)
				err := nodeConnection.Call("OnionRPC.OnionHeartBeat", clientNodeAddr, &output)
				if err != nil {
					fmt.Println("["+time.Now().Format(time.RFC3339Nano)+"]"+"Unable to ping ...", entryNodeAddr)
				}

				time.Sleep(heartBeatInterval * time.Millisecond)
			} else {
				// Remove entry node from the senderHeartBeat map
				entryNodeHeartBeats.RUnlock()
				senderHeartBeats.Lock()
				delete(senderHeartBeats.HeartBeatMap, entryNodeAddr)
				senderHeartBeats.Unlock()

				if len(refreshChannel) != 1 {
					refreshChannel <- true
				}
				return
			}
		} else {
			senderHeartBeats.Lock()
			currentSenderCircuitID := senderHeartBeats.HeartBeatMap[entryNodeAddr]
			if currentSenderCircuitID == heartBeatCircuitID {
				delete(senderHeartBeats.HeartBeatMap, entryNodeAddr)
			}
			senderHeartBeats.Unlock()
			break
		}
	}
}

/* ==========================    GET Request Helpers   ========================== */
func getRequestHelper(destAddress string, currentRetry int) ([]byte, error) {
	exitNode, exists := currentCircuit.circuitMap[clientNode.MinNodes-1]
	if !exists {
		return nil, errorlib.RetryError(destAddress)
	}

	targetAddress := exitNode.Addr.String()

	if streamID, ok := streamDirectory.streamMap[destAddress]; ok {
		dataToReturn, err := handleDataRequest(streamID, targetAddress, destAddress)
		if err != nil {
			return nil, err
		}

		return dataToReturn, nil
	} else {
		//Generate id
		streamID := randomGenerator()

		//Send the relay cell to exit node
		err := sendRelayCellHelper(cells.BEGIN, streamID, targetAddress, []byte(destAddress), -1)
		if err != nil {
			return nil, err
		}

		responseData, err := receiveResponse(destAddress)
		if err != nil {
			return nil, err
		}

		// Decrypt and get data
		relayCell, err := receiveRelayCellHelper(responseData)
		if err != nil {
			return nil, err
		}

		switch relayCell.Command {
		case cells.CONNECTED:
			break
		case cells.TEARDOWN:
			return nil, errorlib.HttpError(string(relayCell.Data))
		default:
			return nil, errorlib.CorruptPacketError{}
		}

		//Add stream to directory and return data
		streamDirectory.streamMap[destAddress] = streamID
		fmt.Printf("StreamID: %s\n", streamID)
		dataToReturn, err := handleDataRequest(streamID, targetAddress, destAddress)
		if err != nil {
			return nil, err
		}

		return dataToReturn, nil
	}
}

func receiveResponse(destAddress string) (data []byte, err error) {
	select {
	case responseData := <-responseChannel:
		return responseData, nil
	case resetCircuit := <-refreshChannel:
		print.Info(print.ONIONLIB, "receiveResponse", "error channel message received, refresh circuit", resetCircuit)
		return nil, errorlib.RetryError(destAddress)

	case <-time.After(time.Duration(clientNode.TimeoutRefresh) * time.Second):
		print.Info(print.ONIONLIB, "Request", "time out", nil)
		return nil, errorlib.RetryError(destAddress)
	}
}

func sendRelayCellHelper(command cells.OnionCommand, streamID, target string, dataToSend []byte, index int) error {
	//1 Create Relay Cell Begin
	exitNode, exists := currentCircuit.circuitMap[clientNode.MinNodes-1]

	if !exists {
		return errorlib.CircuitGenerationError{}
	}

	relayCell := cells.EncodeRelayCell(command, streamID, exitNode.Addr.String(), dataToSend)

	//2 Encrypt Onion
	onionPacket, err := encryptOnionPacket(relayCell, index)
	if err != nil {
		print.Error(print.ONIONLIB, err, "sendRelayCellHelper")

		circuitIDLock.RLock()
		err = errorlib.OnionEncryptionError(circuitID)
		circuitIDLock.RUnlock()
		return err
	}

	//3 Send Onion Packet
	var output resource.ResponseMessage
	circuitIDLock.RLock()
	input := resource.RequestMessage{
		CircuitID:     circuitID,
		IsRelay:       true,
		EncryptedData: onionPacket}
	circuitIDLock.RUnlock()
	currentCircuit.circuitConnection.Go("OnionRPC.ReceiveRelayMessage", input, &output, nil)
	return nil
}

func receiveRelayCellHelper(encryptedData []byte) (*cells.RelayCell, error) {
	decryptIndex := len(currentCircuit.circuitMap) - 1

	//1 Decrypt reply
	decryptedData, err := decryptOnionPacket(encryptedData, decryptIndex, "receiveRelayCellHelper")
	if err != nil {
		print.Error(print.ONIONLIB, err, "receiveRelayCellHelper")
		circuitIDLock.RLock()
		err = errorlib.OnionDecryptionError(circuitID)
		circuitIDLock.RUnlock()
		return nil, err
	}

	//2 Decode response and get relay cell
	relayCell := cells.DecodeRelayCell(decryptedData)
	return &relayCell, nil
}

// Helper method to handle the sending of DATA requests and receving of their responses
func handleDataRequest(streamID, targetAddress, destAddress string) ([]byte, error) {
	err := sendRelayCellHelper(cells.DATA, streamID, targetAddress, []byte(http.MethodGet), -1)
	if err != nil {
		return nil, err
	}

	packetSlice := make([]cells.DataPacket, 0)

	// Iteratively decrypts and decode data responses from entry node
	// until the expected total number of packets to be received has reached
	for {
		responseData, err := receiveResponse(destAddress)
		if err != nil {
			return nil, err
		}

		relayCell, err := receiveRelayCellHelper(responseData)
		if err != nil {
			return nil, err
		}

		dataPacket := cells.DecodeDataResponsePayload(relayCell.Data)

		switch relayCell.Command {
		case cells.RESPONSE:
			break
		case cells.TEARDOWN:
			delete(streamDirectory.streamMap, destAddress)
			return nil, errorlib.HttpError(string(relayCell.Data))
		default:
			return nil, errorlib.CorruptPacketError{}
		}

		//Add packet into slice
		packetSlice = append(packetSlice, dataPacket)

		// obtained all packets
		if len(packetSlice) == dataPacket.PacketTotal {
			break
		}
	}

	// sort the received packets so that they are in order
	sort.Slice(packetSlice, func(i, j int) bool {
		return packetSlice[i].PacketNumber < packetSlice[j].PacketNumber
	})

	// combine the slices
	data := make([]byte, 0)
	for _, packet := range packetSlice {
		data = append(data, packet.Data...)
	}

	return data, nil
}

/* ========================== JoinOnionNetWork Helpers  ========================== */

// Establishes a circuit
func establishCircuit(topology string) (err error) {
	var nodes []resource.OnionInfo

	for {
		nodes, err = getOnionNodesFromServer()
		if err != nil {
			continue
		}
		// Retry with a different server
		break
	}

	if len(nodes) < clientNode.MinNodes {
		return errorlib.InsufficientNumberOfOnionNodeError(len(nodes))
	}

	// Sort the nodes so that we can have a predicatble pattern for testing
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Address.String() < nodes[j].Address.String()
	})

	chosenNodes := chooseTopology(nodes, clientNode.MinNodes, topology)
	mostRecentCircuit = make([]resource.OnionInfo, clientNode.MinNodes)
	copy(mostRecentCircuit, chosenNodes)

	for i := 0; i < len(chosenNodes); i++ {
		print.Info(print.ONIONLIB, "establishCircuit", "chosenNodes", chosenNodes[i].Address.String())
	}

	err = keyExchangeWithEntryNode(chosenNodes[0])
	if err != nil {
		return err
	}

	// After exchange succeeds, listen for entry node heartbeats
	go checkEntryNodeHeartBeats(chosenNodes[0])

	// If this fails need to clean up circuit and make sure entry node connection is closed
	err = keyExchangeWithOnionNodes(chosenNodes)
	if err != nil {
		return err
	}

	refreshStatus.timeSinceCircuitLastBuilt = time.Now().UnixNano()
	return nil
}

// Get a list of available onion nodes from server
// returns error if none of the server is available
func getOnionNodesFromServer() (nodes []resource.OnionInfo, err error) {
	var input string
	var nodesFromServer []resource.OnionInfo
	err = clientNode.ServerConn.Call("ServerRPC.GetNodes", &input, &nodesFromServer)
	if err != nil {
		connectToAvailableServer()
		return nil, errorlib.DisconnectedError("server")
	}

	return nodesFromServer, nil
}

// Initiates key exchange with the entry node
func keyExchangeWithEntryNode(firstNode resource.OnionInfo) error {
	print.Info(print.ONIONLIB, "keyExchangeWithEntryNode", "[CREATE] exchanging key with entry node", firstNode.Address.String())

	// 1. Call helper method sendCreateRequest
	sharedKey, entryConn, circuitIDGenerated, err := sendCreateRequest(firstNode)
	if err != nil {
		print.Info(print.ONIONLIB, "keyExchangeWithEntryNode", "[CREATE-FAILED] error is", err)
		return err
	}

	// Start sending heartbeat to the entry node
	if _, ok := senderHeartBeats.HeartBeatMap[firstNode.Address.String()]; !ok {
		go sendOnionNodeHeartBeat(entryConn, clientNode.Address, firstNode.Address.String(), circuitIDGenerated)
		senderHeartBeats.HeartBeatMap[firstNode.Address.String()] = circuitIDGenerated
	} else {
		print.Error(print.ONIONLIB, err, "Already sending heartbeat to an entry node")
	}

	entryNode := &OnionNode{
		PubKey:    firstNode.Key,
		SharedKey: sharedKey,
		Addr:      firstNode.Address}

	circuitIDLock.Lock()
	circuitID = circuitIDGenerated
	circuitIDLock.Unlock()
	currentCircuit.circuitConnection = entryConn
	currentCircuit.circuitMap[0] = entryNode

	print.Info(print.ONIONLIB, "keyExchangeWithEntryNode", "[CREATE-SUCCESS] circuit id", circuitID)
	return nil
}

// Helper function to call entry node's rpc method ReceiveCreateRequest
func sendCreateRequest(target resource.OnionInfo) (sharedKey []byte, targetConn *rpc.Client, circuitID string, err error) {
	// 1. Create my half of the shared key
	mygroup, mykey, err := encryption.CreateDHKey()
	if err != nil {
		return nil, nil, "", err
	}

	// 2. Encrypts my half of the shared key with the target onio node's public key
	encryptedDHKey, err := encryption.RSAEncrypt(&target.Key, mykey.Bytes())

	print.Encryption(print.ONIONLIB, "keyExchangeWithEntryNode", "RSA encryption", mykey.Bytes(), encryptedDHKey)

	// 3. Generate a circuitID for the connection between me and the entry node
	circuitID, err = resource.GenerateUUID()
	if err != nil {
		return nil, nil, "", err
	}

	// 4. Establishes a connection with the entry node
	targetConn, err = rpc.Dial("tcp", target.Address.String())
	if err != nil {
		return nil, nil, "", err
	}

	// 5. Calls entry node's ReceiveCreateRequest
	var output resource.ResponseMessage
	input := resource.RequestMessage{
		Address:       clientNode.Address,
		CircuitID:     circuitID,
		EncryptedData: encryptedDHKey}

	doneCall := targetConn.Go("OnionRPC.ReceiveCreateRequest", input, &output, nil)

	// 6. Block until a response comes back
	// timeout guarantees that if no response come back within a reasonable time, an error will be thrown
	var messageCall *rpc.Call
	select {
	case doneMessage := <-doneCall.Done:
		err = doneMessage.Error
		if err != nil {
			return nil, nil, "", err
		} else {
			messageCall = doneMessage
		}
	case <-time.After(time.Duration(clientNode.TimeoutRefresh) * time.Second):
		return nil, nil, "", errorlib.CircuitGenerationError{}
	}

	// 7. Decode and verify received entry node's half shared key with the hash of the full shared key
	responseMessage := messageCall.Reply.(*resource.ResponseMessage)

	command := cells.DecodeCommand(responseMessage.Data)
	controlData := cells.DecodeControlData(responseMessage.Data)

	if command == cells.CREATED {
		otherDHKey := controlData[0:128]
		hashedSharedKey := controlData[128:]

		sharedKey, err = encryption.ComputeSharedKey(mygroup, otherDHKey, mykey)
		if err != nil {
			return nil, nil, "", err
		}

		myHashedKey := encryption.HashSharedKey(sharedKey)
		if !bytes.Equal(myHashedKey, hashedSharedKey) {
			return nil, nil, "", errorlib.InvalidKeyExchangeError(target.Address.String())
		}
	} else {
		return nil, nil, "", errorlib.InvalidCommandReceivedError(command)
	}

	return sharedKey, targetConn, circuitID, nil
}

// Initiates key exchange with the rest of the onion nodes (non entry nodes)
func keyExchangeWithOnionNodes(chosenNodes []resource.OnionInfo) error {
	for i := 1; i < len(chosenNodes); i++ {
		target := chosenNodes[i]
		print.Info(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE] exchanging key with", target.Address.String())

		// 1. Calculate half DH key
		mygroup, mykey, err := encryption.CreateDHKey()
		if err != nil {
			return err
		}

		// 2. Encrypt half DH key with target's public key
		encryptedDHKey, err := encryption.RSAEncrypt(&target.Key, mykey.Bytes())
		if err != nil {
			return err
		}

		// 3. Encode relay cell with EXTEND command
		encryptedData := cells.EncodeRelayCell(cells.EXTEND, "", target.Address.String(), encryptedDHKey)

		// 4. Encrypt onion packet
		onionPacket, err := encryptOnionPacket(encryptedData, -1)
		if err != nil {
			print.Error(print.ONIONLIB, err, "keyExchangeWithOnionNodes")
			return errorlib.InvalidKeyExchangeError(chosenNodes[i].Address.String())
		}

		//Log: After encryption log
		print.Encryption(print.ONIONLIB, "keyExchangeWithOnionNodes", "AES Encryption (showing partial)", encryptedData[:20], onionPacket[:20])

		// 5. Send onion packet to entry node
		var output resource.ResponseMessage

		circuitIDLock.RLock()
		input := resource.RequestMessage{
			Address:       clientNode.Address,
			CircuitID:     circuitID,
			IsRelay:       true,
			EncryptedData: onionPacket}
		circuitIDLock.RUnlock()

		currentCircuit.circuitConnection.Go("OnionRPC.ReceiveRelayMessage", input, &output, nil)
		select {
		case output.Data = <-responseChannel:
			break
		case <-time.After(time.Duration(clientNode.TimeoutRefresh) * time.Second):
			print.Debug(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE-FAILED] error response timeout", err)
			return errorlib.InvalidKeyExchangeError(chosenNodes[i].Address.String())
		}

		// 6. Decrypt response
		decrypted, err := decryptOnionPacket(output.Data, i-1, "onionNodekeyexchange")
		if err != nil {
			print.Debug(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE-FAILED] error decrypting onion packet response", decrypted)
			return errorlib.InvalidKeyExchangeError(chosenNodes[i].Address.String())
		}

		// 7. Decode response
		decoded := cells.DecodeRelayCell(decrypted)
		data := decoded.Data
		otherDHKey := data[:128]
		responseHashedKey := data[128:]

		// 8. Use decrypted and decoded data to calculate shared key
		sharedKey, err := encryption.ComputeSharedKey(mygroup, otherDHKey, mykey)
		if err != nil {
			print.Debug(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE-FAILED] error computing shared key", err)
			return errorlib.InvalidKeyExchangeError(chosenNodes[i].Address.String())
		}

		myHashedKey := encryption.HashSharedKey(sharedKey)
		if !bytes.Equal(myHashedKey, responseHashedKey) {
			print.Debug(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE-FAILED] shared key and hash do not match", nil)
			return errorlib.InvalidKeyExchangeError(target.Address.String())
		}

		// 9. Update circuit map entry
		circuitNode := &OnionNode{
			PubKey:    target.Key,
			SharedKey: sharedKey,
			Addr:      target.Address}

		currentCircuit.circuitMap[i] = circuitNode
		print.Info(print.ONIONLIB, "keyExchangeWithOnionNodes", "[CREATE-SUCCESS] address is", circuitNode.Addr)
	}

	printCircuit()
	return nil
}

// Helper method for client to connect to the server so it can obtain an onion-node directory
func connectToAvailableServer() {
	serverAddress, err := resource.ChooseRandomServer()
	if err != nil {
		print.Error(print.ONIONLIB, err, "connectToAvailableServer")
	}

	err = clientNode.ServerConn.Close()
	if err != nil {
		print.Error(print.ONIONLIB, err, "connectToAvailableServer")
	}

	serverConnection, err := rpc.Dial("tcp", serverAddress)
	checkError(err, "connectToAvailableServer: rpc.Dial()")
	clientNode.ServerConn = serverConnection
}

/* ==========================    Destroy and Truncate Helpers   ========================== */
// Truncates circuit node at given index position in the circuit map
func truncateCircuitNode(index int) error {
	// 1. Encode relay cell for truncate command
	target := currentCircuit.circuitMap[index]
	onionPacket := cells.EncodeRelayCell(cells.TRUNCATE, "", target.Addr.String(), []byte(""))
	print.Info(print.ONIONLIB, "truncateCircuitNode", "encoded relay cell", onionPacket)

	// 2. Encrypt relay cell into onion packet
	onionPacket, err := encryptOnionPacket(onionPacket, index-1)
	if err != nil {
		print.Error(print.ONIONLIB, err, "truncateCircuitNode")
		return err
	}
	print.Info(print.ONIONLIB, "truncateCircuitNode", "encrypted packet", onionPacket)

	// 3. Send onion packet to entry node
	var output resource.ResponseMessage
	circuitIDLock.RLock()
	input := resource.RequestMessage{clientNode.Address, circuitID, true, onionPacket}
	circuitIDLock.Unlock()
	currentCircuit.circuitConnection.Go("OnionRPC.ReceiveRelayMessage", input, &output, nil)

	print.Info(print.ONIONLIB, "truncateCircuitNode", "Message sent to entry node ... WAITING", nil)
	output.Data = <-responseChannel
	print.Info(print.ONIONLIB, "truncateCircuitNode", "Received message from entry node ... SUCCESS", nil)
	if err != nil {
		print.Error(print.ONIONLIB, err, "truncateCircuitNode")
		return errorlib.TruncationError(target.Addr.String())
	}

	// 4. Decrypt onion packet received from entry node
	decryptedOnion, err := decryptOnionPacket(output.Data, index-1, "truncateCircuitNode")
	if err != nil {
		print.Error(print.ONIONLIB, err, "truncateCircuitNode")
		return errorlib.OnionDecryptionError(target.Addr.String())
	}

	// 5. Decode decrypted relay cell
	relayCell := cells.DecodeRelayCell(decryptedOnion)
	if relayCell.Command != cells.TRUNCATED {
		return errorlib.InvalidCommandReceivedError(relayCell.Command)
	}

	// 6. Remove circuit node from the circuit
	delete(currentCircuit.circuitMap, index)
	printCircuit()
	return nil
}

// Truncates the entire circuit, circuit node by circuit node
func truncateCircuit() error {
	// 1. Send TRUNCATE command to all nodes' predeccessor to destroy the target node
	// Note: all nodes except the entry node
	for i := len(currentCircuit.circuitMap) - 1; i > 0; i-- {
		err := truncateCircuitNode(i)
		if err != nil {
			print.Error(print.ONIONLIB, err, "truncateCircuit")
		}
	}

	// 2. Send destroy command directly to the entry node
	var output string
	circuitIDLock.RLock()
	input := resource.RequestMessage{
		Address:   clientNode.Address,
		CircuitID: circuitID}
	circuitIDLock.RUnlock()

	currentCircuit.circuitConnection.Go("OnionRPC.SendDestroyRequest", input, &output, nil)
	currentCircuit.circuitMap = make(map[int]*OnionNode)
	return nil
}

// Destroy all nodes in the circuit starting from the entry node going toward the exit node
func destroyCircuit() {
	if len(currentCircuit.circuitMap) == 0 {
		return
	}

	for destAddress, _ := range streamDirectory.streamMap {
		delete(streamDirectory.streamMap, destAddress)
	}

	printStreams()

	var output string
	circuitIDLock.RLock()
	input := resource.RequestMessage{
		Address:   clientNode.Address,
		CircuitID: circuitID}
	circuitIDLock.RUnlock()

	currentCircuit.circuitConnection.Go("OnionRPC.SendDestroyRequest", input, &output, nil)

	entryNodeAddress := currentCircuit.circuitMap[0].Addr.String()
	print.Info(print.ONIONLIB, "destroyCircuit", "removing entry node from entryNodeHeartBeats", entryNodeAddress)
	emptyCircuitAndStreams()
	printCircuit()
}

/* ========================== Encryption & Decryption Helpers  ========================== */
// Encrypts an onion packet iteratively, the layers to encrypt is deterined by the parameter targetIndex
func encryptOnionPacket(encryptedData []byte, targetIndex int) (onionPacket []byte, err error) {
	// Iteratively encrypt relay cell with onion node's shared key
	// starting from the immediate predecessor of the target
	if targetIndex == -1 {
		targetIndex = len(currentCircuit.circuitMap) - 1
	}
	for i := targetIndex; i >= 0; i-- {
		on := currentCircuit.circuitMap[i]
		encryptedData, err = encryption.AESEncryptCTR(on.SharedKey, encryptedData, make([]byte, 16))
		if err != nil {
			return nil, err
		}
	}

	return encryptedData, nil
}

// Decrypts an onion packet iteratively
// -checks that the onion node sharedkey it decrypted with matches the onion node index expected by the caller
// -This is to prevent intermediate malicious nodes from dopping the real packet and replacing it with its own
func decryptOnionPacket(onionPacket []byte, decryptIndex int, function string) (decrypted []byte, err error) {
	// Iteratively decrypt onion packet with onion node's shared key starting from the entry node

	for i := 0; i < len(currentCircuit.circuitMap); i++ {
		on := currentCircuit.circuitMap[i]
		onionPacket, err = encryption.AESEncryptCTR(on.SharedKey, onionPacket, encryption.GenerateIV())
		if err != nil {
			return nil, err
		}

		if cells.IsDigestValid(onionPacket) {
			if i == decryptIndex || -1 == decryptIndex {
				return onionPacket, nil
			}
		}
	}

	// If code reaches here that means digest does not match the hash of the payload
	// or digest matches the hash of the payload but the shared key that decryted the packet is not expected
	print.Debug(print.ONIONLIB, "decryptOnionPacket", "invalid cell digest, unable to decrypt onion packet", nil)
	return onionPacket, errors.New("unable to decrypt onion packet")
}

/* ========================== Onion Node Choosing Helpers  ========================== */
// Converts a slice to a map
func sliceToMap(slice []resource.OnionInfo) (dst map[string]resource.OnionInfo) {
	dst = make(map[string]resource.OnionInfo, len(slice))
	for _, on := range slice {
		dst[on.Address.String()] = on
	}
	return dst
}

// Finds the difference and common set given two slices of OnionInfo
// Used when establishing a circuit with the BestEffort approach
func findDiffAndCommonSet(set1, set2 []resource.OnionInfo) (diffSet, commonSet []resource.OnionInfo) {
	mSet1 := sliceToMap(set1)
	mSet2 := sliceToMap(set2)
	// Compute commonSet
	for key, val := range mSet1 {
		if _, exists := mSet2[key]; exists {
			commonSet = append(commonSet, val)
			delete(mSet1, key)
			delete(mSet2, key)
		}
	}
	// Compute diffSet
	for _, val := range mSet1 {
		diffSet = append(diffSet, val)
	}
	for _, val := range mSet2 {
		diffSet = append(diffSet, val)
	}
	return diffSet, commonSet
}

// BestEffort approach: Chooses nodes randomly by avoid using as many nodes from the previous circuit as possible
func bestEffortRandomChoose(nodes []resource.OnionInfo, minNodes int) (chosenNodes []resource.OnionInfo) {
	if len(mostRecentCircuit) == 0 {
		return chooseRandomlyFromList(nodes, minNodes)
	}

	diffSet, commonSet := findDiffAndCommonSet(nodes, mostRecentCircuit)
	for _, on := range diffSet {
		print.Info(print.ONIONLIB, "establishCircuit", "Difference set", on.Address.String())
	}
	for _, on := range commonSet {
		print.Info(print.ONIONLIB, "establishCircuit", "Common set", on.Address.String())
	}

	dsLength := len(diffSet)

	// diffSet > minNodes
	if dsLength > minNodes {
		return chooseRandomlyFromList(diffSet, minNodes)
	}

	// diffSet <= minNodes
	chosenNodes = append(chosenNodes, diffSet...)
	additionalNodes := chooseRandomlyFromList(commonSet, minNodes-len(diffSet))
	return append(chosenNodes, additionalNodes...)
}

// Chooses minNodes number of nodes from the given list of nodes
// Returns a list of randomly chosen nodes
func chooseRandomlyFromList(nodes []resource.OnionInfo, minNodes int) (chosenNodes []resource.OnionInfo) {
	var chosen []bool
	chosen = make([]bool, len(nodes))

	for len(chosenNodes) < minNodes {
		rand.Seed(time.Now().UnixNano())
		r := rand.Intn(len(nodes))
		if chosen[r] == false {
			chosen[r] = true
			chosenNodes = append(chosenNodes, nodes[r])
		}
	}

	return chosenNodes
}

// Topology multiplexer
// Topology X1 to RT2 are special topologies for demo purposes
// Topology BE is the best effort node choosing approach that prevents using old nodes, a strategy to avoid
// using malicious nodes in a timeout refresh
// Default: randomly chooses minNodes number of nodes
func chooseTopology(nodes []resource.OnionInfo, minNodes int, topology string) (chosenNodes []resource.OnionInfo) {
	print.Info(print.ONIONLIB, "chooseTopology", "chosen topology", topology)

	if topology == "X1" {
		return circuitTest.GetXTopology1(nodes)
	} else if topology == "X2" {
		return circuitTest.GetXTopology2(nodes)
	} else if topology == "T1" {
		return circuitTest.GetTTopology1(nodes)
	} else if topology == "T2" {
		return circuitTest.GetTTopology2(nodes)
	} else if topology == "RT1" {
		return circuitTest.GetReverseTTopology1(nodes)
	} else if topology == "RT2" {
		return circuitTest.GetReverseTTopology2(nodes)
	} else if topology == "BE" {
		return bestEffortRandomChoose(nodes, minNodes)
	} else {
		// DEFAULT
		return chooseRandomlyFromList(nodes, minNodes)
	}
}

/* ========================== General Helpers  ========================== */
// Prints out all currently opened streams in the current circuit
func printStreams() {
	fmt.Println("Current streams in the circuit\n")

	for index, streamID := range streamDirectory.streamMap {
		fmt.Printf("Address: %s, Stream id: %s\n", index, streamID)
	}
}

// Prints out the current circuit
func printCircuit() {
	fmt.Println()
	fmt.Println("------------------[CIRCUIT]------------------")
	for i := 0; i < len(currentCircuit.circuitMap); i++ {
		fmt.Println("onion node:", currentCircuit.circuitMap[i].Addr.String())
		fmt.Printf("shared key: [%x]\n", currentCircuit.circuitMap[i].SharedKey)
		fmt.Println("                      |")
		fmt.Println("                      v")
	}
	fmt.Println("--------------------[end]--------------------\n\n")
}

// Generates a random number for streamIDs
// number generated is returned as a string representation
func randomGenerator() string {
	// potentialNumber := strconv.Itoa(generatedNumber)

	// // Checks that number generated does not collide with any existing streamIDs
	// for _, streamID := range streamDirectory.streamMap {
	// 	if streamID == potentialNumber {
	// 		return randomGenerator(rand.Intn(99))
	// 	}
	// }

	// return potentialNumber

	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()`~!@#$%^&*-+=|{}[]:;'<>,.?/"
	buffer := make([]byte, 2)
	for i := 0; i < 2; i++ {
		buffer[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	potentialID := string(buffer)

	// Checks that number generated does not collide with any existing streamIDs
	for _, streamID := range streamDirectory.streamMap {
		if streamID == potentialID {
			return randomGenerator()
		}
	}

	return potentialID
}

func emptyCircuitAndStreams() {
	circuitIDLock.Lock()
	circuitID = ""
	circuitIDLock.Unlock()
	currentCircuit.circuitMap = make(map[int]*OnionNode)

	if currentCircuit.circuitConnection != nil {
		currentCircuit.circuitConnection.Close()
		currentCircuit.circuitConnection = nil
	}

	streamDirectory.Lock()
	for destAddress, _ := range streamDirectory.streamMap {
		delete(streamDirectory.streamMap, destAddress)
	}
	streamDirectory.Unlock()
}

// checks critical errors and exits the proccess if neccessary
func checkError(err error, method string) {
	if err != nil {
		fmt.Println("[onionlib]", method, err)
		os.Exit(1)
	}
}
