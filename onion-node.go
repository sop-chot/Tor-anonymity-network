package main

import (
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strings"
	"sync"
	"time"

	"./resource"
	"./resource/cells"
	"./resource/encryption"
	"./resource/errorlib"
	"./resource/print"
)

type OnionNode struct {
	pubKey                *rsa.PublicKey
	privKey               *rsa.PrivateKey
	localAddr, serverAddr net.Addr
	serverConnection      *rpc.Client
}

type ConnectionDirectory struct {
	sync.RWMutex
	//key is address
	connectionMap map[string]*rpc.Client
}

type CircuitDirectory struct {
	sync.RWMutex
	//key is a circuitID
	circuitMap map[string]*CircuitInfo
}

type CircuitInfo struct {
	circuitID   string
	nodeAddress string
	sharedKey   []byte
	isParent    bool
}

type StreamDirectory struct {
	sync.RWMutex
	// key is circuitID:streamID
	streamMap map[string]*HttpClientWrapper
}

type HttpClientWrapper struct {
	client     *http.Client
	webAddress string
}

type OnionRPC int

var onionNode *OnionNode

// Directory that stores the addresses of the received heartbeats
var neighbourHeartBeats = resource.HeartBeats{HeartBeatMap: make(map[string]int64)}

// Directory that stores the addresses of the sent heartbeats, value is arbitrary
var senderHeartBeats = resource.HeartBeats{HeartBeatMap: make(map[string]int64)}
var connectionDirectory = ConnectionDirectory{connectionMap: make(map[string]*rpc.Client)}
var circuitDirectory = CircuitDirectory{circuitMap: make(map[string]*CircuitInfo)}
var streamDirectory = StreamDirectory{streamMap: make(map[string]*HttpClientWrapper)}

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	args := os.Args[1:] // store only program arguments in args
	if len(args) != 4 {
		fmt.Println("Usage: go run onion-node.go [server ip:port] [private onion-node ip:port] [public onion-node ip:port] [pemFile]")
		// fmt.Println("Usage: go run onion-node.go [onion-node ip:port] [pemFile]")
		os.Exit(1)
	}

	serverAddr := args[0]
	privateOnionNodeAddr := args[1]
	publicOnionNodeAddr := args[2]
	resolvedPublicAddr, err := net.ResolveTCPAddr("tcp", publicOnionNodeAddr)

	pemFile := args[3]

	// TODO: if we don't want to manually choose the server, we'd use these commented lines
	/* 	onionNodeAddr := args[0]
	   	pemFile := args[1]
	   	serverAddr, err := chooseServer() */

	onionRPC := new(OnionRPC)
	rpc.Register(onionRPC)

	// serverAddr, err := chooseServer()
	// checkCriticalError(err, "main: chooseServer()")

	listener, err := net.Listen("tcp", privateOnionNodeAddr)
	checkCriticalError(err, "main: net.Listen()")

	resolvedServerAddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	serverConnection, err := rpc.Dial("tcp", serverAddr)
	checkCriticalError(err, "main: rpc.Dial()")

	decodedPrivateKey, decodedPublicKey := resource.GetKeyPair(pemFile)

	onionNode = &OnionNode{
		pubKey:           decodedPublicKey,
		privKey:          decodedPrivateKey,
		localAddr:        resolvedPublicAddr,
		serverAddr:       resolvedServerAddr,
		serverConnection: serverConnection}

	registerOnionNode(onionNode)
	go sendServerHeartBeat(*onionNode)
	rpc.Accept(listener)
}

// Listens for responses from child and sends it to the parent
func channelListener(doneCall *rpc.Call) {
	messageCall := <-doneCall.Done
	responseMessage := messageCall.Reply.(*resource.ResponseMessage)
	print.Info(print.ONION_NODE, "channelListener", "received response message from", doneCall.ServiceMethod)

	circuitDirectory.RLock()
	parentCircuitInfo, parentExists := circuitDirectory.circuitMap[responseMessage.CircuitID]
	circuitDirectory.RUnlock()

	if !parentExists {
		fmt.Println("WOW")
		return
	}

	var dataToSend []byte
	err := messageCall.Error

	if err != nil {
		print.Debug(print.ONION_NODE, "channelListener", "child is disconnected", err)
		return
	}

	if responseMessage.IsRelay {
		dataToSend, err = encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, responseMessage.Data, encryption.GenerateIV())
		if err != nil {
			msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
			print.Debug(print.ONION_NODE, "channelListener", msg, err)
		}
	} else {
		relayCell := cells.EncodeRelayCell(cells.EXTENDED, "", "", responseMessage.Data[1:])
		dataToSend, err = encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, relayCell, encryption.GenerateIV())
		if err != nil {
			msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
			print.Debug(print.ONION_NODE, "channelListener", msg, err)
		}
	}

	var output bool
	input := resource.ResponseMessage{
		CircuitID: parentCircuitInfo.circuitID,
		Data:      dataToSend}

	connectionDirectory.RLock()

	nodeConnection, exist := connectionDirectory.connectionMap[parentCircuitInfo.nodeAddress]

	connectionDirectory.RUnlock()

	if exist {
		nodeConnection.Go("OnionRPC.SendResponse", input, &output, nil)
		print.Info(print.ONION_NODE, "channelListener", "response message sent to parent", nil)
	} else {
		msg := fmt.Sprintf("parent node at circuitID [%s] disconnected ,cannot send response further, dropping packet", parentCircuitInfo.circuitID)
		print.Info(print.ONION_NODE, "channelListener", msg, nil)
	}
}

// Registers this onion node to a server, joining the network
func registerOnionNode(onionNode *OnionNode) {
	onionInfo := resource.OnionInfo{Key: *onionNode.pubKey, Address: onionNode.localAddr}
	var output bool
	err := onionNode.serverConnection.Call("ServerRPC.RegisterOnionNode", onionInfo, &output)
	checkCriticalError(err, onionNode.localAddr.String()+" unable to connect to server")
}

// Sends heartbeats to the server
func sendServerHeartBeat(onionNode OnionNode) {
	heartBeatInterval := time.Duration(resource.HeartBeat) / 2
	var output bool
	for {
		err := onionNode.serverConnection.Call("ServerRPC.OnionHeartBeat", *onionNode.pubKey, &output)
		if err != nil {
			fmt.Println(onionNode.localAddr.String() + " unable to send heart beat to server. Trying to connect to another server.")
			connectToAvailableServer()
			return
		}

		time.Sleep(heartBeatInterval * time.Millisecond)
	}
}

// Send heartbeats to onion nodes
func sendOnionNodeHeartBeat(address string) {
	// Setup initial heartbeat mapping
	neighbourHeartBeats.Lock()
	neighbourHeartBeats.HeartBeatMap[address] = time.Now().UnixNano()
	neighbourHeartBeats.Unlock()

	heartBeatInterval := time.Duration(resource.HeartBeat) / 2
	var output bool
	for {

		neighbourHeartBeats.RLock()
		_, ok := neighbourHeartBeats.HeartBeatMap[address]
		neighbourHeartBeats.RUnlock()

		connectionDirectory.RLock()
		nodeConnection, exists := connectionDirectory.connectionMap[address]
		connectionDirectory.RUnlock()

		if ok && exists {
			// If errors occur, it'll be caught when checking for the heartbeat
			fmt.Println("["+time.Now().Format(time.RFC3339Nano)+"]"+"SendOnionNodeHeartBeat: Pinging ...", address)
			err := nodeConnection.Call("OnionRPC.OnionHeartBeat", onionNode.localAddr.String(), &output)
			if err != nil {
				fmt.Println("["+time.Now().Format(time.RFC3339Nano)+"]"+"SendOnionNodeHeartBeat: ERROR pinging ... "+address+": error: ", err)
				fmt.Println("nodeConnection:", *nodeConnection)
				connectionDirectory.Lock()
				delete(connectionDirectory.connectionMap, address)
				connectionDirectory.Unlock()
				break
			}
			time.Sleep(heartBeatInterval * time.Millisecond)
		} else {
			fmt.Println("HEARTBEATMAP IS OK?:", ok)
			fmt.Println("CONNECTIONMAP IS EXIST?:", exists)
			break
		}
	}
}

// Checks that heartbeats from a connected onion node is being received
// Used to determine if neighboring onion node disconnects
func checkOnionHeartBeats(address string) {
	heartBeatInterval := time.Duration(resource.HeartBeat) * time.Millisecond
	time.Sleep(heartBeatInterval)
	for {
		// TODO: UNCOMMENT PRINTS TO SEE HEARTBEATS
		// fmt.Println("Hello Onion Node", address)
		neighbourHeartBeats.RLock()
		oldTimeStamp, exist := neighbourHeartBeats.HeartBeatMap[address]
		neighbourHeartBeats.RUnlock()
		if !exist {
			fmt.Println("checkOnionHeartBeats: unlocked neighbourHeartBeats lock")
			return
		}

		currTimeStamp := time.Now().UnixNano()

		isAddressInUse := false
		circuitDirectory.Lock()
		connectionDirectory.Lock()
		for _, circuitInfo := range circuitDirectory.circuitMap {

			if circuitInfo.nodeAddress == address {
				isAddressInUse = true
				break
			}
		}

		if !isAddressInUse {

			nodeConnection, exist := connectionDirectory.connectionMap[address]

			if exist {
				nodeConnection.Close()
				delete(connectionDirectory.connectionMap, address)
			}
			circuitDirectory.Unlock()
			connectionDirectory.Unlock()
			return

		}

		if currTimeStamp-oldTimeStamp > int64(heartBeatInterval) {

			allDelete(address)
			// TODO: UNCOMMENT PRINTS TO SEE HEARTBEATS
			msg := fmt.Sprintf("[%s] disconnected, goodbye!", address)
			print.Info(print.ONION_NODE, "checkOnionHeartBeats", msg, nil)
			circuitDirectory.Unlock()
			connectionDirectory.Unlock()
			return
		}
		connectionDirectory.Unlock()
		circuitDirectory.Unlock()
		time.Sleep(heartBeatInterval)
	}
}

// OnionHeartBeat ... RPC method to send heartbeats to its parent and child onion node
func (t *OnionRPC) OnionHeartBeat(address string, output *bool) error {
	timeStamp := time.Now().UnixNano()
	neighbourHeartBeats.Lock()
	fmt.Println("[" + time.Now().Format(time.RFC3339Nano) + "]" + address + " ... pinged me")
	neighbourHeartBeats.HeartBeatMap[address] = timeStamp
	neighbourHeartBeats.Unlock()
	return nil
}

func allDelete(myAddress string) {

	for circuitIDKey, circuitInfo := range circuitDirectory.circuitMap {
		if circuitInfo.nodeAddress == myAddress {

			if circuitInfo.isParent {
				fmt.Println("DELETING PARENT")
				childCircuitInfo, childExists := circuitDirectory.circuitMap[circuitInfo.circuitID]

				if childExists {

					// 1: Send SendDestroyRequest to child
					input := resource.RequestMessage{
						Address:       onionNode.localAddr.String(),
						CircuitID:     childCircuitInfo.circuitID,
						IsRelay:       false,
						EncryptedData: []byte(""),
					}
					var output string
					nodeConnection, exist := connectionDirectory.connectionMap[childCircuitInfo.nodeAddress]

					if exist {
						nodeConnection.Go("OnionRPC.SendDestroyRequest", input, &output, nil)
						nodeConnection.Close()
						delete(connectionDirectory.connectionMap, childCircuitInfo.nodeAddress)
					}

					delete(circuitDirectory.circuitMap, circuitInfo.circuitID)
				}

			} else {
				fmt.Println("DELETING CHILD")

				parentCircuitInfo, parentExists := circuitDirectory.circuitMap[circuitInfo.circuitID]

				if parentExists {

					// 1: Encode TRUNCATED relay cell
					relayCell := cells.EncodeRelayCell(cells.TRUNCATED, "", circuitInfo.nodeAddress, []byte(""))
					// 2: Encrypt Relay cell
					encrypted, err := encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, relayCell, encryption.GenerateIV())
					if err != nil {
						msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
						print.Debug(print.ONION_NODE, "onionNodeDisconnectedHelper", msg, err)
					}

					// 3: SendError to parent
					input := resource.ResponseMessage{
						CircuitID: parentCircuitInfo.circuitID,
						IsRelay:   true,
						Data:      encrypted,
					}
					var output bool

					nodeConnection, exist := connectionDirectory.connectionMap[parentCircuitInfo.nodeAddress]
					if exist {
						nodeConnection.Go("OnionRPC.SendError", input, &output, nil)
					}
				}

			}

			nodeConnection, exist := connectionDirectory.connectionMap[myAddress]

			if exist {
				nodeConnection.Close()
				delete(connectionDirectory.connectionMap, myAddress)
			}

			neighbourHeartBeats.Lock()
			delete(neighbourHeartBeats.HeartBeatMap, myAddress)
			neighbourHeartBeats.Unlock()
			delete(circuitDirectory.circuitMap, circuitIDKey)

			for key, _ := range streamDirectory.streamMap {
				if strings.HasPrefix(key, circuitIDKey) {
					closeTCPConnection(key)
				}
			}

		}
	}
}

// SendError ... RPC call to send TRUNCATED error to parent onion node
func (t *OnionRPC) SendError(input resource.ResponseMessage, output *bool) error {
	circuitDirectory.RLock()
	parentCircuitInfo, parentExists := circuitDirectory.circuitMap[input.CircuitID]
	circuitDirectory.RUnlock()

	if parentExists {

		// 1: Encrypt relay packet with my shared key
		encrypted, err := encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, input.Data, encryption.GenerateIV())
		if err != nil {
			msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
			print.Debug(print.ONION_NODE, "SendError", msg, err)
		}

		// 2: Call SendError on parent onion node
		input.CircuitID = parentCircuitInfo.circuitID
		input.Data = encrypted

		connectionDirectory.RLock()
		nodeConnection, exist := connectionDirectory.connectionMap[parentCircuitInfo.nodeAddress]
		if exist {
			nodeConnection.Go("OnionRPC.SendError", input, output, nil)
			print.Info(print.ONION_NODE, "SendError", "Received error from child, error sent to parent", parentCircuitInfo.nodeAddress)
		} else {
			msg := fmt.Sprintf("[%s] does not have a parent onion node, onion node with circuitID [%s] might have disconnected, something might have went wrong", onionNode.localAddr, input.CircuitID)
			print.Debug(print.ONION_NODE, "SendError1", msg, nil)
		}
		connectionDirectory.RUnlock()

	} else {

		msg := fmt.Sprintf("[%s] does not have a parent onion node, onion node with circuitID [%s] might have disconnected, something might have went wrong", onionNode.localAddr, input.CircuitID)
		print.Debug(print.ONION_NODE, "SendError", msg, nil)

	}
	return nil
}

// SendResponse ... RPC call to send responses to parent onion node
func (t *OnionRPC) SendResponse(input resource.ResponseMessage, output *bool) error {
	circuitDirectory.RLock()
	parentCircuitInfo, parentExists := circuitDirectory.circuitMap[input.CircuitID]
	circuitDirectory.RUnlock()

	if parentExists {
		//Encrypt with your shared key
		encryptedData, err := encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, input.Data, encryption.GenerateIV())
		if err != nil {
			msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
			print.Debug(print.ONION_NODE, "SendResponse", msg, err)
			return err
		}

		//Change response message
		input.CircuitID = parentCircuitInfo.circuitID
		input.Data = encryptedData

		//Send to parent

		connectionDirectory.RLock()

		nodeConnection, exist := connectionDirectory.connectionMap[parentCircuitInfo.nodeAddress]
		if exist {
			nodeConnection.Go("OnionRPC.SendResponse", input, output, nil)
		} else {
			msg := fmt.Sprintf("[%s] does not have a parent onion node, onion node with circuitID [%s] might have disconnected, something might have went wrong", onionNode.localAddr, input.CircuitID)
			print.Debug(print.ONION_NODE, "SendResponse1", msg, nil)
		}
		connectionDirectory.RUnlock()
	} else {
		msg := fmt.Sprintf("[%s] does not have a parent onion node, onion node with circuitID [%s] might have disconnected, something might have went wrong", onionNode.localAddr, input.CircuitID)
		print.Debug(print.ONION_NODE, "SendResponse", msg, nil)
	}
	return nil
}

// ReceiveRelayMessage ... RPC method to receive relay message from parent onion node
func (t *OnionRPC) ReceiveRelayMessage(input resource.RequestMessage, output *resource.ResponseMessage) error {
	//Decrypt with your shared key
	circuitDirectory.RLock()
	childCircuitInfo, exist := circuitDirectory.circuitMap[input.CircuitID]
	circuitDirectory.RUnlock()

	// TODO: difference between this and line 441?
	if !exist {
		msg := fmt.Sprintf("my child in the circuit [%s] doesn't exist", input.CircuitID)
		print.Info(print.ONION_NODE, "ReceiveRelayMessage", msg, nil)
		return errorlib.InvalidCircuitStructureError(input.CircuitID)
	}

	decryptedData, err := encryption.AESEncryptCTR(childCircuitInfo.sharedKey, input.EncryptedData, encryption.GenerateIV())
	if err != nil {
		msg := fmt.Sprintf("[%s] is unable to decrypt received message with shared key, this shouldn't happen!", onionNode.localAddr.String())
		print.Debug(print.ONION_NODE, "ReceiveRelayMessage", msg, err)
		return err
	}

	if !cells.IsDigestValid(decryptedData) {
		print.Info(print.ONION_NODE, "ReceiveRelayMessage", "cell digest is invalid, passing packet on to child", nil)
		//Change request message
		input.Address = onionNode.localAddr.String()
		input.CircuitID = childCircuitInfo.circuitID
		input.EncryptedData = decryptedData

		//Send to child

		connectionDirectory.RLock()
		nodeConnection, exists := connectionDirectory.connectionMap[childCircuitInfo.nodeAddress]
		connectionDirectory.RUnlock()

		if exists {
			nodeConnection.Go("OnionRPC.ReceiveRelayMessage", input, output, nil)
		} else {
			fmt.Println("DROPPING RELAY PACKET CHILD NOT THERE")
			return nil
		}

	} else {
		print.Info(print.ONION_NODE, "ReceiveRelayMessage", "cell digest is valid, handling packet as relay cell", nil)
		relayCell := cells.DecodeRelayCell(decryptedData)

		switch relayCell.Command {
		case cells.EXTEND:
			handleExtend(input, output, relayCell)
			break
		case cells.TRUNCATE:
			handleTruncate(input, output, relayCell)
			break
		case cells.BEGIN:
			handleBegin(input, output, relayCell)
			break
		case cells.DATA:
			handleData(input, output, relayCell)
			break
		case cells.END:
			handleEnd(input, output, relayCell)
			break
		default:
			print.Debug(print.ONION_NODE, "ReceiveRelayMessage", "unsupported relay cell command", relayCell.Command)
		}

	}

	return nil
}

// ReceiveCreateRequest ... RPC method to receive circuit create request from parent onion node
func (t *OnionRPC) ReceiveCreateRequest(input resource.RequestMessage, output *resource.ResponseMessage) error {
	msg := fmt.Sprintf("[%s] negotiating key with onion node [%s]", onionNode.localAddr, input.Address)
	print.Info(print.ONION_NODE, "ReceiveCreateRequest", msg, nil)

	parentAddress := input.Address

	fmt.Println("PLZ")
	connectionDirectory.RLock()
	fmt.Println("IM INSIDE")
	_, exists := connectionDirectory.connectionMap[parentAddress]
	fmt.Println("ABOUT TO LEAVE")
	connectionDirectory.RUnlock()

	fmt.Println("WTF", exists)
	if !exists {
		nodeConnection, err := rpc.Dial("tcp", input.Address)
		if err != nil {
			msg := fmt.Sprintf("ReceiveCreateRequest: [%s] is unable to dial to [%s]", onionNode.localAddr.String(), input.Address)
			print.Error(print.ONION_NODE, err, msg)
			return err
		}
		connectionDirectory.Lock()
		connectionDirectory.connectionMap[parentAddress] = nodeConnection
		connectionDirectory.Unlock()
	}

	childCircuitID, err := resource.GenerateUUID()
	if err != nil {
		msg := fmt.Sprintf("[%s] is unable to generate child circuitId", onionNode.localAddr.String())
		print.Debug(print.ONION_NODE, "ReceiveCreateRequest", msg, err)
		return err
	}

	myGroup, myKey, err := encryption.CreateDHKey()
	if err != nil {
		msg := fmt.Sprintf("[%s] is unable to generate its portion of DH key", onionNode.localAddr.String())
		print.Debug(print.ONION_NODE, "ReceiveCreateRequest", msg, err)
		return err
	}

	otherDHKey, err := encryption.RSADecrypt(onionNode.privKey, input.EncryptedData)
	if err != nil {
		msg := fmt.Sprintf("[%s] is unable to decrypt client nodes portion of DH key", onionNode.localAddr.String())
		print.Debug(print.ONION_NODE, "ReceiveCreateRequest", msg, err)
		return err
	}

	sharedKey, err := encryption.ComputeSharedKey(myGroup, otherDHKey, myKey)
	if err != nil {
		msg := fmt.Sprintf("[%s] is unable to generate complete DH key", onionNode.localAddr.String())
		print.Debug(print.ONION_NODE, "ReceiveCreateRequest", msg, err)
		return err
	}

	myHashedKey := encryption.HashSharedKey(sharedKey)

	parentCircuitInfo := &CircuitInfo{
		circuitID:   input.CircuitID,
		nodeAddress: input.Address,
		sharedKey:   sharedKey,
		isParent:    true}

	childCircuitInfo := &CircuitInfo{
		circuitID:   childCircuitID,
		nodeAddress: "",
		sharedKey:   sharedKey,
		isParent:    false}

	fmt.Println("\nParent Info:\n")
	printCircuitInfo(parentCircuitInfo)
	fmt.Println("\nChild Info:\n")
	printCircuitInfo(childCircuitInfo)

	circuitDirectory.Lock()
	if _, ok := circuitDirectory.circuitMap[input.CircuitID]; ok {
		fmt.Println("This shouldn't get here")
		circuitDirectory.Unlock()
		return errorlib.CircuitIDAlreadyExistsError(input.CircuitID)
	}
	if _, ok := circuitDirectory.circuitMap[childCircuitID]; ok {
		fmt.Println("Guess like it did get here")
		circuitDirectory.Unlock()
		return errorlib.CircuitIDAlreadyExistsError(childCircuitID)
	}

	circuitDirectory.circuitMap[input.CircuitID] = childCircuitInfo
	circuitDirectory.circuitMap[childCircuitID] = parentCircuitInfo
	circuitDirectory.Unlock()

	data := make([]byte, 0)
	data = append(data, cells.EncodeControlCmd(cells.CREATED))
	data = append(data, myKey.Bytes()...)
	data = append(data, myHashedKey...)

	responseMessage := resource.ResponseMessage{
		CircuitID: input.CircuitID,
		IsRelay:   false,
		Data:      data}

	print.Info(print.ONION_NODE, "ReceiveCreateRequest", "Onion-node", responseMessage)
	*output = responseMessage

	if !exists {
		go sendOnionNodeHeartBeat(parentAddress)
		go checkOnionHeartBeats(parentAddress)
	}

	return nil
}

// SendDestroyRequest ... RPC method to receive destroy request, destroy request is then propagated to child
func (t *OnionRPC) SendDestroyRequest(input resource.RequestMessage, output *string) error {
	msg := fmt.Sprintf("removing node [%s] from circuit [%s]", onionNode.localAddr.String(), input.CircuitID)
	print.Info(print.ONION_NODE, "SendDestroyRequest", msg, nil)

	circuitDirectory.Lock()
	childCircuitInfo, exist := circuitDirectory.circuitMap[input.CircuitID]

	if exist {
		if childCircuitInfo.nodeAddress != "" {
			var output string
			nextInput := resource.RequestMessage{
				Address:   onionNode.localAddr.String(),
				CircuitID: childCircuitInfo.circuitID}

			connectionDirectory.RLock()
			nodeConnection, exists := connectionDirectory.connectionMap[childCircuitInfo.nodeAddress]
			connectionDirectory.RUnlock()

			if exists {
				nodeConnection.Go("OnionRPC.SendDestroyRequest", nextInput, output, nil)
			}
		}

		for key, _ := range streamDirectory.streamMap {
			if strings.HasPrefix(key, childCircuitInfo.circuitID) {
				closeTCPConnection(key)
			}
		}
	}

	print.Info(print.ONION_NODE, "SendDestroyRequest", "removing circuit (parent)", input.CircuitID)
	delete(circuitDirectory.circuitMap, input.CircuitID)

	if exist {
		print.Info(print.ONION_NODE, "SendDestroyRequest", "removing circuit (child)", childCircuitInfo.circuitID)
		delete(circuitDirectory.circuitMap, childCircuitInfo.circuitID)
	}
	circuitDirectory.Unlock()

	printAllCircuitInfo()
	return nil
}

// Handler for initiating an Extend command to the next relay node
func handleExtend(input resource.RequestMessage, output *resource.ResponseMessage, relayCell cells.RelayCell) error {
	print.Info(print.ONION_NODE, "handleExtend", "Extend Command", nil)

	childAddress := relayCell.Target

	connectionDirectory.RLock()
	_, exists := connectionDirectory.connectionMap[childAddress]
	connectionDirectory.RUnlock()

	fmt.Println("HELLO DALVIR NOI", exists)

	if !exists {
		nodeConnection, err := rpc.Dial("tcp", relayCell.Target)
		if err != nil {
			msg := fmt.Sprintf("handleExtend: [%s] is unable to connect to target child [%s]", onionNode.localAddr.String(), relayCell.Target)
			print.Error(print.ONION_NODE, err, msg)
			return err
		}
		connectionDirectory.Lock()
		connectionDirectory.connectionMap[childAddress] = nodeConnection
		connectionDirectory.Unlock()
	}

	//Update directory
	circuitDirectory.Lock()
	childCircuitInfo, exist := circuitDirectory.circuitMap[input.CircuitID]

	if exist {
		childCircuitInfo.nodeAddress = childAddress
	} else {
		fmt.Println("My child no longer exists")
		return errorlib.InvalidCircuitStructureError(input.CircuitID)
	}
	circuitDirectory.Unlock()

	//Change request message
	input.Address = onionNode.localAddr.String()
	input.CircuitID = childCircuitInfo.circuitID
	input.IsRelay = false
	input.EncryptedData = relayCell.Data

	//Send to child

	connectionDirectory.RLock()
	nodeConnection, stillExist := connectionDirectory.connectionMap[childAddress]
	connectionDirectory.RUnlock()

	if stillExist {
		doneCall := nodeConnection.Go("OnionRPC.ReceiveCreateRequest", input, output, nil)
		print.Info(print.ONION_NODE, "handleExtend", "called target on ReceiveCreateRequest", nil)
		go channelListener(doneCall)

		if !exists {
			fmt.Println("SSSSS")
			go sendOnionNodeHeartBeat(childAddress)
			go checkOnionHeartBeats(childAddress)
		}
	} else {
		fmt.Println("UHOHhhhhhhhh")
	}

	return nil
}

// Handler for the Truncate command, sending a Destroy command to its child node
func handleTruncate(input resource.RequestMessage, output *resource.ResponseMessage, relayCell cells.RelayCell) error {
	print.Info(print.ONION_NODE, "handleTruncate", "Truncate Command", nil)

	// 1. Find child and parent rpc connection by cirID from incoming connection
	circuitDirectory.Lock()
	childCircuitInfo, childExists := circuitDirectory.circuitMap[input.CircuitID]
	circuitDirectory.Unlock()

	// 2. Send Destroy message to child connection

	if childExists {
		input.Address = onionNode.localAddr.String()
		input.CircuitID = childCircuitInfo.circuitID
		input.IsRelay = false
		input.EncryptedData = make([]byte, 16)

		connectionDirectory.RLock()
		nodeConnection, exist := connectionDirectory.connectionMap[childCircuitInfo.nodeAddress]
		if exist {
			nodeConnection.Go("OnionRPC.SendDestroyRequest", input, output, nil)
		}
		connectionDirectory.RUnlock()

		circuitDirectory.Lock()
		childCircuitInfo.nodeAddress = ""
		circuitDirectory.Unlock()
	}

	// 5. Send Truncated command to parent connection
	return sendRelayCellHelper(cells.TRUNCATED, []byte(""), input.CircuitID)
}

// Handler for the Begin command, attempting to initialize a TCP connection with the destination address
func handleBegin(requestMessage resource.RequestMessage, responseMessage *resource.ResponseMessage, relayCell cells.RelayCell) error {
	print.Info(print.ONION_NODE, "handleBegin", "Begin Command", nil)

	streamKey := requestMessage.CircuitID + ":" + relayCell.StreamID

	streamDirectory.Lock()
	if _, ok := streamDirectory.streamMap[streamKey]; ok {
		msg := fmt.Sprintf("Error collision detected for circuitId:streamId: [%s]", streamKey)
		print.Debug(print.ONION_NODE, "handleBegin", msg, nil)
	} else {
		httpClientWrapper, err := createHttpClientWrapper(streamKey, string(relayCell.Data))

		if err != nil {
			streamDirectory.Unlock()
			return sendRelayCellHelper(cells.TEARDOWN, []byte(err.Error()), requestMessage.CircuitID)
		}

		streamDirectory.streamMap[streamKey] = httpClientWrapper
	}
	streamDirectory.Unlock()

	//Send back relay cell
	return sendRelayCellHelper(cells.CONNECTED, []byte("Success"), requestMessage.CircuitID)
}

// Handler for the Data command, attempts to send data from destination addr through an existing stream
func handleData(requestMessage resource.RequestMessage, responseMessage *resource.ResponseMessage, relayCell cells.RelayCell) error {
	print.Info(print.ONION_NODE, "handleData", "Data Command", nil)

	streamKey := requestMessage.CircuitID + ":" + relayCell.StreamID

	streamDirectory.RLock()
	httpClientWrapper, streamExists := streamDirectory.streamMap[streamKey]
	streamDirectory.RUnlock()

	if streamExists {
		httpMethod := string(relayCell.Data)

		req, err := http.NewRequest(httpMethod, httpClientWrapper.webAddress, nil)
		if err != nil {
			msg := fmt.Sprintf("Unable to create request for [%s]", httpClientWrapper.webAddress)
			print.Debug(print.ONION_NODE, "handleData", msg, err)
			return sendRelayCellHelper(cells.TEARDOWN, []byte(err.Error()), requestMessage.CircuitID)
		}

		resp, err := httpClientWrapper.client.Do(req)
		if err != nil {
			msg := fmt.Sprintf("Unable to handle Do for [%s] ", httpClientWrapper.webAddress)
			print.Debug(print.ONION_NODE, "handleData", msg, err)
			return sendRelayCellHelper(cells.TEARDOWN, []byte(err.Error()), requestMessage.CircuitID)
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		packetSize := cells.RelayDataLength - (2 * cells.PacketNumberLength)
		totalPackets := math.Ceil(float64(len(body)) / float64(packetSize))
		counter := 1

		if len(body) == 0 {
			emptyPacket := make([]byte, 0)
			modifiedPacketChunk := cells.EncodeDataResponsePayload(counter, 1, emptyPacket)
			sendRelayCellHelper(cells.RESPONSE, modifiedPacketChunk, requestMessage.CircuitID)
			return nil
			//fmt.Printf("Sending packet [%d] of [%d]", counter, 1)
		}

		for len(body) > 0 {
			// need to change packet size since less than limit
			if len(body) < packetSize {
				packetSize = len(body)
			}

			packetChunk := body[:packetSize]
			body = body[packetSize:]

			//Create the relay cell and send to parent
			modifiedPacketChunk := cells.EncodeDataResponsePayload(counter, int(totalPackets), packetChunk)
			sendRelayCellHelper(cells.RESPONSE, modifiedPacketChunk, requestMessage.CircuitID)
			//	fmt.Printf("Sending packet [%d] of [%d] \n", counter, int(totalPackets))
			counter++
			//if counter%200 == 0 {
			//	fmt.Println("Sleeping so heartbeat doesn't fall behind ...")
			//	time.Sleep(1 * time.Second)
			//}
		}
	} else {
		msg := fmt.Sprintf("Stream entry [%s] does not exist", streamKey)
		print.Debug(print.ONION_NODE, "handleData", msg, nil)
	}

	return nil
}

// Handler for the End command, closes TCP stream
func handleEnd(requestMessage resource.RequestMessage, responseMessage *resource.ResponseMessage, relayCell cells.RelayCell) error {
	print.Info(print.ONION_NODE, "handleEnd", "End Command", nil)
	streamKey := requestMessage.CircuitID + ":" + relayCell.StreamID
	closeTCPConnection(streamKey)
	return nil
}

// Closes TCP Connection
func closeTCPConnection(streamKey string) {
	streamDirectory.Lock()
	if httpClientWrapper, streamExists := streamDirectory.streamMap[streamKey]; streamExists {
		roundTripper := httpClientWrapper.client.Transport
		transport := roundTripper.(*http.Transport)
		transport.CloseIdleConnections()
		delete(streamDirectory.streamMap, streamKey)
	} else {
		msg := fmt.Sprintf("Stream entry [%s] does not exist", streamKey)
		print.Debug(print.ONION_NODE, "closeTCPConnection", msg, nil)
	}
	streamDirectory.Unlock()
}

// Sends relay cell back to this onion node's parent
func sendRelayCellHelper(command cells.OnionCommand, payload []byte, parentCircuitID string) error {

	//Get parentCircuitInfo
	circuitDirectory.RLock()
	childCircuitInfo, childExist := circuitDirectory.circuitMap[parentCircuitID]
	if !childExist {
		// child no longer exists, node has disconnected, simply drop the packet
		fmt.Println("FICLWHY ME")
		circuitDirectory.RUnlock()
		return nil
	}
	parentCircuitInfo, parentExists := circuitDirectory.circuitMap[childCircuitInfo.circuitID]
	circuitDirectory.RUnlock()

	if parentExists {
		relayCell := cells.EncodeRelayCell(command, "", "", payload)
		dataToSend, err := encryption.AESEncryptCTR(parentCircuitInfo.sharedKey, relayCell, encryption.GenerateIV())
		if err != nil {
			msg := fmt.Sprintf("[%s] received error from AESEncryptCTR, this shouldn't happen!", onionNode.localAddr.String())
			print.Debug(print.ONION_NODE, "sendRelayCellHelper", msg, err)
		}

		//Change response message
		var output bool

		responseMessage := resource.ResponseMessage{
			CircuitID: parentCircuitInfo.circuitID,
			IsRelay:   true,
			Data:      dataToSend}

		//Send to parent
		connectionDirectory.RLock()
		nodeConnection, exist := connectionDirectory.connectionMap[parentCircuitInfo.nodeAddress]
		if exist {
			nodeConnection.Go("OnionRPC.SendResponse", responseMessage, &output, nil)
		}
		connectionDirectory.RUnlock()
	}
	return nil
}

// Create an HTTP Client wrapper for streams
func createHttpClientWrapper(streamKey, webAddress string) (*HttpClientWrapper, error) {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true}

	trans := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)

			if err == nil {
				msg := fmt.Sprintf("The stream key [%s] is associated with tcp connection [%s]\n", streamKey, conn.LocalAddr().String())
				print.Info(print.ONION_NODE, "createHttpClientWrapper", msg, nil)
			}
			return conn, err
		},
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second}

	httpClient := &http.Client{
		Transport: trans}

	req, err := http.NewRequest(http.MethodHead, webAddress, nil)
	if err != nil {
		msg := fmt.Sprintf("Unable to create request for [%s]", webAddress)
		print.Debug(print.ONION_NODE, "createHttpClientWrapper", msg, err)
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("Unable to handle Do for [%s] ", webAddress)
		print.Debug(print.ONION_NODE, "createHttpClientWrapper", msg, err)
		return nil, err
	}

	resp.Body.Close()

	return &HttpClientWrapper{httpClient, webAddress}, nil
}

// Randomly chooses an available server to register to
func connectToAvailableServer() {
	err := onionNode.serverConnection.Close()
	if err != nil {
		fmt.Println(err) // TODO: replace this with the proper debugging print
	}

	serverAddress, err := resource.ChooseRandomServer()
	if err != nil {
		fmt.Println(err) // TODO: replace this with the proper debugging print
	}

	serverConnection, err := rpc.Dial("tcp", serverAddress)
	checkCriticalError(err, "connectToAvailableServer: rpc.Dial()")

	onionNode.serverConnection = serverConnection
	resolvedServerAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
	onionNode.serverAddr = resolvedServerAddr

	registerOnionNode(onionNode)
	go sendServerHeartBeat(*onionNode)
}

// Prints all the CircuitInfo that this onion node is aware of
func printAllCircuitInfo() {
	circuitDirectory.RLock()
	for _, circuit := range circuitDirectory.circuitMap {
		printCircuitInfo(circuit)
	}
	circuitDirectory.RUnlock()
}

// Prints CircuitInfo fields to console
func printCircuitInfo(cirInfo *CircuitInfo) {
	fmt.Printf("circuit id: [%s]\n", cirInfo.circuitID)
	fmt.Printf("shared key: [%x]\n", cirInfo.sharedKey)
	fmt.Printf("node      : [%s]\n", cirInfo.nodeAddress)
	fmt.Printf("isParent : [%t]\n", cirInfo.isParent)
}

// Check for critical error - Exit program
func checkCriticalError(err error, msg string) {
	if err != nil {
		fmt.Println()
		fmt.Println("[CRITICAL ERROR][onion-node]: ", msg, err)
		os.Exit(1)
	}
}
