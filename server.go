/**

$ go run server.go

*/

package main

import (
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
	"time"

	"./resource"
	"./resource/encryption"
)

type Server struct {
	//Connections []OnionInfo
	onionLock sync.RWMutex
	onionMap  map[string]resource.OnionInfo // key: PubKeyString => OnionInfo
}

type ServerInfo struct {
	Addr net.Addr
}

type OnionDirectory struct {
	sync.RWMutex
	onionMap map[string]resource.OnionInfo
}

type ServerNeighbours struct {
	sync.RWMutex
	neighbourMap map[string]*rpc.Client
}

type FloodInfo struct {
	VisitedServers []string
	OnionInfo      resource.OnionInfo
}

type ServerInterface interface {
	// Onion Node - Server
	RegisterOnionNode(onionInfo resource.OnionInfo, output *bool) error
	HeartBeat(pubKey rsa.PublicKey, output *bool) error

	// Client Node - Server
	GetNodes(notUsed string, directory *OnionDirectory) error

	// Server - Server
	RegisterServer(address string, directory *map[string]resource.OnionInfo) error
	FloodOnionInfo(onionInfo resource.OnionInfo, output *bool) error
}

type ServerRPC struct{}

// TODO: these might need to be put into a local struct
// Any other file in the main package can access these
var onionDirectory = OnionDirectory{onionMap: make(map[string]resource.OnionInfo)}
var onionHeartBeats = resource.HeartBeats{HeartBeatMap: make(map[string]int64)}
var serverNeighbours = ServerNeighbours{neighbourMap: make(map[string]*rpc.Client)}
var serverHeartBeats = resource.HeartBeats{HeartBeatMap: make(map[string]int64)}
var localAddress string

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})
	gob.Register(&sync.RWMutex{})

	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Println("Usage: go run server.go [private TCP ip:port] [public TCP ip:port] [optional serveraddresses]")
	}

	privateLocalAddress := args[0]
	publicLocalAddress := args[1]
	localAddress = publicLocalAddress // Set the global variable

	fmt.Println("My address is:", publicLocalAddress)

	neighbouringServers := os.Args[3:] // Every other server addresses passed as arguments
	if len(neighbouringServers) > 0 {
		connectToServers(neighbouringServers)
	}

	serverRPC := new(ServerRPC)
	rpc.Register(serverRPC)

	listener, err := net.Listen("tcp", privateLocalAddress)
	checkError(err, "net.Listen")

	rpc.Accept(listener)
}

/* ========================== RPC Methods ========================== */

// RegisterServer - RPC method for other servers to connect to this server
func (s *ServerRPC) RegisterServer(address string, directory *map[string]resource.OnionInfo) (err error) {
	onionDirectory.RLock()
	// Return the onion directory map to the caller
	*directory = onionDirectory.onionMap
	onionDirectory.RUnlock()

	serverConnection, err := rpc.Dial("tcp", address)
	if err != nil {
		fmt.Println(err)
		return
	}

	serverNeighbours.Lock()
	serverNeighbours.neighbourMap[address] = serverConnection
	serverNeighbours.Unlock()

	// Initiate 2 way heartbeat
	go sendServerNeighbourHeartBeat(serverConnection, address)
	go checkServerHeartBeat(address)
	return err
}

// GetNodes - RPC method for the OnionLib to get a list of available onion nodes in the network
// REturns a slice of OnionInfo structs
func (s *ServerRPC) GetNodes(notUsed *string, onionInfoList *[]resource.OnionInfo) error {
	onionDirectory.RLock()
	for _, onionInfo := range onionDirectory.onionMap {
		// Return the info of every onion node that is connected
		*onionInfoList = append(*onionInfoList, onionInfo)
	}
	onionDirectory.RUnlock()

	return nil
}

// RegisterOnionNode - RPC method for onion nodes to connect to this server
func (s *ServerRPC) RegisterOnionNode(onionInfo resource.OnionInfo, output *bool) error {
	pubKey, err := encryption.RSAKeyToString(onionInfo.Key)
	checkError(err, "Encoding public key to string")

	onionDirectory.Lock()
	// TODO: onionInfo gets passed in, might need to make a local copy
	onionDirectory.onionMap[pubKey] = onionInfo
	onionDirectory.Unlock()

	floodOnionInfo(onionInfo)

	// Set heart beat
	timeStamp := time.Now().UnixNano()
	onionHeartBeats.Lock()
	onionHeartBeats.HeartBeatMap[pubKey] = timeStamp
	onionHeartBeats.Unlock()

	go checkOnionHeartBeats(pubKey, onionInfo.Address)
	return nil
}

// OnionHeartBeat - RPC method for onion nodes to send heartbeats
// The server will receive the heartbeats
func (s *ServerRPC) OnionHeartBeat(publicKey rsa.PublicKey, output *bool) error {
	pubKey, err := encryption.RSAKeyToString(publicKey)
	checkError(err, "Encoding public key to string")

	timeStamp := time.Now().UnixNano()
	onionHeartBeats.Lock()
	onionHeartBeats.HeartBeatMap[pubKey] = timeStamp
	onionHeartBeats.Unlock()
	return nil
}

// ServerHeartBeat - RPC method for servers to send heartbeats
// The server will receive the heartbeats
func (s *ServerRPC) ServerHeartBeat(address string, output *bool) error {
	timeStamp := time.Now().UnixNano()
	serverHeartBeats.Lock()
	serverHeartBeats.HeartBeatMap[address] = timeStamp
	serverHeartBeats.Unlock()

	return nil
}

// FloodOnionInfo - Flooding protocol: don't send to servers that are already in the visitedServers list
func (s *ServerRPC) FloodOnionInfo(floodInfo FloodInfo, output *bool) error {
	visitedServers := floodInfo.VisitedServers
	onionInfo := floodInfo.OnionInfo

	fmt.Println("Received", onionInfo)
	err := saveOnionInfo(onionInfo)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Else add itself to the visited list and flood to its neighbours
	visitedServers = append(visitedServers, localAddress)
	floodInfo.VisitedServers = visitedServers

	serverNeighbours.RLock()
	for serverAddr, serverConnection := range serverNeighbours.neighbourMap {
		if hasVisited(visitedServers, serverAddr) {
			// This server instance has already flooded this onion info already
			continue
		}
		err := serverConnection.Call("ServerRPC.FloodOnionInfo", floodInfo, &output)
		if err != nil {
			// Don't terminate
			fmt.Println(err)
		}
	}

	serverNeighbours.RUnlock()

	return nil
}

// FloodDisconnectedOnionInfo - Flooding protocol to flood connected servers
// with info on available/connected onion nodes
func (s *ServerRPC) FloodDisconnectedOnionInfo(floodInfo FloodInfo, output *bool) error {
	visitedServers := floodInfo.VisitedServers
	onionInfo := floodInfo.OnionInfo
	pubKey, err := encryption.RSAKeyToString(onionInfo.Key)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("Received", onionInfo)

	// Can receive a flooded message that a node is disconnected
	// Verify by checking its own heartbeat map
	onionHeartBeats.RLock()
	_, exist := onionHeartBeats.HeartBeatMap[pubKey]
	onionHeartBeats.RUnlock()

	if exist {
		// Onion node is connected to this server, don't flood this
		return nil
	}

	// Else remove the entry from its directory and flood the info to other servers
	onionDirectory.Lock()
	delete(onionDirectory.onionMap, pubKey)
	onionDirectory.Unlock()

	// Add itself to the visited list and flood to its neighbours
	visitedServers = append(visitedServers, localAddress)
	floodInfo.VisitedServers = visitedServers

	serverNeighbours.RLock()
	for serverAddr, serverConnection := range serverNeighbours.neighbourMap {
		if hasVisited(visitedServers, serverAddr) {
			// This server instance has already flooded this onion info already
			continue
		}
		err := serverConnection.Call("ServerRPC.FloodDisconnectedOnionInfo", floodInfo, &output)
		if err != nil {
			// Don't terminate
			fmt.Println(err)
		}
	}

	serverNeighbours.RUnlock()

	return nil
}

/* ========================== Helper Methods ========================== */

// Connects to specified servers, establishing bidirectional heartbeats
func connectToServers(neighbouringServerAddrs []string) (err error) {
	for _, serverAddr := range neighbouringServerAddrs {
		serverConnection, err := rpc.Dial("tcp", serverAddr)
		checkError(err, "connectToServers: rpc.Dial:")

		// TODO: check that having 3 go routines is fine
		go registerToServer(serverConnection, serverAddr)
		go sendServerNeighbourHeartBeat(serverConnection, serverAddr)
		go checkServerHeartBeat(serverAddr)
	}

	return err
}

// Establish a connection and register with a server
func registerToServer(serverConnection *rpc.Client, serverAddr string) (err error) {
	//var directory OnionDirectory
	var directory map[string]resource.OnionInfo
	err = serverConnection.Call("ServerRPC.RegisterServer", localAddress, &directory)
	checkError(err, "RegisterToServer: serverConnection.Call")

	serverNeighbours.Lock()
	serverNeighbours.neighbourMap[serverAddr] = serverConnection
	serverNeighbours.Unlock()

	// Initiate the heartbeat
	timeStamp := time.Now().UnixNano()
	serverHeartBeats.Lock()
	serverHeartBeats.HeartBeatMap[serverAddr] = timeStamp
	serverHeartBeats.Unlock()

	return err
}

// Send heartbeats to other servers
func sendServerNeighbourHeartBeat(serverConnection *rpc.Client, serverAddr string) {
	heartBeatInterval := time.Duration(resource.HeartBeat) / 2
	var output bool
	for {
		err := serverConnection.Call("ServerRPC.ServerHeartBeat", localAddress, &output)
		//checkError(err, "startHeartBeat: RPC call to RServer.HeartBeat")
		if err != nil {
			// Don't terminate
			fmt.Println(err)
			serverHeartBeats.Lock()
			delete(serverHeartBeats.HeartBeatMap, serverAddr)
			serverHeartBeats.Unlock()
			serverNeighbours.Lock()
			delete(serverNeighbours.neighbourMap, serverAddr)
			serverNeighbours.Unlock()
			fmt.Println("Goodbye Server", serverAddr)
			return
		}
		time.Sleep(heartBeatInterval * time.Millisecond)
	}
}

// Check heart beats for a given onion node
func checkOnionHeartBeats(onionPubKey string, address net.Addr) {
	heartBeatInterval := time.Duration(resource.HeartBeat) * time.Millisecond
	time.Sleep(heartBeatInterval)
	for {
		fmt.Println("Hello Onion Node", address.String())
		onionHeartBeats.Lock()
		oldTimeStamp := onionHeartBeats.HeartBeatMap[onionPubKey]
		currTimeStamp := time.Now().UnixNano()

		if currTimeStamp-oldTimeStamp > int64(heartBeatInterval) {
			fmt.Println("Goodbye ", address.String())
			delete(onionHeartBeats.HeartBeatMap, onionPubKey)
			onionDirectory.Lock()
			onionInfo := onionDirectory.onionMap[onionPubKey]
			delete(onionDirectory.onionMap, onionPubKey)
			onionDirectory.Unlock()
			onionHeartBeats.Unlock()

			floodDisconnectedOnionInfo(onionInfo)
			return
		}

		onionHeartBeats.Unlock()
		time.Sleep(heartBeatInterval)
	}
}

// Check heart beats for a given server
func checkServerHeartBeat(address string) {
	heartBeatInterval := time.Duration(resource.HeartBeat) * time.Millisecond
	time.Sleep(heartBeatInterval)
	for {
		fmt.Println("Hello Server", address)
		serverHeartBeats.Lock()
		oldTimeStamp := serverHeartBeats.HeartBeatMap[address]
		currTimeStamp := time.Now().UnixNano()
		// time since last heart beat is greater than 2 seconds
		// remove it from the list of connections
		// Remove from heartbeat map but flag it as disconnected
		if currTimeStamp-oldTimeStamp > int64(heartBeatInterval) {
			fmt.Println("Goodbye Server", address)
			delete(serverHeartBeats.HeartBeatMap, address)
			serverNeighbours.Lock()
			delete(serverNeighbours.neighbourMap, address)
			serverNeighbours.Unlock()
			serverHeartBeats.Unlock()
			return
		}

		serverHeartBeats.Unlock()
		time.Sleep(heartBeatInterval)
	}
}

// When an onion node connets to the server, it floods this info to its neighbors
func floodOnionInfo(onionInfo resource.OnionInfo) {
	var visitedServers []string
	visitedServers = append(visitedServers, localAddress)

	floodInfo := FloodInfo{VisitedServers: visitedServers, OnionInfo: onionInfo}

	var output bool
	serverNeighbours.RLock()

	for _, serverConnection := range serverNeighbours.neighbourMap {
		err := serverConnection.Call("ServerRPC.FloodOnionInfo", floodInfo, &output)
		if err != nil {
			// Don't terminate
			fmt.Println(err)
		}
	}
	serverNeighbours.RUnlock()
}

// Flood information about onion nodes that have failed to neighbouring servers
func floodDisconnectedOnionInfo(onionInfo resource.OnionInfo) {
	var visitedServers []string
	visitedServers = append(visitedServers, localAddress)

	floodInfo := FloodInfo{VisitedServers: visitedServers, OnionInfo: onionInfo}

	var output bool
	serverNeighbours.RLock()

	for _, serverConnection := range serverNeighbours.neighbourMap {
		err := serverConnection.Call("ServerRPC.FloodDisconnectedOnionInfo", floodInfo, &output)
		if err != nil {
			// Don't terminate
			fmt.Println(err)
		}
	}
	serverNeighbours.RUnlock()
}

// Save the flooded onion info into directory
func saveOnionInfo(onionInfo resource.OnionInfo) error {
	pubKey, err := encryption.RSAKeyToString(onionInfo.Key)
	if err != nil {
		fmt.Println(err)
		return err
	}
	onionDirectory.Lock()
	onionDirectory.onionMap[pubKey] = onionInfo
	onionDirectory.Unlock()

	return nil
}

// Helper for flooding protocol
// Check to see if information has already been sent to a given address
// Used to ensure no cycles during flooding protocol
func hasVisited(visitedServers []string, serverToVisit string) bool {
	for _, serverAddr := range visitedServers {
		if serverAddr == serverToVisit {
			return true
		}
	}

	return false
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[server] ERROR", msg, err)
		os.Exit(1)
	}
}
