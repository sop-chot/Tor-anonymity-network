package main

import (
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"net"
	"os"
//	"time"

	"./onionlib"
)

var (
	minNodes = 3
	numRetry = 3
)

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	args := os.Args[1:]
	if len(args) > 4 || len(args) < 3 {
		fmt.Println("Usage: go run client-app.go [private-address ip:port] [client-node ip:port] [server ip:port] [optional topology flag]")
		os.Exit(1)
	}

	privateAddr := args[0]
	clientAddr := args[1]
	serverAddr := args[2]

	var topology string
	if len(args[3:]) > 0 {
		topology = args[3]
	} else {
		topology = ""
	}

	cn, err := onionlib.JoinOnionNetwork(privateAddr, clientAddr, serverAddr, minNodes, numRetry, topology)
	checkError(err, "Joining onion network:")

	//_, err = cn.GetRequest("https://www.google.com")
	//data, err := cn.GetRequest("https://www.google.com")
	_, err = cn.GetRequest("https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports")
	checkError(err, "GetRequest")
	//fmt.Println("Client-app: Received response: ", string(data))

	data2, err := cn.GetRequest("https://www.google.com")
	// data2, err := cn.GetRequest("https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports")
	checkError(err, "GetRequest")
	fmt.Println("Client-app: Received response: ", string(data2))


	cn.UnlinkFromNetwork()
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Println("[client-app] ERROR", msg, err)
		os.Exit(1)
	}
}
