package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"./onionlib"
)

var clientNode *onionlib.ClientNode

// hello world, the web server
func OnionSoup(w http.ResponseWriter, req *http.Request) {

	if req.Method == http.MethodGet {
		data, err := clientNode.GetRequest(req.URL.String())

		if err == nil {
			w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
			fmt.Fprint(w, string(data))
		} else {
			body, _ := ioutil.ReadFile("./resource/index.html")
			fmt.Fprint(w, string(body))
		}
	}

}

func main() {

	args := os.Args[1:]
	if len(args) != 3 {
		fmt.Println("Usage: go run proxy-server.go [private proxy ip:port] [public proxy ip:port] [server ip:port]")
		os.Exit(1)
	}

	//s := strings.Split(args[0], ":")
	httpProxyListen := ":8443"
	//   httpsProxyListen := s[0] + ":443"

	var err error
	clientNode, err = onionlib.JoinOnionNetwork(args[0], args[1], args[2], 3, 3, "BE")
	if err != nil {
		fmt.Println("[proxy-server]")
		os.Exit(1)
	}
	http.HandleFunc("/", OnionSoup)
	http.Handle("/resource/", http.StripPrefix("/resource/", http.FileServer(http.Dir("./resource"))))
	log.Fatal(http.ListenAndServe(httpProxyListen, nil))
	//log.Fatal(http.ListenAndServeTLS(httpsProxyListen, "cert.pem", "key.pem", nil))
}
