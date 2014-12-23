package main

import (
	"encoding/json"
	"fmt"
	//"github.com/codegangsta/cli"
	"crypto/tls"
	"net"
	"os"
)

type kdpassdConf struct {
	Port   string
	CrtUrl string
	KeyUrl string
}

func getPassword(label string) (string, error) {
	return "hoge", nil
}

func getLabelList() ([]string, error) {
	return []string{"huga", "hage"}, nil
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: "+msg+"\n")
		os.Exit(1)
	}
}

func readConf(url string) (config kdpassdConf, err error) {
	confFile, err := os.Open(url)
	if err != nil {
		return
	}
	defer confFile.Close()
	decorder := json.NewDecoder(confFile)
	err = decorder.Decode(&config)
	return
}

func createTLSListener(config kdpassdConf) (listener net.Listener, err error) {
	cert, err := tls.LoadX509KeyPair(config.CrtUrl, config.KeyUrl)
	if err != nil {
		return
	}
	tlsConf := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err = tls.Listen("tcp", ":"+config.Port, &tlsConf)
	return
}

func handleClient(conn net.Conn) {
	msg := make([]byte, 1024)
	msgLen, err := conn.Read(msg)
	checkError(err, "failed to read message")
	fmt.Println(string(msg[:msgLen]))
}

func main() {

	config, err := readConf("kdpassd.conf")
	checkError(err, "failed to read config file.")

	listener, err := createTLSListener(config)
	checkError(err, "could not create TLSListener.")

	for {
		conn, err := listener.Accept()
		checkError(err, "failed accept connection.")
		defer conn.Close()

		fmt.Println("accept!")
		go handleClient(conn)
	}
}
