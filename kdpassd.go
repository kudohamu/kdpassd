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

func handleClient(conn net.Conn) {
	msg := make([]byte, 1024)
	msgLen, err := conn.Read(msg)
	checkError(err, "failed to read message")
	fmt.Println(string(msg[:msgLen]))
}

func main() {
	confFile, err := os.Open("kdpassd.conf")
	checkError(err, "failed reading config file.")
	defer confFile.Close()
	decorder := json.NewDecoder(confFile)
	var config kdpassdConf
	err = decorder.Decode(&config)
	checkError(err, "failed decoding config file.")

	cert, err := tls.LoadX509KeyPair(config.CrtUrl, config.KeyUrl)
	checkError(err, "could not load certification files.")
	tlsConf := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":"+config.Port, &tlsConf)
	checkError(err, "could not listen.")

	for {
		conn, err := listener.Accept()
		checkError(err, "failed accept connection.")
		defer conn.Close()

		fmt.Println("accept!")
		go handleClient(conn)
	}
}
