package main

import (
	"encoding/json"
	"fmt"
	//"github.com/codegangsta/cli"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net"
	"os"
	"strconv"
)

type kdpassdConf struct {
	Port     string
	CrtUrl   string
	KeyUrl   string
	AuthPass string
}

func getPassword(label string) (string, error) {
	return "hoge", nil
}

const (
	SHOW = iota
)

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

func handleClient(conn net.Conn, config kdpassdConf) {
	act := make([]byte, 1)
	actLen, err := conn.Read(act)
	checkError(err, "failed to read action.")
	actNum, _ := strconv.Atoi(string(act[:actLen]))
	switch actNum {
	case SHOW:
		passwd := make([]byte, 256)
		passLen, err := conn.Read(passwd)
		checkError(err, "failed to read password.")
		hash := sha256.New()
		hash.Write(passwd[:passLen])
		hashPass := base64.URLEncoding.EncodeToString(hash.Sum(nil))
		if hashPass != config.AuthPass {
			conn.Write([]byte("failed"))
			return
		}
		conn.Write([]byte("success"))
		label := make([]byte, 1024)
		labelLen, err := conn.Read(label)
		checkError(err, "failed to read label.")
		fmt.Println(string(label[:labelLen]))
	}
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
		go handleClient(conn, config)
	}
}
