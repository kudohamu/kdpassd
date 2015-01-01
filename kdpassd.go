package main

import (
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"github.com/codegangsta/cli"
	"net"
	"os"
	"strconv"
)

type DB struct {
	User string
	Pass string
	Name string
}

type kdpassdConf struct {
	Port     int
	CrtUrl   string
	KeyUrl   string
	AuthPass string
	DB       DB
}

var config kdpassdConf

func getPassword(label string) (string, error) {
	return "hoge", nil
}

const (
	SHOW = iota
	ADD
)

func getLabelList() ([]string, error) {
	return []string{"huga", "hage"}, nil
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %s, %s\n", msg, err)
		os.Exit(1)
	}
}

func readConf(url string) (err error) {
	confFile, err := os.Open(url)
	if err != nil {
		return
	}
	defer confFile.Close()
	decorder := json.NewDecoder(confFile)
	err = decorder.Decode(&config)
	return
}

func createTLSListener() (listener net.Listener, err error) {
	cert, err := tls.LoadX509KeyPair(config.CrtUrl, config.KeyUrl)
	if err != nil {
		return
	}
	tlsConf := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err = tls.Listen("tcp", ":"+strconv.Itoa(config.Port), &tlsConf)
	return
}

func checkAuthPass(conn net.Conn) (AuthPass []byte, err error) {
	passwd := make([]byte, 255)
	passLen, err := conn.Read(passwd)
	if err != nil {
		return
	}
	hash := sha512.New()
	hash.Write(passwd[:passLen])

	if base64.URLEncoding.EncodeToString(hash.Sum(nil)) != config.AuthPass {
		conn.Write([]byte("failed"))
		return
	}
	conn.Write([]byte("success"))

	return passwd[:passLen], err
}

func handleClient(conn net.Conn) {
	act := make([]byte, 1)
	actLen, err := conn.Read(act)
	checkError(err, "failed to read action.")
	actNum, _ := strconv.Atoi(string(act[:actLen]))
	switch actNum {
	case SHOW:
		send(conn)
	case ADD:
		regist(conn)
	}
}

func main() {
	err := readConf("kdpassd.conf")
	checkError(err, "failed to read config file.")

	listener, err := createTLSListener()
	checkError(err, "could not create TLSListener.")

	fmt.Printf("run kdpassd. %d port listen.", config.Port)

	for {
		conn, err := listener.Accept()
		checkError(err, "failed accept connection.")
		defer conn.Close()

		fmt.Println("accept!")
		go handleClient(conn)
	}
}
