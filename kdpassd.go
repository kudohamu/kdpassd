package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"github.com/codegangsta/cli"
	"crypto/cipher"
	"io"
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

func encrypter(plainText, key []byte) (cipherText []byte) {
	hash := sha256.New()
	hash.Write(key)
	cipherBlock, _ := aes.NewCipher(hash.Sum(nil))

	cipherText = make([]byte, len(plainText)+aes.BlockSize)

	iv := cipherText[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	stream := cipher.NewCTR(cipherBlock, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return
}

func decrypter(cipherText, key []byte) (plainText []byte) {
	hash := sha256.New()
	hash.Write(key)
	cipherBlock, _ := aes.NewCipher(hash.Sum(nil))

	plainText = make([]byte, len(plainText)+aes.BlockSize)

	stream := cipher.NewCTR(cipherBlock, cipherText[:aes.BlockSize])
	stream.XORKeyStream(plainText, cipherText[aes.BlockSize:])

	return
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %s, %s\n", msg, err)
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

func sendPasswd(conn net.Conn) {
	authPass, err := checkAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	label := make([]byte, 1023)
	labelLen, err := conn.Read(label)
	checkError(err, "failed to read label.")

	passInfo, err := getPasswsColumn(string(label[:labelLen]))
	checkError(err, "failed to get password.")
	conn.Write(decrypter(passInfo.password, authPass))
	conn.Write(decrypter(passInfo.remark, authPass))
}

func registPasswd(conn net.Conn) {
	authPass, err := checkAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	var column PassInfo
	label := make([]byte, 255)
	labelLen, err := conn.Read(label)
	checkError(err, "failed to read label.")
	column.label = string(label[:labelLen])

	passwd := make([]byte, 255)
	passLen, err := conn.Read(passwd)
	checkError(err, "failed to read password.")
	column.password = encrypter(passwd[:passLen], authPass)

	remark := make([]byte, 1023)
	remarkLen, err := conn.Read(remark)
	checkError(err, "failed to read password.")
	column.remark = encrypter(remark[:remarkLen], authPass)

	err = insertPasswdColumn(column)
	checkError(err, "failed to insert password into database.")
}

func handleClient(conn net.Conn) {
	act := make([]byte, 1)
	actLen, err := conn.Read(act)
	checkError(err, "failed to read action.")
	actNum, _ := strconv.Atoi(string(act[:actLen]))
	switch actNum {
	case SHOW:
		sendPasswd(conn)
	case ADD:
		registPasswd(conn)
	}
}

func main() {
	config, _ = readConf("kdpassd.conf")
	//checkError(err, "failed to read config file.")

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
