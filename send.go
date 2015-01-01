package main

import (
	"net"
)

func send(conn net.Conn) {
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
