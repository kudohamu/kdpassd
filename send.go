package main

import (
	"net"
)

func send(conn net.Conn) {
	authPass, err := askAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	label := make([]byte, 1023)
	labelLen, err := conn.Read(label)
	checkError(err, "failed to read label.")

	column, err := getPasswdColumn(string(label[:labelLen]))
	checkError(err, "failed to get password.")

	column.decrypt(authPass)

	conn.Write(column.password)
	conn.Write(column.remark)
}
