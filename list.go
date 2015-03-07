package main

import (
	"net"
	"strings"
)

func list(conn net.Conn) {
	_, err := askAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	if checkMFA(conn) {
		labels, err := getLabels()
		checkError(err, "failed to get labels list.")

		conn.Write([]byte(strings.Join(labels, "\n")))
		conn.Close()
	}
}
