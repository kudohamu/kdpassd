package main

import (
	"net"
	"strings"
)

func list(conn net.Conn) {
	_, err := checkAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	labels, err := getLabels()
	checkError(err, "failed to get labels list.")

	conn.Write([]byte(strings.Join(labels, "\n")))
	conn.Close()
}
