package main

import (
	"net"
)

func regist(conn net.Conn) {
	authPass, err := askAuthPass(conn)
	checkError(err, "failed to check a authorized password.")

	var column PassInfo
	label := make([]byte, 255)
	labelLen, err := conn.Read(label)
	checkError(err, "failed to read label.")
	column.label = string(label[:labelLen])

	passwd := make([]byte, 255)
	passLen, err := conn.Read(passwd)
	checkError(err, "failed to read password.")
	column.password = passwd[:passLen]

	remark := make([]byte, 1023)
	remarkLen, err := conn.Read(remark)
	checkError(err, "failed to read password.")
	column.remark = remark[:remarkLen]

	column.encrypt(authPass)

	err = insertPasswdColumn(column)
	checkError(err, "failed to insert password into database.")
}
