package main

import (
	"fmt"
)

func delete(label string) {
	if len(label) == 0 {
		fmt.Println("Usage: kdpassd delete [label]")
		return
	}
	_, err := checkAuthPass()
	if err != nil {
		checkError(err, "failed to check the auth password.")
	}
	err = deletePasswdColumn(label)
}
