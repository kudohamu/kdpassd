package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

type PassInfo struct {
	label    string
	password []byte
	remark   []byte
}

func connectDB() (db *sql.DB, err error) {
	db, err = sql.Open("postgres", "user="+config.DB.User+" dbname="+config.DB.Name+" password="+config.DB.Pass+" sslmode=disable")
	return
}

func insertPasswdColumn(passInfo PassInfo) (err error) {
	db, err := connectDB()
	if err != nil {
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO passwd_info(label, password, remark) VALUES($1, $2, $3);", passInfo.label, passInfo.password, passInfo.remark)
	return
}

func getPasswsColumn(label string) (passInfo PassInfo, err error) {
	db, err := connectDB()
	if err != nil {
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT * FROM passwd_info WHERE label = $1;", label).Scan(&passInfo.label, &passInfo.password, &passInfo.remark)
	return
}
