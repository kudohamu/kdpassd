package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "github.com/lib/pq"
	"io"
)

type PassInfo struct {
	label    string
	password []byte
	remark   []byte
}

func (passInfo *PassInfo) encrypt(key []byte) {
	hash := sha256.New()
	hash.Write(key)
	cipherBlock, _ := aes.NewCipher(hash.Sum(nil))

	cipherPass := make([]byte, len(passInfo.password)+aes.BlockSize)

	iv := cipherPass[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	stream := cipher.NewCTR(cipherBlock, iv)
	stream.XORKeyStream(cipherPass[aes.BlockSize:], passInfo.password)

	cipherRemark := make([]byte, len(passInfo.remark)+aes.BlockSize)

	iv = cipherRemark[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	stream = cipher.NewCTR(cipherBlock, iv)
	stream.XORKeyStream(cipherRemark[aes.BlockSize:], passInfo.remark)

	passInfo.password = cipherPass
	passInfo.remark = cipherRemark

	return
}

func (passInfo *PassInfo) decrypt(key []byte) {
	hash := sha256.New()
	hash.Write(key)
	cipherBlock, _ := aes.NewCipher(hash.Sum(nil))

	plainPass := make([]byte, len(passInfo.password)-aes.BlockSize)

	stream := cipher.NewCTR(cipherBlock, passInfo.password[:aes.BlockSize])
	stream.XORKeyStream(plainPass, passInfo.password[aes.BlockSize:])

	plainRemark := make([]byte, len(passInfo.remark)-aes.BlockSize)

	stream = cipher.NewCTR(cipherBlock, passInfo.remark[:aes.BlockSize])
	stream.XORKeyStream(plainRemark, passInfo.remark[aes.BlockSize:])

	passInfo.password = plainPass
	passInfo.remark = plainRemark

	return
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

func getPasswdColumn(label string) (passInfo PassInfo, err error) {
	db, err := connectDB()
	if err != nil {
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT * FROM passwd_info WHERE label = $1;", label).Scan(&passInfo.label, &passInfo.password, &passInfo.remark)
	return
}

func getLabels() (labels []string, err error) {
	db, err := connectDB()
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT label FROM passwd_info;")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var label string
		if err = rows.Scan(&label); err != nil {
			return
		}
		labels = append(labels, label)
	}

	return
}
