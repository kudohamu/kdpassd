package main

import (
	"bytes"
	"fmt"
	"log"
	"net/smtp"
)

//多要素認証用

type Mail struct {
	From       string
	To         string
	MailServer MailServer //SMTPサーバ
	Gmail      Gmail
}

type MailServer struct {
	Addr string
	Port string
}

type Gmail struct {
	User string
	Pass string
}

func (mail *Mail) sendSMTP(mfaCode string) {
	fmt.Println(config.Mail.MailServer.Addr + ":" + config.Mail.MailServer.Port)
	conn, err := smtp.Dial(mail.MailServer.Addr + ":" + mail.MailServer.Port)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Quit()

	conn.Mail(mail.From)
	conn.Rcpt(mail.To)

	wc, err := conn.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	buf := bytes.NewBufferString("To:" + mail.To)
	buf.WriteString("\r\n")
	buf.WriteString("Subject:kdpassd Multi-Factor Authentication code")
	buf.WriteString("\r\n")
	buf.WriteString("MFA code is...")
	buf.WriteString("\r\n")
	buf.WriteString(mfaCode)
	buf.WriteString("\r\n")
	buf.WriteString("This code expires after 3 minutes.")
	if _, err = buf.WriteTo(wc); err != nil {
		log.Fatal(err)
	}
}

func (mail *Mail) sendGMail(mfaCode string) {
	// Set up authentication information.
	auth := smtp.PlainAuth(
		"",
		mail.Gmail.User,
		mail.Gamil.Pass,
		"smtp.gmail.com",
	)

	err := smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		mail.Gamil.User,
		[]string{mail.To},
		[]byte(mfaCode),
	)
	if err != nil {
		log.Fatal(err)
	}
}
