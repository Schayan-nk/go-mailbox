package mailbox_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Schayan-nk/go-mailbox"
)

// Read the ten newest messages, and look at their attachments only after
// CheckAttachment has.
func Example() {
	cfg := mailbox.Config{
		Protocol: "imap",
		IMAPHost: "imap.example.com",
		Address:  "me@example.com",
		Password: "app-password",
	}
	box, err := mailbox.OpenReader(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer box.Close()

	uids := box.UIDs() // oldest first
	for _, uid := range uids[max(0, len(uids)-10):] {
		m, err := box.Message(uid)
		if err != nil {
			continue
		}
		fmt.Println(m.Date.Format(time.DateOnly), m.Addr, m.Subject)
		for _, a := range m.Attachments {
			s := mailbox.CheckAttachment(a)
			switch {
			case s.Danger:
				fmt.Println("  not opened:", a.Name, s.Why)
			case s.Format == "pdf":
				pdf := mailbox.ReadPDF(context.Background(), a.Data, 4000)
				if pdf.Danger() == "" {
					fmt.Println("  ", a.Name, pdf.Pages, "pages")
				}
			}
		}
	}
}

// Send one plain-text message. Port 465 (the default) is TLS from the first
// byte; any other port must offer STARTTLS.
func ExampleConfig_SendMail() {
	cfg := mailbox.Config{
		SMTPHost: "smtp.example.com",
		Address:  "me@example.com",
		Password: "app-password",
	}
	if err := cfg.SendMail(context.Background(), "you@example.com", "Hello", "One line of plain text."); err != nil {
		log.Fatal(err)
	}
}
