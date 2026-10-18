package mailbox

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Sending from the mailbox: SendMail for plain text, SendHTML for HTML with
// its plain-text reading. Both are for machine-sent mail -- sign-in codes,
// reports -- and say so (Auto-Submitted: auto-generated).
//
// ENCRYPTED OR NOT AT ALL. Port 465 is TLS from the first byte; any
// other port must offer STARTTLS, and a server that does not is refused
// rather than handed the mailbox password in the clear.
//
// Signed in as the mailbox itself and sent From it: a mail server that sees a
// message from an address its account does not own rejects it or marks it as
// spoofed, and a message in the spam folder is a message nobody reads.

// ErrCannotSend means outbound mail is not configured.
var ErrCannotSend = errors.New("mailbox: sending is not configured (Config.SMTPHost)")

// SendMail sends one plain-text message to one recipient.
func (c Config) SendMail(ctx context.Context, to, subject, body string) error {
	if !c.CanSend() {
		return ErrCannotSend
	}
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(c.smtpPort()))
	return sendMail(ctx, addr, c.smtpPort() == 465, c.Address, c.Password, to, subject, body)
}

// sendMail sends a plain-text body.
func sendMail(ctx context.Context, addr string, implicitTLS bool, from, password, to, subject, body string) error {
	return sendMessage(ctx, addr, implicitTLS, from, password, to, subject,
		func(from, to string) []byte { return message(from, to, subject, body) })
}

// SendHTML sends one message with an HTML body and its plain-text reading,
// for a mail client that shows no HTML.
func (c Config) SendHTML(ctx context.Context, to, subject, text, html string) error {
	if !c.CanSend() {
		return ErrCannotSend
	}
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(c.smtpPort()))
	return sendMessage(ctx, addr, c.smtpPort() == 465, c.Address, c.Password, to, subject,
		func(from, to string) []byte { return htmlMessage(from, to, subject, text, html) })
}

// sendMessage signs in and delivers what build writes for one recipient.
func sendMessage(ctx context.Context, addr string, implicitTLS bool, from, password, to, subject string,
	build func(from, to string) []byte) error {
	// Nothing that reaches a header may carry a line break: that is how a
	// second recipient or a second header is smuggled in.
	for _, v := range []string{from, to, subject} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("mail: a line break in a header")
		}
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("mail: %q is not an address", to)
	}
	return deliver(ctx, addr, implicitTLS, from, password, []string{rcpt.Address}, build(from, rcpt.Address))
}

// deliver signs in and hands one message to the server for every recipient
// -- the To and the Cc of a reply are one message, not two.
func deliver(ctx context.Context, addr string, implicitTLS bool, from, password string,
	rcpts []string, data []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}
	var conn net.Conn
	if implicitTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfigFor(host)}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("mail: connecting to %s: %w", addr, err)
	}
	conn.SetDeadline(deadline)
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mail: %s: %w", addr, err)
	}
	defer cl.Close()
	if err := cl.Hello("localhost"); err != nil {
		return err
	}
	if !implicitTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fmt.Errorf("mail: %s offers no encryption; refusing to send the password in the clear", addr)
		}
		if err := cl.StartTLS(tlsConfigFor(host)); err != nil {
			return fmt.Errorf("mail: STARTTLS with %s: %w", addr, err)
		}
	}
	if err := cl.Auth(smtp.PlainAuth("", from, password, host)); err != nil {
		return fmt.Errorf("mail: signing in to %s: %w", addr, err)
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	for _, r := range rcpts {
		if err := cl.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// message builds the RFC 5322 text: UTF-8 throughout, the subject encoded,
// the body in base64 so Persian survives every relay.
func message(from, to, subject, body string) []byte {
	var b strings.Builder
	headers(&b, from, to, subject)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b64(&b, body)
	return []byte(b.String())
}

// htmlMessage is the same with two readings of one body: plain text first and
// HTML second, so a client that can show the HTML shows it and one that
// cannot still has every figure.
func htmlMessage(from, to, subject, text, html string) []byte {
	var b strings.Builder
	headers(&b, from, to, subject)
	bound := make([]byte, 12)
	rand.Read(bound)
	boundary := "mailbox-" + hex.EncodeToString(bound)
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", text}, {"text/html", html}} {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + part.typ + "; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b64(&b, part.body)
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func headers(b *strings.Builder, from, to, subject string) {
	id := make([]byte, 12)
	rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", to)
	h("Subject", mime.BEncoding.Encode("UTF-8", subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	// Machine-sent: an out-of-office reply to it helps nobody.
	h("Auto-Submitted", "auto-generated")
}

func b64(b *strings.Builder, body string) {
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
}
