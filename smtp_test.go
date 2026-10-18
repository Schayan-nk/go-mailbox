package mailbox

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is just enough of a mail server: EHLO, AUTH PLAIN, MAIL, RCPT,
// DATA, QUIT -- over TLS from the first byte, as port 465 is.
type fakeSMTP struct {
	mu         sync.Mutex
	auth, from string
	rcpt, data string
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func (f *fakeSMTP) serve(t *testing.T, ln net.Listener) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		f.mu.Lock()
		switch {
		case strings.HasPrefix(up, "EHLO"):
			say("250-fake")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.auth = strings.TrimSpace(line[len("AUTH PLAIN"):])
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.from = line
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.rcpt = line
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.data = b.String()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			f.mu.Unlock()
			return
		default:
			say("250 ok")
		}
		f.mu.Unlock()
	}
}

func TestACodeIsSentOverTLSAsTheMailbox(t *testing.T) {
	cert, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	old := tlsConfigFor
	tlsConfigFor = func(host string) *tls.Config { return &tls.Config{ServerName: host, RootCAs: pool} }
	defer func() { tlsConfigFor = old }()

	f := &fakeSMTP{}
	go f.serve(t, ln)
	err = sendMail(context.Background(), ln.Addr().String(), true,
		"mailbox@example.com", "s3cret", "ali@example.com", "کد ورود", "کد ورود شما: 123456")
	if err != nil {
		t.Fatalf("sending: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cred, _ := base64.StdEncoding.DecodeString(f.auth)
	if string(cred) != "\x00mailbox@example.com\x00s3cret" {
		t.Errorf("signed in as %q", cred)
	}
	if !strings.Contains(f.from, "mailbox@example.com") || !strings.Contains(f.rcpt, "ali@example.com") {
		t.Errorf("envelope: %s / %s", f.from, f.rcpt)
	}
	for _, want := range []string{"From: mailbox@example.com", "To: ali@example.com",
		"Content-Type: text/plain; charset=UTF-8", "Auto-Submitted: auto-generated", "Subject: =?UTF-8?b?"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("the message lacks %q:\n%s", want, f.data)
		}
	}
	parts := strings.SplitN(f.data, "\r\n\r\n", 2)
	body, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
	if !strings.Contains(string(body), "123456") {
		t.Errorf("the body did not survive: %q", body)
	}
}

func TestNothingSmugglesAHeaderOrTheClearPassword(t *testing.T) {
	for _, to := range []string{"a@b.de\r\nBcc: x@y.de", "not an address"} {
		if err := sendMail(context.Background(), "127.0.0.1:1", true, "mailbox@example.com", "p", to, "s", "b"); err == nil {
			t.Errorf("recipient %q was accepted", to)
		}
	}
	// A plain server with no STARTTLS is refused before the password is sent.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	f := &fakeSMTP{}
	go f.serve(t, ln)
	err := sendMail(context.Background(), ln.Addr().String(), false, "mailbox@example.com", "s3cret", "ali@example.com", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "encryption") {
		t.Errorf("a server without encryption: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" {
		t.Error("the password went to a server without encryption")
	}
}
