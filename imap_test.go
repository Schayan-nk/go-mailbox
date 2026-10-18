package mailbox

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake IMAP server, so the client is tested against the protocol rather
// than against a description of it.
//
// WHY THIS IS WORTH THE HUNDRED LINES. The IMAP client here is hand-written,
// and the part most likely to be wrong is the part that cannot be checked by
// reading it: literals. A server answers with {1234} meaning "count the next
// 1234 bytes, they are data, and they may contain CRLF". Every message below
// is delivered that way, and one of them deliberately contains a line that
// looks exactly like the end of a response -- which is what breaks a reader
// that works line by line, and which short ASCII test messages never catch.

type fakeIMAP struct {
	t        *testing.T
	ln       net.Listener
	messages map[uint32][]byte
	flags    map[uint32]string
	lists    []string // what LIST answers, one untagged line each

	mu    sync.Mutex
	saw   []string // every command line received, for assertions
	wg    sync.WaitGroup
	creds [2]string
	pool  *x509.CertPool
}

func newFakeIMAP(t *testing.T, msgs map[uint32][]byte) *fakeIMAP {
	t.Helper()
	cert, pool := imapSelfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeIMAP{
		t: t, ln: ln, messages: msgs, pool: pool,
		flags: map[uint32]string{},
		creds: [2]string{"owner@example.com", "p@ss word\\\"x"},
	}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() { ln.Close(); f.wg.Wait() })
	return f
}

func (f *fakeIMAP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeIMAP) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.saw...)
}

func (f *fakeIMAP) serve() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeIMAP) session(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	defer w.Flush()

	fmt.Fprint(w, "* OK fake IMAP ready\r\n")
	w.Flush()

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		f.saw = append(f.saw, line)
		f.mu.Unlock()

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag, cmd := parts[0], strings.ToUpper(parts[1])
		rest := ""
		if len(parts) > 2 {
			rest = parts[2]
		}

		switch cmd {
		case "LOGIN":
			// The password arrives as a literal when it has a character a
			// quoted string cannot carry. Answer the continuation, then read
			// exactly that many bytes -- which is the same discipline the
			// client uses in the other direction.
			if i := strings.LastIndex(rest, "{"); i >= 0 && strings.HasSuffix(rest, "}") {
				var n int
				fmt.Sscanf(rest[i:], "{%d}", &n)
				fmt.Fprint(w, "+ go ahead\r\n")
				w.Flush()
				buf := make([]byte, n)
				if _, err := readFull(r, buf); err != nil {
					return
				}
				r.ReadString('\n') // the CRLF after the literal
				f.mu.Lock()
				f.saw = append(f.saw, "LITERAL:"+string(buf))
				f.mu.Unlock()
			}
			fmt.Fprintf(w, "%s OK signed in\r\n", tag)
		case "SELECT":
			fmt.Fprintf(w, "* %d EXISTS\r\n", len(f.messages))
			fmt.Fprint(w, "* OK [UIDVALIDITY 1] ok\r\n")
			fmt.Fprintf(w, "%s OK [READ-WRITE] selected\r\n", tag)
		case "UID":
			f.uidCommand(w, tag, rest)
		case "LIST":
			for _, l := range f.lists {
				fmt.Fprint(w, l+"\r\n")
			}
			fmt.Fprintf(w, "%s OK listed\r\n", tag)
		case "LOGOUT":
			fmt.Fprint(w, "* BYE\r\n")
			fmt.Fprintf(w, "%s OK bye\r\n", tag)
			w.Flush()
			return
		default:
			fmt.Fprintf(w, "%s BAD unknown\r\n", tag)
		}
		w.Flush()
	}
}

func (f *fakeIMAP) uidCommand(w *bufio.Writer, tag, rest string) {
	sub := strings.ToUpper(strings.SplitN(rest, " ", 2)[0])
	switch sub {
	case "SEARCH":
		var ids []string
		for uid := range f.messages {
			ids = append(ids, fmt.Sprint(uid))
		}
		// Deliberately out of order: the client is responsible for sorting,
		// and a server is under no obligation to.
		fmt.Fprintf(w, "* SEARCH %s\r\n", strings.Join(ids, " "))
		fmt.Fprintf(w, "%s OK done\r\n", tag)

	case "FETCH":
		args := strings.SplitN(rest, " ", 3)
		if len(args) < 3 {
			fmt.Fprintf(w, "%s BAD fetch\r\n", tag)
			return
		}
		upper := strings.ToUpper(args[2])
		wantHeaderOnly := strings.Contains(upper, "BODY.PEEK[HEADER]")
		// A partial fetch, BODY.PEEK[]<0.N>, is answered with the first N
		// octets and a key naming where it started -- which is what a real
		// server does and what the listing now asks for.
		partial := 0
		if i := strings.Index(upper, "BODY.PEEK[]<0."); i >= 0 {
			fmt.Sscanf(upper[i:], "BODY.PEEK[]<0.%d>", &partial)
		}
		wantStructure := strings.Contains(upper, "BODYSTRUCTURE")
		seq := 0
		for _, idStr := range strings.Split(args[1], ",") {
			var uid uint32
			fmt.Sscanf(idStr, "%d", &uid)
			raw, ok := f.messages[uid]
			if !ok {
				continue
			}
			seq++
			body := raw
			key := "BODY[]"
			if wantHeaderOnly {
				key = "BODY[HEADER]"
				if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
					body = raw[:i+4]
				}
			} else if partial > 0 {
				key = "BODY[]<0>"
				if partial < len(body) {
					body = body[:partial]
				}
			}
			flags := f.flags[uid]
			// A structure naming one attached file, when asked for. Enough to
			// exercise the scan that decides whether to draw a paperclip
			// without writing out a whole BODYSTRUCTURE grammar.
			structure := ""
			if wantStructure {
				structure = ` BODYSTRUCTURE (("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 12 1)` +
					`("application" "pdf" ("name" "report.pdf") NIL NIL "base64" 400` +
					` ("attachment" ("filename" "report.pdf"))) "mixed")`
			}
			// The literal: announce the length, then the bytes, counted.
			fmt.Fprintf(w, "* %d FETCH (UID %d FLAGS (%s) INTERNALDATE %q RFC822.SIZE %d%s %s {%d}\r\n",
				seq, uid, flags, "20-Sep-2026 09:15:00 +0330", len(raw), structure, key, len(body))
			w.Write(body)
			fmt.Fprint(w, ")\r\n")
		}
		fmt.Fprintf(w, "%s OK done\r\n", tag)

	case "STORE":
		args := strings.Fields(rest)
		if len(args) >= 3 {
			var uid uint32
			fmt.Sscanf(args[1], "%d", &uid)
			if strings.HasPrefix(args[2], "+") {
				f.flags[uid] = `\Seen`
			} else {
				f.flags[uid] = ""
			}
		}
		fmt.Fprintf(w, "%s OK stored\r\n", tag)

	default:
		fmt.Fprintf(w, "%s BAD unknown uid command\r\n", tag)
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// trustThisServer lets the client verify the test server's certificate, and
// puts the real setting back afterwards.
//
// NOT InsecureSkipVerify. The certificate is generated by this test, so the
// test can hand the client a root pool containing exactly that certificate
// and nothing else -- which keeps verification switched ON and merely says
// what to trust. Turning verification off would test a client that is not the
// client being shipped, and would leave a pattern in the file for somebody to
// copy somewhere it matters.
//
// The production path has no way to reach either of these: there is no flag
// on Config for it, because a flag is a thing somebody eventually sets.
func trustThisServer(t *testing.T, f *fakeIMAP) func() {
	t.Helper()
	prev := tlsConfigFor
	tlsConfigFor = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, RootCAs: f.pool, MinVersion: tls.VersionTLS12}
	}
	return func() { tlsConfigFor = prev }
}

// imapSelfSigned returns a certificate for 127.0.0.1 and a pool that trusts it.
func imapSelfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// ------------------------------------------------------------------ tests

// A message whose body contains a line that looks like the end of a FETCH.
//
// This is the case a line-by-line reader gets wrong and a counting reader
// gets right, and it is not contrived: ")" alone on a line happens in code
// samples, and ") " happens constantly in quoted replies.
func trapMessage() []byte {
	return []byte("From: \"Karimi, Nima\" <n.karimi@example.com>\r\n" +
		"Subject: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("پیش‌فاکتور")) + "?=\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"line one\r\n" +
		")\r\n" +
		"d3 OK done\r\n" +
		"* 1 FETCH (UID 9 BODY[] {5}\r\n" +
		"last line\r\n")
}

func plainMessage(subject string) []byte {
	return []byte("From: a@b.com\r\nSubject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n")
}

func testConfig(f *fakeIMAP) Config {
	return Config{
		Address: f.creds[0], Password: f.creds[1],
		Protocol: "imap", IMAPHost: "127.0.0.1", IMAPPort: f.port(),
		Mailbox: "INBOX",
	}
}

// The whole path: connect, sign in, list, read one, mark it read.
func TestTheClientReadsAMailbox(t *testing.T) {
	f := newFakeIMAP(t, map[uint32][]byte{
		7: plainMessage("first"),
		9: trapMessage(),
		3: plainMessage("third"),
	})
	// The fake server presents a self-signed certificate, which is the one
	// thing a real client must refuse -- so the test trusts it explicitly
	// rather than the client being made lax.
	restore := trustThisServer(t, f)
	defer restore()

	c, err := OpenIMAP(testConfig(f))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	uids, err := c.Search(time.Time{})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// Sorted, although the server answered out of order.
	want := []uint32{3, 7, 9}
	if len(uids) != len(want) {
		t.Fatalf("got %v, want %v", uids, want)
	}
	for i := range want {
		if uids[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted)", uids, want)
		}
	}

	msgs, err := c.Headers(uids)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d headers, want 3", len(msgs))
	}
	byUID := map[uint32]*Message{}
	for _, m := range msgs {
		u, _ := strconv.ParseUint(m.UIDL[strings.IndexByte(m.UIDL, '.')+1:], 10, 32)
		byUID[uint32(u)] = m
	}
	if got := byUID[9].Subject; got != "پیش‌فاکتور" {
		t.Errorf("subject is %q, want the Persian", got)
	}
	if got := byUID[9].Addr; got != "n.karimi@example.com" {
		t.Errorf("address is %q", got)
	}
	// A LISTING CARRIES A PREVIEW. It fetches the first few kilobytes rather
	// than the headers alone, because the rows show the first line of each
	// message beneath its subject -- built header-only first, and every
	// preview line came out empty.
	//
	// And the preview is the message's own text, not the protocol text that
	// happens to follow it in the response.
	if !strings.Contains(byUID[9].Body, "line one") {
		t.Errorf("the listing carries no preview; its body is %q", byUID[9].Body)
	}

	// The paperclip. A listing cannot see attachments in the few kilobytes it
	// fetched, so the count comes from the server's BODYSTRUCTURE instead.
	for _, m := range msgs {
		if m.NamedParts != 1 {
			t.Errorf("uid %s reports %d attached files, want 1 from BODYSTRUCTURE",
				m.UIDL, m.NamedParts)
		}
	}

	// THE TRAP. The body contains ")", a tagged completion line, and the
	// opening of another FETCH response. All of it is data.
	full, err := c.messageByUID(9)
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	for _, want := range []string{"line one", ")", "d3 OK done", "last line"} {
		if !strings.Contains(full.Body, want) {
			t.Errorf("the body lost %q; it is:\n%s", want, full.Body)
		}
	}

	if err := c.MarkSeen(9, true); err != nil {
		t.Fatalf("mark seen: %v", err)
	}
	if f.flags[9] != `\Seen` {
		t.Errorf("the server was not told to set \\Seen; flags are %q", f.flags[9])
	}

	// And the flag comes back on the next read.
	again, err := c.Headers([]uint32{9})
	if err != nil {
		t.Fatalf("headers again: %v", err)
	}
	if len(again) != 1 || !again[0].Seen {
		t.Error("the message does not read as seen after being marked")
	}
}

// A password a quoted string cannot carry goes as a literal.
//
// The configured password holds a space, a backslash and a double quote.
// Sent as a quoted string without escaping, the quote ends the argument early
// and the rest is read as another command -- which is a sign-in failure
// nobody can explain, and on some servers an account lockout.
func TestAnAwkwardPasswordSurvivesLogin(t *testing.T) {
	f := newFakeIMAP(t, map[uint32][]byte{1: plainMessage("x")})
	restore := trustThisServer(t, f)
	defer restore()

	cfg := testConfig(f)
	cfg.Password = "p@ss word\\\"x\n" // a newline forces the literal path
	c, err := OpenIMAP(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	var sawLiteral string
	for _, line := range f.commands() {
		if strings.HasPrefix(line, "LITERAL:") {
			sawLiteral = strings.TrimPrefix(line, "LITERAL:")
		}
		// The password must never appear on the command line itself.
		if strings.HasPrefix(line, "d") && strings.Contains(line, "LOGIN") {
			if strings.Contains(line, "p@ss") {
				t.Errorf("the password was written inline: %q", line)
			}
		}
	}
	if sawLiteral != cfg.Password {
		t.Errorf("the server received %q, want %q", sawLiteral, cfg.Password)
	}
}

// An empty mailbox is an answer, not an error.
func TestAnEmptyMailboxIsNotAnError(t *testing.T) {
	f := newFakeIMAP(t, map[uint32][]byte{})
	restore := trustThisServer(t, f)
	defer restore()

	c, err := OpenIMAP(testConfig(f))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	uids, err := c.Search(time.Time{})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(uids) != 0 {
		t.Errorf("got %v from an empty mailbox", uids)
	}
	msgs, err := c.Headers(uids)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("got %d messages from an empty mailbox", len(msgs))
	}
}

// A copy of what was sent goes where the account keeps its sent mail: the
// folder the server flags \Sent -- "Sent Items" on one real provider -- or
// failing a flag, the usual name.
func TestTheSentFolderIsTheOneTheServerFlags(t *testing.T) {
	for _, c := range []struct {
		lists []string
		want  string
	}{
		{[]string{
			`* LIST (\HasNoChildren) "." "New Customers"`,
			`* LIST (\HasNoChildren) "." "Deleted Items"`,
			`* LIST (\Sent \HasNoChildren) "." "Sent Items"`,
			`* LIST (\HasNoChildren) "." "INBOX"`,
		}, "Sent Items"},
		{[]string{`* LIST (\HasNoChildren) "/" INBOX`, `* LIST (\HasNoChildren) "/" "Sent"`}, "Sent"},
		{[]string{`* LIST (\HasNoChildren) "/" INBOX`}, ""},
	} {
		f := newFakeIMAP(t, map[uint32][]byte{})
		f.lists = c.lists
		restore := trustThisServer(t, f)
		m, err := OpenIMAP(testConfig(f))
		if err != nil {
			restore()
			t.Fatalf("open: %v", err)
		}
		got, err := m.SentFolder()
		m.Close()
		restore()
		if err != nil || got != c.want {
			t.Errorf("%v: got %q, %v; want %q", c.lists, got, err, c.want)
		}
	}
}

// An unconfigured mailbox is refused before any connection is attempted.
// Folder names cross the wire in modified UTF-7 (RFC 3501, 5.1.3): a Persian
// name must survive the round trip, "&" is "&-", and ASCII is itself.
func TestFolderNamesRoundTrip(t *testing.T) {
	for _, name := range []string{"INBOX", "New Customers", "مشتریان جدید", "R&D", "Sent Items/2026", "خرید & فروش"} {
		wire := EncodeFolder(name)
		for _, r := range wire {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("%q went out as %q, which is not 7-bit", name, wire)
			}
		}
		if back := DecodeFolder(wire); back != name {
			t.Errorf("%q -> %q -> %q", name, wire, back)
		}
	}
	// The RFC's own example: "~peter/mail/台北/日本語".
	if got := DecodeFolder("~peter/mail/&U,BTFw-/&ZeVnLIqe-"); got != "~peter/mail/台北/日本語" {
		t.Errorf("RFC example decodes to %q", got)
	}
	if got := EncodeFolder("R&D"); got != "R&-D" {
		t.Errorf("R&D encodes to %q", got)
	}
}

func TestOpenRefusesAnUnconfiguredMailbox(t *testing.T) {
	if _, err := OpenIMAP(Config{Protocol: "imap"}); err == nil {
		t.Fatal("an empty configuration opened a mailbox")
	}
	if _, err := OpenIMAP(Config{Protocol: "imap", Address: "a@b.com", IMAPHost: "h"}); err == nil {
		t.Fatal("a configuration with no password opened a mailbox")
	}
}
