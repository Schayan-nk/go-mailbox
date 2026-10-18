package mailbox

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// POP3: sign in, list what is in the mailbox, ask for a message's unique id,
// fetch its headers and the first few lines, fetch the whole thing.
//
// A MUCH SMALLER PROTOCOL THAN IMAP, and the whole of it is here. There are
// no folders, no flags, no search and no partial fetches, so three things
// that would ordinarily come from the server are the caller's:
//
//   READ AND UNREAD. POP3 has no \Seen and nowhere to put one. Keep your own
//   record, keyed by the message's UIDL.
//
//   NO TRASH FOLDER. POP3's DELE does not move a message, it destroys it at
//   QUIT. Only Delete sends it: call it for a message you have kept
//   somewhere else and checked.
//
//   NO SEARCH. UIDL lists everything in one command, cheaply, and the newest
//   few are then fetched by number. The ids are stable, so a cache keyed by
//   them never fetches a message twice.

// defaultTimeout bounds every exchange.
//
// Per command rather than for the whole session: fetching fifty messages is
// legitimately slow, and a single command that has not answered in a minute
// is a connection that has died without saying so -- which on a mail path is
// the normal way for things to fail.
const defaultTimeout = 60 * time.Second

// tlsConfigFor builds the settings for one connection.
//
// A variable so the tests can point the client at a server presenting a
// self-signed certificate. That is the ONE thing a real mail client must
// refuse, so it is overridden in the test rather than softened here -- a flag
// on Config would be a switch somebody could eventually set in production.
var tlsConfigFor = func(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// pop3 is a signed-in session.
type pop3 struct {
	c net.Conn
	r *bufio.Reader
	w *bufio.Writer
}

// dialPOP3 opens an implicit-TLS connection and reads the greeting.
//
// Port 995, encrypted from the first byte, rather than 110 with STLS. STLS
// begins in the clear and upgrades, which leaves a plaintext moment and a
// downgrade to strip; on a mailbox holding a company's commercial
// correspondence that is not a trade worth making.
func dialPOP3(host string, port int, timeout time.Duration, control func(string, string, syscall.RawConn) error) (*pop3, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// control, when set, vets the address actually connected to after DNS --
	// how a mailbox somebody typed in is kept off your own network.
	d := &net.Dialer{Timeout: timeout, Control: control}
	c, err := tls.DialWithDialer(d, "tcp", addr, tlsConfigFor(host))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	p := &pop3{c: c, r: bufio.NewReaderSize(c, 64<<10), w: bufio.NewWriter(c)}
	_ = p.deadline(timeout)

	// The greeting. A server that will not greet is not one to send a
	// password to, so this is read before anything is written.
	if _, err := p.line(); err != nil {
		c.Close()
		return nil, fmt.Errorf("greeting: %w", err)
	}
	return p, nil
}

func (p *pop3) deadline(d time.Duration) error {
	if d <= 0 {
		return p.c.SetDeadline(time.Time{})
	}
	return p.c.SetDeadline(time.Now().Add(d))
}

func (p *pop3) Close() error { return p.c.Close() }

// maxLine bounds one response line.
//
// A server that never sends a newline would otherwise be an unbounded read.
const maxLine = 1 << 20

// line reads one response line and returns it without its ending, refusing
// anything the server marked as an error.
func (p *pop3) line() (string, error) {
	s, err := p.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(s) > maxLine {
		return "", errors.New("response line too long")
	}
	s = strings.TrimRight(s, "\r\n")
	switch {
	case strings.HasPrefix(s, "+OK"):
		return strings.TrimSpace(strings.TrimPrefix(s, "+OK")), nil
	case strings.HasPrefix(s, "-ERR"):
		// The server's own words. A sign-in failure is the most common thing
		// to go wrong here and the reason is the useful half -- but callers
		// must not put this in front of a reader, because it can name the
		// host and the account.
		return "", fmt.Errorf("server refused: %s",
			strings.TrimSpace(strings.TrimPrefix(s, "-ERR")))
	}
	return "", fmt.Errorf("unexpected response %q", s)
}

// cmd sends a command and reads its single-line reply.
func (p *pop3) cmd(timeout time.Duration, format string, args ...any) (string, error) {
	if err := p.deadline(timeout); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(p.w, format+"\r\n", args...); err != nil {
		return "", err
	}
	if err := p.w.Flush(); err != nil {
		return "", err
	}
	return p.line()
}

// maxMultiline bounds one multi-line response.
//
// RETR of a message with a large attachment is the big one, and this is the
// cap that stops a mailbox item from becoming a memory problem.
const maxMultiline = 64 << 20

// multiline reads a dot-terminated response body.
//
// TWO THINGS MAKE THIS MORE THAN ReadString. The body ends at a line
// containing exactly ".", and any body line that begins with "." was sent
// with an extra one -- dot-stuffing, so that real content cannot imitate the
// terminator. Un-stuffing is not optional: a message quoting shell output, or
// any line starting with a full stop, comes out corrupted without it.
func (p *pop3) multiline(timeout time.Duration) ([]byte, error) {
	if err := p.deadline(timeout); err != nil {
		return nil, err
	}
	var out []byte
	for {
		s, err := p.r.ReadString('\n')
		if err != nil {
			return out, fmt.Errorf("truncated response: %w", err)
		}
		if len(out)+len(s) > maxMultiline {
			return out, errors.New("response too large")
		}
		body := strings.TrimRight(s, "\r\n")
		if body == "." {
			return out, nil
		}
		body = strings.TrimPrefix(body, ".") // un-stuff
		out = append(out, body...)
		out = append(out, '\r', '\n')
	}
}

// login authenticates with USER and PASS.
//
// Sent verbatim, with no quoting of any kind, because POP3 has none: the
// command is a line and the password is the rest of it. A password
// containing a CR or LF would therefore be two commands, so it is refused
// rather than sent -- which is a configuration mistake worth naming, not a
// thing to pass through and let the server puzzle over.
func (p *pop3) login(user, pass string, timeout time.Duration) error {
	if strings.ContainsAny(user, "\r\n") || strings.ContainsAny(pass, "\r\n") {
		return errors.New("the address or password contains a line break")
	}
	if _, err := p.cmd(timeout, "USER %s", user); err != nil {
		return err
	}
	_, err := p.cmd(timeout, "PASS %s", pass)
	return err
}

// ---------------------------------------------------------------- POP3Box

// POP3Box is a signed-in mailbox.
type POP3Box struct {
	conn    *pop3
	timeout time.Duration

	// order is the server's message numbers, newest last, and uids the
	// matching unique ids.
	//
	// MESSAGE NUMBERS ARE ONLY VALID FOR THIS SESSION. They are positions in
	// the mailbox and they shift when anything is removed, so nothing outside
	// this type ever sees one -- callers work in UIDLs, which never move and
	// never repeat.
	nums []int
	uids []string
}

// OpenPOP3 connects, signs in and reads the mailbox listing.
func OpenPOP3(cfg Config) (*POP3Box, error) {
	if !cfg.Enabled() {
		return nil, fmt.Errorf("the mailbox is not configured: set %s",
			strings.Join(cfg.Validate(), ", "))
	}
	conn, err := dialPOP3(cfg.POP3Host, cfg.pop3Port(), defaultTimeout, cfg.DialControl)
	if err != nil {
		return nil, err
	}
	b := &POP3Box{conn: conn, timeout: defaultTimeout}
	if err := conn.login(cfg.Address, cfg.Password, defaultTimeout); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sign in as %s: %w", cfg.Address, err)
	}
	if err := b.readUIDs(); err != nil {
		conn.Close()
		return nil, err
	}
	return b, nil
}

// Close ends the session politely.
//
// QUIT rather than dropping the socket. POP3 holds an EXCLUSIVE LOCK on the
// mailbox for the length of a session -- that is in the specification, not a
// quirk -- so a session that is abandoned rather than closed keeps everybody
// else out until the server's timeout expires. Two dropped connections in a
// row and the next poll cannot sign in at all.
//
// QUIT is also what commits any DELE issued in the session. Close ignores the
// server's answer to it, which is right for every session that deleted
// nothing; a session that deleted ends with Commit, which does not.
func (b *POP3Box) Close() error {
	_, _ = b.conn.cmd(5*time.Second, "QUIT")
	return b.conn.Close()
}

// Commit ends the session with QUIT and says whether the server took it --
// which is what makes a Delete in the session final. On an error nothing was
// removed: a server that did not answer QUIT never entered its UPDATE state.
func (b *POP3Box) Commit() error {
	_, err := b.conn.cmd(60*time.Second, "QUIT")
	b.conn.Close()
	if err != nil {
		return fmt.Errorf("QUIT: %w", err)
	}
	return nil
}

// Raw fetches one whole message as the server holds it, byte for byte: what a
// backup keeps.
func (b *POP3Box) Raw(uid string) ([]byte, error) {
	n, ok := b.numberOf(uid)
	if !ok {
		return nil, fmt.Errorf("message %q is not in the mailbox", uid)
	}
	if _, err := b.conn.cmd(b.timeout, "RETR %d", n); err != nil {
		return nil, err
	}
	return b.conn.multiline(b.timeout)
}

// Head fetches one message's header section alone (TOP n 0) -- what to
// compare with a kept copy before deleting, so a UIDL cannot delete a
// message other than the one that was kept.
func (b *POP3Box) Head(uid string) ([]byte, error) {
	n, ok := b.numberOf(uid)
	if !ok {
		return nil, fmt.Errorf("message %q is not in the mailbox", uid)
	}
	if _, err := b.conn.cmd(b.timeout, "TOP %d 0", n); err != nil {
		return nil, err
	}
	raw, err := b.conn.multiline(b.timeout)
	if err != nil {
		return nil, err
	}
	return HeaderSection(raw), nil
}

// HeaderSection is a message's headers, up to the blank line that ends them.
func HeaderSection(raw []byte) []byte {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i]
	}
	return bytes.TrimRight(raw, "\r\n")
}

// Delete marks one message for removal.
//
// DESTRUCTIVE. POP3's DELE does not move a message anywhere: at QUIT it is
// gone, and there is no trash to bring it back from. Call it only for a
// message whose copy you have kept and checked against the bytes the server
// gave (Raw, Head), and end the session with Commit.
func (b *POP3Box) Delete(uid string) error {
	n, ok := b.numberOf(uid)
	if !ok {
		return fmt.Errorf("message %q is not in the mailbox", uid)
	}
	_, err := b.conn.cmd(b.timeout, "DELE %d", n)
	return err
}

// readUIDs asks for every message's unique id.
//
// UIDL IS THE WHOLE REASON THIS WORKS. Without it there is no way to say
// "this is the same message I saw last time": message numbers shift, and
// nothing else in POP3 is stable. Read state, caches and links should all be
// keyed by these.
func (b *POP3Box) readUIDs() error {
	if _, err := b.conn.cmd(b.timeout, "UIDL"); err != nil {
		return fmt.Errorf("UIDL: %w", err)
	}
	raw, err := b.conn.multiline(b.timeout)
	if err != nil {
		return fmt.Errorf("UIDL: %w", err)
	}
	b.nums, b.uids = nil, nil
	for line := range strings.SplitSeq(string(raw), "\r\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		num, uid, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(num))
		if err != nil {
			continue
		}
		uid = strings.TrimSpace(uid)
		if uid == "" {
			continue
		}
		b.nums = append(b.nums, n)
		b.uids = append(b.uids, uid)
	}
	return nil
}

// UIDs returns every message's unique id, oldest first.
func (b *POP3Box) UIDs() []string { return append([]string(nil), b.uids...) }

// Count is how many messages are in the mailbox.
func (b *POP3Box) Count() int { return len(b.uids) }

// numberOf finds the session message number for a unique id.
func (b *POP3Box) numberOf(uid string) (int, bool) {
	for i, u := range b.uids {
		if u == uid {
			return b.nums[i], true
		}
	}
	return 0, false
}

// previewLines is how much of a message's body a listing asks for.
//
// TOP <n> <lines> is POP3's one partial fetch, and it is a better fit than
// the byte range IMAP offers: it returns the headers in full and then counts
// LINES of body, so a preview never stops in the middle of one. Forty is
// comfortably more than the two lines a row shows, and enough that a message
// which opens with a greeting and a blank line still has something under it.
const previewLines = 40

// Preview fetches a message's headers and the start of its body.
func (b *POP3Box) Preview(uid string) (*Message, error) {
	n, ok := b.numberOf(uid)
	if !ok {
		return nil, fmt.Errorf("message %q is not in the mailbox", uid)
	}
	if _, err := b.conn.cmd(b.timeout, "TOP %d %d", n, previewLines); err != nil {
		// TOP is optional in the specification. Every mail host worth the
		// name has it, but a server without it must still produce a list --
		// so fall back to the whole message rather than showing nothing.
		return b.Message(uid)
	}
	raw, err := b.conn.multiline(b.timeout)
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	m.UIDL = uid
	// A TOP response stops partway through the body, so the attachments it
	// contains are not the message's. See NamedParts.
	m.NamedParts = guessAttachments(raw, m)
	return m, nil
}

// Message fetches one whole message.
func (b *POP3Box) Message(uid string) (*Message, error) {
	n, ok := b.numberOf(uid)
	if !ok {
		return nil, fmt.Errorf("message %q is not in the mailbox", uid)
	}
	if _, err := b.conn.cmd(b.timeout, "RETR %d", n); err != nil {
		return nil, err
	}
	raw, err := b.conn.multiline(b.timeout)
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	m.UIDL = uid
	m.NamedParts = len(m.Attachments)
	return m, nil
}

// Size is a message's length in octets, as the server reports it.
func (b *POP3Box) Size(uid string) (int64, error) {
	n, ok := b.numberOf(uid)
	if !ok {
		return 0, fmt.Errorf("message %q is not in the mailbox", uid)
	}
	line, err := b.conn.cmd(b.timeout, "LIST %d", n)
	if err != nil {
		return 0, err
	}
	// "+OK 3 4096" -- the number, then the size.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, nil
	}
	size, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	if err != nil {
		return 0, nil
	}
	return size, nil
}

// Sizes returns every message's length, keyed by unique id, in one command.
//
// One LIST rather than one per message: a mailbox of two hundred would
// otherwise be two hundred round trips to somebody else's server to fill in a
// column.
func (b *POP3Box) Sizes() (map[string]int64, error) {
	if _, err := b.conn.cmd(b.timeout, "LIST"); err != nil {
		return nil, err
	}
	raw, err := b.conn.multiline(b.timeout)
	if err != nil {
		return nil, err
	}
	byNum := map[int]int64{}
	for line := range strings.SplitSeq(string(raw), "\r\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err1 := strconv.Atoi(fields[0])
		size, err2 := strconv.ParseInt(fields[1], 10, 64)
		if err1 == nil && err2 == nil {
			byNum[n] = size
		}
	}
	out := make(map[string]int64, len(b.uids))
	for i, u := range b.uids {
		out[u] = byNum[b.nums[i]]
	}
	return out, nil
}

// guessAttachments decides whether to draw a paperclip, from a partial fetch.
//
// A GUESS, AND NAMED ONE. IMAP can be asked for a message's structure without
// its contents; POP3 cannot, so the only honest options are to fetch every
// message in full -- hundreds of megabytes to draw a list -- or to read what
// the headers imply.
//
// Two signals, in order of confidence. A filename in the part of the message
// actually fetched is proof. Otherwise multipart/mixed is the strong hint:
// "mixed" is the type that means "a body and some things attached to it",
// where multipart/alternative is a message sent twice over in two formats and
// multipart/related is a body with its own inline images.
//
// It can be wrong in one direction -- a mixed message whose parts are all
// text reads as having an attachment -- and the cost of that is a paperclip
// on a row that opens to none. The opposite mistake, a missing paperclip on a
// contract, is the one worth avoiding.
func guessAttachments(raw []byte, m *Message) int {
	if n := len(m.Attachments); n > 0 {
		return n
	}
	head := string(raw)
	if i := strings.Index(head, "\r\n\r\n"); i > 0 {
		head = head[:i]
	}
	lower := strings.ToLower(head)
	if strings.Contains(lower, "multipart/mixed") {
		return 1
	}
	return 0
}
