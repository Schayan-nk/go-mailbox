package mailbox

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The IMAP wire format, read properly.
//
// WHY THIS IS WRITTEN RATHER THAN IMPORTED. Go's standard library has SMTP
// and has no IMAP, and the maintained Go IMAP library is still on a beta tag.
// This binary is one executable that a company runs its day on, with five
// direct dependencies chosen carefully, and a beta protocol library is not a
// thing to add to it for the slice of IMAP actually needed here: sign in,
// select a mailbox, list what is in it, fetch a message, mark one read.
//
// WHAT MAKES IMAP EASY TO GET WRONG is the literal. A server may answer with
// {1234} at the end of a line, meaning "the next 1234 bytes are data, count
// them, and they may contain anything at all including CRLF". A reader that
// works line by line -- which is the obvious way to read a line protocol --
// will split a message body on its own newlines and then try to interpret the
// pieces as protocol. It appears to work, because short ASCII messages have
// no embedded CRLF in the wrong place, and it corrupts the first Persian
// attachment it meets.
//
// So this is a real tokeniser reading straight off the socket, and literals
// are read by counting bytes.

// tokenKind is what the tokeniser just read.
type tokenKind int

const (
	tokAtom    tokenKind = iota // NIL, OK, FLAGS, 1234, \Seen
	tokString                   // "a quoted string"
	tokLiteral                  // {n} followed by n bytes
	tokLParen
	tokRParen
	tokEOL
)

type token struct {
	kind tokenKind
	text string // for atoms and quoted strings
	data []byte // for literals
}

// maxLiteral bounds one literal.
//
// The server declares the length and this code then reads that many bytes, so
// without a cap a wrong or hostile number is an allocation of that size. The
// cap is above any message this mailbox realistically holds and far below
// anything that would hurt.
const maxLiteral = 64 << 20

// imapConn is a connection in the middle of a conversation.
type imapConn struct {
	c   net.Conn
	r   *bufio.Reader
	w   *bufio.Writer
	seq int
}

// dialIMAP opens an implicit-TLS connection and reads the greeting.
//
// Implicit TLS -- port 993, encrypted from the first byte -- rather than
// STARTTLS on 143. STARTTLS begins in the clear and upgrades, which means
// there is a plaintext moment and a downgrade to strip; on a mailbox holding
// a company's commercial correspondence that is not a trade worth making,
// and every mail host worth using offers 993. The TLS settings are
// tlsConfigFor, shared with POP3 (pop3.go).
func dialIMAP(host string, port int, timeout time.Duration, control func(string, string, syscall.RawConn) error) (*imapConn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// control vets the address actually reached, after DNS, for a host a
	// person typed (Config.DialControl).
	d := &net.Dialer{Timeout: timeout, Control: control}
	c, err := tls.DialWithDialer(d, "tcp", addr, tlsConfigFor(host))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	ic := &imapConn{c: c, r: bufio.NewReaderSize(c, 64<<10), w: bufio.NewWriter(c)}

	// The greeting. A server that will not greet is not one to send a
	// password to, so this is read before anything is written.
	_ = ic.deadline(timeout)
	toks, err := ic.response()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("greeting: %w", err)
	}
	if !hasAtom(toks, "OK") && !hasAtom(toks, "PREAUTH") {
		c.Close()
		return nil, fmt.Errorf("server refused the connection: %s", flatten(toks))
	}
	return ic, nil
}

func (ic *imapConn) deadline(d time.Duration) error {
	if d <= 0 {
		return ic.c.SetDeadline(time.Time{})
	}
	return ic.c.SetDeadline(time.Now().Add(d))
}

func (ic *imapConn) Close() error { return ic.c.Close() }

// next reads one token.
func (ic *imapConn) next() (token, error) {
	for {
		b, err := ic.r.ReadByte()
		if err != nil {
			return token{}, err
		}
		switch b {
		case ' ':
			continue
		case '\r':
			// A bare CR is not valid but is written by something out there;
			// treat CR and CRLF alike rather than desynchronising over it.
			if p, _ := ic.r.Peek(1); len(p) == 1 && p[0] == '\n' {
				_, _ = ic.r.ReadByte()
			}
			return token{kind: tokEOL}, nil
		case '\n':
			return token{kind: tokEOL}, nil
		case '(':
			return token{kind: tokLParen}, nil
		case ')':
			return token{kind: tokRParen}, nil
		case '"':
			s, err := ic.quoted()
			return token{kind: tokString, text: s}, err
		case '{':
			data, err := ic.literal()
			return token{kind: tokLiteral, data: data}, err
		default:
			_ = ic.r.UnreadByte()
			s, err := ic.atom()
			return token{kind: tokAtom, text: s}, err
		}
	}
}

// quoted reads the rest of a "quoted string", the opening quote consumed.
func (ic *imapConn) quoted() (string, error) {
	var b strings.Builder
	for {
		c, err := ic.r.ReadByte()
		if err != nil {
			return b.String(), err
		}
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			// Only \ and " are escapable in IMAP; anything else after a
			// backslash is that character, which is what writing it plainly
			// achieves.
			n, err := ic.r.ReadByte()
			if err != nil {
				return b.String(), err
			}
			b.WriteByte(n)
		default:
			b.WriteByte(c)
		}
	}
}

// literal reads {n}CRLF and then exactly n bytes.
//
// This is the whole reason for a tokeniser. The n bytes are data and may
// contain CRLF, braces, quotes and NUL; they are counted, never scanned.
func (ic *imapConn) literal() ([]byte, error) {
	var num strings.Builder
	for {
		c, err := ic.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == '}' {
			break
		}
		// A "{123+}" is a non-synchronising literal (LITERAL+). The plus is
		// about who waits for whom on the way in and says nothing about the
		// length, so it is skipped.
		if c == '+' {
			continue
		}
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("bad literal length near %q", c)
		}
		num.WriteByte(c)
	}
	n, err := strconv.Atoi(num.String())
	if err != nil {
		return nil, fmt.Errorf("bad literal length %q", num.String())
	}
	if n < 0 || n > maxLiteral {
		return nil, fmt.Errorf("literal of %d bytes refused", n)
	}
	// The CRLF that ends the {n} line.
	if c, err := ic.r.ReadByte(); err == nil && c == '\r' {
		if p, _ := ic.r.Peek(1); len(p) == 1 && p[0] == '\n' {
			_, _ = ic.r.ReadByte()
		}
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(ic.r, buf); err != nil {
		return nil, fmt.Errorf("short literal: %w", err)
	}
	return buf, nil
}

// atom reads an unquoted word.
func (ic *imapConn) atom() (string, error) {
	var b strings.Builder
	for {
		c, err := ic.r.ReadByte()
		if err != nil {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
		if c == ' ' || c == '(' || c == ')' || c == '\r' || c == '\n' {
			_ = ic.r.UnreadByte()
			return b.String(), nil
		}
		b.WriteByte(c)
	}
}

// response reads tokens up to the end of one line, keeping parentheses.
//
// Nesting is flattened into the token stream rather than built into a tree:
// every reader here wants a particular named item out of a FETCH, and finding
// it is a scan, not a walk.
func (ic *imapConn) response() ([]token, error) {
	var out []token
	for {
		t, err := ic.next()
		if err != nil {
			return out, err
		}
		if t.kind == tokEOL {
			if len(out) == 0 {
				continue // a blank line between responses
			}
			return out, nil
		}
		out = append(out, t)
		if len(out) > 100000 {
			return out, errors.New("response too long")
		}
	}
}

// cmd sends a command and collects everything until its tagged completion.
//
// Returns the untagged responses, which is where all the data is; the tagged
// line only says whether it worked.
func (ic *imapConn) cmd(timeout time.Duration, format string, args ...any) ([][]token, error) {
	ic.seq++
	tag := "d" + strconv.Itoa(ic.seq)
	if err := ic.deadline(timeout); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(ic.w, "%s %s\r\n", tag, fmt.Sprintf(format, args...)); err != nil {
		return nil, err
	}
	if err := ic.w.Flush(); err != nil {
		return nil, err
	}
	return ic.collect(tag, timeout)
}

// collect reads until the tagged completion for tag.
func (ic *imapConn) collect(tag string, timeout time.Duration) ([][]token, error) {
	var untagged [][]token
	for {
		if err := ic.deadline(timeout); err != nil {
			return untagged, err
		}
		toks, err := ic.response()
		if err != nil {
			return untagged, err
		}
		if len(toks) == 0 {
			continue
		}
		first := toks[0]
		switch {
		case first.kind == tokAtom && first.text == "*":
			untagged = append(untagged, toks[1:])
		case first.kind == tokAtom && first.text == "+":
			// A continuation request. Nothing here sends a command that needs
			// one -- literals are only ever received, never sent -- so this
			// means the conversation has desynchronised, and continuing would
			// send the rest of a command into a server waiting for data.
			return untagged, errors.New("unexpected continuation request")
		case first.kind == tokAtom && first.text == tag:
			if len(toks) < 2 || toks[1].kind != tokAtom {
				return untagged, errors.New("malformed completion")
			}
			switch toks[1].text {
			case "OK":
				return untagged, nil
			default:
				// NO is a refusal, BAD is a protocol error. Both carry a
				// human-readable reason, and that reason is the useful half
				// of any mail problem -- so it is passed through rather than
				// replaced with a generic failure.
				return untagged, fmt.Errorf("%s: %s", toks[1].text, flatten(toks[2:]))
			}
		default:
			// A response with no tag and no star. Nothing to do with it, and
			// skipping is safer than guessing.
		}
	}
}

// ---------------------------------------------------------------- helpers

func hasAtom(toks []token, want string) bool {
	for _, t := range toks {
		if t.kind == tokAtom && strings.EqualFold(t.text, want) {
			return true
		}
	}
	return false
}

// flatten renders tokens as text, for an error message.
//
// Literals are shown as their length rather than their contents: this string
// goes into a log, and a literal is message data.
func flatten(toks []token) string {
	var parts []string
	for _, t := range toks {
		switch t.kind {
		case tokAtom:
			parts = append(parts, t.text)
		case tokString:
			parts = append(parts, `"`+t.text+`"`)
		case tokLiteral:
			parts = append(parts, "{"+strconv.Itoa(len(t.data))+" bytes}")
		case tokLParen:
			parts = append(parts, "(")
		case tokRParen:
			parts = append(parts, ")")
		}
	}
	return strings.Join(parts, " ")
}

// astring renders a string as a command argument.
//
// Three forms, and the choice matters for exactly one value: the password.
// A quoted string cannot carry CRLF or 8-bit bytes, so a password containing
// either has to go as a literal -- and a password containing a quote or a
// backslash has to be escaped or it ends the argument early and the rest of
// it is read as another command.
func astring(s string) (string, bool) {
	needsLiteral := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' || s[i] == 0 || s[i] >= 0x80 {
			needsLiteral = true
			break
		}
	}
	if needsLiteral {
		return s, true
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String(), false
}
