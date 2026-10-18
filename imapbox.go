package mailbox

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// What a mail client needs from an IMAP session on top
// of the protocol in imap.go: the five questions of Reader, keyed by UIDL
// strings, and three ways of putting a message somewhere -- a folder made, a
// message appended, a message moved.

// uidl names a message the way the rest of this package does.
func (m *IMAP) uidl(uid uint32) string {
	return strconv.FormatUint(uint64(m.validity), 10) + "." + strconv.FormatUint(uint64(uid), 10)
}

// uidOf reads a UIDL back, and refuses one from another folder or from before
// the server renumbered this one -- acting on it would address a different
// message.
func (m *IMAP) uidOf(uidl string) (uint32, error) {
	v, u, ok := strings.Cut(uidl, ".")
	if !ok || v != strconv.FormatUint(uint64(m.validity), 10) {
		return 0, fmt.Errorf("message %s is not in %s as it is now", uidl, m.box)
	}
	n, err := strconv.ParseUint(u, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("message id %q is not an IMAP UID", uidl)
	}
	return uint32(n), nil
}

// UIDs lists the folder in arrival order, newest last, as POP3 does.
func (m *IMAP) UIDs() []string {
	out := make([]string, len(m.uids))
	for i, u := range m.uids {
		out[i] = m.uidl(u)
	}
	return out
}

// Count is how many messages the folder held when it was opened.
func (m *IMAP) Count() int { return len(m.uids) }

// Sizes is every message's size, in one command.
func (m *IMAP) Sizes() (map[string]int64, error) {
	out := map[string]int64{}
	// "1:*" on an empty folder is an error on some servers; there is nothing
	// to ask about anyway.
	if len(m.uids) == 0 {
		return out, nil
	}
	res, err := m.conn.cmd(m.timeout, "UID FETCH 1:* (RFC822.SIZE)")
	if err != nil {
		return out, err
	}
	for _, line := range res {
		if !isFetch(line) {
			continue
		}
		u, ok1 := itemNumber(line, "UID")
		n, ok2 := itemNumber(line, "RFC822.SIZE")
		if ok1 && ok2 {
			out[m.uidl(uint32(u))] = int64(n)
		}
	}
	return out, nil
}

// Preview is enough of one message to list it (see Headers).
func (m *IMAP) Preview(uidl string) (*Message, error) {
	u, err := m.uidOf(uidl)
	if err != nil {
		return nil, err
	}
	got, err := m.Headers([]uint32{u})
	if err != nil {
		return nil, err
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("message %s is not in %s", uidl, m.box)
	}
	return got[0], nil
}

// Previews is Preview for several messages at once: one FETCH per batch
// rather than one per message, which is the difference between a page of the
// Sent folder in a second and in thirty. The order is the server's, not the
// order asked; callers sort.
func (m *IMAP) Previews(uidls []string) ([]*Message, error) {
	uids := make([]uint32, 0, len(uidls))
	for _, s := range uidls {
		u, err := m.uidOf(s)
		if err != nil {
			return nil, err
		}
		uids = append(uids, u)
	}
	if len(uids) == 0 {
		return nil, nil
	}
	return m.Headers(uids)
}

// Message is one whole message.
func (m *IMAP) Message(uidl string) (*Message, error) {
	u, err := m.uidOf(uidl)
	if err != nil {
		return nil, err
	}
	return m.messageByUID(u)
}

// Folder is the folder this session has open.
func (m *IMAP) Folder() string { return m.box }

// EnsureFolder makes a folder unless it is there already, matching the name
// without regard to case -- "New Customers" and "new customers" are one
// folder to the person who asked for it.
func (m *IMAP) EnsureFolder(name string) (string, error) {
	have, err := m.Folders()
	if err != nil {
		return "", err
	}
	for _, f := range have {
		if strings.EqualFold(strings.TrimSpace(f), strings.TrimSpace(name)) {
			return f, nil
		}
	}
	q, _ := astring(EncodeFolder(name))
	if _, err := m.conn.cmd(m.timeout, "CREATE %s", q); err != nil {
		return "", fmt.Errorf("create folder %q: %w", name, err)
	}
	return name, nil
}

// Move puts a message from the open folder into another one. UID MOVE is
// atomic on the server; without it, COPY and a \Deleted flag -- never an
// expunge (see Trash).
func (m *IMAP) Move(uidl, folder string) error {
	u, err := m.uidOf(uidl)
	if err != nil {
		return err
	}
	q, _ := astring(EncodeFolder(folder))
	if _, err := m.conn.cmd(m.timeout, "UID MOVE %d %s", u, q); err == nil {
		return nil
	}
	if _, err := m.conn.cmd(m.timeout, "UID COPY %d %s", u, q); err != nil {
		return fmt.Errorf("copy to %s: %w", folder, err)
	}
	_, err = m.conn.cmd(m.timeout, `UID STORE %d +FLAGS.SILENT (\Deleted)`, u)
	return err
}

// Append stores a whole message (RFC 5322 bytes) in a folder, marked read --
// how a reply that was sent is filed where the person keeps that thread.
//
// The bytes go as a synchronising literal: announced, the server's "+"
// awaited, then sent -- the same exchange as a literal password.
func (m *IMAP) Append(folder string, raw []byte) error {
	q, _ := astring(EncodeFolder(folder))
	m.conn.seq++
	tag := "p" + strconv.Itoa(m.conn.seq)
	if err := m.conn.deadline(m.timeout); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(m.conn.w, "%s APPEND %s (\\Seen) {%d}\r\n", tag, q, len(raw)); err != nil {
		return err
	}
	if err := m.conn.w.Flush(); err != nil {
		return err
	}
	toks, err := m.conn.response()
	if err != nil {
		return err
	}
	if len(toks) == 0 || toks[0].kind != tokAtom || toks[0].text != "+" {
		return fmt.Errorf("the server would not take the message into %s: %s", folder, flatten(toks))
	}
	if _, err := m.conn.w.Write(raw); err != nil {
		return err
	}
	if _, err := m.conn.w.WriteString("\r\n"); err != nil {
		return err
	}
	if err := m.conn.w.Flush(); err != nil {
		return err
	}
	_, err = m.conn.collect(tag, m.timeout)
	return err
}

// ------------------------------------------------ folder names on the wire
//
// IMAP names folders in "modified UTF-7" (RFC 3501, 5.1.3): printable ASCII
// as itself except "&", which is "&-", and everything else as UTF-16 in
// base64 -- with "," for "/" and no padding -- between "&" and "-". A Persian
// folder name therefore arrives as "&BkUGNAYq...-", and a name typed in
// Persian has to leave that way.

var mutf7 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

// EncodeFolder is a folder name as the server spells it.
func EncodeFolder(name string) string {
	var b strings.Builder
	var run []rune
	flush := func() {
		if len(run) == 0 {
			return
		}
		u := utf16.Encode(run)
		raw := make([]byte, 0, len(u)*2)
		for _, c := range u {
			raw = append(raw, byte(c>>8), byte(c))
		}
		b.WriteByte('&')
		b.WriteString(mutf7.EncodeToString(raw))
		b.WriteByte('-')
		run = run[:0]
	}
	for _, r := range name {
		switch {
		case r == '&':
			flush()
			b.WriteString("&-")
		case r >= 0x20 && r <= 0x7e:
			flush()
			b.WriteRune(r)
		default:
			run = append(run, r)
		}
	}
	flush()
	return b.String()
}

// DecodeFolder is a folder name as a person reads it. A name that is not
// valid modified UTF-7 is returned as it came rather than lost.
func DecodeFolder(wire string) string {
	if !strings.Contains(wire, "&") {
		return wire
	}
	var b strings.Builder
	for i := 0; i < len(wire); i++ {
		if wire[i] != '&' {
			b.WriteByte(wire[i])
			continue
		}
		end := strings.IndexByte(wire[i:], '-')
		if end < 0 {
			return wire
		}
		chunk := wire[i+1 : i+end]
		i += end
		if chunk == "" {
			b.WriteByte('&')
			continue
		}
		raw, err := mutf7.DecodeString(chunk)
		if err != nil || len(raw)%2 != 0 {
			return wire
		}
		u := make([]uint16, len(raw)/2)
		for j := range u {
			u[j] = uint16(raw[2*j])<<8 | uint16(raw[2*j+1])
		}
		b.WriteString(string(utf16.Decode(u)))
	}
	return b.String()
}
