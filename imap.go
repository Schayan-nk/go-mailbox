package mailbox

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// IMAP is a signed-in session on one mailbox.
//
// For the mailboxes POP3 cannot serve: an account a desktop client also reads
// -- over POP3 the client empties the server's inbox, and over IMAP both see
// the same folders -- and anything that reads one folder and files into
// another.
//
// It answers Reader's five questions (reader.go) with UIDLs of
// the form "<uidvalidity>.<uid>": unique within the account, and stable for as
// long as the server keeps the folder's UIDVALIDITY, which is what a POP3 UIDL
// promises too -- so a read-state record or a preview cache keyed by them
// works for both protocols.
type IMAP struct {
	conn     *imapConn
	timeout  time.Duration
	box      string
	validity uint32
	uids     []uint32
}

// OpenIMAP connects, signs in and selects the mailbox (INBOX unless the
// configuration names another), and lists its messages.
//
// One function because there is nothing useful to do between those steps, and
// because it means the password is written in exactly one place.
func OpenIMAP(cfg Config) (*IMAP, error) {
	if !cfg.Enabled() {
		return nil, fmt.Errorf("the mailbox is not configured: set %s",
			strings.Join(cfg.Validate(), ", "))
	}
	port := cfg.IMAPPort
	if port <= 0 {
		port = 993
	}
	conn, err := dialIMAP(cfg.IMAPHost, port, defaultTimeout, cfg.DialControl)
	if err != nil {
		return nil, err
	}
	m := &IMAP{conn: conn, timeout: defaultTimeout}
	if err := m.login(cfg.Address, cfg.Password); err != nil {
		conn.Close()
		// The server's own words, minus anything that could be the password.
		// A sign-in failure is the most common thing to go wrong here and the
		// reason is the useful half -- but "LOGIN failed" must never come
		// back carrying what was sent.
		return nil, fmt.Errorf("sign in as %s: %w", cfg.Address, err)
	}
	box := cfg.Mailbox
	if box == "" {
		box = "INBOX"
	}
	if err := m.selectBox(box); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *IMAP) Close() error {
	// LOGOUT rather than just closing the socket. A server that is told
	// goodbye releases the session immediately; one that is dropped keeps it
	// until a timeout, and mail hosts cap concurrent sessions per account --
	// so a poll every fifteen minutes that never logs out eventually cannot
	// connect at all.
	_, _ = m.conn.cmd(5*time.Second, "LOGOUT")
	return m.conn.Close()
}

// login authenticates.
func (m *IMAP) login(user, pass string) error {
	u, uLit := astring(user)
	p, pLit := astring(pass)
	if !uLit && !pLit {
		_, err := m.conn.cmd(m.timeout, "LOGIN %s %s", u, p)
		return err
	}
	// A password with a newline, a NUL or a non-ASCII byte in it cannot be a
	// quoted string, so it goes as a literal -- which means announcing the
	// length, waiting for the server's "+", and only then sending the bytes.
	return m.loginLiteral(user, pass)
}

// loginLiteral sends LOGIN with the password as a synchronising literal.
func (m *IMAP) loginLiteral(user, pass string) error {
	m.conn.seq++
	tag := "d" + strconv.Itoa(m.conn.seq)
	u, _ := astring(user)

	if err := m.conn.deadline(m.timeout); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(m.conn.w, "%s LOGIN %s {%d}\r\n", tag, u, len(pass)); err != nil {
		return err
	}
	if err := m.conn.w.Flush(); err != nil {
		return err
	}
	// Exactly one response is expected here and it must be the continuation.
	// Anything else -- usually a tagged NO, because the server disliked the
	// command before the password was even sent -- is reported as it came.
	toks, err := m.conn.response()
	if err != nil {
		return err
	}
	if len(toks) == 0 || toks[0].kind != tokAtom || toks[0].text != "+" {
		return fmt.Errorf("server did not accept a literal password: %s", flatten(toks))
	}
	if _, err := fmt.Fprintf(m.conn.w, "%s\r\n", pass); err != nil {
		return err
	}
	if err := m.conn.w.Flush(); err != nil {
		return err
	}
	_, err = m.conn.collect(tag, m.timeout)
	return err
}

// selectBox opens a mailbox, notes its UIDVALIDITY and lists its messages.
//
// The name goes out in IMAP's modified UTF-7, so a folder called «مشتریان
// جدید» is opened by the name the server knows it by.
func (m *IMAP) selectBox(box string) error {
	q, _ := astring(EncodeFolder(box))
	res, err := m.conn.cmd(m.timeout, "SELECT %s", q)
	if err != nil {
		return fmt.Errorf("open mailbox %q: %w", box, err)
	}
	m.box, m.validity = box, 0
	for _, line := range res {
		if v := uidValidityRe.FindStringSubmatch(flatten(line)); v != nil {
			if n, err := strconv.ParseUint(v[1], 10, 32); err == nil {
				m.validity = uint32(n)
			}
		}
	}
	uids, err := m.Search(time.Time{})
	if err != nil {
		return fmt.Errorf("list mailbox %q: %w", box, err)
	}
	m.uids = uids
	return nil
}

var uidValidityRe = regexp.MustCompile(`(?i)UIDVALIDITY\s+(\d+)`)

// Folders lists the mailboxes on the account.
//
// Worth having for more than diagnostics. "INBOX" is the only folder name
// guaranteed to exist, and everything else is the provider's or the account
// holder's invention -- providers disagree about whether
// sent mail lives in "Sent", "Sent Items", "INBOX.Sent" or
// "[Gmail]/Sent Mail". Anything that wants to read a second folder has to ask
// rather than assume.
func (m *IMAP) Folders() ([]string, error) {
	res, err := m.conn.cmd(m.timeout, `LIST "" "*"`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range res {
		if len(line) == 0 || line[0].kind != tokAtom || !strings.EqualFold(line[0].text, "LIST") {
			continue
		}
		// The shape is: LIST (flags) "delimiter" name. The name is last, and
		// taking it from the end avoids having to parse the flag list or the
		// delimiter -- either of which a server may write in several ways.
		last := line[len(line)-1]
		switch last.kind {
		case tokString, tokAtom:
			if last.text != "" {
				out = append(out, DecodeFolder(last.text))
			}
		case tokLiteral:
			out = append(out, DecodeFolder(string(last.data)))
		}
	}
	return out, nil
}

// SentFolder is the folder the account keeps its sent mail in: the one the
// server flags \Sent (RFC 6154), else the first of
// the usual names that exists, else "".
func (m *IMAP) SentFolder() (string, error) {
	res, err := m.conn.cmd(m.timeout, `LIST "" "*"`)
	if err != nil {
		return "", err
	}
	var names []string
	for _, line := range res {
		if len(line) < 2 || line[0].kind != tokAtom || !strings.EqualFold(line[0].text, "LIST") {
			continue
		}
		name := ""
		switch last := line[len(line)-1]; last.kind {
		case tokString, tokAtom:
			name = DecodeFolder(last.text)
		case tokLiteral:
			name = DecodeFolder(string(last.data))
		}
		if name == "" {
			continue
		}
		for _, t := range line[1:] {
			if t.kind == tokRParen {
				break
			}
			if t.kind == tokAtom && strings.EqualFold(t.text, `\Sent`) {
				return name, nil
			}
		}
		names = append(names, name)
	}
	for _, want := range []string{"Sent Items", "Sent", "Sent Messages", "INBOX.Sent", "Gesendete Objekte", "Gesendet"} {
		for _, n := range names {
			if strings.EqualFold(n, want) {
				return n, nil
			}
		}
	}
	// Nested under INBOX ("INBOX.Sent Items", "INBOX/Sent") or named in
	// Persian: the last part of the name, against the same words.
	for _, n := range names {
		if sentFolderWord(n) {
			return n, nil
		}
	}
	return "", nil
}

// sentFolderWords are what a Sent folder's own name says, folded to lower case.
var sentFolderWords = []string{"sent", "sent items", "sent messages", "sent mail", "sent-mail",
	"ارسال شده", "ارسال‌شده", "موارد ارسالی", "موارد ارسال شده", "پیام های ارسالی", "پیام‌های ارسالی", "ارسالی"}

// SentFolderWord says whether a folder's name, or its last part, names a
// Sent folder.
func SentFolderWord(name string) bool { return sentFolderWord(name) }

func sentFolderWord(name string) bool {
	last := name
	if i := strings.LastIndexAny(name, "./"); i >= 0 {
		last = name[i+1:]
	}
	last = strings.ToLower(strings.TrimSpace(last))
	for _, w := range sentFolderWords {
		if last == w {
			return true
		}
	}
	return false
}

// Select opens a different mailbox on the same connection.
func (m *IMAP) Select(box string) error { return m.selectBox(box) }

// Search returns the UIDs of messages received on or after since.
//
// UIDs rather than sequence numbers. A sequence number is the message's
// position in the mailbox RIGHT NOW: delete one message and every number
// after it shifts down, so a number read in one command can address a
// different message in the next. A UID never moves and never repeats.
//
// A zero time searches the whole mailbox.
func (m *IMAP) Search(since time.Time) ([]uint32, error) {
	cmd := "UID SEARCH ALL"
	if !since.IsZero() {
		// SINCE takes a date and compares dates only -- there is no way to
		// ask for "since this hour" -- so the day is rounded down. Fetching a
		// few already-seen messages is harmless; missing one is not.
		cmd = "UID SEARCH SINCE " + since.Format("2-Jan-2006")
	}
	res, err := m.conn.cmd(m.timeout, "%s", cmd)
	if err != nil {
		return nil, err
	}
	var uids []uint32
	for _, line := range res {
		if len(line) == 0 || line[0].kind != tokAtom || !strings.EqualFold(line[0].text, "SEARCH") {
			continue
		}
		for _, t := range line[1:] {
			if t.kind != tokAtom {
				continue
			}
			if n, err := strconv.ParseUint(t.text, 10, 32); err == nil {
				uids = append(uids, uint32(n))
			}
		}
	}
	slices.Sort(uids)
	return uids, nil
}

// maxBatch bounds one FETCH.
//
// The server answers a fetch in full before the tagged completion, so the
// whole batch is in memory at once. Headers are small, but a hundred of them
// from a mailbox full of long threads is still worth bounding.
const maxBatch = 100

// previewOctets is how much of each message a listing fetches.
//
// A LISTING NEEDS A LITTLE OF THE BODY, not none and not all of it. The rows
// show the first line or two of each message beneath its subject, and a
// header-only fetch cannot produce that -- it was built that way first, and
// the preview line came out empty on every row.
//
// Fetching whole messages instead would mean pulling every attachment in the
// mailbox to render a list, which for two hundred messages is hundreds of
// megabytes to show a column of subjects.
//
// So a partial fetch: the first 8 KB of each. That covers the headers, the
// MIME boundary and the beginning of the first text part, which is exactly
// what a preview is made of. Parsing stops wherever the bytes stop -- the
// parser already keeps whatever it read before a truncated part, because
// real mailboxes contain truncated messages anyway.
const previewOctets = 8192

// Headers fetches enough of each message to list it.
//
// BODY.PEEK rather than BODY: reading with BODY sets \Seen as a side effect,
// so merely listing the mailbox would mark every message read in the owner's
// other mail clients. PEEK is the same fetch without that.
func (m *IMAP) Headers(uids []uint32) ([]*Message, error) {
	// BODYSTRUCTURE as well, for the paperclip.
	//
	// The partial fetch above covers the first 8 KB, and an attachment sits
	// well past that -- so counting attachments from those bytes reports none
	// on every row, which is what the first version did. BODYSTRUCTURE is the
	// server describing the whole message's shape without sending it, which
	// is exactly the question being asked.
	items := fmt.Sprintf(
		"(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[]<0.%d>)", previewOctets)
	var out []*Message
	for start := 0; start < len(uids); start += maxBatch {
		end := min(start+maxBatch, len(uids))
		// The response names a partial body as BODY[]<0>, carrying the octet
		// it started at. fetchBatch falls back to the line's only literal if
		// a server spells that differently.
		batch, err := m.fetchBatch(uids[start:end], items, "BODY[]<0>")
		if err != nil {
			return out, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

// messageByUID fetches one whole message, body and attachments included.
func (m *IMAP) messageByUID(uid uint32) (*Message, error) {
	got, err := m.fetchBatch([]uint32{uid}, "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])", "BODY[]")
	if err != nil {
		return nil, err
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("message %d is not in %s", uid, m.box)
	}
	return got[0], nil
}

// fetchBatch runs one UID FETCH and parses what comes back.
//
// bodyKey names the item carrying the bytes -- "BODY[HEADER]" for a listing,
// "BODY[]" for a whole message. Deliberately never BODY[HEADER.FIELDS (...)]:
// that response key contains spaces and parentheses, which would have to be
// special-cased in the tokeniser, and fetching the whole header instead costs
// a few hundred bytes and removes the special case.
func (m *IMAP) fetchBatch(uids []uint32, items, bodyKey string) ([]*Message, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	set := make([]string, len(uids))
	for i, u := range uids {
		set[i] = strconv.FormatUint(uint64(u), 10)
	}
	res, err := m.conn.cmd(m.timeout, "UID FETCH %s %s", strings.Join(set, ","), items)
	if err != nil {
		return nil, err
	}

	var out []*Message
	for _, line := range res {
		if !isFetch(line) {
			continue
		}
		body, ok := itemLiteral(line, bodyKey)
		if !ok {
			// A FETCH with no body part is not an error: servers send
			// unsolicited FETCH responses to announce a flag change, and one
			// of those arriving mid-command is normal.
			continue
		}
		msg, err := Parse(body)
		if err != nil {
			// One unparseable message must not lose the other ninety-nine.
			continue
		}
		if u, ok := itemNumber(line, "UID"); ok {
			msg.UIDL = m.uidl(uint32(u))
		}
		if n, ok := itemNumber(line, "RFC822.SIZE"); ok {
			msg.Size = int64(n)
		}
		msg.Seen = hasFlag(line, `\Seen`)
		// A listing's partial fetch cannot see the attachments, so the count
		// it produced is not the message's -- it is the count within the
		// first few kilobytes, which is nearly always zero. Where the server
		// described the structure, that is the better answer.
		if n, ok := namedParts(line); ok && len(msg.Attachments) < n {
			msg.NamedParts = n
		} else {
			msg.NamedParts = len(msg.Attachments)
		}
		// INTERNALDATE is when the SERVER received it, and is used only when
		// the message carries no Date header of its own or carries one that
		// will not parse -- which spam routinely does, and which would
		// otherwise sort those to the year zero.
		if msg.Date.IsZero() {
			if s, ok := itemString(line, "INTERNALDATE"); ok {
				if t, err := time.Parse("02-Jan-2006 15:04:05 -0700", s); err == nil {
					msg.Date = t
				}
			}
		}
		out = append(out, msg)
	}
	return out, nil
}

// Trash moves a message to the account's trash folder.
//
// MOVED, NEVER DELETED. There is no expunge here and there must not be one:
// the trash icon in every mail client means "put this where I can get it back
// from", and a control that quietly destroyed a customer's letter instead
// would be the same shape on screen and a different thing entirely.
//
// UID MOVE first, because it is atomic -- the server copies, flags and
// expunges the original in one step, and a connection dropped halfway cannot
// leave the message in both folders. Servers without that extension (RFC
// 6851) get COPY, then \Deleted on the original, which is the pre-2013 way of
// saying the same thing. Still no expunge: the copy is safely in the trash,
// and the original is marked in the way every client already hides.
//
// The destination is found rather than assumed. Many call it "Trash",
// Exchange "Deleted Items" and Gmail "[Gmail]/Trash", so a hardcoded name
// would work in testing and fail at somebody else's provider.
func (m *IMAP) Trash(uid uint32) error {
	dest, err := m.trashFolder()
	if err != nil {
		return err
	}
	q, _ := astring(dest)
	if _, err := m.conn.cmd(m.timeout, "UID MOVE %d %s", uid, q); err == nil {
		return nil
	}
	// No MOVE: copy, then mark the original deleted.
	if _, err := m.conn.cmd(m.timeout, "UID COPY %d %s", uid, q); err != nil {
		return fmt.Errorf("copy to %s: %w", dest, err)
	}
	_, err = m.conn.cmd(m.timeout, `UID STORE %d +FLAGS.SILENT (\Deleted)`, uid)
	return err
}

// trashFolderNames are what providers call it, in the order to prefer them.
var trashFolderNames = []string{
	"Trash", "Deleted Items", "Deleted Messages", "[Gmail]/Trash", "INBOX.Trash",
}

// trashFolder finds the account's trash, or says it could not.
//
// Refusing is the right answer when there is none: creating a folder on
// somebody's mail account because a button was pressed is a bigger decision
// than the button was offering to make.
func (m *IMAP) trashFolder() (string, error) {
	boxes, err := m.Folders()
	if err != nil {
		return "", err
	}
	for _, want := range trashFolderNames {
		for _, b := range boxes {
			if strings.EqualFold(b, want) {
				return b, nil
			}
		}
	}
	// Last resort: anything whose name contains "trash" or "deleted", which
	// catches a localised name an English list cannot.
	for _, b := range boxes {
		lb := strings.ToLower(b)
		if strings.Contains(lb, "trash") || strings.Contains(lb, "deleted") {
			return b, nil
		}
	}
	return "", errors.New("this account has no trash folder")
}

// MarkSeen sets the \Seen flag on the server.
//
// On the SERVER, so that a message read here is read in every other client too.
// Keeping "read" in a local file instead would give the same person two
// inboxes that disagree about what they have already looked at.
func (m *IMAP) MarkSeen(uid uint32, seen bool) error {
	op := "+FLAGS.SILENT"
	if !seen {
		op = "-FLAGS.SILENT"
	}
	_, err := m.conn.cmd(m.timeout, `UID STORE %d %s (\Seen)`, uid, op)
	return err
}

// ---------------------------------------------------------- FETCH reading

// isFetch reports whether an untagged line is a FETCH response.
//
// The shape is "<sequence number> FETCH (...)", so FETCH is the second token.
func isFetch(line []token) bool {
	return len(line) >= 2 && line[1].kind == tokAtom && strings.EqualFold(line[1].text, "FETCH")
}

// itemAfter finds the token following a named item.
func itemAfter(line []token, key string) (token, bool) {
	for i := 0; i < len(line)-1; i++ {
		if line[i].kind == tokAtom && strings.EqualFold(line[i].text, key) {
			return line[i+1], true
		}
	}
	return token{}, false
}

func itemLiteral(line []token, key string) ([]byte, bool) {
	if t, ok := itemAfter(line, key); ok {
		switch t.kind {
		case tokLiteral:
			return t.data, true
		case tokString:
			// A short part can legitimately come back as a quoted string
			// rather than a literal, and an empty body is exactly that case.
			return []byte(t.text), true
		}
	}
	// THE KEY IS NOT ALWAYS SPELLED THE WAY IT WAS ASKED FOR. A partial fetch
	// of BODY.PEEK[]<0.8192> comes back as BODY[]<0> on most servers and as
	// BODY[] on some, and there is no point growing a list of spellings: a
	// FETCH response to any of these commands carries exactly one literal,
	// and it is the message. So take it.
	for _, t := range line {
		if t.kind == tokLiteral {
			return t.data, true
		}
	}
	return nil, false
}

func itemNumber(line []token, key string) (uint64, bool) {
	t, ok := itemAfter(line, key)
	if !ok || t.kind != tokAtom {
		return 0, false
	}
	n, err := strconv.ParseUint(t.text, 10, 64)
	return n, err == nil
}

func itemString(line []token, key string) (string, bool) {
	t, ok := itemAfter(line, key)
	if !ok {
		return "", false
	}
	if t.kind == tokString || t.kind == tokAtom {
		return t.text, true
	}
	return "", false
}

// namedParts counts the files a message carries, from its BODYSTRUCTURE.
//
// NOT A FULL PARSE, deliberately. BODYSTRUCTURE is a deeply nested list whose
// exact shape varies with the part type, and writing a complete parser for it
// would be several hundred lines to answer a yes-or-no question about a
// paperclip. What actually marks a part as a file is a parameter called NAME
// or FILENAME, so the flat token stream is scanned for those -- the
// tokeniser has already done the hard part by tracking literals and quoting.
//
// This counts inline images too, which is right rather than a compromise: an
// embedded signature logo IS a file that arrived, and the reading pane lists
// it as one. The list and the opened message therefore agree, which they
// would not if one of them quietly skipped inline parts.
//
// The second return distinguishes "no structure in this response" from "a
// structure with nothing named in it" -- the first means fall back to
// counting bytes, the second means the answer really is none.
func namedParts(line []token) (int, bool) {
	start := -1
	for i, t := range line {
		if t.kind == tokAtom && strings.EqualFold(t.text, "BODYSTRUCTURE") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return 0, false
	}
	n := 0
	for _, t := range line[start:] {
		// A parameter name arrives as a quoted string; the value after it is
		// the filename. Counting the keys counts the parts that have one.
		if t.kind == tokString &&
			(strings.EqualFold(t.text, "NAME") || strings.EqualFold(t.text, "FILENAME")) {
			n++
		}
	}
	// A part can carry both NAME (on the type) and FILENAME (on the
	// disposition), which would count it twice. Halving is wrong when only
	// one of the two is present, so take the larger of the halves -- for one
	// key it gives 1, for both it gives 1, and for three files with both keys
	// it gives 3.
	if n > 1 {
		if half := (n + 1) / 2; half > 0 {
			return half, true
		}
	}
	return n, true
}

// hasFlag reports whether a flag is set, reading only the FLAGS list.
//
// Scoped to that list rather than searched for across the whole response,
// because "\Seen" as a bare word can appear elsewhere -- in a PERMANENTFLAGS
// announcement, say -- and a listing that reports every message as read
// because of one is worse than one that reports none.
func hasFlag(line []token, flag string) bool {
	for i := 0; i < len(line)-1; i++ {
		if line[i].kind != tokAtom || !strings.EqualFold(line[i].text, "FLAGS") {
			continue
		}
		if line[i+1].kind != tokLParen {
			continue
		}
		for _, t := range line[i+2:] {
			if t.kind == tokRParen {
				return false
			}
			if t.kind == tokAtom && strings.EqualFold(t.text, flag) {
				return true
			}
		}
	}
	return false
}
