package mailbox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"
)

// Message is one email, read out of its wire format.
//
// EVERYTHING HERE IS ATTACKER-CONTROLLED. This is the one part of the
// application whose input arrives from strangers: anyone who knows the
// address can put bytes into this parser, choose the filename on an
// attachment, and write whatever they like in a header. So every limit below
// is a real limit and not a sanity check, and nothing here trusts a declared
// length, a declared type or a declared name.
type Message struct {
	// UIDL is the server's permanent unique id for this message.
	//
	// The only stable handle POP3 offers. A message's NUMBER is its position
	// in the mailbox and shifts whenever anything is removed, so nothing
	// outside the client should use one: key a cache, a read-state record
	// or a link by this instead.
	UIDL    string
	Subject string
	From    string // display name and address, as written
	Addr    string // just the address, lowercased, for matching
	To      string
	Cc      string
	// Via is the mailboxes the message was delivered to before this one, read
	// off the "Received: ... for <address>" trail, lowercased: the addresses
	// it was forwarded here from. This mailbox's own address is left out.
	Via []string
	// MessageID and References are what a reply to it threads on.
	MessageID  string
	References string
	Date       time.Time
	Body       string
	HTML       bool // the body came from text/html and was reduced to text
	Seen       bool
	Size       int64

	Attachments []Attachment

	// NamedParts is how many files the message carries, counted from the
	// server's own description of its structure rather than from the bytes in
	// Attachments.
	//
	// The two differ in exactly one case, and it is the common one: a LISTING
	// fetches only the first few kilobytes of each message, so Attachments is
	// empty even for a message carrying three PDFs. The list needs the number
	// to decide whether to draw a paperclip, and that number has to come from
	// somewhere other than bytes it deliberately did not fetch.
	//
	// For a whole message the two agree, and this is simply len(Attachments).
	NamedParts int
}

// Attachment is one file that arrived with a message.
type Attachment struct {
	Name string // the sender's name for it, decoded but NOT yet safe as a path
	Type string
	Size int
	Data []byte
}

const (
	// maxBodyBytes bounds the text kept from one message.
	//
	// Generous for prose and far below what a mail server will accept, which
	// is the point: the body is held in memory and usually shown, searched or
	// classified, and none of those wants a 40 MB text part.
	maxBodyBytes = 1 << 20

	// maxAttachmentBytes bounds one attachment, and maxAttachmentsTotal the
	// whole message. Both are needed: twenty files of 20 MB is not twenty
	// separate problems, it is one.
	maxAttachmentBytes  = 25 << 20
	maxAttachmentsTotal = 60 << 20

	// maxAttachments bounds the COUNT, which the byte caps do not. A message
	// carrying ten thousand one-byte parts costs nothing to send and would
	// otherwise cost ten thousand allocations and ten thousand files.
	maxAttachments = 50

	// maxDepth bounds multipart nesting. A message may legitimately be
	// mixed-inside-alternative-inside-signed, which is three; anything past
	// this is either broken or built to be.
	maxDepth = 12
)

// errTooDeep is returned when nesting passes maxDepth. The message is still
// usable -- whatever was parsed before the limit is kept.
var errTooDeep = errors.New("multipart nesting too deep")

// wordDecoder decodes RFC 2047 encoded-words in headers: the
// =?UTF-8?B?...?= that a subject in any non-Latin script arrives as.
//
// The CharsetReader matters more here than anywhere else in this file. Go
// handles UTF-8 and ASCII alone; a Persian subject line from an older Windows
// client arrives as windows-1256, and without this it comes through as
// mojibake -- which is not a cosmetic problem, because the subject is part of
// what is searched and filed.
var wordDecoder = mime.WordDecoder{CharsetReader: charsetReader}

// charsetReader converts a labelled charset to UTF-8.
//
// Unknown charsets are passed through unchanged rather than refused. A
// message with a charset nobody has heard of is still a message, and the
// bytes are usually ASCII-compatible anyway; failing the whole parse over the
// label would lose a message that is perfectly readable.
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	label = strings.TrimSpace(strings.ToLower(label))
	switch label {
	case "", "utf-8", "utf8", "us-ascii", "ascii", "default":
		return input, nil
	}
	enc, err := ianaindex.MIME.Encoding(label)
	if err != nil || enc == nil {
		// Also try the IANA index proper: some senders write "cp1256" or
		// "win-1256", which the MIME index does not carry but IANA does.
		if enc2, err2 := ianaindex.IANA.Encoding(label); err2 == nil && enc2 != nil {
			return transform.NewReader(input, enc2.NewDecoder()), nil
		}
		return input, nil
	}
	return transform.NewReader(input, enc.NewDecoder()), nil
}

// decodeHeader turns a raw header value into readable text.
func decodeHeader(v string) string {
	if v == "" {
		return ""
	}
	out, err := wordDecoder.DecodeHeader(v)
	if err != nil {
		// A malformed encoded-word is not a reason to lose the header. The
		// raw form is at worst ugly and at best already readable.
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(out)
}

// Parse reads one message from its raw RFC 5322 bytes.
//
// It does not fail on a malformed message. A mailbox contains what people and
// their software actually send, which includes messages that violate the
// specification in ways no parser can refuse without losing mail somebody
// needs to read -- so a part that cannot be decoded is skipped and the rest
// is kept, and an unreadable body leaves Body empty rather than returning an
// error. The only error returned is for bytes that are not a message at all.
func Parse(raw []byte) (*Message, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	msg := &Message{
		Subject: decodeHeader(m.Header.Get("Subject")),
		From:    decodeHeader(m.Header.Get("From")),
		To:      decodeHeader(m.Header.Get("To")),
		Cc:      decodeHeader(m.Header.Get("Cc")),
		Size:    int64(len(raw)),
	}
	msg.Addr = addressOf(m.Header.Get("From"))
	msg.Via = deliveredVia(m.Header)
	msg.MessageID = strings.TrimSpace(m.Header.Get("Message-Id"))
	msg.References = strings.TrimSpace(m.Header.Get("References"))
	if t, err := m.Header.Date(); err == nil {
		msg.Date = t
	}

	ct := m.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	// The part walk collects into the message. An error from it means the
	// structure was too deep or unreadable, not that there is nothing to
	// show -- so whatever was gathered is kept either way.
	_ = walkPart(msg, ct, m.Header.Get("Content-Transfer-Encoding"),
		m.Header.Get("Content-Disposition"), m.Body, 0)

	msg.Body = strings.TrimSpace(msg.Body)
	return msg, nil
}

// addressOf pulls the bare address out of a From header.
func addressOf(v string) string {
	if a, err := mail.ParseAddress(v); err == nil {
		return strings.ToLower(strings.TrimSpace(a.Address))
	}
	// A From header that will not parse still usually contains an address in
	// angle brackets; that is worth one look before giving up, because the
	// address is what everything downstream matches on.
	if i, j := strings.LastIndex(v, "<"), strings.LastIndex(v, ">"); i >= 0 && j > i {
		return strings.ToLower(strings.TrimSpace(v[i+1 : j]))
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// walkPart descends one MIME part, gathering text and attachments.
func walkPart(msg *Message, contentType, encoding, disposition string, body io.Reader, depth int) error {
	if depth > maxDepth {
		return errTooDeep
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// An unparseable Content-Type is treated as plain text, which is what
		// it most often is -- a client that wrote the header badly, not a
		// client that sent something exotic.
		mediaType, params = "text/plain", map[string]string{}
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return nil // multipart with no boundary: nothing can be read
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextPart()
			if err != nil {
				// io.EOF ends the loop; anything else means the message is
				// truncated or malformed, and the parts already read are
				// still worth keeping.
				break
			}
			err = walkPart(msg,
				part.Header.Get("Content-Type"),
				part.Header.Get("Content-Transfer-Encoding"),
				part.Header.Get("Content-Disposition"),
				part, depth+1)
			part.Close()
			if errors.Is(err, errTooDeep) {
				return err
			}
		}
		return nil
	}

	// A leaf part. Whether it is an attachment is decided by the disposition
	// and by whether it carries a filename -- NOT by its media type. An
	// attached .txt is still an attachment, and an inline image with a name
	// is still a file that arrived.
	name := partName(disposition, params)
	disp, _, _ := mime.ParseMediaType(disposition)
	isAttachment := disp == "attachment" || name != ""

	if isAttachment {
		return takeAttachment(msg, mediaType, encoding, name, body)
	}

	switch mediaType {
	case "text/plain":
		text := readText(encoding, params["charset"], body)
		appendBody(msg, text, false)
	case "text/html":
		// Only if nothing better turned up. A multipart/alternative carries
		// both, the plain part comes first, and the plain part is the one
		// the sender wrote.
		if msg.Body == "" {
			appendBody(msg, htmlToText(readText(encoding, params["charset"], body)), true)
		}
	}
	return nil
}

// partName finds the sender's filename for a part.
func partName(disposition string, ctParams map[string]string) string {
	if disposition != "" {
		if _, params, err := mime.ParseMediaType(disposition); err == nil {
			if n := params["filename"]; n != "" {
				return decodeHeader(n)
			}
		}
	}
	// Some clients put the name only on the Content-Type, which is older
	// practice but still common from ERP systems that generate mail.
	if n := ctParams["name"]; n != "" {
		return decodeHeader(n)
	}
	return ""
}

// decodeBody wraps a reader in whatever transfer encoding was declared.
func decodeBody(encoding string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// Newline-tolerant: base64 in mail is wrapped at 76 columns, and
		// some senders wrap it badly. A decoder that stops at the first
		// unexpected byte loses the rest of the file.
		return newTolerantBase64(r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// readText decodes one text part to a UTF-8 string.
func readText(encoding, charset string, r io.Reader) string {
	dec := decodeBody(encoding, r)
	conv, err := charsetReader(charset, dec)
	if err != nil {
		conv = dec
	}
	b, _ := io.ReadAll(io.LimitReader(conv, maxBodyBytes))
	return string(b)
}

// appendBody adds text to the message body.
//
// Line endings are normalised to LF first. Mail carries CRLF, and a page that
// shows the body with white-space:pre-wrap -- where a stray CR is a segment
// break in some engines and not in others, so the same message reads
// single-spaced in one browser and double-spaced in the next. Normalising
// once here settles it for every reader rather than in each of them.
func appendBody(msg *Message, text string, fromHTML bool) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	if msg.Body != "" {
		// More than one text part is normal -- a forwarded message inside a
		// reply, say -- and they are joined rather than fought over.
		if len(msg.Body)+len(text) > maxBodyBytes {
			return
		}
		msg.Body += "\n\n" + text
		return
	}
	msg.Body = text
	msg.HTML = fromHTML
}

// takeAttachment reads one attached file into memory.
//
// Into memory, and capped, because the caller decides where these go: the
// pipeline writes them to disk under a name IT chooses, and the sender's name
// never reaches the filesystem unexamined. Streaming straight to a file would
// mean choosing that name here, at the point that knows least about it.
func takeAttachment(msg *Message, mediaType, encoding, name string, body io.Reader) error {
	if len(msg.Attachments) >= maxAttachments {
		return nil
	}
	var used int
	for _, a := range msg.Attachments {
		used += a.Size
	}
	room := maxAttachmentsTotal - used
	if room <= 0 {
		return nil
	}
	if room > maxAttachmentBytes {
		room = maxAttachmentBytes
	}

	// Read one byte past the cap so that hitting it exactly is
	// distinguishable from a file that happens to be that size.
	data, _ := io.ReadAll(io.LimitReader(decodeBody(encoding, body), int64(room)+1))
	if len(data) > room {
		// Truncated rather than dropped: a name and a type that say "this
		// arrived and was too big" is more use to somebody reading the message
		// than a file that silently is not there.
		msg.Attachments = append(msg.Attachments, Attachment{
			Name: name, Type: mediaType, Size: len(data) - 1, Data: nil,
		})
		return nil
	}
	if name == "" {
		name = "attachment"
	}
	msg.Attachments = append(msg.Attachments, Attachment{
		Name: name, Type: mediaType, Size: len(data), Data: data,
	})
	return nil
}

// ---------------------------------------------------------------- HTML

var (
	// Script and style hold text that is not prose. Removed whole, with their
	// contents, before any tag stripping -- otherwise a stylesheet's rules
	// end up in the body as words.
	//
	// Spelled out per tag rather than as <(script|style|head)>...</\1>,
	// because Go's regexp is RE2 and RE2 has no backreferences -- by design,
	// since they are what makes a pattern able to take exponential time, and
	// this one reads bytes that arrive from strangers.
	htmlDrop = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>` +
		`|<style\b[^>]*>.*?</style\s*>` +
		`|<head\b[^>]*>.*?</head\s*>`)
	htmlBreak = regexp.MustCompile(`(?i)<(br|/p|/div|/tr|/h[1-6]|/li)\b[^>]*>`)
	htmlTag   = regexp.MustCompile(`(?s)<[^>]*>`)
	htmlBlank = regexp.MustCompile(`\n{3,}`)
)

// htmlToText reduces an HTML body to the words in it.
//
// Not a renderer and not trying to be. The result is read by a person, a
// search index or a classifier, and all want the sentences: what matters is
// that block boundaries become line breaks rather than running two paragraphs
// into one word, and that markup never reaches any of them as text.
func htmlToText(s string) string {
	s = htmlDrop.ReplaceAllString(s, " ")
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = htmlTag.ReplaceAllString(s, "")
	// Entities last, so that a &lt; written by the sender is not then read as
	// the start of a tag -- which is how a stripper turns text into silence.
	s = htmlUnescape(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var lines []string
	for ln := range strings.SplitSeq(s, "\n") {
		lines = append(lines, strings.TrimSpace(ln))
	}
	s = strings.Join(lines, "\n")
	return strings.TrimSpace(htmlBlank.ReplaceAllString(s, "\n\n"))
}

var htmlEntities = strings.NewReplacer(
	"&nbsp;", " ", "&#160;", " ",
	"&lt;", "<", "&gt;", ">",
	"&quot;", `"`, "&#34;", `"`,
	"&apos;", "'", "&#39;", "'",
	"&zwnj;", "‌", // Persian needs this one: it separates letters within a word
	"&amp;", "&", "&#38;", "&", // last: an entity written &amp;lt; is text, not a tag
)

func htmlUnescape(s string) string { return htmlEntities.Replace(s) }

var (
	emailIn     = regexp.MustCompile(`[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	receivedFor = regexp.MustCompile(`(?i)\bfor\s+<?([A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?`)
)

// deliveredVia reads the mailboxes a message passed through from its Received
// trail ("for <x>"), leaving out the one it finally arrived in -- the envelope
// recipient, which is this mailbox. Mail forwarded into a shared mailbox says
// here which address it was first sent to.
func deliveredVia(h mail.Header) []string {
	final := map[string]bool{}
	for _, k := range []string{"X-Envelope-To", "Envelope-To", "Delivered-To", "X-Original-To"} {
		for _, v := range h[k] {
			for _, a := range emailIn.FindAllString(v, -1) {
				final[strings.ToLower(a)] = true
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, v := range h["Received"] {
		for _, m := range receivedFor.FindAllStringSubmatch(v, -1) {
			a := strings.ToLower(m[1])
			if final[a] || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
