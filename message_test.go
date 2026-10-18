package mailbox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// raw assembles a message from headers and a body, with the CRLF line endings
// that actually come off the wire. Tests written with bare newlines pass
// against a parser that would fail on real mail.
func raw(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n"))
}

// A Persian subject survives its encoded-word.
//
// Every subject that is not Latin arrives as RFC 2047 -- =?UTF-8?B?...?= --
// and the subject is not decoration: it is the whole of what a message list
// shows.
func TestAPersianSubjectIsDecoded(t *testing.T) {
	want := "درخواست پیش‌فاکتور"
	enc := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(want)) + "?="

	m, err := Parse(raw(
		"From: Nima <n.karimi@example.com>",
		"Subject: "+enc,
		"Content-Type: text/plain; charset=utf-8",
		"",
		"salam",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Subject != want {
		t.Errorf("subject is %q, want %q", m.Subject, want)
	}
	if m.Addr != "n.karimi@example.com" {
		t.Errorf("address is %q", m.Addr)
	}
}

// A subject in windows-1256 is decoded too.
//
// This is the case Go does NOT handle on its own: its word decoder knows
// UTF-8 and ASCII, and an older Windows mail client in this region sends
// Arabic script as windows-1256. Without a charset reader wired in it comes
// through as mojibake, which is not cosmetic -- it is what then gets
// searched and filed.
func TestAWindows1256SubjectIsDecoded(t *testing.T) {
	// "سلام" in windows-1256.
	cp1256 := []byte{0xD3, 0xE1, 0xC7, 0xE3}
	enc := "=?windows-1256?B?" + base64.StdEncoding.EncodeToString(cp1256) + "?="

	m, err := Parse(raw("From: a@b.com", "Subject: "+enc, "", "x"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Subject != "سلام" {
		t.Errorf("subject is %q (% x), want the Persian for hello", m.Subject, m.Subject)
	}
}

// A quoted-printable Persian body is readable.
func TestAQuotedPrintableBodyIsDecoded(t *testing.T) {
	// "=D8=B3=D9=84=D8=A7=D9=85" is UTF-8 "سلام" in quoted-printable.
	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"=D8=B3=D9=84=D8=A7=D9=85",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Body != "سلام" {
		t.Errorf("body is %q, want the Persian for hello", m.Body)
	}
}

// The plain part wins over the HTML one.
//
// A multipart/alternative carries both and the plain part is what the sender
// actually typed. Reading the HTML instead means every reader gets
// markup-derived text when a cleaner version was right there.
func TestThePlainPartIsPreferredOverHTML(t *testing.T) {
	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		`Content-Type: multipart/alternative; boundary="B"`,
		"",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"the real text",
		"--B",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>the marked up text</p>",
		"--B--",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Body != "the real text" {
		t.Errorf("body is %q, want the plain part", m.Body)
	}
	if m.HTML {
		t.Error("the message is flagged as HTML-derived when a plain part was available")
	}
}

// An HTML-only message still has a readable body.
//
// Plenty of business mail is HTML with no plain alternative at all. A parser
// that only reads text/plain hands its caller an empty string for those.
func TestAnHTMLOnlyMessageIsReducedToItsWords(t *testing.T) {
	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<html><head><style>p{color:red}</style></head><body>",
		"<p>First line</p><p>Second line</p>",
		"<script>var x = 'not prose';</script>",
		"</body></html>",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !m.HTML {
		t.Error("the message is not flagged as HTML-derived")
	}
	for _, want := range []string{"First line", "Second line"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body is missing %q; it is %q", want, m.Body)
		}
	}
	// The stylesheet and the script are not prose and must not reach the body.
	for _, bad := range []string{"color:red", "not prose", "<p>", "<script"} {
		if strings.Contains(m.Body, bad) {
			t.Errorf("body still contains %q; it is %q", bad, m.Body)
		}
	}
	// Two paragraphs must not run together into one word.
	if strings.Contains(m.Body, "lineSecond") {
		t.Errorf("the paragraphs ran together: %q", m.Body)
	}
}

// An attachment is decoded even when its base64 is wrapped badly.
//
// Go's streaming base64 decoder stops at the first byte outside the alphabet
// and everything after it is lost. Mail is wrapped at 76 columns by a dozen
// clients and some of them leave trailing spaces or a stray blank line -- and
// a PDF truncated at that point does not announce itself, it just fails to
// open a week later.
func TestAnAttachmentSurvivesBadlyWrappedBase64(t *testing.T) {
	want := bytes.Repeat([]byte("PDF-payload-"), 40)
	enc := base64.StdEncoding.EncodeToString(want)

	// Wrap it, and damage the wrapping the way a bad client does: trailing
	// spaces, a blank line in the middle, and no final padding alignment.
	var b strings.Builder
	for i := 0; i < len(enc); i += 40 {
		end := min(i+40, len(enc))
		b.WriteString(enc[i:end])
		b.WriteString("   \r\n") // trailing spaces
		if i == 40 {
			b.WriteString("\r\n") // a blank line mid-stream
		}
	}

	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		`Content-Type: multipart/mixed; boundary="B"`,
		"",
		"--B",
		"Content-Type: text/plain",
		"",
		"see attached",
		"--B",
		"Content-Type: application/pdf; name=\"report.pdf\"",
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="report.pdf"`,
		"",
		b.String(),
		"--B--",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.Name != "report.pdf" {
		t.Errorf("attachment name is %q", a.Name)
	}
	if !bytes.Equal(a.Data, want) {
		t.Errorf("attachment is %d bytes, want %d -- it was truncated", len(a.Data), len(want))
	}
}

// An attachment named in an encoded-word keeps its name.
func TestAnAttachmentNameIsDecoded(t *testing.T) {
	name := "پیش‌فاکتور.pdf"
	enc := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(name)) + "?="

	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		`Content-Type: multipart/mixed; boundary="B"`,
		"",
		"--B",
		"Content-Type: application/pdf",
		`Content-Disposition: attachment; filename="`+enc+`"`,
		"",
		"x",
		"--B--",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Name != name {
		t.Errorf("attachment names are %v, want %q", names(m), name)
	}
}

// Nesting is bounded.
//
// A message may legitimately be mixed inside alternative inside signed. A
// message nested five hundred deep is either broken or built to be, and this
// parser reads bytes that anyone on the internet can send.
func TestDeepNestingIsRefusedWithoutLosingWhatWasRead(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: a@b.com\r\nSubject: t\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"B0\"\r\n\r\n")
	depth := maxDepth + 20
	for i := range depth {
		b.WriteString("--B" + itoa(i) + "\r\n")
		b.WriteString("Content-Type: multipart/mixed; boundary=\"B" + itoa(i+1) + "\"\r\n\r\n")
	}

	// It must return rather than run away, and must not panic.
	m, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Subject != "t" {
		t.Errorf("the headers were lost: subject is %q", m.Subject)
	}
}

// An oversize attachment is reported, not silently dropped.
//
// A name and a size that say "this arrived and was too big" is something a
// reader can act on. A file that is simply not there looks like the sender
// forgot it.
func TestAnOversizeAttachmentIsKeptAsARecord(t *testing.T) {
	// A part that decodes to more than the per-file cap. Written as plain
	// bytes rather than base64 so the test stays fast.
	big := strings.Repeat("x", maxAttachmentBytes+1024)

	m, err := Parse(raw(
		"From: a@b.com",
		"Subject: t",
		`Content-Type: multipart/mixed; boundary="B"`,
		"",
		"--B",
		"Content-Type: application/octet-stream",
		`Content-Disposition: attachment; filename="huge.bin"`,
		"",
		big,
		"--B--",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.Name != "huge.bin" {
		t.Errorf("name is %q", a.Name)
	}
	if a.Data != nil {
		t.Errorf("the oversize attachment kept %d bytes; it must keep none", len(a.Data))
	}
	if a.Size < maxAttachmentBytes {
		t.Errorf("size is %d, which does not report it as oversize", a.Size)
	}
}

// A From header that will not parse still yields an address.
//
// Real mail carries headers no parser accepts -- an unquoted comma in a
// display name is enough -- and the address is what every later step matches
// on, so losing it loses the message's identity.
func TestAnUnparseableFromStillYieldsAnAddress(t *testing.T) {
	m, err := Parse(raw(
		`From: Karimi, Nima <n.karimi@example.com>`,
		"Subject: t",
		"",
		"x",
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Addr != "n.karimi@example.com" {
		t.Errorf("address is %q, want the one in angle brackets", m.Addr)
	}
}

func names(m *Message) []string {
	out := make([]string, 0, len(m.Attachments))
	for _, a := range m.Attachments {
		out = append(out, a.Name)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
