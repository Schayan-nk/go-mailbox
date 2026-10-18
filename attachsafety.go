package mailbox

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/mail"
	"path"
	"regexp"
	"strings"
)

// Whether an attachment may be read at all, decided WITHOUT opening it.
//
// Everything a stranger attaches is judged on three things that cost nothing
// to look at and cannot run: the name it was given, the type it declared and
// the first bytes it actually carries. A file that fails any of them is shown
// with a warning and never read -- not extracted, not described from its
// text, never passed to a model. What passes is read only if its type is on
// a short allow-list the repository has its own in-process readers for.
//
// NOTHING HERE EXECUTES, RENDERS OR UNPACKS. The zip checks read the central
// directory, which is a list of names and sizes, and at most two small XML
// parts, bounded; they do not decompress the document.

const (
	// MaxReadBytes is the largest attachment that is read. A bigger one is
	// described from its name and size.
	MaxReadBytes = 10 << 20
	// MaxZipEntries and MaxZipUnpacked bound a DOCX or XLSX before it is
	// opened: a real document has tens of parts and a few megabytes, a zip
	// bomb has thousands or gigabytes. The declared sizes are enough to
	// check, because archive/zip refuses to inflate past what an entry
	// declares.
	MaxZipEntries  = 2000
	MaxZipUnpacked = 50 << 20
)

// Safety is the verdict on one attachment.
type Safety struct {
	// Format is what it will be read as -- pdf, docx, xlsx, txt, csv -- or
	// "" when it is described from its name alone.
	Format string
	// Danger means: show the warning, never read it.
	Danger bool
	Why    []string
	// Note is why a harmless file was not read (too big, a format there is
	// no reader for), in Persian.
	Note string
}

func (s *Safety) warn(why string) {
	s.Danger, s.Format = true, ""
	for _, w := range s.Why {
		if w == why {
			return
		}
	}
	s.Why = append(s.Why, why)
}

const (
	whyExec    = "فایل اجرایی یا اسکریپت است و با باز شدن اجرا می‌شود"
	whyMacro   = "سند آفیس ماکرودار است؛ ماکرو می‌تواند برنامه اجرا کند"
	whyDisk    = "فایل دیسک مجازی است و می‌تواند برنامه پنهان کند"
	whyWeb     = "صفحهٔ وب یا تصویر SVG است؛ این نوع پیوست ابزار رایج فیشینگ است"
	whyArchive = "فایل فشرده است؛ باز نشد و محتوایش بررسی نشده است"
	whyCrypt   = "رمزگذاری‌شده یا دارای گذرواژه است و بررسی‌شدنی نیست"
	whyBidi    = "نام فایل نویسهٔ پنهان جهت‌دهی دارد که پسوند واقعی را وارونه نشان می‌دهد"
	whyPadding = "نام فایل با فاصله‌های پشت سر هم پسوند واقعی را پنهان می‌کند"
	whyPE      = "محتوای فایل برنامهٔ اجرایی ویندوز است"
	whyBomb    = "بازشدهٔ آن بیش از اندازهٔ یک سند واقعی است؛ احتمال بمب فشرده‌سازی"
	whyOLE     = "شیء جاسازی‌شده دارد که می‌تواند برنامه باشد"
	whyRemote  = "به قالب یا فایلی بیرون از خودش پیوند دارد که هنگام باز شدن دریافت می‌شود"
)

var dangerExt = map[string]string{}

func init() {
	for why, exts := range map[string]string{
		whyExec:    "exe scr com bat cmd ps1 psm1 vbs vbe js jse wsf wsh msi msp jar lnk hta cpl reg pif dll msc scf msix appx appxbundle application gadget",
		whyMacro:   "docm xlsm pptm dotm xlam xltm potm ppam ppsm sldm xlsb",
		whyDisk:    "iso img vhd vhdx",
		whyWeb:     "html htm shtml xhtml mht mhtml svg svgz",
		whyArchive: "zip rar 7z gz tgz tar bz2 xz cab arj lzh ace z",
	} {
		for _, e := range strings.Fields(exts) {
			dangerExt[e] = why
		}
	}
}

// docLike are the extensions a double extension hides behind.
var docLike = map[string]bool{"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true,
	"ppt": true, "pptx": true, "txt": true, "csv": true, "rtf": true, "jpg": true, "jpeg": true,
	"png": true, "gif": true, "tif": true, "tiff": true}

// magicOf is what each checked extension must actually be.
var magicOf = map[string]string{
	"pdf": "pdf", "docx": "zip", "xlsx": "zip", "pptx": "zip", "doc": "cfb", "xls": "cfb", "ppt": "cfb",
	"png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif", "tif": "tiff", "tiff": "tiff",
}

// readable is the allow-list: the formats this application reads itself.
var readable = map[string]bool{"pdf": true, "docx": true, "xlsx": true, "txt": true, "csv": true}

// dangerMIME are declared types that mean a program or a web page.
var dangerMIME = []string{"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
	"application/x-ms-installer", "application/x-msi", "application/hta", "application/java-archive",
	"application/javascript", "text/javascript", "application/x-sh", "application/x-bat",
	"application/x-ms-shortcut", "text/html", "application/xhtml+xml", "image/svg+xml",
	"application/vnd.ms-word.document.macroenabled", "application/vnd.ms-excel.sheet.macroenabled"}

// CheckAttachment judges one attachment from its name, declared type and
// first bytes, and for a DOCX or XLSX from its zip directory.
func CheckAttachment(a Attachment) Safety {
	var s Safety
	name := a.Name
	if strings.ContainsAny(name, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069") {
		s.warn(whyBidi)
	}
	// Windows drops trailing dots and spaces, so "x.exe." runs as x.exe.
	name = strings.TrimRight(baseName(name), " .\t")
	ext := extOf(name)
	stem := strings.TrimSuffix(name, "."+ext)
	if ext != "" && strings.HasSuffix(name, "."+ext) && strings.TrimRight(stem, " _") != stem &&
		len(stem)-len(strings.TrimRight(stem, " _")) >= 3 {
		s.warn(whyPadding)
	}
	if why, bad := dangerExt[ext]; bad {
		if inner := extOf(stem); docLike[inner] {
			s.warn(fmt.Sprintf("پسوند دوگانه دارد (.%s.%s) تا فایل را سند نشان دهد", inner, ext))
		}
		s.warn(why)
	}
	mime := strings.ToLower(strings.TrimSpace(strings.SplitN(a.Type, ";", 2)[0]))
	for _, d := range dangerMIME {
		if strings.HasPrefix(mime, d) {
			s.warn(fmt.Sprintf("نوع اعلام‌شدهٔ فایل (%s) برنامه یا صفحهٔ وب است", mime))
			break
		}
	}
	if a.Data == nil {
		return s // listed but not fetched: judged on its name only
	}
	magic := Sniff(a.Data)
	if magic == "exe" {
		s.warn(whyPE)
	}
	if want, ok := magicOf[ext]; ok && magic != want && !s.Danger {
		if want == "zip" && magic == "cfb" {
			// An OOXML file with a password is stored as a compound file.
			if bytes.Contains(a.Data, utf16le("EncryptionInfo")) {
				s.warn(whyCrypt)
			} else {
				s.warn(fmt.Sprintf("محتوای فایل با پسوند .%s نمی‌خواند؛ قالب قدیمی آفیس با نام تازه است", ext))
			}
		} else {
			s.warn(fmt.Sprintf("محتوای فایل با پسوند .%s نمی‌خواند (%s)", ext, magicLabel(magic)))
		}
	}
	if (ext == "txt" || ext == "csv") && magic != "" && magic != "html" {
		s.warn(fmt.Sprintf("فایل متنی نیست و محتوایش %s است", magicLabel(magic)))
	}
	if s.Danger {
		return s
	}
	switch {
	case ext == "pdf":
		p := PDFInfo{Encrypted: bytes.Contains(a.Data, []byte("/Encrypt"))}
		if !p.Encrypted {
			p.Active = PDFActive(a.Data)
		}
		if why := p.Danger(); why != "" {
			s.warn(why)
		}
	case ext == "docx" || ext == "xlsx":
		for _, why := range InspectZip(a.Data, ext) {
			s.warn(why)
		}
	}
	if s.Danger {
		return s
	}
	switch {
	case !readable[ext]:
		if ext == "doc" || ext == "xls" || ext == "ppt" {
			s.Note = "قالب قدیمی آفیس است؛ فقط از روی نام توضیح داده شد"
		}
	case len(a.Data) > MaxReadBytes:
		s.Note = fmt.Sprintf("بزرگ‌تر از %s مگابایت است؛ خوانده نشد", faDigits(fmt.Sprint(MaxReadBytes>>20)))
	case (ext == "txt" || ext == "csv") && bytes.IndexByte(head(a.Data, 8192), 0) >= 0:
		s.Note = "محتوای متنی ندارد"
	default:
		s.Format = ext
	}
	return s
}

// InspectZip reads a DOCX or XLSX package's directory and the two small parts
// that betray a macro or a remote template. It returns why the package must
// not be opened, or nothing.
func InspectZip(data []byte, ext string) []string {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return []string{fmt.Sprintf("ساختار فایل با پسوند .%s نمی‌خواند", ext)}
	}
	if len(zr.File) > MaxZipEntries {
		return []string{whyBomb}
	}
	var why []string
	add := func(w string) {
		for _, x := range why {
			if x == w {
				return
			}
		}
		why = append(why, w)
	}
	want := map[string]string{"docx": "word/document.xml", "xlsx": "xl/workbook.xml"}[ext]
	var total uint64
	found := false
	for _, f := range zr.File {
		total += f.UncompressedSize64
		n := strings.ToLower(f.Name)
		switch {
		case f.Flags&1 != 0:
			add(whyCrypt)
		case strings.HasSuffix(n, "vbaproject.bin") || strings.Contains(n, "/activex/"):
			add(whyMacro)
		case strings.Contains(n, "/embeddings/") && !strings.HasSuffix(n, ".xlsx") && !strings.HasSuffix(n, ".docx") &&
			!strings.HasSuffix(n, ".png") && !strings.HasSuffix(n, ".jpeg") && !strings.HasSuffix(n, ".emf"):
			add(whyOLE)
		case n == "[content_types].xml" && bytes.Contains(bytes.ToLower(smallPart(f)), []byte("macroenabled")):
			add(whyMacro)
		case strings.HasSuffix(n, ".rels") && remoteRel(smallPart(f)):
			add(whyRemote)
		}
		if n == want {
			found = true
		}
	}
	if total > MaxZipUnpacked {
		add(whyBomb)
	}
	if !found {
		add(fmt.Sprintf("ساختار فایل با پسوند .%s نمی‌خواند", ext))
	}
	return why
}

var (
	relElement = regexp.MustCompile(`(?s)<Relationship\b[^>]*>`)
	relLoads   = regexp.MustCompile(`Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"`)
	relRemote  = regexp.MustCompile(`(?i)Target="\s*(https?:|\\\\|file:/{0,2}\\\\|file:/{4})`)
)

// remoteRel finds the relationship that makes Word fetch something from
// elsewhere when the document opens: a template, an OLE link, a frame or a
// sub-document whose target is a web address or a network share. A LOCAL
// template path -- Normal.dotm on the author's disk -- is in most documents
// and is not a finding; a hyperlink is not loaded until somebody clicks it.
func remoteRel(rels []byte) bool {
	for _, r := range relElement.FindAll(rels, -1) {
		if bytes.Contains(r, []byte(`TargetMode="External"`)) && relLoads.Match(r) && relRemote.Match(r) {
			return true
		}
	}
	return false
}

// smallPart reads a zip part only when it is small, and only its first 64 KB.
func smallPart(f *zip.File) []byte {
	if f.UncompressedSize64 > 1<<20 {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
	return b
}

// Sniff names what bytes actually are, from their first bytes: pdf, zip,
// cfb, exe, elf, png, jpeg, gif, tiff, rar, 7z, gzip, html, or "".
func Sniff(b []byte) string {
	h := head(b, 1024)
	switch {
	case bytes.HasPrefix(h, []byte("MZ")) && isPE(b):
		return "exe"
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(bytes.TrimLeft(h, " \t\r\n\x00\xef\xbb\xbf"), []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(h, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(h, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
		return "cfb"
	case bytes.HasPrefix(h, []byte("\x89PNG")):
		return "png"
	case bytes.HasPrefix(h, []byte("\xff\xd8\xff")):
		return "jpeg"
	case bytes.HasPrefix(h, []byte("GIF8")):
		return "gif"
	case bytes.HasPrefix(h, []byte("II*\x00")) || bytes.HasPrefix(h, []byte("MM\x00*")):
		return "tiff"
	case bytes.HasPrefix(h, []byte("Rar!\x1a\x07")):
		return "rar"
	case bytes.HasPrefix(h, []byte("7z\xbc\xaf\x27\x1c")):
		return "7z"
	case bytes.HasPrefix(h, []byte("\x1f\x8b")):
		return "gzip"
	}
	t := bytes.ToLower(bytes.TrimLeft(head(h, 512), " \t\r\n\xef\xbb\xbf"))
	for _, p := range []string{"<!doctype html", "<html", "<script", "<svg", "<?xml-stylesheet"} {
		if bytes.HasPrefix(t, []byte(p)) {
			return "html"
		}
	}
	return ""
}

// isPE confirms an "MZ" header with the PE signature it points at, so a text
// file that happens to start with the two letters is not called a program.
func isPE(b []byte) bool {
	if len(b) < 0x40 {
		return false
	}
	off := int(binary.LittleEndian.Uint32(b[0x3c:]))
	return off > 0 && off+4 <= len(b) && string(b[off:off+4]) == "PE\x00\x00"
}

func magicLabel(m string) string {
	switch m {
	case "":
		return "قالبش شناخته نشد"
	case "exe", "elf":
		return "برنامهٔ اجرایی"
	case "html":
		return "صفحهٔ وب"
	case "zip", "rar", "7z", "gzip":
		return "فایل فشرده"
	case "cfb":
		return "سند قدیمی آفیس"
	}
	return "در واقع " + strings.ToUpper(m) + " است"
}

// DisplayName is the name part of a From line: «Ali Karimi» of
// «Ali Karimi <karimi@example.com>».
func DisplayName(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Name
	}
	if i := strings.Index(from, "<"); i >= 0 {
		return from[:i]
	}
	return from
}

// FoldName is a display name for comparing: lower case, no quotes, one space,
// Persian letters normalised.
func FoldName(s string) string {
	s = strings.NewReplacer("\"", "", "'", "", "ي", "ی", "ك", "ک", "\u200c", " ").Replace(strings.ToLower(s))
	return strings.Join(strings.Fields(s), " ")
}

func baseName(n string) string {
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	return strings.TrimSpace(n)
}

func extOf(n string) string {
	return strings.ToLower(strings.TrimPrefix(path.Ext(n), "."))
}

func head(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func utf16le(s string) []byte {
	b := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return b
}

var faDigitsR = strings.NewReplacer("0", "۰", "1", "۱", "2", "۲", "3", "۳", "4", "۴", "5", "۵", "6", "۶", "7", "۷", "8", "۸", "9", "۹", ".", "٫")

func faDigits(s string) string { return faDigitsR.Replace(s) }
