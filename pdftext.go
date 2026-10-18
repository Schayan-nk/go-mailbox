package mailbox

import (
	"bytes"
	"compress/zlib"
	"context"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Reading a PDF attachment's text in-process, bounded, without any tool.
//
// A mail attachment is a file a stranger chose, and handing it to another
// program (pdftotext, say) to open is exactly what a careful mail reader
// should not do. So this is a deliberately small reader:
// it finds the objects, inflates Flate streams under a budget, maps glyphs
// through each font's ToUnicode table, and pulls the strings out of the
// text operators. It is not a renderer and does not try to be -- a PDF it
// cannot read yields no text and is described from its name and page count.
//
// It never follows an action, never touches an embedded file, and reports
// the presence of either so the caller can refuse the document.

const (
	pdfMaxObjects  = 20000
	pdfMaxStream   = 8 << 20
	pdfMaxInflated = 40 << 20
)

// PDFInfo is what ReadPDF found.
type PDFInfo struct {
	Pages     int
	Title     string
	Encrypted bool
	// Active names what can act when the file is opened (JavaScript, Launch,
	// EmbeddedFile, RichMedia, XFA); non-empty means do not use the text.
	Active string
	Text   string
}

// Danger is why what ReadPDF found means the file must not be used, or "".
func (p PDFInfo) Danger() string {
	switch {
	case p.Encrypted:
		return whyCrypt
	case p.Active != "":
		return "PDF کد یا فایل جاسازی‌شده دارد (" + p.Active + ")"
	}
	return ""
}

type pdfObj struct {
	dict   string
	raw    []byte // the stream as stored, when there is one
	stream []byte // inflated, on demand
	done   bool
}

type pdfDoc struct {
	ctx    context.Context
	objs   map[int]*pdfObj
	budget int
}

var (
	pdfObjHead   = regexp.MustCompile(`(\d{1,7})\s+\d{1,5}\s+obj\b`)
	pdfActiveKey = regexp.MustCompile(`/(JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|XFA)[\s/<>\[\]()]`)
	pdfNameEsc   = regexp.MustCompile(`#([0-9A-Fa-f]{2})`)
	pdfRef       = regexp.MustCompile(`^(\d+)\s+\d+\s+R`)
	pdfFontPair  = regexp.MustCompile(`/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R`)
	pdfPageType  = regexp.MustCompile(`/Type\s*/Page\b`)
	pdfRoot      = regexp.MustCompile(`/Root\s+(\d+)\s+\d+\s+R`)
	pdfAnyRef    = regexp.MustCompile(`(\d+)\s+\d+\s+R`)
)

// pdfNameFix undoes the #xx escapes a PDF name may use to hide a key --
// /J#61vaScript is /JavaScript.
func pdfNameFix(b []byte) []byte {
	if !bytes.Contains(b, []byte("#")) {
		return b
	}
	return pdfNameEsc.ReplaceAllFunc(b, func(m []byte) []byte {
		v, _ := strconv.ParseUint(string(m[1:]), 16, 8)
		return []byte{byte(v)}
	})
}

// ReadPDF reads what it can of a PDF, returning at most maxText runes of
// text. It stops when ctx does.
func ReadPDF(ctx context.Context, data []byte, maxText int) PDFInfo {
	var info PDFInfo
	if bytes.Contains(data, []byte("/Encrypt")) {
		info.Encrypted = true
		return info
	}
	d := &pdfDoc{ctx: ctx, objs: map[int]*pdfObj{}, budget: pdfMaxInflated}
	d.scan(data)
	// Compressed object streams hold dictionaries too, and a script hidden
	// in one is still a script.
	var packed []int
	for n, o := range d.objs {
		if strings.Contains(o.dict, "/ObjStm") {
			packed = append(packed, n)
		}
	}
	sort.Ints(packed)
	for _, n := range packed {
		if ctx.Err() != nil {
			return info
		}
		first, _ := pdfToken(d.objs[n].dict, keyAt(d.objs[n].dict, "/First"))
		at, _ := strconv.Atoi(first)
		d.unpackObjStm(d.streamOf(n), at)
	}
	for _, o := range d.objs {
		if m := pdfActiveKey.FindStringSubmatch(o.dict + " "); m != nil {
			info.Active = m[1]
			return info
		}
		if strings.Contains(o.dict, "/Encrypt") {
			info.Encrypted = true
			return info
		}
		if info.Title == "" && strings.Contains(o.dict, "/Title") &&
			(strings.Contains(o.dict, "/Producer") || strings.Contains(o.dict, "/Creator") || strings.Contains(o.dict, "/CreationDate")) {
			if t, _ := pdfToken(o.dict, strings.Index(o.dict, "/Title")+6); t != "" {
				info.Title = clip(strings.TrimSpace(pdfTextString(pdfStringBytes(t))), 160)
			}
		}
	}
	pages := d.pages(data)
	info.Pages = len(pages)
	info.Text = d.text(pages, maxText)
	return info
}

// scan finds every "N G obj" and keeps its dictionary and stream.
func (d *pdfDoc) scan(data []byte) {
	pos := 0
	for len(d.objs) < pdfMaxObjects && d.ctx.Err() == nil {
		loc := pdfObjHead.FindSubmatchIndex(data[pos:])
		if loc == nil {
			return
		}
		num, _ := strconv.Atoi(string(data[pos+loc[2] : pos+loc[3]]))
		start := pos + loc[1]
		end := bytes.Index(data[start:], []byte("endobj"))
		if end < 0 {
			end = len(data) - start
		}
		body := data[start : start+end]
		o := &pdfObj{}
		if si := bytes.Index(body, []byte("stream")); si >= 0 && bytes.Contains(body[:si], []byte("<<")) {
			o.dict = string(pdfNameFix(body[:si]))
			s := start + si + len("stream")
			if s < len(data) && data[s] == '\r' {
				s++
			}
			if s < len(data) && data[s] == '\n' {
				s++
			}
			e := bytes.Index(data[s:], []byte("endstream"))
			if e < 0 {
				e = len(data) - s
			}
			o.raw = data[s : s+e]
			end = s + e - start
			if k := bytes.Index(data[s+e:], []byte("endobj")); k >= 0 {
				end = s + e + k - start
			}
		} else {
			o.dict = string(pdfNameFix(body))
		}
		if _, dup := d.objs[num]; !dup || o.raw != nil {
			d.objs[num] = o // a later revision of an object replaces the first
		}
		pos = start + end
	}
}

// streamOf inflates object n's stream, once, within the document's budget.
// Images and embedded font programs are never inflated: they hold no text.
func (d *pdfDoc) streamOf(n int) []byte {
	o := d.objs[n]
	if o == nil || o.raw == nil {
		return nil
	}
	if o.done {
		return o.stream
	}
	o.done = true
	for _, skip := range []string{"/Image", "/Length1", "/Length2", "/Length3", "/FontFile", "/Type1C", "/CIDFontType0C", "/OpenType", "/XRef", "/Predictor"} {
		if strings.Contains(o.dict, skip) {
			return nil
		}
	}
	filter, _ := pdfToken(o.dict, keyAt(o.dict, "/Filter"))
	filter = strings.Trim(filter, "[] \r\n")
	switch filter {
	case "":
		o.stream = o.raw
	case "/FlateDecode", "/Fl":
		limit := min(pdfMaxStream, d.budget)
		if limit <= 0 {
			return nil
		}
		zr, err := zlib.NewReader(bytes.NewReader(o.raw))
		if err != nil {
			return nil
		}
		// A truncated or checksum-less stream still yields what it inflated.
		o.stream, _ = io.ReadAll(io.LimitReader(zr, int64(limit)))
		d.budget -= len(o.stream)
	}
	return o.stream
}

// unpackObjStm adds the dictionaries a compressed object stream holds.
func (d *pdfDoc) unpackObjStm(s []byte, i int) {
	if s == nil || i <= 0 || i >= len(s) {
		return
	}
	nums := strings.Fields(string(s[:i]))
	type at struct{ num, off int }
	var list []at
	for k := 0; k+1 < len(nums); k += 2 {
		n, e1 := strconv.Atoi(nums[k])
		o, e2 := strconv.Atoi(nums[k+1])
		if e1 != nil || e2 != nil {
			return
		}
		list = append(list, at{n, o})
	}
	for k, a := range list {
		from, to := i+a.off, len(s)
		if k+1 < len(list) {
			to = i + list[k+1].off
		}
		if from < i || from >= to || to > len(s) || len(d.objs) >= pdfMaxObjects {
			continue
		}
		if _, have := d.objs[a.num]; !have {
			d.objs[a.num] = &pdfObj{dict: string(pdfNameFix(s[from:to]))}
		}
	}
}

// pages are the page objects in reading order: the page tree from /Root when
// it can be walked, otherwise every page object in number order.
func (d *pdfDoc) pages(data []byte) []int {
	var out []int
	seen := map[int]bool{}
	var walk func(n, depth int)
	walk = func(n, depth int) {
		o := d.objs[n]
		if o == nil || seen[n] || depth > 32 || len(out) > 5000 {
			return
		}
		seen[n] = true
		if pdfPageType.MatchString(o.dict) {
			out = append(out, n)
			return
		}
		kids, _ := pdfToken(o.dict, keyAt(o.dict, "/Kids"))
		for _, m := range pdfAnyRef.FindAllStringSubmatch(kids, -1) {
			k, _ := strconv.Atoi(m[1])
			walk(k, depth+1)
		}
	}
	var root string
	if all := pdfRoot.FindAllSubmatch(data, -1); len(all) > 0 {
		root = string(all[len(all)-1][1])
	} else {
		for _, o := range d.objs {
			if m := pdfRoot.FindStringSubmatch(o.dict); m != nil {
				root = m[1]
			}
		}
	}
	if r, err := strconv.Atoi(root); err == nil && d.objs[r] != nil {
		if p := d.ref(d.objs[r].dict, "/Pages"); p > 0 {
			walk(p, 0)
		}
	}
	if len(out) == 0 {
		for n, o := range d.objs {
			if pdfPageType.MatchString(o.dict) {
				out = append(out, n)
			}
		}
		sort.Ints(out)
	}
	return out
}

// ref is the object a key points at, or 0.
func (d *pdfDoc) ref(dict, key string) int {
	t, _ := pdfToken(dict, keyAt(dict, key))
	if m := pdfRef.FindStringSubmatch(t); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// sub is a key's dictionary, inline or by reference.
func (d *pdfDoc) sub(dict, key string) string {
	t, _ := pdfToken(dict, keyAt(dict, key))
	if strings.HasPrefix(t, "<<") {
		return t
	}
	if n := d.ref(dict, key); n > 0 && d.objs[n] != nil {
		return d.objs[n].dict
	}
	return ""
}

// text reads the pages' content streams in order.
func (d *pdfDoc) text(pages []int, maxText int) string {
	var b strings.Builder
	fonts := map[int]*pdfFont{}
	global := map[string]int{}
	for _, o := range d.objs {
		for _, m := range pdfFontPair.FindAllStringSubmatch(d.sub(o.dict, "/Font"), -1) {
			if _, ok := global[m[1]]; !ok {
				global[m[1]], _ = strconv.Atoi(m[2])
			}
		}
	}
	for _, p := range pages {
		if d.ctx.Err() != nil || b.Len() >= maxText*4 {
			break
		}
		page := d.objs[p].dict
		names := map[string]int{}
		for _, m := range pdfFontPair.FindAllStringSubmatch(d.sub(d.sub(page, "/Resources"), "/Font"), -1) {
			names[m[1]], _ = strconv.Atoi(m[2])
		}
		font := func(name string) *pdfFont {
			n, ok := names[name]
			if !ok {
				n = global[name]
			}
			if f, ok := fonts[n]; ok {
				return f
			}
			f := d.font(n)
			fonts[n] = f
			return f
		}
		contents, _ := pdfToken(page, keyAt(page, "/Contents"))
		for _, m := range pdfAnyRef.FindAllStringSubmatch(contents, 64) {
			n, _ := strconv.Atoi(m[1])
			pdfShow(d.streamOf(n), font, &b)
		}
		b.WriteByte('\n')
	}
	t := norm.NFKC.String(b.String())
	letters, total := 0, 0
	for _, r := range t {
		if unicode.IsSpace(r) {
			continue
		}
		total++
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			letters++
		}
	}
	// Glyph ids read without a map come out as noise; noise is not text.
	if total == 0 || letters*10 < total*6 {
		return ""
	}
	return clip(strings.TrimSpace(t), maxText)
}

type pdfFont struct {
	width int // bytes per code
	cmap  map[uint32]string
	cid   bool
}

func (d *pdfDoc) font(n int) *pdfFont {
	f := &pdfFont{width: 1}
	o := d.objs[n]
	if o == nil {
		return f
	}
	if strings.Contains(o.dict, "/Type0") || strings.Contains(o.dict, "/Identity-H") {
		f.width, f.cid = 2, true
	}
	if cm := d.ref(o.dict, "/ToUnicode"); cm > 0 {
		f.cmap, f.width = parseCMap(d.streamOf(cm), f.width)
	}
	return f
}

// decode turns a shown string into text through the font's map.
func (f *pdfFont) decode(s []byte, b *strings.Builder) {
	if f == nil {
		f = &pdfFont{width: 1}
	}
	if f.cmap == nil {
		if f.cid {
			return // glyph ids with no map: nothing readable
		}
		for _, c := range s {
			if c >= 32 {
				b.WriteRune(rune(c))
			}
		}
		return
	}
	for i := 0; i+f.width <= len(s); i += f.width {
		var c uint32
		for k := 0; k < f.width; k++ {
			c = c<<8 | uint32(s[i+k])
		}
		b.WriteString(f.cmap[c])
	}
}

// clip is s cut to at most n runes.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
