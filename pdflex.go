package mailbox

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// The small lexer under pdftext.go: tokens in a dictionary, strings in a
// content stream, and the text operators that show them.

// PDFActive names what a PDF carries that can act when it is opened --
// script, a launch action, an embedded file, rich media, an XFA form -- as
// far as its uncompressed dictionaries show. ReadPDF looks again inside the
// compressed ones.
//
// Only the text BETWEEN streams is searched: a compressed stream is noise,
// and a megabyte of noise spells "/JS" somewhere often enough to matter.
func PDFActive(b []byte) string {
	for pos := 0; pos < len(b); {
		i := bytes.Index(b[pos:], []byte("stream"))
		seg := b[pos:]
		if i >= 0 {
			seg = b[pos : pos+i]
		}
		if m := pdfActiveKey.FindSubmatch(pdfNameFix(seg)); m != nil {
			return string(m[1])
		}
		if i < 0 {
			break
		}
		j := bytes.Index(b[pos+i+6:], []byte("endstream"))
		if j < 0 {
			break
		}
		pos += i + 6 + j + len("endstream")
	}
	return ""
}

// keyAt is where a key's value starts in a dictionary, or -1. "/Font" must
// not match "/FontFile", so the key has to end at a delimiter.
func keyAt(dict, key string) int {
	for from := 0; ; {
		i := strings.Index(dict[from:], key)
		if i < 0 {
			return -1
		}
		end := from + i + len(key)
		if end >= len(dict) || strings.IndexByte(" \t\r\n/<>[]()", dict[end]) >= 0 {
			return end
		}
		from = end
	}
}

// pdfToken is the value starting at i: a dictionary, an array, a string, a
// name, a reference ("12 0 R") or a number, as written.
func pdfToken(s string, i int) (string, int) {
	if i < 0 || i >= len(s) {
		return "", len(s)
	}
	for i < len(s) && strings.IndexByte(" \t\r\n", s[i]) >= 0 {
		i++
	}
	if i >= len(s) {
		return "", i
	}
	start := i
	switch c := s[i]; {
	case strings.HasPrefix(s[i:], "<<"):
		depth := 0
		for i < len(s)-1 {
			switch {
			case s[i] == '<' && s[i+1] == '<':
				depth++
				i += 2
			case s[i] == '>' && s[i+1] == '>':
				depth--
				i += 2
				if depth == 0 {
					return s[start:i], i
				}
			case s[i] == '(':
				_, i = pdfLiteral([]byte(s), i)
			default:
				i++
			}
		}
		return s[start:], len(s)
	case c == '<':
		if j := strings.IndexByte(s[i:], '>'); j >= 0 {
			return s[i : i+j+1], i + j + 1
		}
	case c == '(':
		_, j := pdfLiteral([]byte(s), i)
		return s[i:j], j
	case c == '[':
		depth := 0
		for i < len(s) {
			switch s[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return s[start : i+1], i + 1
				}
			case '(':
				_, i = pdfLiteral([]byte(s), i)
				continue
			}
			i++
		}
		return s[start:], len(s)
	case c == '/':
		i++
		for i < len(s) && strings.IndexByte(" \t\r\n/<>[]()", s[i]) < 0 {
			i++
		}
		return s[start:i], i
	}
	if m := pdfRef.FindStringIndex(s[i:]); m != nil {
		return s[i : i+m[1]], i + m[1]
	}
	for i < len(s) && strings.IndexByte(" \t\r\n/<>[]()", s[i]) < 0 {
		i++
	}
	return s[start:i], i
}

// pdfLiteral reads the (string) at i, returning its bytes and what follows.
func pdfLiteral(s []byte, i int) ([]byte, int) {
	var out []byte
	depth := 0
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '(':
			depth++
			if depth == 1 {
				continue
			}
		case c == ')':
			depth--
			if depth == 0 {
				return out, i + 1
			}
		case c == '\\' && i+1 < len(s):
			i++
			switch e := s[i]; e {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'b', 'f':
				c = ' '
			case '\r', '\n':
				if e == '\r' && i+1 < len(s) && s[i+1] == '\n' {
					i++
				}
				continue
			default:
				if e >= '0' && e <= '7' {
					v, k := 0, 0
					for ; k < 3 && i+k < len(s) && s[i+k] >= '0' && s[i+k] <= '7'; k++ {
						v = v*8 + int(s[i+k]-'0')
					}
					i += k - 1
					c = byte(v)
				} else {
					c = e
				}
			}
		}
		out = append(out, c)
	}
	return out, len(s)
}

// pdfHex reads a <hex string>.
func pdfHex(h []byte) []byte {
	var clean []byte
	for _, c := range h {
		if (c >= '0' && c <= '9') || (c|0x20 >= 'a' && c|0x20 <= 'f') {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 == 1 {
		clean = append(clean, '0')
	}
	out := make([]byte, len(clean)/2)
	for k := range out {
		v, _ := strconv.ParseUint(string(clean[2*k:2*k+2]), 16, 8)
		out[k] = byte(v)
	}
	return out
}

// pdfStringBytes is a string token's bytes, literal or hex.
func pdfStringBytes(tok string) []byte {
	switch {
	case strings.HasPrefix(tok, "("):
		b, _ := pdfLiteral([]byte(tok), 0)
		return b
	case strings.HasPrefix(tok, "<") && !strings.HasPrefix(tok, "<<"):
		return pdfHex([]byte(strings.Trim(tok, "<>")))
	}
	return nil
}

// pdfTextString decodes a document string: UTF-16 with its byte-order mark,
// otherwise one byte per character.
func pdfTextString(b []byte) string {
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u))
	}
	r := make([]rune, 0, len(b))
	for _, c := range b {
		if c >= 32 {
			r = append(r, rune(c))
		}
	}
	return string(r)
}

// pdfShow runs a content stream's text operators into b. Nothing else in the
// stream is interpreted: no drawing, no images, no forms.
func pdfShow(s []byte, font func(string) *pdfFont, b *strings.Builder) {
	var f *pdfFont
	var ops, arr []any
	inArr := false
	lastY := math.NaN()
	push := func(v any) {
		if inArr {
			arr = append(arr, v)
			return
		}
		if ops = append(ops, v); len(ops) > 16 {
			ops = ops[1:]
		}
	}
	end := func(sep byte) {
		if t := b.String(); t != "" && !strings.HasSuffix(t, "\n") && (sep == '\n' || !strings.HasSuffix(t, " ")) {
			b.WriteByte(sep)
		}
	}
	num := func(k int) float64 {
		if k < 0 || k >= len(ops) {
			return 0
		}
		v, _ := ops[k].(float64)
		return v
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0 || c == '\f':
			i++
		case c == '%':
			for i < len(s) && s[i] != '\n' && s[i] != '\r' {
				i++
			}
		case c == '(':
			var lit []byte
			lit, i = pdfLiteral(s, i)
			push(lit)
		case c == '<' && i+1 < len(s) && s[i+1] == '<':
			_, j := pdfToken(string(s[i:min(len(s), i+4096)]), 0)
			i += max(j, 2)
		case c == '<':
			j := bytes.IndexByte(s[i:], '>')
			if j < 0 {
				return
			}
			push(pdfHex(s[i+1 : i+j]))
			i += j + 1
		case c == '[':
			inArr, arr = true, nil
			i++
		case c == ']':
			inArr = false
			push(arr)
			i++
		case c == '/':
			j := i + 1
			for j < len(s) && bytes.IndexByte([]byte(" \t\r\n/<>[]()%"), s[j]) < 0 {
				j++
			}
			push(string(s[i+1 : j]))
			i = j
		case (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.':
			j := i + 1
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
				j++
			}
			v, _ := strconv.ParseFloat(string(s[i:j]), 64)
			push(v)
			i = j
		default:
			j := i + 1
			for j < len(s) && bytes.IndexByte([]byte(" \t\r\n/<>[]()%"), s[j]) < 0 {
				j++
			}
			op := string(s[i:j])
			i = j
			n := len(ops)
			switch op {
			case "Tf":
				if n >= 2 {
					if name, ok := ops[n-2].(string); ok {
						f = font(name)
					}
				}
			case "Tj", "'", `"`:
				if op != "Tj" {
					end('\n')
				}
				if n > 0 {
					if str, ok := ops[n-1].([]byte); ok {
						f.decode(str, b)
					}
				}
			case "TJ":
				if n > 0 {
					a, _ := ops[n-1].([]any)
					for _, e := range a {
						switch v := e.(type) {
						case []byte:
							f.decode(v, b)
						case float64:
							if v < -200 {
								end(' ')
							}
						}
					}
				}
			case "Td", "TD":
				if num(n-1) != 0 {
					end('\n')
				} else {
					end(' ')
				}
			case "Tm":
				if y := num(n - 1); y != lastY {
					if !math.IsNaN(lastY) {
						end('\n')
					}
					lastY = y
				} else {
					end(' ')
				}
			case "T*":
				end('\n')
			case "ET":
				end(' ')
			case "BI":
				// Inline image data is binary; skip to the EI that ends it.
				k := bytes.Index(s[i:], []byte("ID"))
				e := -1
				if k >= 0 {
					e = bytes.Index(s[i+k:], []byte("\nEI"))
				}
				if e < 0 {
					return
				}
				i += k + e + 3
			}
			ops = ops[:0]
		}
	}
}

var cmapHex = regexp.MustCompile(`<([0-9A-Fa-f\s]*)>|\[|\]|(begin|end)(bfchar|bfrange|codespacerange)`)

// parseCMap reads a ToUnicode table's bfchar and bfrange entries.
func parseCMap(s []byte, width int) (map[uint32]string, int) {
	out := map[uint32]string{}
	section, inArr := "", false
	var toks []string
	var arr []string
	flush := func() {
		switch section {
		case "codespacerange":
			if len(toks) == 2 {
				width = max(1, len(toks[0])/2)
				toks = toks[:0]
			}
		case "bfchar":
			if len(toks) == 2 {
				c, _ := strconv.ParseUint(toks[0], 16, 32)
				out[uint32(c)] = utf16Hex(toks[1])
				toks = toks[:0]
			}
		case "bfrange":
			if len(toks) == 3 || (len(toks) == 2 && arr != nil) {
				lo, _ := strconv.ParseUint(toks[0], 16, 32)
				hi, _ := strconv.ParseUint(toks[1], 16, 32)
				for c := lo; c <= hi && c-lo < 65536 && len(out) < 1<<17; c++ {
					switch {
					case arr != nil && int(c-lo) < len(arr):
						out[uint32(c)] = utf16Hex(arr[c-lo])
					case arr == nil:
						r := []rune(utf16Hex(toks[2]))
						if len(r) > 0 {
							r[len(r)-1] += rune(c - lo)
							out[uint32(c)] = string(r)
						}
					}
				}
				toks, arr = toks[:0], nil
			}
		}
	}
	for _, m := range cmapHex.FindAllSubmatch(s, -1) {
		switch {
		case len(m[2]) > 0:
			section = ""
			if string(m[2]) == "begin" {
				section = string(m[3])
			}
			toks, arr = toks[:0], nil
		case string(m[0]) == "[":
			inArr, arr = true, []string{}
		case string(m[0]) == "]":
			inArr = false
			flush()
		default:
			h := strings.Join(strings.Fields(string(m[1])), "")
			if inArr {
				arr = append(arr, h)
			} else {
				toks = append(toks, h)
				flush()
			}
		}
	}
	return out, width
}

func utf16Hex(h string) string {
	var u []uint16
	for i := 0; i+4 <= len(h); i += 4 {
		v, _ := strconv.ParseUint(h[i:i+4], 16, 16)
		u = append(u, uint16(v))
	}
	if len(h) == 2 {
		v, _ := strconv.ParseUint(h, 16, 8)
		u = append(u, uint16(v))
	}
	return string(utf16.Decode(u))
}
