package mailbox

import (
	"bytes"
	"encoding/base64"
	"io"
)

// newTolerantBase64 decodes base64 out of a mail part.
//
// WHY NOT base64.NewDecoder DIRECTLY. Go's streaming decoder stops at the
// first byte that is not in the alphabet and returns an error, and everything
// after that point is lost. That is correct for a protocol and wrong for
// mail, where the encoded data is wrapped at 76 columns by a dozen different
// clients and some of them do it badly: a stray space at the end of a line, a
// bare CR, a blank line in the middle, a final chunk that is not padded to
// four characters. Any one of those truncates a PDF to however much came
// before it -- and a half-read attachment does not announce itself, it just
// fails to open later.
//
// So: gather the alphabet characters, ignore everything else, and decode what
// was gathered. Buffered rather than streamed because the callers are already
// reading into memory under a cap, and because the padding at the end cannot
// be fixed until the end is known.
func newTolerantBase64(r io.Reader) io.Reader {
	raw, err := io.ReadAll(r)
	if err != nil && len(raw) == 0 {
		return bytes.NewReader(nil)
	}

	clean := make([]byte, 0, len(raw))
	for _, c := range raw {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/':
			clean = append(clean, c)
		case c == '-':
			clean = append(clean, '+') // URL-safe alphabet, seen from some senders
		case c == '_':
			clean = append(clean, '/')
		}
		// Everything else -- '=', whitespace, line breaks, anything a broken
		// client wrote -- is dropped. Padding is recomputed below, which is
		// safer than trusting padding that may itself be wrong.
	}

	// Pad to a multiple of four. A length of exactly one more than a multiple
	// is impossible in valid base64, so the last character is dropped rather
	// than padded into a byte that was never sent.
	switch len(clean) % 4 {
	case 1:
		clean = clean[:len(clean)-1]
	case 2:
		clean = append(clean, '=', '=')
	case 3:
		clean = append(clean, '=')
	}

	out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
	n, err := base64.StdEncoding.Decode(out, clean)
	if err != nil && n == 0 {
		return bytes.NewReader(nil)
	}
	// A decode that failed part-way still decoded everything up to the fault,
	// and n says how much. That prefix is the file as far as it was readable.
	return bytes.NewReader(out[:n])
}
