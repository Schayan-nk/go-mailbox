package mailbox

import (
	"strings"
	"syscall"
)

// Config is where a mailbox is and how to sign in to it.
//
// NOTHING HAS A CREDENTIAL AS A DEFAULT. A blank password stays blank and
// fails loudly at Validate; a fallback would mean a misconfigured caller
// silently authenticating as somebody else or -- worse on a mail server --
// locking an account out by retrying a wrong password on every poll.
type Config struct {
	Address string // the mailbox, and the address mail is sent as
	// Password is used exactly as given: a space at its edge is a character
	// of the password, and trimming it would turn a working credential into
	// a sign-in failure nobody can explain.
	Password string

	POP3Host string
	POP3Port int // 995 when zero
	SMTPHost string
	// SMTPPort is 465 when zero. 465 is TLS from the first byte; any other
	// port must offer STARTTLS. Nothing is ever sent over a plain connection.
	SMTPPort int

	// Protocol is "pop3" (the default) or "imap". IMAP is what a mailbox
	// with folders needs: one read alongside a desktop client, where POP3
	// would see an inbox the other client has already emptied.
	Protocol string
	IMAPHost string
	IMAPPort int // 993 when zero
	// Mailbox is the IMAP folder opened; "INBOX" when empty.
	Mailbox string

	// DialControl, when set, vets the address a connection is actually made
	// to, after DNS. Set it for a mailbox somebody typed in, so their
	// settings cannot point your server at its own network.
	DialControl func(network, address string, c syscall.RawConn) error
}

// Enabled reports whether there is enough here to read a mailbox at all.
func (c Config) Enabled() bool {
	if c.UsesIMAP() {
		return c.Address != "" && c.Password != "" && c.IMAPHost != ""
	}
	return c.Address != "" && c.Password != "" && c.POP3Host != ""
}

// Validate names what is missing for reading the mailbox. Sending needs
// SMTPHost as well (CanSend): a mailbox that can be read but not sent from
// is a reasonable state to run in.
func (c Config) Validate() []string {
	var missing []string
	for _, f := range []struct{ name, val string }{
		{"Address", c.Address},
		{"Password", c.Password},
		{c.serverKey(), c.server()},
	} {
		if strings.TrimSpace(f.val) == "" {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// CanSend reports whether outbound mail is possible: an address, its
// password and an SMTP host. Reading is not needed to send.
func (c Config) CanSend() bool { return c.Address != "" && c.Password != "" && c.SMTPHost != "" }

func (c Config) pop3Port() int { return orDefault(c.POP3Port, 995) }
func (c Config) smtpPort() int { return orDefault(c.SMTPPort, 465) }

func orDefault(n, def int) int {
	if n > 0 {
		return n
	}
	return def
}
