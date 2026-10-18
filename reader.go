package mailbox

import "strings"

// Reader is an open mailbox, whichever protocol reaches it: the five things
// a mail client asks. POP3Box and IMAP both answer them, with message ids
// (UIDLs) that are stable for as long as the message stays where it is.
type Reader interface {
	// UIDs lists the messages in arrival order, newest last.
	UIDs() []string
	Sizes() (map[string]int64, error)
	// Preview is enough of a message to list it; Message is all of it.
	Preview(uid string) (*Message, error)
	Message(uid string) (*Message, error)
	Close() error
}

var (
	_ Reader = (*POP3Box)(nil)
	_ Reader = (*IMAP)(nil)
)

// UsesIMAP says whether this mailbox is read over IMAP.
func (c Config) UsesIMAP() bool { return strings.EqualFold(strings.TrimSpace(c.Protocol), "imap") }

// server and serverKey are the host the protocol reads from, and the name of
// the setting that supplies it, for Validate.
func (c Config) server() string {
	if c.UsesIMAP() {
		return c.IMAPHost
	}
	return c.POP3Host
}

func (c Config) serverKey() string {
	if c.UsesIMAP() {
		return "IMAPHost"
	}
	return "POP3Host"
}

// OpenReader opens the mailbox the configuration names, over its protocol.
func OpenReader(cfg Config) (Reader, error) {
	if cfg.UsesIMAP() {
		return OpenIMAP(cfg)
	}
	return OpenPOP3(cfg)
}
