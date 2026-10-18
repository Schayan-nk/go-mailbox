// Package mailbox reads mailboxes over POP3 and IMAP, parses the messages in
// them without trusting a byte, judges their attachments before anything
// opens them, reads a PDF attachment's text in-process, and sends over SMTP
// that is encrypted or not at all.
//
// Everything a mailbox holds was written by strangers, so every reader here
// is bounded: line and literal lengths, part counts and nesting, decoded and
// inflated sizes, and a timeout on every exchange with a server.
package mailbox
