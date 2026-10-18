# go-mailbox

Read mailboxes over POP3 and IMAP, parse the messages in them without
trusting a byte, judge their attachments before anything opens them, read a
PDF attachment's text in-process, and send over SMTP that is encrypted or not
at all. Pure Go; the one dependency is `golang.org/x/text`, for legacy
character sets.

It is the mail layer of DocFind, a document and workflow system, where it
reads commercial mailboxes full of Persian and English mail from strangers.
Everything a mailbox holds was written by somebody else, so every reader here
is bounded: line and literal lengths, part counts and nesting, decoded and
inflated sizes, and a timeout on every exchange with a server.

- **POP3 and IMAP behind one interface.** `Reader` lists, sizes, previews and
  fetches messages by a stable id (the POP3 UIDL, or `<uidvalidity>.<uid>` on
  IMAP), so read state and caches keyed by it work the same over both.
- **IMAP written for this, not imported.** Literals, quoting and the
  modified UTF-7 of folder names (Persian ones included) are read properly.
  Lists use `BODY.PEEK` and never mark mail read in the owner's other clients;
  `MarkSeen` sets `\Seen` on the server on purpose. Folders, the Sent folder
  (by its `\Sent` flag, else by name, in several languages), search by date,
  move (`MOVE`, or `COPY` and `\Deleted`), the trash found rather than
  assumed, append and create.
- **POP3 that never deletes by accident.** Listing, previewing and opening
  have no path to `DELE`. `Delete` does, and only `Commit` (a checked `QUIT`)
  makes it final; `Raw` and `Head` give you what to keep and compare first.
- **A parser for hostile input.** RFC 2047 headers in any charset (Persian
  from older Windows clients arrives as windows-1256), quoted-printable,
  base64 that survives the line damage relays do, the plain part preferred to
  HTML and HTML reduced to its words, and caps on body size, attachment size,
  count and nesting. A malformed part is skipped, not fatal.
- **Attachments judged before they are read.** `CheckAttachment` decides from
  the name, the declared type and the first bytes: executables and scripts,
  macro-enabled Office files, disk images, HTML and SVG, archives, encrypted
  files, names that hide their extension (right-to-left override, padding,
  double extensions), a declared type the bytes contradict, zip bombs, and
  DOCX or XLSX files with embedded objects or remote templates. The verdicts
  are written in Persian.
- **PDF text without another program.** `ReadPDF` inflates streams under a
  budget, maps glyphs through each font's ToUnicode table and pulls out the
  text, and says when the file carries JavaScript, a launch action, an
  embedded file, rich media or XFA, so you can refuse it.
- **SMTP that will not send in the clear.** Port 465 is TLS from the first
  byte; any other port must offer STARTTLS or the message is not sent.
  `SendMail` and `SendHTML` are for machine-sent mail and say so
  (`Auto-Submitted: auto-generated`).
- **A hook for typed-in servers.** `Config.DialControl` vets the address a
  connection is actually made to, after DNS, so a mailbox somebody entered
  cannot point your server at its own network.

Sign-in is by password (POP3 `USER`/`PASS`, IMAP `LOGIN`, SMTP `AUTH PLAIN`),
always inside TLS; there is no OAuth.

## Install

```sh
go get github.com/Schayan-nk/go-mailbox
```

## Use

```go
cfg := mailbox.Config{
	Protocol: "imap", // or "pop3", the default
	IMAPHost: "imap.example.com",
	Address:  "me@example.com",
	Password: "app-password",
}
box, err := mailbox.OpenReader(cfg)
if err != nil {
	log.Fatal(err)
}
defer box.Close()

uids := box.UIDs() // oldest first
for _, uid := range uids[max(0, len(uids)-10):] {
	m, err := box.Message(uid)
	if err != nil {
		continue
	}
	fmt.Println(m.Date.Format(time.DateOnly), m.Addr, m.Subject)
	for _, a := range m.Attachments {
		s := mailbox.CheckAttachment(a)
		switch {
		case s.Danger:
			fmt.Println("  not opened:", a.Name, s.Why)
		case s.Format == "pdf":
			pdf := mailbox.ReadPDF(context.Background(), a.Data, 4000)
			if pdf.Danger() == "" {
				fmt.Println("  ", a.Name, pdf.Pages, "pages")
			}
		}
	}
}
```

Sending:

```go
cfg := mailbox.Config{SMTPHost: "smtp.example.com", Address: "me@example.com", Password: "app-password"}
err := cfg.SendMail(ctx, "you@example.com", "Hello", "One line of plain text.")
```

Ports default to 995 (POP3), 993 (IMAP) and 465 (SMTP). `OpenPOP3` and
`OpenIMAP` return the protocol's own type when you need more than `Reader`:
`Raw`, `Head`, `Delete` and `Commit` on POP3; folders, search, move, trash,
append and flags on IMAP.

## Development

```sh
go vet ./...
go test ./...
```

The tests run each protocol against a small fake server in the same process,
over TLS, including the hostile cases: a password with a line break in it,
one that has to go as an IMAP literal, a recipient that smuggles in a `Bcc`
header, and a server that offers no encryption before the password is sent.

## License

MIT. See [LICENSE](LICENSE).
