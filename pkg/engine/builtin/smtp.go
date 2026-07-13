package builtin

import (
	"net"
	"net/textproto"
	"time"
)

// session is a minimal SMTP client for verification probes. It is intentionally
// small: it drives only the envelope conversation needed to test a recipient
// (greeting, EHLO/HELO, MAIL FROM, RCPT TO, RSET, QUIT) and never sends DATA, so
// no mail is ever delivered.
type session struct {
	text       *textproto.Conn
	conn       net.Conn
	cmdTimeout time.Duration
}

// newSession wraps an established connection.
func newSession(conn net.Conn, cmdTimeout time.Duration) *session {
	return &session{
		text:       textproto.NewConn(conn),
		conn:       conn,
		cmdTimeout: cmdTimeout,
	}
}

// greeting reads the server's opening banner, expecting a 220.
func (s *session) greeting() (int, string, error) {
	s.setDeadline()
	return s.text.ReadResponse(220)
}

// command sends a single line and reads the full (possibly multi-line) reply.
// The status code is returned as-is for the caller to classify; a mismatched
// class is not treated as an error here.
func (s *session) command(format string, args ...any) (int, string, error) {
	s.setDeadline()
	if err := s.text.PrintfLine(format, args...); err != nil {
		return 0, "", err
	}
	return s.text.ReadResponse(0) // expectCode 0 disables class checking
}

// quit politely ends the session; errors are ignored since the caller is done.
func (s *session) quit() {
	s.setDeadline()
	_ = s.text.PrintfLine("QUIT")
	_, _, _ = s.text.ReadResponse(221)
}

// close closes the underlying connection.
func (s *session) close() { _ = s.text.Close() }

// setDeadline arms the per-command timeout on the connection.
func (s *session) setDeadline() {
	if s.cmdTimeout > 0 {
		_ = s.conn.SetDeadline(time.Now().Add(s.cmdTimeout))
	}
}
