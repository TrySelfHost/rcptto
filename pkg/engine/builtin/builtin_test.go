package builtin

import (
	"context"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/engine/mock"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// mockSMTP is a minimal, scriptable SMTP server for engine tests. The rcpt
// callback returns the full reply line (without CRLF) for each RCPT TO address,
// letting each test drive a specific server behavior.
type mockSMTP struct {
	ln   net.Listener
	rcpt func(addr string) string
}

func startMockSMTP(t *testing.T, rcpt func(addr string) string) *mockSMTP {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockSMTP{ln: ln, rcpt: rcpt}
	go m.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return m
}

func (m *mockSMTP) port() int { return m.ln.Addr().(*net.TCPAddr).Port }

func (m *mockSMTP) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handle(conn)
	}
}

func (m *mockSMTP) handle(conn net.Conn) {
	defer conn.Close()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 mock ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			_ = tp.PrintfLine("250 mock")
		case strings.HasPrefix(up, "MAIL FROM"):
			_ = tp.PrintfLine("250 2.1.0 OK")
		case strings.HasPrefix(up, "RCPT TO"):
			_ = tp.PrintfLine("%s", m.rcpt(extractAddr(line)))
		case strings.HasPrefix(up, "RSET"):
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(up, "QUIT"):
			_ = tp.PrintfLine("221 Bye")
			return
		default:
			_ = tp.PrintfLine("250 OK")
		}
	}
}

func extractAddr(line string) string {
	if i := strings.IndexByte(line, '<'); i >= 0 {
		if j := strings.IndexByte(line[i:], '>'); j > 0 {
			return line[i+1 : i+j]
		}
	}
	return ""
}

// newEngine builds an engine pointed at the mock server's port with a fixed clock.
func newEngine(port int, detectCatchAll bool) *Engine {
	return New(Config{
		Port:           port,
		ConnectTimeout: 2 * time.Second,
		CommandTimeout: 2 * time.Second,
		DetectCatchAll: detectCatchAll,
		Now:            func() time.Time { return time.Unix(0, 0).UTC() },
	})
}

func task(email string, mx ...string) engine.Task {
	return engine.Task{Email: email, Normalized: email, Domain: "example.com", Provider: "custom", MX: mx}
}

func TestVerifyDeliverable(t *testing.T) {
	srv := startMockSMTP(t, func(string) string { return "250 2.1.5 Recipient OK" })
	e := newEngine(srv.port(), false)

	v, sigs, err := e.Verify(context.Background(), task("valid@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusDeliverable || v.SubStatus != verdict.SubValidMailbox {
		t.Fatalf("got (%s,%s), want deliverable/valid_mailbox", v.Status, v.SubStatus)
	}
	if !v.Checks.SMTP.Probed || v.Checks.SMTP.Code != 250 {
		t.Errorf("smtp check = %+v", v.Checks.SMTP)
	}
	if v.Engine != "builtin" || v.EgressID != "eg_1" {
		t.Errorf("engine=%q egress=%q", v.Engine, v.EgressID)
	}
	if len(sigs) != 1 || sigs[0].Kind != engine.SignalAccepted {
		t.Errorf("signals = %+v", sigs)
	}
}

func TestVerifyMailboxNotFound(t *testing.T) {
	srv := startMockSMTP(t, func(string) string { return "550 5.1.1 No such user here" })
	e := newEngine(srv.port(), false)

	v, sigs, _ := e.Verify(context.Background(), task("ghost@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusUndeliverable || v.SubStatus != verdict.SubMailboxNotFound {
		t.Fatalf("got (%s,%s), want undeliverable/mailbox_not_found", v.Status, v.SubStatus)
	}
	if sigs[0].Kind != engine.SignalMailboxGone {
		t.Errorf("signal = %s, want mailbox_gone", sigs[0].Kind)
	}
}

func TestVerifyCatchAll(t *testing.T) {
	// Server accepts every recipient, including the random probe.
	srv := startMockSMTP(t, func(string) string { return "250 OK" })
	e := newEngine(srv.port(), true)

	v, _, _ := e.Verify(context.Background(), task("anyone@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusRisky || v.SubStatus != verdict.SubCatchAll {
		t.Fatalf("got (%s,%s), want risky/catch_all", v.Status, v.SubStatus)
	}
	if !v.Checks.CatchAll {
		t.Errorf("catch_all check flag not set")
	}
}

func TestVerifyNotCatchAllStaysDeliverable(t *testing.T) {
	// Real address accepted; the random probe (rcptto-probe-*) is rejected.
	srv := startMockSMTP(t, func(addr string) string {
		if strings.HasPrefix(addr, "rcptto-probe-") {
			return "550 5.1.1 No such user"
		}
		return "250 OK"
	})
	e := newEngine(srv.port(), true)

	v, _, _ := e.Verify(context.Background(), task("real@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusDeliverable {
		t.Fatalf("got %s, want deliverable (not catch-all)", v.Status)
	}
	if v.Checks.CatchAll {
		t.Errorf("catch_all should be false")
	}
}

func TestVerifyGreylist(t *testing.T) {
	srv := startMockSMTP(t, func(string) string { return "451 4.7.1 Greylisting in effect, try again later" })
	e := newEngine(srv.port(), false)

	v, sigs, _ := e.Verify(context.Background(), task("user@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusUnknown || v.SubStatus != verdict.SubGreylisted {
		t.Fatalf("got (%s,%s), want unknown/greylisted (4.7.1 is greylisting, not a block)", v.Status, v.SubStatus)
	}
	if sigs[0].Kind != engine.SignalTempFail {
		t.Errorf("signal = %s, want tempfail", sigs[0].Kind)
	}
}

func TestVerifyPolicyBlock(t *testing.T) {
	srv := startMockSMTP(t, func(string) string { return "550 5.7.1 Message rejected due to spam policy" })
	e := newEngine(srv.port(), false)

	v, sigs, _ := e.Verify(context.Background(), task("user@example.com", "127.0.0.1"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusUnknown || v.SubStatus != verdict.SubBlocked {
		t.Fatalf("got (%s,%s), want unknown/blocked", v.Status, v.SubStatus)
	}
	if sigs[0].Kind != engine.SignalBlocked {
		t.Errorf("signal = %s, want blocked", sigs[0].Kind)
	}
}

func TestVerifyNoMX(t *testing.T) {
	e := newEngine(2525, false)
	v, sigs, _ := e.Verify(context.Background(), task("user@example.com"), mock.NewBinding("eg_1"))
	if v.Status != verdict.StatusUnknown || v.SubStatus != verdict.SubNoConnect {
		t.Fatalf("got (%s,%s), want unknown/no_connect", v.Status, v.SubStatus)
	}
	if sigs[0].Kind != engine.SignalConnRefused {
		t.Errorf("signal = %s, want conn_refused", sigs[0].Kind)
	}
}

func TestVerifyUnreachableThenFailover(t *testing.T) {
	// 127.0.0.2 has nothing listening (still loopback → connection refused); the
	// engine must fail over to 127.0.0.1 where the mock is running.
	srv := startMockSMTP(t, func(string) string { return "250 OK" })
	e := newEngine(srv.port(), false)

	v, _, err := e.Verify(context.Background(), task("user@example.com", "127.0.0.2", "127.0.0.1"), mock.NewBinding("eg_1"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusDeliverable {
		t.Fatalf("got %s, want deliverable via failover to second MX", v.Status)
	}
}
