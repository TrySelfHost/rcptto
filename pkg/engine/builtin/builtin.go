// Package builtin implements the default verification engine: a native SMTP
// prober that speaks just enough of the protocol to test a recipient without
// ever sending mail. It is permissively licensed (Apache-2.0, like the core) and
// linked in-process, so the default deployment needs no external engine.
//
// The engine is deliberately dumb about routing: it receives its egress binding
// and the destination MX list from the control plane and never chooses either
// itself. That keeps reputation decisions centralized and workers stateless.
package builtin

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Default timeouts and SMTP port.
const (
	defaultPort           = 25
	defaultConnectTimeout = 10 * time.Second
	defaultCommandTimeout = 10 * time.Second
	defaultHELO           = "localhost"
	defaultMailFrom       = "verify@localhost"
)

// Config configures the builtin engine. All fields are optional.
type Config struct {
	// Port is the SMTP port to dial. Defaults to 25; overridable for tests.
	Port int
	// ConnectTimeout bounds establishing each TCP connection.
	ConnectTimeout time.Duration
	// CommandTimeout bounds each SMTP command/response round-trip.
	CommandTimeout time.Duration
	// DetectCatchAll enables the catch-all probe on accepted recipients.
	DetectCatchAll bool
	// HELO is the fallback EHLO/HELO name used when the egress binding provides none.
	HELO string
	// MailFrom is the fallback envelope sender used when the binding provides none.
	MailFrom string
	// Now supplies verdict timestamps. Defaults to time.Now.
	Now func() time.Time
}

// Engine is the builtin SMTP verification engine.
type Engine struct {
	mu  sync.RWMutex
	cfg Config
}

// compile-time guarantee that *Engine satisfies the engine contract.
var _ engine.Engine = (*Engine)(nil)

// New returns a builtin Engine, applying defaults for unset Config fields.
func New(cfg Config) *Engine {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = defaultCommandTimeout
	}
	if cfg.HELO == "" {
		cfg.HELO = defaultHELO
	}
	if cfg.MailFrom == "" {
		cfg.MailFrom = defaultMailFrom
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{cfg: cfg}
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return "builtin" }

// Capabilities implements engine.Engine.
func (e *Engine) Capabilities() engine.Caps {
	return engine.Caps{SupportsCatchAll: true, SupportsProxy: true, NeedsPort25: true}
}

// Verify implements engine.Engine. It probes each MX host in preference order
// until one accepts a connection and completes the envelope conversation. If no
// host is reachable, it returns an unknown verdict with a connection signal
// rather than an error — an unreachable destination is a normal result.
func (e *Engine) Verify(ctx context.Context, t engine.Task, eg engine.EgressBinding) (verdict.Verdict, []engine.Signal, error) {
	if len(t.MX) == 0 {
		return e.result(t, eg, verdict.StatusUnknown, verdict.SubNoConnect, 0, "", false),
			e.signals(eg, engine.SignalConnRefused, t, 0, "no mx"), nil
	}

	for _, host := range t.MX {
		v, sigs, connected := e.probeHost(ctx, t, eg, host)
		if connected {
			return v, sigs, nil
		}
	}

	// No MX host was reachable (all connections refused or timed out).
	return e.result(t, eg, verdict.StatusUnknown, verdict.SubNoConnect, 0, "", false),
		e.signals(eg, engine.SignalConnRefused, t, 0, "all mx unreachable"), nil
}

// probeHost runs the full probe against a single MX host. connected reports
// whether the TCP connection was established (and thus whether the verdict is
// authoritative); when false, the caller should try the next host.
func (e *Engine) probeHost(ctx context.Context, t engine.Task, eg engine.EgressBinding, host string) (verdict.Verdict, []engine.Signal, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(e.cfg.Port))

	dialCtx, cancel := context.WithTimeout(ctx, e.cfg.ConnectTimeout)
	conn, err := eg.DialContext(dialCtx, "tcp", addr)
	cancel()
	if err != nil {
		return verdict.Verdict{}, nil, false
	}

	sess := newSession(conn, e.cfg.CommandTimeout)
	defer sess.close()

	if code, _, err := sess.greeting(); err != nil || code >= 500 {
		return e.result(t, eg, verdict.StatusUnknown, verdict.SubBlocked, code, "greeting rejected", false),
			e.signals(eg, engine.SignalBlocked, t, code, "greeting"), true
	}

	if !e.greet(sess, eg) {
		return e.result(t, eg, verdict.StatusUnknown, verdict.SubBlocked, 0, "helo rejected", false),
			e.signals(eg, engine.SignalBlocked, t, 0, "helo"), true
	}

	if code, msg, ok := e.mailFrom(sess, eg); !ok {
		out := classifyRCPT(code, msg) // reuse 4xx/5xx classification for MAIL FROM rejects
		return e.result(t, eg, out.status, out.subStatus, code, msg, false),
			e.signals(eg, out.signal, t, code, msg), true
	}

	code, msg, err := sess.command("RCPT TO:<%s>", t.Email)
	if err != nil {
		return e.result(t, eg, verdict.StatusUnknown, verdict.SubTemporaryFailure, 0, "rcpt io error", false),
			e.signals(eg, engine.SignalTempFail, t, 0, "rcpt io"), true
	}

	out := classifyRCPT(code, msg)
	catchAll := false
	if out.status == verdict.StatusDeliverable && e.detectCatchAllEnabled() {
		catchAll = e.detectCatchAll(sess, t.Domain)
		if catchAll {
			out.status = verdict.StatusRisky
			out.subStatus = verdict.SubCatchAll
		}
	}

	sess.quit()

	v := e.result(t, eg, out.status, out.subStatus, code, msg, catchAll)
	return v, e.signals(eg, out.signal, t, code, msg), true
}

// greet sends EHLO, falling back to HELO, and reports whether the server
// accepted the greeting.
func (e *Engine) greet(sess *session, eg engine.EgressBinding) bool {
	helo := firstNonEmpty(eg.HELO(), e.cfg.HELO)
	if code, _, err := sess.command("EHLO %s", helo); err == nil && code < 400 {
		return true
	}
	code, _, err := sess.command("HELO %s", helo)
	return err == nil && code < 400
}

// mailFrom issues MAIL FROM and reports whether it was accepted, returning the
// reply for classification on failure.
func (e *Engine) mailFrom(sess *session, eg engine.EgressBinding) (int, string, bool) {
	from := firstNonEmpty(eg.MailFrom(), e.cfg.MailFrom)
	code, msg, err := sess.command("MAIL FROM:<%s>", from)
	if err != nil {
		return 0, "mail from io error", false
	}
	return code, msg, code >= 200 && code < 300
}

// detectCatchAll probes a random, almost-certainly-nonexistent recipient; if the
// server accepts it, the domain is catch-all. An inconclusive probe (error or
// non-2xx) is treated as "not catch-all" so a real accepted recipient stands.
func (e *Engine) detectCatchAll(sess *session, domain string) bool {
	code, _, err := sess.command("RCPT TO:<%s@%s>", randomLocalPart(), domain)
	return err == nil && code >= 200 && code < 300
}

// result assembles a Verdict. The builtin engine populates only the SMTP-related
// checks; funnel findings (syntax, mx, disposable, ...) are merged upstream.
func (e *Engine) result(t engine.Task, eg engine.EgressBinding, status verdict.Status, sub verdict.SubStatus, code int, msg string, catchAll bool) verdict.Verdict {
	egressID := ""
	if eg != nil {
		egressID = eg.ID()
	}
	return verdict.Verdict{
		Email:      t.Email,
		Normalized: firstNonEmpty(t.Normalized, t.Email),
		Status:     status,
		SubStatus:  sub,
		Confidence: confidenceFor(status),
		Checks: verdict.Checks{
			CatchAll: catchAll,
			SMTP: verdict.SMTPCheck{
				Probed:   code != 0,
				Code:     code,
				Response: shortResponse(msg),
			},
		},
		Provider:  t.Provider,
		Engine:    e.Name(),
		EgressID:  egressID,
		CheckedAt: e.cfg.Now(),
	}
}

// signals builds the egress-feedback slice for a probe outcome.
func (e *Engine) signals(eg engine.EgressBinding, kind engine.SignalKind, t engine.Task, code int, detail string) []engine.Signal {
	egressID := ""
	if eg != nil {
		egressID = eg.ID()
	}
	dest := firstNonEmpty(t.Provider, t.Domain)
	return []engine.Signal{{
		Kind:        kind,
		EgressID:    egressID,
		Destination: dest,
		Code:        code,
		Detail:      shortResponse(detail),
	}}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// SetDetectCatchAll toggles catch-all detection at runtime. Detection is
// accurate but costs a second probe for every accepted address, so it is worth
// disabling when egress budget is tight.
func (e *Engine) SetDetectCatchAll(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.DetectCatchAll = on
}

// detectCatchAllEnabled reads the flag under the lock.
func (e *Engine) detectCatchAllEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.DetectCatchAll
}
