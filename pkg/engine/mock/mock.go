// Package mock provides a deterministic engine.Engine implementation and a
// trivial engine.EgressBinding, so the rest of the codebase can be tested
// without touching real mail servers or outbound port 25.
//
// Out of the box the engine derives an outcome from the address's local-part
// prefix (valid@, invalid@, catchall@, tempfail@, blocked@, role@,
// disposable@, timeout@); unknown prefixes fall through to a configurable
// default. Explicit per-address rules override the prefix heuristics.
package mock

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Compile-time guarantees that the mock types satisfy the engine contracts.
var (
	_ engine.Engine        = (*Engine)(nil)
	_ engine.EgressBinding = Binding{}
)

// Outcome is a canned engine result: the SMTP-level portion of a Verdict plus
// the egress Signals a real probe would have emitted.
type Outcome struct {
	Status    verdict.Status
	SubStatus verdict.SubStatus
	SMTPCode  int
	Signal    engine.SignalKind
}

// Engine is a deterministic, concurrency-safe mock verification engine.
type Engine struct {
	// Rules maps a lower-cased email address to a fixed Outcome. Rules take
	// precedence over the built-in prefix heuristics.
	Rules map[string]Outcome
	// Default is returned when neither a rule nor a prefix heuristic matches.
	Default Outcome
	// now is injectable for deterministic timestamps in tests.
	now func() time.Time
}

// New returns a mock Engine with sensible defaults: a matched prefix drives the
// outcome, and anything unrecognized is reported as deliverable.
func New() *Engine {
	return &Engine{
		Rules:   map[string]Outcome{},
		Default: Outcome{Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox, SMTPCode: 250, Signal: engine.SignalAccepted},
		now:     time.Now,
	}
}

// WithRule registers an explicit per-address Outcome and returns the engine for
// chaining. The email is matched case-insensitively.
func (e *Engine) WithRule(email string, o Outcome) *Engine {
	e.Rules[strings.ToLower(email)] = o
	return e
}

// WithNow overrides the clock, for deterministic CheckedAt values in tests.
func (e *Engine) WithNow(now func() time.Time) *Engine {
	e.now = now
	return e
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return "mock" }

// Capabilities implements engine.Engine.
func (e *Engine) Capabilities() engine.Caps {
	return engine.Caps{SupportsCatchAll: true, SupportsProxy: true, NeedsPort25: false}
}

// prefixOutcomes maps a local-part prefix to a canned Outcome.
var prefixOutcomes = map[string]Outcome{
	"valid":      {verdict.StatusDeliverable, verdict.SubValidMailbox, 250, engine.SignalAccepted},
	"invalid":    {verdict.StatusUndeliverable, verdict.SubMailboxNotFound, 550, engine.SignalMailboxGone},
	"catchall":   {verdict.StatusRisky, verdict.SubCatchAll, 250, engine.SignalAccepted},
	"role":       {verdict.StatusRisky, verdict.SubRoleAccount, 250, engine.SignalAccepted},
	"disposable": {verdict.StatusRisky, verdict.SubDisposable, 250, engine.SignalAccepted},
	"tempfail":   {verdict.StatusUnknown, verdict.SubGreylisted, 451, engine.SignalTempFail},
	"blocked":    {verdict.StatusUnknown, verdict.SubBlocked, 554, engine.SignalBlocked},
	"timeout":    {verdict.StatusUnknown, verdict.SubTimeout, 0, engine.SignalTimeout},
}

// Verify implements engine.Engine. It never dials; it derives a fixed result
// from the task and records which egress binding was assigned.
func (e *Engine) Verify(_ context.Context, t engine.Task, eg engine.EgressBinding) (verdict.Verdict, []engine.Signal, error) {
	o := e.outcomeFor(t.Email)

	egressID := ""
	if eg != nil {
		egressID = eg.ID()
	}

	v := verdict.Verdict{
		Email:      t.Email,
		Normalized: firstNonEmpty(t.Normalized, strings.ToLower(t.Email)),
		Status:     o.Status,
		SubStatus:  o.SubStatus,
		Confidence: confidenceFor(o.Status),
		Checks: verdict.Checks{
			Syntax:   verdict.SyntaxCheck{Valid: true},
			MX:       verdict.MXCheck{Found: true},
			CatchAll: o.SubStatus == verdict.SubCatchAll,
			Role:     o.SubStatus == verdict.SubRoleAccount,
			SMTP:     verdict.SMTPCheck{Probed: true, Code: o.SMTPCode, Response: string(o.SubStatus)},
		},
		Provider:  t.Provider,
		Engine:    e.Name(),
		EgressID:  egressID,
		CheckedAt: e.now(),
	}

	sigs := []engine.Signal{{
		Kind:        o.Signal,
		EgressID:    egressID,
		Destination: firstNonEmpty(t.Provider, t.Domain),
		Code:        o.SMTPCode,
		Detail:      string(o.SubStatus),
	}}
	return v, sigs, nil
}

func (e *Engine) outcomeFor(email string) Outcome {
	key := strings.ToLower(email)
	if o, ok := e.Rules[key]; ok {
		return o
	}
	if at := strings.IndexByte(key, '@'); at > 0 {
		if o, ok := prefixOutcomes[key[:at]]; ok {
			return o
		}
	}
	return e.Default
}

func confidenceFor(s verdict.Status) float64 {
	switch s {
	case verdict.StatusDeliverable:
		return 0.95
	case verdict.StatusUndeliverable:
		return 0.95
	case verdict.StatusRisky:
		return 0.5
	default:
		return 0.0
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Binding is a trivial engine.EgressBinding for tests. It dials directly via the
// default dialer (though the mock engine never actually dials).
type Binding struct {
	IDValue       string
	HELOValue     string
	MailFromValue string
}

// NewBinding returns a Binding with a given id and reasonable defaults.
func NewBinding(id string) Binding {
	return Binding{IDValue: id, HELOValue: "mail.test.invalid", MailFromValue: "probe@test.invalid"}
}

func (b Binding) ID() string       { return b.IDValue }
func (b Binding) HELO() string     { return b.HELOValue }
func (b Binding) MailFrom() string { return b.MailFromValue }

// DialContext dials directly; provided for interface completeness.
func (b Binding) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
