// Package engine defines the pluggable verification-engine contract.
//
// An Engine performs the SMTP-level check for a single address. It is the seam
// that makes rcpttō engine-agnostic: the default builtin engine, an
// out-of-process Reacher adapter, provider-API adapters, and a deterministic
// mock all implement this one interface. Everything above the engine (funnel,
// scheduler, reputation manager) is engine-independent.
//
// Engines never choose their own egress. The control plane assigns an
// EgressBinding per task; the engine dials strictly through it. This keeps
// reputation routing centralized and workers stateless.
package engine

import (
	"context"
	"net"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Task is a single address to verify, together with the routing context the
// control plane has already resolved for it.
type Task struct {
	ID         string // stable task id (for idempotency and tracing)
	JobID      string
	Email      string
	Normalized string // canonical form (e.g. gmail dots/+tags collapsed)
	Domain     string
	Provider   string // resolved destination provider class, if known
}

// EgressBinding is the network identity a probe must originate from. It abstracts
// over a bound local IP, a SOCKS5 proxy dial, or a residential proxy — the engine
// only cares that it can DialContext and knows which HELO name to present.
//
// Implementations are provided by the worker's egress-binder; the mock package
// provides a trivial direct-dial binding for tests.
type EgressBinding interface {
	// ID identifies the egress identity used, for auditability in the Verdict.
	ID() string
	// HELO is the EHLO/HELO hostname to present to the destination MTA.
	HELO() string
	// MailFrom is the envelope sender to use in the probe (often an empty or
	// benign address on a domain with valid SPF/PTR).
	MailFrom() string
	// DialContext opens a connection to addr (typically "<mx-host>:25"). Proxy
	// vs. local-IP binding is transparent to the caller.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// SignalKind classifies a single egress-feedback signal emitted by a probe.
// These feed the reputation manager's health scoring and circuit breakers.
type SignalKind string

const (
	SignalAccepted    SignalKind = "accepted"     // 2xx to RCPT TO
	SignalMailboxGone SignalKind = "mailbox_gone" // hard 5xx: no such user (a good, useful result)
	SignalTempFail    SignalKind = "tempfail"     // 4xx: greylist / transient
	SignalBlocked     SignalKind = "blocked"      // 5xx block / policy rejection of our egress
	SignalConnRefused SignalKind = "conn_refused"
	SignalTimeout     SignalKind = "timeout"
)

// Signal is one piece of egress feedback tied to a probe against a destination.
type Signal struct {
	Kind        SignalKind
	EgressID    string
	Destination string // destination provider or MX host
	Code        int    // SMTP reply code, if any
	Detail      string // short, non-sensitive detail
}

// Caps advertises what an engine supports, so the platform can route around
// limitations (e.g. skip catch-all detection on an engine that lacks it).
type Caps struct {
	SupportsCatchAll bool
	SupportsProxy    bool
	NeedsPort25      bool
}

// Engine is the pluggable verification contract. Implementations must be safe
// for concurrent use by multiple goroutines.
type Engine interface {
	// Verify performs the SMTP-level check for t, dialing exclusively through eg.
	// It returns a Verdict plus any egress Signals observed. A non-nil error is
	// reserved for engine-internal faults; an unreachable or blocking destination
	// is a normal result expressed via Verdict.Status (Unknown) and Signals.
	Verify(ctx context.Context, t Task, eg EgressBinding) (verdict.Verdict, []Signal, error)

	// Name is the stable identifier recorded in Verdict.Engine (e.g. "builtin").
	Name() string

	// Capabilities describes what this engine can do.
	Capabilities() Caps
}
