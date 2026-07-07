// Package verdict defines the stable, public result types produced by rcpttō.
//
// The Verdict is the single most important contract in the system: it is what
// the API returns, what SDKs deserialize, and what downstream consumers store.
// Because it is public and versioned, changes here are additive only — Status
// values and SubStatus reason codes may be added but never removed or repurposed.
//
// A deliberate design choice: Status is four-valued, not boolean. Collapsing
// verification to true/false is the industry's cardinal sin — it forces the
// platform to guess a caller's risk tolerance. Instead we report Deliverable,
// Undeliverable, Risky, or Unknown, each with a machine-readable SubStatus, and
// let callers decide.
package verdict

import (
	"fmt"
	"time"
)

// Status is the top-level, four-valued verification outcome.
type Status string

const (
	// StatusDeliverable means the address is very likely to accept mail.
	StatusDeliverable Status = "deliverable"
	// StatusUndeliverable means the address will not accept mail (bad syntax,
	// no MX, or a mailbox the server explicitly rejected).
	StatusUndeliverable Status = "undeliverable"
	// StatusRisky means the address may accept mail, but sending carries risk:
	// catch-all domains, role accounts, and disposable addresses land here.
	StatusRisky Status = "risky"
	// StatusUnknown means we could not reach a confident conclusion: greylisting,
	// timeouts, provider blocks, blocked port 25, or a policy-driven skip.
	StatusUnknown Status = "unknown"
)

// Valid reports whether s is a known Status value.
func (s Status) Valid() bool {
	switch s {
	case StatusDeliverable, StatusUndeliverable, StatusRisky, StatusUnknown:
		return true
	default:
		return false
	}
}

// String returns the Status as its underlying string value.
func (s Status) String() string { return string(s) }

// SubStatus is a stable, machine-readable reason code that explains a Status.
// This enum is append-only: never remove or repurpose a value once released.
type SubStatus string

const (
	// Deliverable reasons.
	SubValidMailbox SubStatus = "valid_mailbox"

	// Undeliverable reasons.
	SubInvalidSyntax   SubStatus = "invalid_syntax"
	SubNoMXRecord      SubStatus = "no_mx_record"
	SubDomainNotFound  SubStatus = "domain_not_found"
	SubMailboxNotFound SubStatus = "mailbox_not_found" // server returned a hard 5xx for the RCPT

	// Risky reasons.
	SubCatchAll          SubStatus = "catch_all"
	SubRoleAccount       SubStatus = "role_account"
	SubDisposable        SubStatus = "disposable"
	SubFullMailbox       SubStatus = "full_mailbox"
	SubLowDeliverability SubStatus = "low_deliverability"

	// Unknown reasons.
	SubGreylisted       SubStatus = "greylisted"
	SubTimeout          SubStatus = "timeout"
	SubBlocked          SubStatus = "blocked"        // destination refused/blocked our egress
	SubPort25Blocked    SubStatus = "port25_blocked" // our side cannot open outbound :25
	SubProviderSkipped  SubStatus = "provider_skipped"
	SubTemporaryFailure SubStatus = "temporary_failure"
	SubNoConnect        SubStatus = "no_connect"
)

// String returns the SubStatus as its underlying string value.
func (s SubStatus) String() string { return string(s) }

// Checks is the per-stage breakdown behind a Verdict. Fields are populated as
// far as the funnel and engine progressed; later stages are zero-valued when an
// earlier stage produced a terminal result.
type Checks struct {
	Syntax     SyntaxCheck `json:"syntax"`
	MX         MXCheck     `json:"mx"`
	Disposable bool        `json:"disposable"`
	Role       bool        `json:"role"`
	Free       bool        `json:"free"`
	CatchAll   bool        `json:"catch_all"`
	SMTP       SMTPCheck   `json:"smtp"`
}

// SyntaxCheck reports RFC 5322 validity.
type SyntaxCheck struct {
	Valid bool `json:"valid"`
}

// MXCheck reports DNS MX resolution.
type MXCheck struct {
	Found   bool     `json:"found"`
	Records []string `json:"records,omitempty"`
}

// SMTPCheck reports the outcome of the SMTP-level probe, when one was performed.
type SMTPCheck struct {
	Probed   bool   `json:"probed"`
	Code     int    `json:"code,omitempty"`     // last SMTP reply code observed
	Response string `json:"response,omitempty"` // short, non-sensitive summary
}

// Verdict is the complete, public result of verifying one email address.
type Verdict struct {
	Email      string    `json:"email"`
	Normalized string    `json:"normalized"`
	Status     Status    `json:"status"`
	SubStatus  SubStatus `json:"sub_status"`
	Confidence float64   `json:"confidence"` // 0..1
	Checks     Checks    `json:"checks"`
	Provider   string    `json:"provider,omitempty"` // gmail | microsoft | yahoo | custom | ...
	Engine     string    `json:"engine,omitempty"`   // which engine produced the SMTP verdict
	EgressID   string    `json:"egress_id,omitempty"`
	Cached     bool      `json:"cached"`
	CheckedAt  time.Time `json:"checked_at"`
}

// Validate performs a light structural check on a Verdict. It is intended for
// tests and defensive boundaries (e.g. before persisting), not as business logic.
func (v Verdict) Validate() error {
	if v.Email == "" {
		return fmt.Errorf("verdict: empty email")
	}
	if !v.Status.Valid() {
		return fmt.Errorf("verdict: invalid status %q", v.Status)
	}
	if v.Confidence < 0 || v.Confidence > 1 {
		return fmt.Errorf("verdict: confidence %v out of range [0,1]", v.Confidence)
	}
	return nil
}
