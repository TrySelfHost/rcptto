// Package pipeline implements the verification funnel: an ordered sequence of
// cheap-to-expensive stages that either reach a terminal verdict for an address
// or mark it as needing an SMTP probe.
//
// The ordering is deliberate. Each stage is cheaper than the next, and any stage
// may short-circuit the funnel with a terminal verdict. Every address eliminated
// before the probe stage is a saved SMTP connection — and, more importantly, a
// saved unit of egress reputation, which is the platform's scarcest resource.
//
// Default stage order:
//
//	syntax → normalize → disposable → role → free → mx
//
// Local, in-memory checks (syntax, normalize, disposable, role, free) run before
// the single network-bound stage (mx), so unreachable or throwaway addresses are
// rejected without a DNS round-trip where possible.
package pipeline

import (
	"context"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// State is the mutable working context threaded through the stages for a single
// address. Stages read the resolved fields populated by earlier stages and set
// their own findings; a stage reaches a terminal decision by calling Reject.
type State struct {
	// Input is the address exactly as submitted.
	Input string
	// Email is the probe target: the original local-part with a lower-cased
	// domain. This is what an SMTP probe would issue RCPT TO against.
	Email string
	// Normalized is the canonical dedup/cache key (lower-cased, with
	// provider-specific normalization such as Gmail dot/plus-tag collapsing).
	Normalized string
	// LocalPart and Domain are the split components of Email.
	LocalPart string
	Domain    string
	// Provider is the resolved destination provider class (e.g. "gmail",
	// "microsoft", "google_workspace", "custom"), populated during normalize
	// and optionally refined by the mx stage.
	Provider string
	// MX holds the resolved mail-exchanger hostnames, in preference order.
	MX []string
	// Checks accumulates per-stage findings, carried into the final verdict.
	Checks verdict.Checks

	terminal *verdict.Verdict
	now      func() time.Time
}

// Reject sets a terminal verdict on the state and signals the pipeline to stop.
// The accumulated Checks and resolved Provider are attached to the verdict.
func (s *State) Reject(status verdict.Status, sub verdict.SubStatus, confidence float64) {
	v := verdict.Verdict{
		Email:      s.Email,
		Normalized: s.Normalized,
		Status:     status,
		SubStatus:  sub,
		Confidence: confidence,
		Checks:     s.Checks,
		Provider:   s.Provider,
		CheckedAt:  s.now(),
	}
	s.terminal = &v
}

// terminated reports whether a stage has set a terminal verdict.
func (s *State) terminated() bool { return s.terminal != nil }

// Result is the outcome of running the pipeline for one address. Exactly one of
// the two modes applies, distinguished by Terminal:
//
//   - Terminal == true:  Verdict holds the funnel's final answer; no probe needed.
//   - Terminal == false: Task holds the resolved routing context for the scheduler
//     to dispatch an SMTP probe; Checks holds findings gathered so far.
type Result struct {
	// Terminal indicates the funnel decided without a probe.
	Terminal bool
	// Verdict is valid when Terminal is true.
	Verdict verdict.Verdict
	// Task is valid when Terminal is false: the address that survived the funnel.
	Task engine.Task
	// Checks holds the accumulated findings (also embedded in Verdict when Terminal).
	Checks verdict.Checks
	// Provider and MX are the resolved routing context, valid in both modes.
	Provider string
	MX       []string
}

// Stage is a single step in the funnel. Run inspects and mutates s, returning
// stop=true once a terminal verdict has been set (via State.Reject) so the
// pipeline halts. A non-nil error indicates a stage-internal fault, not an
// undeliverable address (which is expressed through State.Reject).
type Stage interface {
	// Name identifies the stage, for tracing and metrics.
	Name() string
	// Run executes the stage against s.
	Run(ctx context.Context, s *State) (stop bool, err error)
}

// Pipeline runs an ordered list of stages against an address.
type Pipeline struct {
	stages []Stage
	now    func() time.Time
}

// Run executes the funnel for a single address and returns its Result.
func (p *Pipeline) Run(ctx context.Context, email string) (Result, error) {
	s := &State{Input: email, Email: email, Normalized: email, now: p.now}

	for _, stage := range p.stages {
		stop, err := stage.Run(ctx, s)
		if err != nil {
			return Result{}, err
		}
		if stop || s.terminated() {
			break
		}
	}

	if s.terminated() {
		return Result{
			Terminal: true,
			Verdict:  *s.terminal,
			Checks:   s.Checks,
			Provider: s.Provider,
			MX:       s.MX,
		}, nil
	}

	return Result{
		Terminal: false,
		Task: engine.Task{
			Email:      s.Email,
			Normalized: s.Normalized,
			Domain:     s.Domain,
			Provider:   s.Provider,
		},
		Checks:   s.Checks,
		Provider: s.Provider,
		MX:       s.MX,
	}, nil
}

// Stages returns the ordered stage names, for diagnostics.
func (p *Pipeline) Stages() []string {
	names := make([]string, len(p.stages))
	for i, st := range p.stages {
		names[i] = st.Name()
	}
	return names
}
