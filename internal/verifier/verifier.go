// Package verifier orchestrates a single-address verification: it runs the
// funnel, and for addresses that survive it, probes them with the configured
// engine through an egress identity. It also applies the result cache and the
// post-probe aggregation that merges funnel findings with the SMTP verdict.
//
// This is the composition root for the verification core: it depends on the
// pipeline, the engine port, the egress port, the store port, and a signal
// sink — never on their concrete implementations.
package verifier

import (
	"context"
	"time"

	"github.com/tryselfhost/rcptto/internal/pipeline"
	"github.com/tryselfhost/rcptto/internal/policy"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// defaultCacheTTL is used when Config.CacheTTL is unset.
const defaultCacheTTL = 24 * time.Hour

// SignalSink receives the egress feedback produced by probes. The reputation
// manager will implement this; the default is a no-op.
type SignalSink interface {
	Emit(ctx context.Context, signals []engine.Signal)
}

type noopSink struct{}

func (noopSink) Emit(context.Context, []engine.Signal) {}

// Config configures a Service. Pipeline and Engine are required; the rest have
// defaults.
type Config struct {
	Pipeline *pipeline.Pipeline
	Engine   engine.Engine
	Egress   EgressProvider    // defaults to DirectProvider{}
	Cache    store.ResultStore // optional; nil disables caching
	CacheTTL time.Duration     // defaults to 24h
	Sink     SignalSink        // defaults to no-op
	Policy   *policy.Set       // defaults to policy.Default()
	Now      func() time.Time  // defaults to time.Now
}

// Service verifies a single address end to end.
type Service struct {
	pipeline *pipeline.Pipeline
	engine   engine.Engine
	egress   EgressProvider
	cache    store.ResultStore
	cacheTTL time.Duration
	sink     SignalSink
	policy   *policy.Set
	now      func() time.Time
}

// New builds a Service, applying defaults for unset Config fields. It panics if
// Pipeline or Engine is nil, since neither has a sensible default.
func New(cfg Config) *Service {
	if cfg.Pipeline == nil || cfg.Engine == nil {
		panic("verifier: Pipeline and Engine are required")
	}
	s := &Service{
		pipeline: cfg.Pipeline,
		engine:   cfg.Engine,
		egress:   cfg.Egress,
		cache:    cfg.Cache,
		cacheTTL: cfg.CacheTTL,
		sink:     cfg.Sink,
		policy:   cfg.Policy,
		now:      cfg.Now,
	}
	if s.egress == nil {
		s.egress = DirectProvider{}
	}
	if s.cacheTTL == 0 {
		s.cacheTTL = defaultCacheTTL
	}
	if s.sink == nil {
		s.sink = noopSink{}
	}
	if s.policy == nil {
		s.policy = policy.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Verify verifies a single email address, returning a complete Verdict.
func (s *Service) Verify(ctx context.Context, email string) (verdict.Verdict, error) {
	res, err := s.pipeline.Run(ctx, email)
	if err != nil {
		return verdict.Verdict{}, err
	}

	key := res.Verdict.Normalized
	if !res.Terminal {
		key = res.Task.Normalized
	}

	if v, ok := s.cacheGet(ctx, key); ok {
		v.Cached = true
		return v, nil
	}

	final := res.Verdict
	if !res.Terminal {
		if rule := s.policy.Lookup(policyKey(res)); rule.Strategy == policy.StrategySkip {
			final = s.skipVerdict(res, rule)
		} else {
			final, err = s.probe(ctx, res)
			if err != nil {
				return verdict.Verdict{}, err
			}
		}
	}

	// Do not cache unknown/deferred results — they are retryable (greylisting,
	// timeouts, no egress available now). Only stable verdicts are cached.
	if final.Status != verdict.StatusUnknown {
		s.cachePut(ctx, key, final)
	}
	return final, nil
}

// policyKey returns the lookup key for a funnel result: the resolved provider
// class when known, otherwise the domain, mirroring how the egress manager
// keys destinations (see internal/egress destOf).
func policyKey(res pipeline.Result) string {
	if res.Provider != "" && res.Provider != "custom" {
		return res.Provider
	}
	return res.Task.Domain
}

// skipVerdict builds the honest, no-probe verdict for a policy-skipped address.
// Status is risky rather than a flat unknown: the funnel already confirmed
// syntax and a deliverable MX, so the address is plausible — we simply cannot
// confirm the mailbox without probing a provider that would not reward it with
// a trustworthy answer.
func (s *Service) skipVerdict(res pipeline.Result, rule policy.Rule) verdict.Verdict {
	return verdict.Verdict{
		Email:      res.Task.Email,
		Normalized: res.Task.Normalized,
		Status:     verdict.StatusRisky,
		SubStatus:  verdict.SubProviderSkipped,
		Confidence: 0.3,
		Checks:     res.Checks,
		Provider:   res.Provider,
		CheckedAt:  s.now(),
	}
}

// probe runs the engine against a survived funnel result and merges findings.
// When no egress identity is available (e.g. all quarantined), it returns an
// honest deferred "unknown" rather than failing the request.
func (s *Service) probe(ctx context.Context, res pipeline.Result) (verdict.Verdict, error) {
	binding, err := s.egress.Binding(ctx, res.Task)
	if err != nil {
		return s.noEgressVerdict(res), nil
	}
	ev, signals, err := s.engine.Verify(ctx, res.Task, binding)
	if err != nil {
		return verdict.Verdict{}, err
	}
	s.sink.Emit(ctx, signals)
	return merge(res, ev), nil
}

// noEgressVerdict builds a deferred unknown verdict that preserves the funnel's
// findings, used when the egress pool cannot currently supply an identity.
func (s *Service) noEgressVerdict(res pipeline.Result) verdict.Verdict {
	return verdict.Verdict{
		Email:      res.Task.Email,
		Normalized: res.Task.Normalized,
		Status:     verdict.StatusUnknown,
		SubStatus:  verdict.SubTemporaryFailure,
		Confidence: 0.1,
		Checks:     res.Checks,
		Provider:   res.Provider,
		CheckedAt:  s.now(),
	}
}

// merge combines the funnel's findings with the engine's SMTP verdict into the
// final result. The engine populates the SMTP and catch-all checks; the funnel
// populates syntax, MX, and the disposable/role/free flags. A live mailbox that
// is a role account is downgraded to risky.
func merge(res pipeline.Result, ev verdict.Verdict) verdict.Verdict {
	out := ev
	out.Checks.Syntax = res.Checks.Syntax
	out.Checks.MX = res.Checks.MX
	out.Checks.Disposable = res.Checks.Disposable
	out.Checks.Role = res.Checks.Role
	out.Checks.Free = res.Checks.Free

	if out.Normalized == "" {
		out.Normalized = res.Task.Normalized
	}
	if out.Provider == "" {
		out.Provider = res.Provider
	}

	if out.Status == verdict.StatusDeliverable && res.Checks.Role {
		out.Status = verdict.StatusRisky
		out.SubStatus = verdict.SubRoleAccount
		out.Confidence = 0.5
	}
	return out
}

func (s *Service) cacheGet(ctx context.Context, key string) (verdict.Verdict, bool) {
	if s.cache == nil || key == "" {
		return verdict.Verdict{}, false
	}
	v, ok, err := s.cache.Get(ctx, key)
	if err != nil || !ok {
		return verdict.Verdict{}, false
	}
	return v, true
}

func (s *Service) cachePut(ctx context.Context, key string, v verdict.Verdict) {
	if s.cache == nil || key == "" {
		return
	}
	_ = s.cache.Put(ctx, key, v, s.cacheTTL)
}
