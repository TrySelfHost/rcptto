// Package policy implements the provider-policy engine: a declarative mapping
// from destination provider (or domain) to a verification strategy. This is
// the honesty layer described in the design doc — it encodes the uncomfortable
// truth that major consumer providers either block SMTP probing outright or
// return uninformative results, and routes around that reality instead of
// pretending a probe against Gmail means what it would against a small
// corporate mail server.
//
// A single egress identity's reputation is the platform's scarcest resource.
// Every address routed to "skip" instead of "probe" is a probe never spent
// against a provider that would not have rewarded it with a trustworthy
// answer anyway.
package policy

import (
	"sort"
	"strings"
)

// Strategy is how a destination provider should be verified.
type Strategy string

const (
	// StrategyProbe performs a full SMTP verification via the engine.
	StrategyProbe Strategy = "probe"
	// StrategySkip does not probe; the funnel's findings alone determine the
	// verdict, reported as risky/unknown with an honest reason.
	StrategySkip Strategy = "skip"
	// StrategyStatistical combines cheap signals (domain reputation, syntax
	// patterns) into a confidence score without a live probe. Not yet
	// implemented by the verifier; reserved for a future milestone.
	StrategyStatistical Strategy = "statistical"
)

// Rule is one provider's policy.
type Rule struct {
	Strategy Strategy
	// Reason is a short, human-readable explanation recorded for operators;
	// it is not shown to API callers.
	Reason string
}

// Set is a resolved, hot-swappable collection of provider policies.
type Set struct {
	rules   map[string]Rule
	defRule Rule
}

// defaultDefault is used when no explicit default rule is configured.
var defaultDefaultRule = Rule{Strategy: StrategyProbe, Reason: "no policy configured; probe by default"}

// New builds a Set from rules keyed by provider or domain (case-insensitive).
// A rule keyed "default" overrides the built-in default (probe); it is removed
// from the lookup map and stored separately.
func New(rules map[string]Rule) *Set {
	s := &Set{rules: make(map[string]Rule, len(rules)), defRule: defaultDefaultRule}
	for k, v := range rules {
		key := strings.ToLower(k)
		if key == "default" {
			s.defRule = v
			continue
		}
		s.rules[key] = v
	}
	return s
}

// Default returns the built-in provider policy set, encoding the well-known
// reality of the major consumer mailbox providers: Gmail and Yahoo silently
// degrade or block repeated SMTP probing, and Microsoft aggressively
// rate-limits and blocks it, so probing them yields more reputation damage
// than signal. Everything else defaults to a normal probe.
func Default() *Set {
	return New(map[string]Rule{
		"gmail":        {Strategy: StrategySkip, Reason: "Gmail throttles/blocks repeated SMTP probing; results are unreliable"},
		"yahoo":        {Strategy: StrategySkip, Reason: "Yahoo commonly accepts-then-bounces later; a probe verdict is not trustworthy"},
		"microsoft":    {Strategy: StrategySkip, Reason: "Microsoft aggressively rate-limits and blocks unfamiliar probing IPs"},
		"microsoft365": {Strategy: StrategySkip, Reason: "Microsoft 365 inherits Microsoft's probing-hostile posture"},
	})
}

// Lookup resolves the policy for a provider/domain, falling back to the
// configured default when there is no explicit rule. Lookup is case-insensitive
// and never returns the zero Rule — an unset Strategy always resolves to probe.
func (s *Set) Lookup(providerOrDomain string) Rule {
	if r, ok := s.rules[strings.ToLower(providerOrDomain)]; ok {
		return normalize(r)
	}
	return normalize(s.defRule)
}

// Entry pairs a provider/domain key with its resolved Rule, for enumeration.
type Entry struct {
	Key  string
	Rule Rule
}

// List returns every explicit rule plus the current default, sorted by key
// with "default" last. Intended for admin/observability surfaces.
func (s *Set) List() []Entry {
	out := make([]Entry, 0, len(s.rules)+1)
	for k, r := range s.rules {
		out = append(out, Entry{Key: k, Rule: normalize(r)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	out = append(out, Entry{Key: "default", Rule: normalize(s.defRule)})
	return out
}

// Set installs or replaces a single rule at runtime (hot-reload/admin edit).
// A key of "default" replaces the fallback rule.
func (s *Set) Set(providerOrDomain string, r Rule) {
	key := strings.ToLower(providerOrDomain)
	if key == "default" {
		s.defRule = r
		return
	}
	s.rules[key] = r
}

// normalize fills an empty Strategy with probe, so a caller-constructed Rule
// with an unset Strategy behaves as "probe" rather than an invalid value.
func normalize(r Rule) Rule {
	if r.Strategy == "" {
		r.Strategy = StrategyProbe
	}
	return r
}
