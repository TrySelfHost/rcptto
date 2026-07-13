package pipeline

import (
	"context"
	"strings"
)

// normalizeStage lower-cases the domain, derives the probe target (Email) and
// the canonical dedup key (Normalized), and resolves the destination provider
// class from the domain. It is never terminal.
type normalizeStage struct{}

func (normalizeStage) Name() string { return "normalize" }

func (normalizeStage) Run(_ context.Context, s *State) (bool, error) {
	domain := strings.ToLower(s.Domain)
	s.Domain = domain
	// Probe target: original local-part case is preserved; only the domain is
	// lower-cased (domains are case-insensitive, local-parts are not).
	s.Email = s.LocalPart + "@" + domain

	provider := providerForDomain(domain)
	if provider == "" {
		provider = providerCustom
	}
	s.Provider = provider

	s.Normalized = canonicalKey(s.LocalPart, domain, provider)
	return false, nil
}

// canonicalKey builds the normalized dedup/cache key. The local-part is
// lower-cased for all providers; Gmail additionally has dots removed and any
// "+tag" suffix stripped, and googlemail.com is folded to gmail.com.
func canonicalKey(local, domain, provider string) string {
	nl := strings.ToLower(local)
	canonDomain := domain

	if provider == providerGmail {
		nl = strings.ReplaceAll(nl, ".", "")
		if i := strings.IndexByte(nl, '+'); i >= 0 {
			nl = nl[:i]
		}
		canonDomain = "gmail.com"
	}
	return nl + "@" + canonDomain
}
