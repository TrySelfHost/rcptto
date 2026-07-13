package pipeline

import (
	"context"
	"regexp"
	"strings"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// RFC 5321 size limits.
const (
	maxEmailLen  = 254
	maxLocalLen  = 64
	maxDomainLen = 255
)

// localPartRe matches an unquoted RFC 5322 local part: dot-separated atoms of
// permitted atext characters, with no leading, trailing, or consecutive dots.
var localPartRe = regexp.MustCompile(
	"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$",
)

// domainLabelRe matches a single DNS label: alphanumerics and hyphens, not
// beginning or ending with a hyphen, up to 63 characters.
var domainLabelRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// syntaxStage validates address syntax. An invalid address is terminal
// (undeliverable / invalid_syntax); a valid one is split into LocalPart/Domain
// for downstream stages.
type syntaxStage struct{}

func (syntaxStage) Name() string { return "syntax" }

func (syntaxStage) Run(_ context.Context, s *State) (bool, error) {
	addr := strings.TrimSpace(s.Input)
	s.Email = addr

	local, domain, ok := splitAndValidate(addr)
	if !ok {
		s.Checks.Syntax = verdict.SyntaxCheck{Valid: false}
		s.Reject(verdict.StatusUndeliverable, verdict.SubInvalidSyntax, 0.99)
		return true, nil
	}

	s.LocalPart = local
	s.Domain = domain
	s.Checks.Syntax = verdict.SyntaxCheck{Valid: true}
	return false, nil
}

// splitAndValidate splits addr into local and domain parts and validates both,
// returning ok=false if the address is not syntactically deliverable.
func splitAndValidate(addr string) (local, domain string, ok bool) {
	if l := len(addr); l == 0 || l > maxEmailLen {
		return "", "", false
	}

	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", "", false
	}
	local, domain = addr[:at], addr[at+1:]

	if len(local) > maxLocalLen || len(domain) > maxDomainLen {
		return "", "", false
	}
	if !localPartRe.MatchString(local) {
		return "", "", false
	}
	if !validDomain(domain) {
		return "", "", false
	}
	return local, domain, true
}

// validDomain reports whether domain is a syntactically valid, fully-qualified
// hostname: at least two labels, each a valid DNS label, with an alphabetic
// top-level domain of at least two characters.
func validDomain(domain string) bool {
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabelRe.MatchString(label) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || !isAllAlpha(tld) {
		return false
	}
	return true
}

func isAllAlpha(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}
