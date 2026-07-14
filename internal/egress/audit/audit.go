// Package audit provides reputation audits for egress identities: DNS-based
// blocklist (DNSBL) checks and reverse-DNS (PTR / forward-confirmed rDNS)
// verification. These turn reputation loss into a leading indicator — a listing
// or broken rDNS is detected on a schedule, before probe results start
// degrading, so an identity can be quarantined pre-emptively.
//
// All lookups go through the Resolver port, so the checkers are testable without
// real DNS; the direct implementation wraps the system resolver.
package audit

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Resolver abstracts the DNS lookups the audits need.
type Resolver interface {
	// LookupHost resolves a hostname to its A/AAAA addresses.
	LookupHost(ctx context.Context, host string) ([]string, error)
	// LookupAddr resolves an IP to its PTR (reverse DNS) names.
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DirectResolver is the default Resolver, backed by the system resolver.
type DirectResolver struct{}

// LookupHost implements Resolver.
func (DirectResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// LookupAddr implements Resolver.
func (DirectResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// DNSBL checks an IPv4 address against one or more DNS blocklist zones.
type DNSBL struct {
	resolver Resolver
	zones    []string
}

// NewDNSBL returns a DNSBL checker for the given zones (e.g. "zen.spamhaus.org").
// A nil resolver uses the system resolver.
func NewDNSBL(resolver Resolver, zones []string) *DNSBL {
	if resolver == nil {
		resolver = DirectResolver{}
	}
	return &DNSBL{resolver: resolver, zones: zones}
}

// Check returns the zones that currently list ip. IPv6 and unparseable inputs
// return no listings (IPv6 DNSBL is not yet supported). Transient lookup errors
// for a zone are skipped rather than reported as a listing, so a DNS blip never
// causes a false quarantine.
func (d *DNSBL) Check(ctx context.Context, ip string) ([]string, error) {
	rev, ok := reverseIPv4(ip)
	if !ok {
		return nil, nil
	}
	var listed []string
	for _, zone := range d.zones {
		query := rev + "." + zone
		addrs, err := d.resolver.LookupHost(ctx, query)
		if err != nil {
			// NXDOMAIN means "not listed"; any other error is treated as
			// inconclusive and skipped.
			continue
		}
		for _, a := range addrs {
			if isListingCode(a) {
				listed = append(listed, zone)
				break
			}
		}
	}
	return listed, nil
}

// PTRResult is the outcome of a reverse-DNS audit.
type PTRResult struct {
	// Names are the PTR records found for the IP.
	Names []string
	// FCrDNS is true when at least one PTR name forward-resolves back to the IP
	// (forward-confirmed reverse DNS) — a key deliverability signal.
	FCrDNS bool
	// HELOMatch is true when a PTR name matches the identity's HELO hostname.
	HELOMatch bool
}

// PTRAuditor verifies reverse DNS for egress IPs.
type PTRAuditor struct {
	resolver Resolver
}

// NewPTRAuditor returns a PTR auditor. A nil resolver uses the system resolver.
func NewPTRAuditor(resolver Resolver) *PTRAuditor {
	if resolver == nil {
		resolver = DirectResolver{}
	}
	return &PTRAuditor{resolver: resolver}
}

// Audit performs a forward-confirmed reverse-DNS check for ip and compares the
// PTR names against the given HELO hostname.
func (a *PTRAuditor) Audit(ctx context.Context, ip, helo string) (PTRResult, error) {
	names, err := a.resolver.LookupAddr(ctx, ip)
	if err != nil {
		return PTRResult{}, fmt.Errorf("ptr lookup: %w", err)
	}

	res := PTRResult{Names: names}
	for _, name := range names {
		n := strings.TrimSuffix(name, ".")
		if strings.EqualFold(n, helo) {
			res.HELOMatch = true
		}
		addrs, err := a.resolver.LookupHost(ctx, n)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr == ip {
				res.FCrDNS = true
			}
		}
	}
	return res, nil
}

// reverseIPv4 reverses the octets of an IPv4 address ("1.2.3.4" -> "4.3.2.1").
// It returns ok=false for non-IPv4 or unparseable input.
func reverseIPv4(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]), true
}

// isListingCode reports whether a DNSBL response address denotes an actual
// listing. Listings live in 127.0.0.0/16 (commonly 127.0.0.2..11); the
// 127.255.255.0/24 range is reserved by providers such as Spamhaus for error
// codes (e.g. "query via public resolver refused") and must not be treated as
// a listing, or every identity would be falsely quarantined.
func isListingCode(addr string) bool {
	return strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "127.255.")
}
