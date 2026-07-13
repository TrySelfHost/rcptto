package pipeline

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// mxStage resolves the domain's mail exchangers. This is the only network-bound
// stage, so it runs last. Outcomes:
//
//   - MX records found            → records recorded, provider refined, continue.
//   - No MX but A/AAAA present    → implicit MX (RFC 5321 §5.1), continue.
//   - Null MX (single ".")        → terminal undeliverable (RFC 7505).
//   - No MX and no host           → terminal undeliverable (no_mx_record).
//   - NXDOMAIN                     → terminal undeliverable (domain_not_found).
//   - Transient DNS error         → returned as an error for the caller to retry.
type mxStage struct {
	resolver Resolver
}

func (mxStage) Name() string { return "mx" }

func (m mxStage) Run(ctx context.Context, s *State) (bool, error) {
	records, err := m.resolver.LookupMX(ctx, s.Domain)
	if err != nil {
		// A domain may exist with A/AAAA records but no MX (implicit MX, RFC
		// 5321 §5.1). Try that before concluding the failure's meaning.
		if implicitMX(ctx, m.resolver, s) {
			return false, nil
		}
		var dnsErr *net.DNSError
		switch {
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			s.Reject(verdict.StatusUndeliverable, verdict.SubDomainNotFound, 0.98)
			return true, nil
		case errors.As(err, &dnsErr) && dnsErr.IsTemporary:
			// Transient failure: surface it so the caller can retry rather than
			// recording a false undeliverable.
			return false, err
		default:
			s.Reject(verdict.StatusUndeliverable, verdict.SubNoMXRecord, 0.9)
			return true, nil
		}
	}

	// Null MX (RFC 7505): a single "." record means the domain sends no mail.
	if len(records) == 1 && records[0].Host == "." {
		s.Reject(verdict.StatusUndeliverable, verdict.SubNoMXRecord, 0.95)
		return true, nil
	}

	hosts := mxHosts(records)
	if len(hosts) == 0 {
		if implicitMX(ctx, m.resolver, s) {
			return false, nil
		}
		s.Reject(verdict.StatusUndeliverable, verdict.SubNoMXRecord, 0.9)
		return true, nil
	}

	s.MX = hosts
	s.Checks.MX = verdict.MXCheck{Found: true, Records: hosts}

	// Refine provider only when the domain itself gave no consumer signal, so
	// Google Workspace / Microsoft 365 on custom domains are detected without
	// overriding consumer classifications (e.g. gmail.com stays "gmail").
	if s.Provider == providerCustom {
		if refined := refineProviderFromMX(hosts); refined != "" {
			s.Provider = refined
		}
	}
	return false, nil
}

// implicitMX checks for A/AAAA records on the domain and, if present, treats the
// domain as its own mail exchanger. It sets state and returns true on success.
func implicitMX(ctx context.Context, r Resolver, s *State) bool {
	addrs, err := r.LookupHost(ctx, s.Domain)
	if err != nil || len(addrs) == 0 {
		return false
	}
	s.MX = []string{s.Domain}
	s.Checks.MX = verdict.MXCheck{Found: true, Records: s.MX}
	return true
}

// mxHosts extracts trimmed, non-empty hostnames from MX records, preserving the
// resolver's preference order.
func mxHosts(records []*net.MX) []string {
	hosts := make([]string, 0, len(records))
	for _, rec := range records {
		h := strings.TrimSuffix(rec.Host, ".")
		if h != "" && h != "." {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
