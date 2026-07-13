package verifier

import (
	"context"
	"net"

	"github.com/tryselfhost/rcptto/pkg/engine"
)

// EgressProvider supplies the egress identity a probe must originate from. It is
// the seam where the reputation manager will later select a health-scored,
// per-destination-appropriate identity. For now the default provider returns a
// single direct-dial identity bound to the host's own address.
type EgressProvider interface {
	// Binding returns the egress identity to use for probing t.
	Binding(ctx context.Context, t engine.Task) (engine.EgressBinding, error)
}

// DirectProvider returns a single identity that dials directly from the host,
// with no proxy and no reputation management. Suitable for development and small
// single-IP deployments.
type DirectProvider struct {
	// ID identifies this egress in verdicts and signals.
	ID string
	// HELO is the EHLO/HELO name presented to destination servers.
	HELO string
	// MailFrom is the envelope sender used in probes.
	MailFrom string
}

// Binding implements EgressProvider.
func (p DirectProvider) Binding(_ context.Context, _ engine.Task) (engine.EgressBinding, error) {
	return directBinding{
		id:       firstNonEmpty(p.ID, "direct"),
		helo:     firstNonEmpty(p.HELO, "localhost"),
		mailFrom: firstNonEmpty(p.MailFrom, "verify@localhost"),
	}, nil
}

// directBinding is an engine.EgressBinding that dials from the host directly.
type directBinding struct {
	id       string
	helo     string
	mailFrom string
}

func (b directBinding) ID() string       { return b.id }
func (b directBinding) HELO() string     { return b.helo }
func (b directBinding) MailFrom() string { return b.mailFrom }

func (b directBinding) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
