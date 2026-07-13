// Package egress implements the reputation-managed egress control plane: the
// subsystem that treats each sending identity (IP + rDNS/HELO + optional proxy)
// as a health-scored, lifecycle-managed resource. It is the platform's core
// differentiator — accuracy in SMTP verification is governed by egress
// reputation, not by the probe engine.
//
// The Manager implements both verifier.EgressProvider (it selects the best
// identity for a destination) and verifier.SignalSink (it consumes probe
// feedback to update health, trip circuit breakers, and quarantine identities).
// Those two interfaces close the reputation feedback loop:
//
//	scheduler → Binding(dest) → probe → Emit(signals) → health/routing update
package egress

import (
	"context"
	"net"

	"github.com/tryselfhost/rcptto/pkg/engine"
)

// State is an identity's lifecycle position.
type State string

const (
	// StateWarming ramps a new or recovered identity's volume over several days.
	StateWarming State = "warming"
	// StateActive is a healthy identity at full capacity.
	StateActive State = "active"
	// StateQuarantined is temporarily withdrawn after a reputation hit.
	StateQuarantined State = "quarantined"
	// StateDisabled is administratively withdrawn.
	StateDisabled State = "disabled"
)

// Kind is the transport class of an identity.
type Kind string

const (
	// KindLocalIP dials directly from a host IP.
	KindLocalIP Kind = "local_ip"
	// KindSOCKS5 dials through a SOCKS5 proxy.
	KindSOCKS5 Kind = "socks5"
	// KindResidential dials through a residential proxy.
	KindResidential Kind = "residential"
)

// Transport dials the actual connection for an identity, abstracting over a
// bound local IP, a SOCKS5 proxy, etc. The direct transport is provided here;
// proxy transports are separate adapters.
type Transport interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DirectTransport dials from the host, optionally binding a specific source
// address (to pin an egress IP on a multi-homed host).
type DirectTransport struct {
	// LocalAddr, when set, binds the connection's source address.
	LocalAddr net.Addr
}

// DialContext implements Transport.
func (t DirectTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{LocalAddr: t.LocalAddr}
	return d.DialContext(ctx, network, addr)
}

// Spec is an operator-provided egress identity definition.
type Spec struct {
	// ID uniquely identifies the identity (recorded in verdicts and signals).
	ID string
	// Kind is the transport class.
	Kind Kind
	// HELO is the EHLO/HELO name presented to destinations. Its forward and
	// reverse DNS should match the egress IP for good reputation.
	HELO string
	// MailFrom is the envelope sender used in probes.
	MailFrom string
	// ASN and Region describe the identity for routing diversity.
	ASN    string
	Region string
	// Transport dials connections for this identity. Required.
	Transport Transport
	// WarmUp starts the identity in the warming state instead of active. Use for
	// fresh IPs that have not yet built a sending reputation.
	WarmUp bool
}

// binding is the engine.EgressBinding handed to a worker for one probe.
type binding struct {
	id        string
	helo      string
	mailFrom  string
	transport Transport
}

func (b binding) ID() string       { return b.id }
func (b binding) HELO() string     { return b.helo }
func (b binding) MailFrom() string { return b.mailFrom }

func (b binding) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return b.transport.DialContext(ctx, network, addr)
}

// compile-time guarantee that binding satisfies the engine contract.
var _ engine.EgressBinding = binding{}
