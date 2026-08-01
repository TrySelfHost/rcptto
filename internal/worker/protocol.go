// Package worker implements the remote probe protocol: the contract between
// the rcpttō control plane and worker agents running on separate machines.
//
// A worker agent exists for one reason: an egress IP can only be dialed from
// the machine that owns it. To pool IPs across several VPS, the control plane
// keeps all the intelligence (funnel, provider policy, reputation, scheduling)
// and delegates only the SMTP probe itself to an agent on the machine holding
// the desired IP.
//
// The wire types here are deliberately separate from the internal engine and
// verdict types. Control plane and agents are separate deployments that may run
// different versions, so the protocol needs to evolve on its own schedule
// rather than tracking internal refactors.
package worker

import (
	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// ProtocolVersion is the wire contract version. Agents reject requests from a
// control plane advertising an incompatible major version.
const ProtocolVersion = 1

// Paths served by a worker agent.
const (
	PathVerify = "/worker/v1/verify"
	PathHealth = "/worker/v1/health"
)

// VerifyRequest asks an agent to probe one address from its local egress IP.
type VerifyRequest struct {
	// Version is the sender's ProtocolVersion.
	Version int `json:"version"`
	// Task is the address to probe plus the routing context the control plane
	// already resolved (MX hosts, provider class).
	Task TaskWire `json:"task"`
	// DetectCatchAll asks the agent to run the catch-all probe on acceptance.
	DetectCatchAll bool `json:"detect_catch_all"`
}

// TaskWire is the wire form of engine.Task.
type TaskWire struct {
	ID         string   `json:"id,omitempty"`
	JobID      string   `json:"job_id,omitempty"`
	Email      string   `json:"email"`
	Normalized string   `json:"normalized,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	Provider   string   `json:"provider,omitempty"`
	MX         []string `json:"mx,omitempty"`
}

// VerifyResponse returns the probe outcome and the egress feedback the control
// plane needs to update reputation.
type VerifyResponse struct {
	Version int             `json:"version"`
	Verdict verdict.Verdict `json:"verdict"`
	Signals []SignalWire    `json:"signals,omitempty"`
}

// SignalWire is the wire form of engine.Signal.
type SignalWire struct {
	Kind        string `json:"kind"`
	EgressID    string `json:"egress_id,omitempty"`
	Destination string `json:"destination,omitempty"`
	Code        int    `json:"code,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// HealthResponse describes an agent and the egress identity it owns, so the
// control plane can register it and detect when it goes away.
type HealthResponse struct {
	Version int `json:"version"`
	// ID is the egress identity this agent provides. It must match the id the
	// control plane has configured for this agent.
	ID string `json:"id"`
	// IP is the agent's public egress address, for DNSBL and rDNS audits.
	IP string `json:"ip,omitempty"`
	// HELO is the hostname the agent presents to destination mail servers.
	HELO string `json:"helo,omitempty"`
	// Region and ASN describe the agent for routing diversity.
	Region string `json:"region,omitempty"`
	ASN    string `json:"asn,omitempty"`
}

// ---- conversions -------------------------------------------------------------

// TaskToWire converts an internal task to its wire form.
func TaskToWire(t engine.Task) TaskWire {
	return TaskWire{
		ID:         t.ID,
		JobID:      t.JobID,
		Email:      t.Email,
		Normalized: t.Normalized,
		Domain:     t.Domain,
		Provider:   t.Provider,
		MX:         append([]string(nil), t.MX...),
	}
}

// ToTask converts a wire task back to the internal form.
func (t TaskWire) ToTask() engine.Task {
	return engine.Task{
		ID:         t.ID,
		JobID:      t.JobID,
		Email:      t.Email,
		Normalized: t.Normalized,
		Domain:     t.Domain,
		Provider:   t.Provider,
		MX:         append([]string(nil), t.MX...),
	}
}

// SignalsToWire converts internal signals to their wire form.
func SignalsToWire(sigs []engine.Signal) []SignalWire {
	out := make([]SignalWire, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, SignalWire{
			Kind:        string(s.Kind),
			EgressID:    s.EgressID,
			Destination: s.Destination,
			Code:        s.Code,
			Detail:      s.Detail,
		})
	}
	return out
}

// ToSignals converts wire signals back to the internal form.
func ToSignals(wire []SignalWire) []engine.Signal {
	out := make([]engine.Signal, 0, len(wire))
	for _, s := range wire {
		out = append(out, engine.Signal{
			Kind:        engine.SignalKind(s.Kind),
			EgressID:    s.EgressID,
			Destination: s.Destination,
			Code:        s.Code,
			Detail:      s.Detail,
		})
	}
	return out
}
