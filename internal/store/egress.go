package store

import (
	"context"
	"time"
)

// EgressState is the persisted reputation state of one egress identity.
//
// It deliberately excludes circuit breakers: those are short-lived (minutes)
// and re-trip immediately if the underlying problem persists, so persisting
// them adds complexity for no real benefit. Everything that represents
// *accumulated* reputation — warm-up progress, quarantine, health scores — is
// persisted, because silently discarding it on restart would reset a multi-day
// warm-up to day zero and un-quarantine a burned IP.
type EgressState struct {
	// ID matches the configured egress identity's ID.
	ID string `json:"id"`
	// State is the lifecycle state (warming, active, quarantined, disabled).
	State string `json:"state"`
	// WarmupStage is the index into the warm-up ramp.
	WarmupStage int `json:"warmup_stage"`
	// UsedToday counts probes issued in the current daily window.
	UsedToday int `json:"used_today"`
	// LastReset is when the daily counter last rolled over.
	LastReset time.Time `json:"last_reset"`
	// BlockStreak is the count of consecutive block signals.
	BlockStreak int `json:"block_streak"`
	// QuarantinedUntil is when a quarantine expires (zero if not quarantined).
	QuarantinedUntil time.Time `json:"quarantined_until,omitempty"`
	// QuarantineReason records why the identity was withdrawn.
	QuarantineReason string `json:"quarantine_reason,omitempty"`
	// Health maps a destination key to its rolling health score in [0,1].
	Health map[string]float64 `json:"health,omitempty"`
}

// EgressStore persists egress reputation state across restarts.
type EgressStore interface {
	// LoadEgress returns all persisted identity states. A missing identity is
	// not an error; the caller reconciles against its configured pool.
	LoadEgress(ctx context.Context) ([]EgressState, error)
	// SaveEgress replaces the persisted state for the given identities.
	SaveEgress(ctx context.Context, states []EgressState) error
}
