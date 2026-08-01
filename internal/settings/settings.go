// Package settings holds the operator-tunable runtime configuration.
//
// These are not ordinary preferences. Several of them govern how aggressively
// the platform opens SMTP connections to other people's mail servers, and
// raising them is the fastest way to get an egress IP blocked — damage that
// takes days of re-warming to undo, not an afternoon. So every field carries a
// hard cap that the platform refuses to exceed regardless of what is submitted,
// and the dangerous ones are flagged as such in the UI.
package settings

import (
	"errors"
	"fmt"
)

// Hard limits. Values above these are refused rather than clamped silently, so
// an operator is told their request was unsafe instead of quietly ignored.
const (
	MaxProbeRate           = 10.0
	MaxProbeBurst          = 50.0
	MaxJobConcurrency      = 100
	MaxEmailsPerJobCeiling = 1_000_000
	MaxThreshold           = 50
)

// Settings is the tunable runtime configuration.
type Settings struct {
	// ProbeRate is sustained SMTP probes per second, per destination mail
	// server. This is the single most reputation-sensitive value here: it caps
	// how hard any one server is hit, which is what stops a list concentrated
	// on one domain from looking like an attack.
	ProbeRate float64 `json:"probe_rate"`
	// ProbeBurst is how many probes may go back-to-back to one destination
	// after an idle period.
	ProbeBurst float64 `json:"probe_burst"`
	// JobConcurrency is how many addresses a job verifies in parallel. Raising
	// it does not bypass the per-destination limiter, but it does increase
	// aggregate load across many destinations at once.
	JobConcurrency int `json:"job_concurrency"`
	// MaxEmailsPerJob caps a single submission.
	MaxEmailsPerJob int `json:"max_emails_per_job"`
	// DetectCatchAll probes a random local part to detect catch-all domains.
	// Accurate, but costs a second probe per accepted address.
	DetectCatchAll bool `json:"detect_catch_all"`
	// QuarantineThreshold is how many consecutive block signals withdraw an
	// egress identity. Lower is more cautious.
	QuarantineThreshold int `json:"quarantine_threshold"`
	// CircuitThreshold is how many failures against one destination open that
	// (identity, destination) circuit breaker. Lower is more cautious.
	CircuitThreshold int `json:"circuit_threshold"`
}

// Default returns the shipped configuration: deliberately conservative, sized
// so a single warmed IP stays comfortably inside what its reputation supports.
func Default() Settings {
	return Settings{
		ProbeRate:           1,
		ProbeBurst:          5,
		JobConcurrency:      10,
		MaxEmailsPerJob:     100_000,
		DetectCatchAll:      true,
		QuarantineThreshold: 5,
		CircuitThreshold:    3,
	}
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid setting")

// Validate reports whether the settings are usable and safe. It refuses rather
// than clamps: silently lowering a submitted value would leave an operator
// believing the platform is running faster than it is.
func (s Settings) Validate() error {
	switch {
	case s.ProbeRate <= 0:
		return fmt.Errorf("%w: probe rate must be greater than zero", ErrInvalid)
	case s.ProbeRate > MaxProbeRate:
		return fmt.Errorf("%w: probe rate above %.0f/second per destination risks being blocked", ErrInvalid, MaxProbeRate)
	case s.ProbeBurst <= 0:
		return fmt.Errorf("%w: probe burst must be greater than zero", ErrInvalid)
	case s.ProbeBurst > MaxProbeBurst:
		return fmt.Errorf("%w: probe burst above %.0f risks being blocked", ErrInvalid, MaxProbeBurst)
	case s.JobConcurrency < 1:
		return fmt.Errorf("%w: job concurrency must be at least 1", ErrInvalid)
	case s.JobConcurrency > MaxJobConcurrency:
		return fmt.Errorf("%w: job concurrency above %d is not supported", ErrInvalid, MaxJobConcurrency)
	case s.MaxEmailsPerJob < 1:
		return fmt.Errorf("%w: maximum addresses per job must be at least 1", ErrInvalid)
	case s.MaxEmailsPerJob > MaxEmailsPerJobCeiling:
		return fmt.Errorf("%w: maximum addresses per job above %d is not supported", ErrInvalid, MaxEmailsPerJobCeiling)
	case s.QuarantineThreshold < 1 || s.QuarantineThreshold > MaxThreshold:
		return fmt.Errorf("%w: quarantine threshold must be between 1 and %d", ErrInvalid, MaxThreshold)
	case s.CircuitThreshold < 1 || s.CircuitThreshold > MaxThreshold:
		return fmt.Errorf("%w: circuit-breaker threshold must be between 1 and %d", ErrInvalid, MaxThreshold)
	}
	return nil
}

// WithDefaults fills zero-valued fields from Default, so a partially populated
// record (an older row, or a field added in a later version) stays usable.
func (s Settings) WithDefaults() Settings {
	d := Default()
	if s.ProbeRate <= 0 {
		s.ProbeRate = d.ProbeRate
	}
	if s.ProbeBurst <= 0 {
		s.ProbeBurst = d.ProbeBurst
	}
	if s.JobConcurrency <= 0 {
		s.JobConcurrency = d.JobConcurrency
	}
	if s.MaxEmailsPerJob <= 0 {
		s.MaxEmailsPerJob = d.MaxEmailsPerJob
	}
	if s.QuarantineThreshold <= 0 {
		s.QuarantineThreshold = d.QuarantineThreshold
	}
	if s.CircuitThreshold <= 0 {
		s.CircuitThreshold = d.CircuitThreshold
	}
	return s
}
