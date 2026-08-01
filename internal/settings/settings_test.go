package settings

import (
	"errors"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("shipped defaults must be valid: %v", err)
	}
}

// Defaults must be conservative: the platform should not ship pointed at a
// rate that risks an operator's IP before they have touched anything.
func TestDefaultsAreConservative(t *testing.T) {
	d := Default()
	if d.ProbeRate > 2 {
		t.Errorf("default probe rate %v is too aggressive to ship", d.ProbeRate)
	}
	if d.ProbeRate >= MaxProbeRate {
		t.Errorf("default probe rate should leave headroom below the cap")
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	cases := map[string]func(*Settings){
		"zero probe rate":       func(s *Settings) { s.ProbeRate = 0 },
		"negative probe rate":   func(s *Settings) { s.ProbeRate = -1 },
		"probe rate above cap":  func(s *Settings) { s.ProbeRate = MaxProbeRate + 1 },
		"probe burst above cap": func(s *Settings) { s.ProbeBurst = MaxProbeBurst + 1 },
		"zero concurrency":      func(s *Settings) { s.JobConcurrency = 0 },
		"concurrency above cap": func(s *Settings) { s.JobConcurrency = MaxJobConcurrency + 1 },
		"max emails above cap":  func(s *Settings) { s.MaxEmailsPerJob = MaxEmailsPerJobCeiling + 1 },
		"quarantine zero":       func(s *Settings) { s.QuarantineThreshold = 0 },
		"quarantine above cap":  func(s *Settings) { s.QuarantineThreshold = MaxThreshold + 1 },
		"circuit zero":          func(s *Settings) { s.CircuitThreshold = 0 },
		"circuit above cap":     func(s *Settings) { s.CircuitThreshold = MaxThreshold + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := Default()
			mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error should wrap ErrInvalid, got %v", err)
			}
		})
	}
}

// Refusing rather than clamping matters: silently lowering a submitted value
// would leave the operator believing the platform runs faster than it does.
func TestValidateRefusesRatherThanClamps(t *testing.T) {
	s := Default()
	s.ProbeRate = MaxProbeRate + 5
	if err := s.Validate(); err == nil {
		t.Fatal("an over-cap value must be refused")
	}
	if s.ProbeRate != MaxProbeRate+5 {
		t.Errorf("Validate must not mutate the value, got %v", s.ProbeRate)
	}
}

func TestWithDefaultsFillsZeroFields(t *testing.T) {
	// A partially populated record — an older stored row, or a field added in a
	// later version — must remain usable.
	got := Settings{ProbeRate: 3}.WithDefaults()
	d := Default()

	if got.ProbeRate != 3 {
		t.Errorf("explicit value overwritten: %v", got.ProbeRate)
	}
	if got.ProbeBurst != d.ProbeBurst || got.JobConcurrency != d.JobConcurrency {
		t.Errorf("zero fields not filled: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("filled record should validate: %v", err)
	}
}

func TestBoundaryValuesAccepted(t *testing.T) {
	s := Default()
	s.ProbeRate = MaxProbeRate
	s.ProbeBurst = MaxProbeBurst
	s.JobConcurrency = MaxJobConcurrency
	s.MaxEmailsPerJob = MaxEmailsPerJobCeiling
	s.QuarantineThreshold = MaxThreshold
	s.CircuitThreshold = MaxThreshold
	if err := s.Validate(); err != nil {
		t.Errorf("values exactly at the cap should be allowed: %v", err)
	}
}
