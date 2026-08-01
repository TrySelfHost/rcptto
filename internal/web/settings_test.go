package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tryselfhost/rcptto/internal/settings"
)

// stubSettings records applied settings and can reject, standing in for the
// real manager without touching live components.
type stubSettings struct {
	mu      sync.Mutex
	current settings.Settings
	applied []settings.Settings
	err     error
}

func newStubSettings() *stubSettings {
	return &stubSettings{current: settings.Default()}
}

func (s *stubSettings) Current() settings.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

func (s *stubSettings) Apply(_ context.Context, in settings.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if err := in.Validate(); err != nil {
		return err
	}
	s.applied = append(s.applied, in)
	s.current = in
	return nil
}

func TestSettingsPageShowsCurrentValuesAndWarnings(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, Settings: newStubSettings()}).Handler()

	rec := do(t, h, "GET", "/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for _, name := range []string{"probe_rate", "probe_burst", "job_concurrency", "quarantine_threshold", "circuit_threshold", "detect_catch_all"} {
		if !strings.Contains(body, name) {
			t.Errorf("settings page missing field %q", name)
		}
	}
	// The reputation-affecting fields must be marked as such.
	if !strings.Contains(body, "affects reputation") {
		t.Errorf("dangerous fields should carry a warning")
	}
	// Guidance belongs beside the value, not in docs nobody reads.
	if !strings.Contains(body, "per destination mail server") {
		t.Errorf("probe rate should explain what it does")
	}
}

func TestSettingsSaveApplies(t *testing.T) {
	st := newStubSettings()
	h := New(Config{Verifier: stubVerifier{}, Settings: st}).Handler()

	form := "probe_rate=2&probe_burst=8&job_concurrency=20&max_emails_per_job=5000" +
		"&quarantine_threshold=4&circuit_threshold=2&detect_catch_all=1"
	rec := do(t, h, "POST", "/settings", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "saved and applied") {
		t.Errorf("expected a confirmation: %s", rec.Body.String())
	}

	if len(st.applied) != 1 {
		t.Fatalf("applied %d times, want 1", len(st.applied))
	}
	got := st.applied[0]
	if got.ProbeRate != 2 || got.ProbeBurst != 8 || got.JobConcurrency != 20 {
		t.Errorf("applied = %+v", got)
	}
	if got.QuarantineThreshold != 4 || got.CircuitThreshold != 2 {
		t.Errorf("reputation guards not applied: %+v", got)
	}
	if !got.DetectCatchAll {
		t.Errorf("catch-all checkbox not applied")
	}
}

// An unchecked checkbox submits nothing, which must read as false rather than
// silently leaving the old value in place.
func TestUncheckedBoxDisables(t *testing.T) {
	st := newStubSettings()
	h := New(Config{Verifier: stubVerifier{}, Settings: st}).Handler()

	form := "probe_rate=1&probe_burst=5&job_concurrency=10&max_emails_per_job=1000" +
		"&quarantine_threshold=5&circuit_threshold=3"
	if rec := do(t, h, "POST", "/settings", form); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if st.applied[0].DetectCatchAll {
		t.Errorf("an unchecked box must disable the setting")
	}
}

// An unsafe value must be refused with the reason, and the form must come back
// populated so one field can be corrected without re-entering everything.
func TestUnsafeValueRejectedWithReason(t *testing.T) {
	st := newStubSettings()
	h := New(Config{Verifier: stubVerifier{}, Settings: st}).Handler()

	form := "probe_rate=500&probe_burst=5&job_concurrency=10&max_emails_per_job=1000" +
		"&quarantine_threshold=5&circuit_threshold=3"
	rec := do(t, h, "POST", "/settings", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "Rejected") || !strings.Contains(body, "risks being blocked") {
		t.Errorf("expected a clear refusal with the reason: %s", body)
	}
	if len(st.applied) != 0 {
		t.Errorf("an unsafe value must not be applied: %+v", st.applied)
	}
	// The submitted value is echoed back for correction.
	if !strings.Contains(body, `value="500"`) {
		t.Errorf("form should retain the submitted value for correction: %s", body)
	}
}

func TestBadNumberFallsBackToCurrent(t *testing.T) {
	st := newStubSettings()
	h := New(Config{Verifier: stubVerifier{}, Settings: st}).Handler()

	form := "probe_rate=abc&probe_burst=5&job_concurrency=10&max_emails_per_job=1000" +
		"&quarantine_threshold=5&circuit_threshold=3"
	if rec := do(t, h, "POST", "/settings", form); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(st.applied) != 1 || st.applied[0].ProbeRate != settings.Default().ProbeRate {
		t.Errorf("unparseable input should keep the current value, got %+v", st.applied)
	}
}

func TestSettingsDisabledReturns501(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	if rec := do(t, h, "GET", "/settings", ""); rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

// The settings form swaps into itself; a missing target would fail silently.
func TestSettingsFormTargetExists(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, Settings: newStubSettings()}).Handler()
	body := do(t, h, "GET", "/settings", "").Body.String()

	if !strings.Contains(body, `id="settings-form"`) {
		t.Errorf("settings page missing the #settings-form target")
	}
	if !strings.Contains(body, `hx-target="#settings-form"`) {
		t.Errorf("settings form should target itself")
	}
}
