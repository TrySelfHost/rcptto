package mock

import (
	"context"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

func TestPrefixOutcomes(t *testing.T) {
	e := New().WithNow(func() time.Time { return time.Unix(0, 0).UTC() })
	eg := NewBinding("eg_test")

	tests := []struct {
		email     string
		status    verdict.Status
		subStatus verdict.SubStatus
		signal    engine.SignalKind
	}{
		{"valid@example.com", verdict.StatusDeliverable, verdict.SubValidMailbox, engine.SignalAccepted},
		{"invalid@example.com", verdict.StatusUndeliverable, verdict.SubMailboxNotFound, engine.SignalMailboxGone},
		{"catchall@example.com", verdict.StatusRisky, verdict.SubCatchAll, engine.SignalAccepted},
		{"role@example.com", verdict.StatusRisky, verdict.SubRoleAccount, engine.SignalAccepted},
		{"tempfail@example.com", verdict.StatusUnknown, verdict.SubGreylisted, engine.SignalTempFail},
		{"blocked@example.com", verdict.StatusUnknown, verdict.SubBlocked, engine.SignalBlocked},
		{"anything-else@example.com", verdict.StatusDeliverable, verdict.SubValidMailbox, engine.SignalAccepted}, // default
	}

	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			v, sigs, err := e.Verify(context.Background(), engine.Task{Email: tc.email, Domain: "example.com"}, eg)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.Status != tc.status || v.SubStatus != tc.subStatus {
				t.Errorf("got (%s,%s) want (%s,%s)", v.Status, v.SubStatus, tc.status, tc.subStatus)
			}
			if v.Engine != "mock" {
				t.Errorf("engine name = %q, want mock", v.Engine)
			}
			if v.EgressID != "eg_test" {
				t.Errorf("egress id = %q, want eg_test", v.EgressID)
			}
			if len(sigs) != 1 || sigs[0].Kind != tc.signal {
				t.Errorf("signals = %+v, want kind %s", sigs, tc.signal)
			}
			if sigs[0].EgressID != "eg_test" {
				t.Errorf("signal egress id = %q, want eg_test", sigs[0].EgressID)
			}
			if err := v.Validate(); err != nil {
				t.Errorf("verdict invalid: %v", err)
			}
		})
	}
}

func TestExplicitRuleOverridesPrefix(t *testing.T) {
	// "valid@" normally deliverable; an explicit rule must win.
	e := New().WithRule("valid@example.com", Outcome{
		Status: verdict.StatusUnknown, SubStatus: verdict.SubBlocked, SMTPCode: 554, Signal: engine.SignalBlocked,
	})
	v, _, err := e.Verify(context.Background(), engine.Task{Email: "valid@example.com"}, NewBinding("eg_1"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Status != verdict.StatusUnknown || v.SubStatus != verdict.SubBlocked {
		t.Fatalf("rule did not override prefix: got (%s,%s)", v.Status, v.SubStatus)
	}
}

func TestVerifyNilBinding(t *testing.T) {
	e := New()
	v, _, err := e.Verify(context.Background(), engine.Task{Email: "valid@example.com"}, nil)
	if err != nil {
		t.Fatalf("Verify with nil binding: %v", err)
	}
	if v.EgressID != "" {
		t.Errorf("expected empty egress id, got %q", v.EgressID)
	}
}

func TestNormalizationFallback(t *testing.T) {
	e := New()
	// No Normalized provided -> engine lowercases Email.
	v, _, _ := e.Verify(context.Background(), engine.Task{Email: "Valid@Example.COM"}, NewBinding("x"))
	if v.Normalized != "valid@example.com" {
		t.Errorf("normalized = %q, want valid@example.com", v.Normalized)
	}
}
