package verdict

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStatusValid(t *testing.T) {
	valid := []Status{StatusDeliverable, StatusUndeliverable, StatusRisky, StatusUnknown}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("expected %q to be valid", s)
		}
	}
	for _, s := range []Status{"", "bogus", "Deliverable"} {
		if s.Valid() {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

func TestVerdictValidate(t *testing.T) {
	base := Verdict{Email: "a@b.com", Status: StatusDeliverable, Confidence: 0.9}

	tests := []struct {
		name    string
		mutate  func(*Verdict)
		wantErr bool
	}{
		{"ok", func(*Verdict) {}, false},
		{"empty email", func(v *Verdict) { v.Email = "" }, true},
		{"bad status", func(v *Verdict) { v.Status = "nope" }, true},
		{"confidence high", func(v *Verdict) { v.Confidence = 1.5 }, true},
		{"confidence low", func(v *Verdict) { v.Confidence = -0.1 }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			tc.mutate(&v)
			err := v.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerdictJSONRoundTrip(t *testing.T) {
	in := Verdict{
		Email:      "jane@example.com",
		Normalized: "jane@example.com",
		Status:     StatusRisky,
		SubStatus:  SubCatchAll,
		Confidence: 0.5,
		Checks: Checks{
			Syntax:   SyntaxCheck{Valid: true},
			MX:       MXCheck{Found: true, Records: []string{"mx1.example.com"}},
			CatchAll: true,
			SMTP:     SMTPCheck{Probed: true, Code: 250, Response: "catch_all"},
		},
		Provider:  "custom",
		Engine:    "mock",
		EgressID:  "eg_1",
		CheckedAt: time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC),
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out Verdict
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Status != in.Status || out.SubStatus != in.SubStatus {
		t.Errorf("status mismatch: got (%s,%s) want (%s,%s)", out.Status, out.SubStatus, in.Status, in.SubStatus)
	}
	if !out.Checks.CatchAll || out.Checks.SMTP.Code != 250 {
		t.Errorf("checks not preserved: %+v", out.Checks)
	}
	if !out.CheckedAt.Equal(in.CheckedAt) {
		t.Errorf("time not preserved: got %v want %v", out.CheckedAt, in.CheckedAt)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("round-tripped verdict invalid: %v", err)
	}
}
