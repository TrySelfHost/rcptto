package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// stubEgress is a canned Egress implementation recording calls for assertions.
type stubEgress struct {
	identities []EgressIdentity
	quarantine struct{ id, reason string }
	enabled    string
	disable    struct{ id, reason string }
}

func (s *stubEgress) Identities() []EgressIdentity { return s.identities }
func (s *stubEgress) Quarantine(id, reason string) { s.quarantine.id, s.quarantine.reason = id, reason }
func (s *stubEgress) Enable(id string)             { s.enabled = id }
func (s *stubEgress) Disable(id, reason string)    { s.disable.id, s.disable.reason = id, reason }

// stubPolicy is a canned Policy implementation recording calls for assertions.
type stubPolicy struct {
	entries []PolicyEntry
	set     struct{ key, strategy, reason string }
}

func (s *stubPolicy) List() []PolicyEntry { return s.entries }
func (s *stubPolicy) Set(key, strategy, reason string) {
	s.set.key, s.set.strategy, s.set.reason = key, strategy, reason
}

func TestAdminListEgress(t *testing.T) {
	eg := &stubEgress{identities: []EgressIdentity{{ID: "a", IP: "1.2.3.4", State: "active"}}}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := doJSON(t, h, "GET", "/v1/admin/egress", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Identities []EgressIdentity `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Identities) != 1 || got.Identities[0].ID != "a" {
		t.Errorf("identities = %+v", got.Identities)
	}
}

func TestAdminQuarantineEgress(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := doJSON(t, h, "POST", "/v1/admin/egress/eg_1/quarantine", `{"reason":"manual test"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if eg.quarantine.id != "eg_1" || eg.quarantine.reason != "manual test" {
		t.Errorf("quarantine call = %+v", eg.quarantine)
	}
}

func TestAdminQuarantineDefaultReason(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := doJSON(t, h, "POST", "/v1/admin/egress/eg_1/quarantine", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if eg.quarantine.reason != "manual" {
		t.Errorf("reason = %q, want default 'manual'", eg.quarantine.reason)
	}
}

func TestAdminEnableEgress(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := doJSON(t, h, "POST", "/v1/admin/egress/eg_1/enable", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if eg.enabled != "eg_1" {
		t.Errorf("enabled = %q, want eg_1", eg.enabled)
	}
}

func TestAdminDisableEgress(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := doJSON(t, h, "POST", "/v1/admin/egress/eg_1/disable", `{"reason":"bad ip"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if eg.disable.id != "eg_1" || eg.disable.reason != "bad ip" {
		t.Errorf("disable call = %+v", eg.disable)
	}
}

func TestAdminEgressDisabledReturns501(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler() // no Egress configured
	rec := doJSON(t, h, "GET", "/v1/admin/egress", "", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestAdminListPolicies(t *testing.T) {
	pol := &stubPolicy{entries: []PolicyEntry{{Key: "gmail", Strategy: "skip", Reason: "test"}}}
	h := New(Config{Verifier: stubVerifier{}, Policy: pol}).Handler()

	rec := doJSON(t, h, "GET", "/v1/admin/policies", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Policies []PolicyEntry `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Policies) != 1 || got.Policies[0].Key != "gmail" {
		t.Errorf("policies = %+v", got.Policies)
	}
}

func TestAdminSetPolicy(t *testing.T) {
	pol := &stubPolicy{}
	h := New(Config{Verifier: stubVerifier{}, Policy: pol}).Handler()

	rec := doJSON(t, h, "PUT", "/v1/admin/policies/gmail", `{"strategy":"probe","reason":"override"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if pol.set.key != "gmail" || pol.set.strategy != "probe" || pol.set.reason != "override" {
		t.Errorf("set call = %+v", pol.set)
	}
}

func TestAdminSetPolicyInvalidStrategy(t *testing.T) {
	pol := &stubPolicy{}
	h := New(Config{Verifier: stubVerifier{}, Policy: pol}).Handler()

	rec := doJSON(t, h, "PUT", "/v1/admin/policies/gmail", `{"strategy":"bogus"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminPolicyDisabledReturns501(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler() // no Policy configured
	rec := doJSON(t, h, "GET", "/v1/admin/policies", "", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestAdminRoutesRequireAuth(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg, APIKeys: []string{"secret"}}).Handler()

	rec := doJSON(t, h, "GET", "/v1/admin/egress", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without key", rec.Code)
	}
	rec = doJSON(t, h, "GET", "/v1/admin/egress", "", map[string]string{"X-API-Key": "secret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with key", rec.Code)
	}
}
