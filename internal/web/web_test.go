package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// stubVerifier returns a canned verdict.
type stubVerifier struct {
	v   verdict.Verdict
	err error
}

func (s stubVerifier) Verify(context.Context, string) (verdict.Verdict, error) { return s.v, s.err }

// stubJobs is a canned Jobs implementation recording calls.
type stubJobs struct {
	job       store.Job
	jobs      []store.Job
	results   []store.Result
	next      int
	getErr    error
	canceled  string
	submitted []jobs.Row
}

func (s *stubJobs) Submit(_ context.Context, rows []jobs.Row) (store.Job, error) {
	s.submitted = rows
	return s.job, nil
}
func (s *stubJobs) Get(context.Context, string) (store.Job, error) { return s.job, s.getErr }
func (s *stubJobs) List(context.Context, int) ([]store.Job, error) { return s.jobs, nil }
func (s *stubJobs) Results(context.Context, string, int, int) ([]store.Result, int, error) {
	return s.results, s.next, s.getErr
}
func (s *stubJobs) Cancel(_ context.Context, id string) error { s.canceled = id; return nil }

// stubEgress records control calls.
type stubEgress struct {
	identities                     []EgressIdentity
	quarantined, enabled, disabled string
}

func (s *stubEgress) Identities() []EgressIdentity { return s.identities }
func (s *stubEgress) Quarantine(id, _ string)      { s.quarantined = id; s.setState(id, "quarantined") }
func (s *stubEgress) Enable(id string)             { s.enabled = id; s.setState(id, "warming") }
func (s *stubEgress) Disable(id, _ string)         { s.disabled = id; s.setState(id, "disabled") }

func (s *stubEgress) setState(id, state string) {
	for i := range s.identities {
		if s.identities[i].ID == id {
			s.identities[i].State = state
		}
	}
}

// stubPolicy records policy edits.
type stubPolicy struct {
	entries  []PolicyEntry
	setKey   string
	setValue string
}

func (s *stubPolicy) List() []PolicyEntry { return s.entries }
func (s *stubPolicy) Set(key, strategy, _ string) {
	s.setKey, s.setValue = key, strategy
	for i := range s.entries {
		if s.entries[i].Key == key {
			s.entries[i].Strategy = strategy
		}
	}
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestTemplatesParse is the guard that New() does not panic — template parse
// errors are otherwise only discovered at runtime.
func TestTemplatesParse(t *testing.T) {
	New(Config{Verifier: stubVerifier{}})
}

func TestHomeRenders(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := do(t, h, "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"<!doctype html>", "Verify an address", "Bulk verification", "/assets/htmx.min.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
}

func TestVerifySubmitRendersVerdict(t *testing.T) {
	v := verdict.Verdict{
		Email: "a@b.com", Normalized: "a@b.com",
		Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox,
		Confidence: 0.9, Engine: "builtin",
	}
	h := New(Config{Verifier: stubVerifier{v: v}}).Handler()

	rec := do(t, h, "POST", "/verify", "email=a%40b.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "deliverable") || !strings.Contains(body, "valid_mailbox") {
		t.Errorf("verdict not rendered: %s", body)
	}
	if !strings.Contains(body, "90%") {
		t.Errorf("confidence percent not rendered: %s", body)
	}
}

func TestVerifySubmitEmptyEmail(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := do(t, h, "POST", "/verify", "email=")
	if !strings.Contains(rec.Body.String(), "email is required") {
		t.Errorf("expected validation message, got: %s", rec.Body.String())
	}
}

func TestJobsListRenders(t *testing.T) {
	j := &stubJobs{jobs: []store.Job{
		{ID: "job_1", Status: store.JobCompleted, Total: 10, Done: 10, CreatedAt: time.Unix(0, 0).UTC()},
	}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := do(t, h, "GET", "/jobs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "job_1") {
		t.Errorf("job id not rendered: %s", rec.Body.String())
	}
}

func TestJobShowRendersProgressAndResults(t *testing.T) {
	j := &stubJobs{
		job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 4, Done: 2, CreatedAt: time.Unix(0, 0).UTC()},
		results: []store.Result{
			{Label: "Acme Ltd", Verdict: verdict.Verdict{
				Email: "a@b.com", Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox,
			}},
		},
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "width:50%") {
		t.Errorf("progress bar not at 50%%: %s", body)
	}
	if !strings.Contains(body, "a@b.com") {
		t.Errorf("result row not rendered")
	}
	// A running job must poll for updates.
	if !strings.Contains(body, `hx-trigger="every 2s"`) {
		t.Errorf("running job should poll for status")
	}
}

func TestJobShowNotFound(t *testing.T) {
	j := &stubJobs{getErr: store.ErrJobNotFound}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()
	if rec := do(t, h, "GET", "/jobs/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestJobCancel(t *testing.T) {
	j := &stubJobs{job: store.Job{ID: "job_1", Status: store.JobCanceled, Total: 2, Done: 1}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := do(t, h, "POST", "/jobs/job_1/cancel", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if j.canceled != "job_1" {
		t.Errorf("cancel not called, got %q", j.canceled)
	}
}

func TestJobsDisabledReturns501(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler() // no Jobs
	if rec := do(t, h, "GET", "/jobs", ""); rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestEgressPageAndActions(t *testing.T) {
	eg := &stubEgress{identities: []EgressIdentity{{ID: "direct", IP: "1.2.3.4", State: "active"}}}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()

	rec := do(t, h, "GET", "/egress", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "1.2.3.4") {
		t.Fatalf("egress page: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "POST", "/egress/direct/quarantine", "reason=test")
	if rec.Code != http.StatusOK {
		t.Fatalf("quarantine status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if eg.quarantined != "direct" {
		t.Errorf("quarantine not called")
	}
	// The returned row fragment must reflect the new state.
	if !strings.Contains(rec.Body.String(), "quarantined") {
		t.Errorf("row fragment does not show new state: %s", rec.Body.String())
	}

	if rec = do(t, h, "POST", "/egress/direct/enable", ""); eg.enabled != "direct" {
		t.Errorf("enable not called (status %d)", rec.Code)
	}
	if rec = do(t, h, "POST", "/egress/direct/disable", ""); eg.disabled != "direct" {
		t.Errorf("disable not called (status %d)", rec.Code)
	}
}

func TestEgressUnknownIDNotFound(t *testing.T) {
	eg := &stubEgress{}
	h := New(Config{Verifier: stubVerifier{}, Egress: eg}).Handler()
	if rec := do(t, h, "POST", "/egress/ghost/enable", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestPoliciesPageAndEdit(t *testing.T) {
	pol := &stubPolicy{entries: []PolicyEntry{{Key: "gmail", Strategy: "skip", Reason: "unreliable"}}}
	h := New(Config{Verifier: stubVerifier{}, Policy: pol}).Handler()

	rec := do(t, h, "GET", "/policies", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "gmail") {
		t.Fatalf("policies page: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "POST", "/policies/gmail", "strategy=probe")
	if rec.Code != http.StatusOK {
		t.Fatalf("policy set status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if pol.setKey != "gmail" || pol.setValue != "probe" {
		t.Errorf("policy set called with (%q,%q)", pol.setKey, pol.setValue)
	}
	if !strings.Contains(rec.Body.String(), "probe") {
		t.Errorf("row fragment does not show new strategy: %s", rec.Body.String())
	}
}

func TestPolicyInvalidStrategy(t *testing.T) {
	pol := &stubPolicy{}
	h := New(Config{Verifier: stubVerifier{}, Policy: pol}).Handler()
	if rec := do(t, h, "POST", "/policies/gmail", "strategy=bogus"); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAssetsServed(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := do(t, h, "GET", "/assets/htmx.min.js", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() < 1000 {
		t.Errorf("htmx asset looks too small: %d bytes", rec.Body.Len())
	}
}

func TestJobSubmitParsesTextarea(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 2}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	// Blank lines and surrounding whitespace must be stripped.
	body := "emails=" + url.QueryEscape(" a@example.com \n\n b@example.com \n   \n")
	rec := do(t, h, "POST", "/jobs", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	want := []string{"a@example.com", "b@example.com"}
	if len(jb.submitted) != len(want) {
		t.Fatalf("submitted = %q, want %q", jb.submitted, want)
	}
	for i := range want {
		if jb.submitted[i].Email != want[i] {
			t.Errorf("submitted[%d] = %q, want %q", i, jb.submitted[i].Email, want[i])
		}
	}
	if !strings.Contains(rec.Body.String(), "job_1") {
		t.Errorf("response should link the new job id: %s", rec.Body.String())
	}
}

func TestJobStatusFragmentPolls(t *testing.T) {
	jb := &stubJobs{
		job:     store.Job{ID: "job_1", Status: store.JobRunning, Total: 4, Done: 2, CreatedAt: time.Unix(0, 0)},
		results: []store.Result{{Verdict: verdict.Verdict{Email: "a@x.com", Status: verdict.StatusDeliverable}}},
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	// A fragment, not a full page.
	if strings.Contains(body, "<html") {
		t.Errorf("status endpoint must return a fragment, not a full page")
	}
	// Progress is rendered as a percentage of done/total.
	if !strings.Contains(body, "50%") {
		t.Errorf("expected 50%% progress in fragment: %s", body)
	}
	if !strings.Contains(body, "running") {
		t.Errorf("expected running status in fragment: %s", body)
	}
}

func TestJobResultsPageReturnsRowsAndOOBButton(t *testing.T) {
	jb := &stubJobs{
		job:     store.Job{ID: "job_1", Status: store.JobRunning, Total: 100, Done: 100},
		results: []store.Result{{Verdict: verdict.Verdict{Email: "a@x.com", Status: verdict.StatusRisky}}},
		next:    50, // more results remain
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/results?cursor=50", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "a@x.com") {
		t.Errorf("expected result rows in response: %s", body)
	}
	// The out-of-band swap refreshes the load-more button with the next cursor.
	if !strings.Contains(body, `hx-swap-oob="true"`) {
		t.Errorf("expected out-of-band button refresh: %s", body)
	}
}

func TestJobResultsPageNotFound(t *testing.T) {
	jb := &stubJobs{getErr: store.ErrJobNotFound}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/missing/results", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
