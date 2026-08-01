package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// stubJobs is a canned Jobs implementation for handler tests.
type stubJobs struct {
	job     store.Job
	results []store.Result
	next    int
	submit  error
	get     error
	cancel  error
}

func (s stubJobs) Submit(context.Context, []jobs.Row) (store.Job, error) { return s.job, s.submit }
func (s stubJobs) Get(context.Context, string) (store.Job, error)        { return s.job, s.get }
func (s stubJobs) List(context.Context, int) ([]store.Job, error)        { return []store.Job{s.job}, s.get }
func (s stubJobs) Results(context.Context, string, int, int) ([]store.Result, int, error) {
	return s.results, s.next, s.get
}
func (s stubJobs) Cancel(context.Context, string) error { return s.cancel }

func TestCreateJobAccepted(t *testing.T) {
	j := stubJobs{job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 3}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := doJSON(t, h, "POST", "/v1/jobs", `{"emails":["a@x.com","b@x.com"]}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got store.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "job_1" || got.Status != store.JobRunning {
		t.Errorf("job = %+v", got)
	}
}

func TestGetJobNotFound(t *testing.T) {
	j := stubJobs{get: store.ErrJobNotFound}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := doJSON(t, h, "GET", "/v1/jobs/missing", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestJobResults(t *testing.T) {
	j := stubJobs{
		results: []store.Result{{Label: "Acme", Verdict: verdict.Verdict{Email: "a@x.com", Status: verdict.StatusDeliverable}}},
		next:    5,
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: j}).Handler()

	rec := doJSON(t, h, "GET", "/v1/jobs/job_1/results?cursor=0&limit=1", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got resultsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Results) != 1 || got.NextCursor != 5 {
		t.Errorf("results=%d next=%d", len(got.Results), got.NextCursor)
	}
}

func TestCancelJob(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, Jobs: stubJobs{}}).Handler()
	rec := doJSON(t, h, "POST", "/v1/jobs/job_1/cancel", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestJobsDisabledReturns501(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler() // no Jobs configured
	rec := doJSON(t, h, "POST", "/v1/jobs", `{"emails":["a@x.com"]}`, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}
