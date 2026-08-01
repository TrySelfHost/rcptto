package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tryselfhost/rcptto/internal/store"
)

func sampleStats() store.JobStats {
	return store.JobStats{
		Total: 10,
		ByStatus: map[string]int{
			"deliverable": 6, "undeliverable": 2, "risky": 1, "unknown": 1,
		},
		BySubStatus: map[string]int{
			"valid_mailbox": 6, "mailbox_not_found": 2, "provider_skipped": 1, "greylisted": 1,
		},
		ByProvider: map[string]int{"custom": 7, "gmail": 3},
		Probed:     7,
		NotProbed:  3,
	}
}

func TestMetricsPageShowsHeadlineNumbers(t *testing.T) {
	jb := &stubJobs{
		job:   store.Job{ID: "job_1", Status: store.JobCompleted, Total: 10, Done: 10},
		stats: sampleStats(),
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// 6 of 10 deliverable.
	if !strings.Contains(body, "60%") {
		t.Errorf("deliverable rate missing: %s", body)
	}
	// 7 of 10 actually probed — the egress cost of the list.
	if !strings.Contains(body, "70%") {
		t.Errorf("probed share missing")
	}
	for _, want := range []string{"valid_mailbox", "mailbox_not_found", "gmail", "custom"} {
		if !strings.Contains(body, want) {
			t.Errorf("breakdown missing %q", want)
		}
	}
}

func TestMetricsPercentagesAndOrdering(t *testing.T) {
	m := buildJobMetrics(store.Job{ID: "j", Total: 10}, sampleStats())

	if m.DeliverablePercent != 60 {
		t.Errorf("deliverable = %d%%, want 60%%", m.DeliverablePercent)
	}
	if m.ProbedPercent != 70 || m.NotProbedPercent != 30 {
		t.Errorf("probed split = %d/%d, want 70/30", m.ProbedPercent, m.NotProbedPercent)
	}
	// Unknown results are retryable, not final answers.
	if m.Retryable != 1 {
		t.Errorf("retryable = %d, want 1", m.Retryable)
	}
	// Largest first, so the dominant outcome leads.
	if len(m.Statuses) == 0 || m.Statuses[0].Key != "deliverable" {
		t.Errorf("statuses should be sorted by count: %+v", m.Statuses)
	}
	for i := 1; i < len(m.Statuses); i++ {
		if m.Statuses[i-1].Count < m.Statuses[i].Count {
			t.Errorf("statuses not sorted descending: %+v", m.Statuses)
		}
	}
}

// A job with no results yet must render rather than divide by zero.
func TestMetricsEmptyJob(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 5}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No results yet") {
		t.Errorf("empty job should explain itself: %s", rec.Body.String())
	}
	if m := buildJobMetrics(store.Job{}, store.JobStats{}); m.DeliverablePercent != 0 {
		t.Errorf("empty stats must not divide by zero, got %d", m.DeliverablePercent)
	}
}

func TestMetricsUnknownJobIs404(t *testing.T) {
	jb := &stubJobs{getErr: store.ErrJobNotFound}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()
	if rec := do(t, h, "GET", "/jobs/missing/metrics", ""); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The report links must point at pages that exist, matching the htmx/link
// contract that a missing target is otherwise silent.
func TestJobPagesLinkToReport(t *testing.T) {
	jb := &stubJobs{
		job:   store.Job{ID: "job_1", Status: store.JobCompleted, Total: 1, Done: 1},
		jobs:  []store.Job{{ID: "job_1", Status: store.JobCompleted, Total: 1, Done: 1}},
		stats: sampleStats(),
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	for _, path := range []string{"/jobs", "/jobs/job_1"} {
		body := do(t, h, "GET", path, "").Body.String()
		if !strings.Contains(body, "/jobs/job_1/metrics") {
			t.Errorf("%s should link to the report page", path)
		}
	}
	if rec := do(t, h, "GET", "/jobs/job_1/metrics", ""); rec.Code != http.StatusOK {
		t.Errorf("linked report page returned %d", rec.Code)
	}
}
