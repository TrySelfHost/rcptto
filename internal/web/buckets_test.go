package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

func res(status verdict.Status, sub verdict.SubStatus, email string) store.Result {
	return store.Result{Verdict: verdict.Verdict{Email: email, Status: status, SubStatus: sub}}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   verdict.Verdict
		want Bucket
	}{
		{"deliverable", verdict.Verdict{Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox}, BucketSafe},
		// Role accounts are carried as risky/role_account but are real mailboxes
		// and usually the intended recipient for outreach.
		{"role account is safe", verdict.Verdict{Status: verdict.StatusRisky, SubStatus: verdict.SubRoleAccount}, BucketSafe},
		{"catch-all is risky", verdict.Verdict{Status: verdict.StatusRisky, SubStatus: verdict.SubCatchAll}, BucketRisky},
		{"disposable is risky", verdict.Verdict{Status: verdict.StatusRisky, SubStatus: verdict.SubDisposable}, BucketRisky},
		{"no mailbox", verdict.Verdict{Status: verdict.StatusUndeliverable, SubStatus: verdict.SubMailboxNotFound}, BucketUndeliverable},
		{"bad syntax", verdict.Verdict{Status: verdict.StatusUndeliverable, SubStatus: verdict.SubInvalidSyntax}, BucketUndeliverable},
		// A deliberate skip is not a failure and must not be discarded.
		{"provider skipped", verdict.Verdict{Status: verdict.StatusRisky, SubStatus: verdict.SubProviderSkipped}, BucketSkipped},
		{"greylisted retries", verdict.Verdict{Status: verdict.StatusUnknown, SubStatus: verdict.SubGreylisted}, BucketRetry},
		{"blocked retries", verdict.Verdict{Status: verdict.StatusUnknown, SubStatus: verdict.SubBlocked}, BucketRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.in); got != tc.want {
				t.Errorf("classify = %q, want %q", got, tc.want)
			}
		})
	}
}

// bucketCounts derives totals from aggregates while classify works per row.
// They must agree, or the download button would promise a count the file does
// not deliver.
func TestBucketCountsAgreeWithClassify(t *testing.T) {
	results := []store.Result{
		res(verdict.StatusDeliverable, verdict.SubValidMailbox, "a@x.com"),
		res(verdict.StatusDeliverable, verdict.SubValidMailbox, "b@x.com"),
		res(verdict.StatusRisky, verdict.SubRoleAccount, "info@x.com"),
		res(verdict.StatusRisky, verdict.SubCatchAll, "c@x.com"),
		res(verdict.StatusRisky, verdict.SubProviderSkipped, "d@gmail.com"),
		res(verdict.StatusRisky, verdict.SubProviderSkipped, "e@yahoo.com"),
		res(verdict.StatusUndeliverable, verdict.SubMailboxNotFound, "f@x.com"),
		res(verdict.StatusUnknown, verdict.SubGreylisted, "g@x.com"),
	}

	// Build the aggregate the store would produce for these rows.
	stats := store.JobStats{
		Total:       len(results),
		ByStatus:    map[string]int{},
		BySubStatus: map[string]int{},
		ByProvider:  map[string]int{},
	}
	for _, r := range results {
		stats.ByStatus[string(r.Verdict.Status)]++
		stats.BySubStatus[string(r.Verdict.SubStatus)]++
	}

	derived := bucketCounts(stats)
	for _, b := range bucketOrder {
		if b == BucketAll {
			continue
		}
		actual := len(filterBucket(results, b))
		if derived[b] != actual {
			t.Errorf("bucket %q: derived count %d, actual rows %d", b, derived[b], actual)
		}
	}
	if derived[BucketAll] != len(results) {
		t.Errorf("all = %d, want %d", derived[BucketAll], len(results))
	}
}

func TestBucketCountsNeverNegative(t *testing.T) {
	// A sub-status appearing under an unexpected status must not produce a
	// negative count on a download button.
	stats := store.JobStats{
		Total:       1,
		ByStatus:    map[string]int{"deliverable": 1},
		BySubStatus: map[string]int{string(verdict.SubRoleAccount): 5},
	}
	for b, n := range bucketCounts(stats) {
		if n < 0 {
			t.Errorf("bucket %q has negative count %d", b, n)
		}
	}
}

func TestExportFiltersByBucket(t *testing.T) {
	jb := &stubJobs{
		job: store.Job{ID: "job_1", Status: store.JobCompleted, Total: 4, Done: 4},
		results: []store.Result{
			{Label: "Acme", Verdict: verdict.Verdict{Email: "good@x.com", Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox}},
			{Label: "Beta", Verdict: verdict.Verdict{Email: "info@x.com", Status: verdict.StatusRisky, SubStatus: verdict.SubRoleAccount}},
			{Label: "Gamma", Verdict: verdict.Verdict{Email: "bad@x.com", Status: verdict.StatusUndeliverable, SubStatus: verdict.SubMailboxNotFound}},
			{Label: "Delta", Verdict: verdict.Verdict{Email: "d@gmail.com", Status: verdict.StatusRisky, SubStatus: verdict.SubProviderSkipped}},
		},
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	t.Run("safe includes role accounts", func(t *testing.T) {
		body := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=safe", "").Body.String()
		if !strings.Contains(body, "good@x.com") || !strings.Contains(body, "info@x.com") {
			t.Errorf("safe bucket should hold the deliverable and the role account: %s", body)
		}
		if strings.Contains(body, "bad@x.com") || strings.Contains(body, "d@gmail.com") {
			t.Errorf("safe bucket leaked other groups: %s", body)
		}
	})

	t.Run("undeliverable only", func(t *testing.T) {
		body := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=undeliverable", "").Body.String()
		if !strings.Contains(body, "bad@x.com") || strings.Contains(body, "good@x.com") {
			t.Errorf("undeliverable bucket wrong: %s", body)
		}
	})

	t.Run("skipped is its own group", func(t *testing.T) {
		body := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=skipped", "").Body.String()
		if !strings.Contains(body, "d@gmail.com") {
			t.Errorf("skipped bucket should hold the policy-skipped address: %s", body)
		}
		if strings.Contains(body, "bad@x.com") {
			t.Errorf("skipped must not be mixed with undeliverable: %s", body)
		}
	})

	t.Run("all is unfiltered", func(t *testing.T) {
		body := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=all", "").Body.String()
		for _, e := range []string{"good@x.com", "info@x.com", "bad@x.com", "d@gmail.com"} {
			if !strings.Contains(body, e) {
				t.Errorf("all bucket missing %s", e)
			}
		}
	})

	t.Run("filename names the bucket", func(t *testing.T) {
		rec := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=safe", "")
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "job_1-safe.csv") {
			t.Errorf("content-disposition = %q, want the bucket in the name", cd)
		}
	})

	t.Run("unknown bucket rejected", func(t *testing.T) {
		if rec := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=bogus", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

// The download controls must point at exports that work.
func TestJobPagesShowBucketDownloads(t *testing.T) {
	jb := &stubJobs{
		job:     store.Job{ID: "job_1", Status: store.JobCompleted, Total: 1, Done: 1},
		results: []store.Result{res(verdict.StatusDeliverable, verdict.SubValidMailbox, "a@x.com")},
		stats:   sampleStats(),
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	for _, path := range []string{"/jobs/job_1", "/jobs/job_1/metrics"} {
		body := do(t, h, "GET", path, "").Body.String()
		if !strings.Contains(body, "Safe to send") {
			t.Errorf("%s missing the safe download control", path)
		}
		if !strings.Contains(body, "bucket=safe") {
			t.Errorf("%s missing a bucketed export link", path)
		}
		if !strings.Contains(body, "Not checked") {
			t.Errorf("%s should distinguish policy-skipped addresses", path)
		}
	}
	if rec := do(t, h, "GET", "/jobs/job_1/export/csv?bucket=safe", ""); rec.Code != http.StatusOK {
		t.Errorf("linked bucket export returned %d", rec.Code)
	}
}
