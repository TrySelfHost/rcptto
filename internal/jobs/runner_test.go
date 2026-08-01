package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// okVerifier returns a fixed deliverable verdict.
type okVerifier struct{}

func (okVerifier) Verify(_ context.Context, email string) (verdict.Verdict, error) {
	return verdict.Verdict{Email: email, Status: verdict.StatusDeliverable}, nil
}

// blockingVerifier blocks until the context is canceled, then reports the error.
type blockingVerifier struct{}

func (blockingVerifier) Verify(ctx context.Context, email string) (verdict.Verdict, error) {
	<-ctx.Done()
	return verdict.Verdict{Email: email, Status: verdict.StatusUnknown}, ctx.Err()
}

func newRunner(v Verifier) (*Runner, *memory.JobStore) {
	st := memory.NewJobStore()
	return New(Config{Store: st, Verifier: v, Concurrency: 4}), st
}

func TestSubmitCompletesAndDeduplicates(t *testing.T) {
	r, _ := newRunner(okVerifier{})

	job, err := r.Submit(context.Background(), []Row{{Email: "a@example.com"}, {Email: "A@Example.com"}, {Email: " a@example.com "}, {Email: "b@example.com"}})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Total != 2 {
		t.Fatalf("total = %d, want 2 (deduped)", job.Total)
	}

	r.Wait()

	got, _ := r.Get(context.Background(), job.ID)
	if got.Status != store.JobCompleted || got.Done != 2 {
		t.Fatalf("final: status=%s done=%d", got.Status, got.Done)
	}
	items, _, _ := r.Results(context.Background(), job.ID, 0, 10)
	if len(items) != 2 {
		t.Errorf("results = %d, want 2", len(items))
	}
}

func TestSubmitEmptyIsError(t *testing.T) {
	r, _ := newRunner(okVerifier{})
	if _, err := r.Submit(context.Background(), []Row{{Email: "  "}, {Email: ""}}); !errors.Is(err, ErrNoEmails) {
		t.Errorf("err = %v, want ErrNoEmails", err)
	}
}

func TestSubmitTooManyIsError(t *testing.T) {
	st := memory.NewJobStore()
	r := New(Config{Store: st, Verifier: okVerifier{}, MaxEmails: 2})
	if _, err := r.Submit(context.Background(), []Row{{Email: "a@x.com"}, {Email: "b@x.com"}, {Email: "c@x.com"}}); !errors.Is(err, ErrTooManyEmails) {
		t.Errorf("err = %v, want ErrTooManyEmails", err)
	}
}

func TestCancel(t *testing.T) {
	r, _ := newRunner(blockingVerifier{})

	job, err := r.Submit(context.Background(), []Row{{Email: "a@x.com"}, {Email: "b@x.com"}, {Email: "c@x.com"}})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Give the pool a moment to pick up work, then cancel.
	time.Sleep(20 * time.Millisecond)
	if err := r.Cancel(context.Background(), job.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	r.Wait()

	got, _ := r.Get(context.Background(), job.ID)
	if got.Status != store.JobCanceled {
		t.Fatalf("status = %s, want canceled", got.Status)
	}
}

func TestGetAndCancelNotFound(t *testing.T) {
	r, _ := newRunner(okVerifier{})
	if _, err := r.Get(context.Background(), "missing"); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("Get err = %v, want ErrJobNotFound", err)
	}
	if err := r.Cancel(context.Background(), "missing"); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("Cancel err = %v, want ErrJobNotFound", err)
	}
}

func TestCancelCompletedIsNoop(t *testing.T) {
	r, _ := newRunner(okVerifier{})
	job, _ := r.Submit(context.Background(), []Row{{Email: "a@x.com"}})
	r.Wait()
	if err := r.Cancel(context.Background(), job.ID); err != nil {
		t.Errorf("cancel completed: %v", err)
	}
	got, _ := r.Get(context.Background(), job.ID)
	if got.Status != store.JobCompleted {
		t.Errorf("status = %s, want completed (cancel must not override)", got.Status)
	}
}

// countingVerifier records how many times each address was verified, so the
// fan-out behavior (probe once, report per label) can be asserted.
type countingVerifier struct {
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingVerifier) Verify(_ context.Context, email string) (verdict.Verdict, error) {
	c.mu.Lock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[strings.ToLower(email)]++
	c.mu.Unlock()
	return verdict.Verdict{Email: email, Status: verdict.StatusDeliverable}, nil
}

// The same address under two client names must yield two result rows — the
// caller needs an answer against each name — but must only be probed once, so
// duplicates cost no extra egress reputation.
func TestSameEmailUnderTwoLabelsProbesOnceReportsTwice(t *testing.T) {
	cv := &countingVerifier{}
	st := memory.NewJobStore()
	r := New(Config{Store: st, Verifier: cv, Concurrency: 4})

	job, err := r.Submit(context.Background(), []Row{
		{Label: "Acme Ltd", Email: "shared@example.com"},
		{Label: "Beta Inc", Email: "shared@example.com"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Total != 2 {
		t.Fatalf("total = %d, want 2 result rows", job.Total)
	}
	r.Wait()

	if got := cv.calls["shared@example.com"]; got != 1 {
		t.Errorf("address probed %d times, want 1 (the verdict should fan out)", got)
	}

	items, _, err := r.Results(context.Background(), job.ID, 0, 10)
	if err != nil {
		t.Fatalf("results: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("results = %d, want 2", len(items))
	}
	labels := map[string]bool{}
	for _, it := range items {
		labels[it.Label] = true
		if it.Verdict.Email != "shared@example.com" {
			t.Errorf("unexpected email in result: %+v", it.Verdict)
		}
	}
	if !labels["Acme Ltd"] || !labels["Beta Inc"] {
		t.Errorf("both labels should appear in results, got %+v", labels)
	}
}

// An exact duplicate of the same (label, address) pair is collapsed.
func TestExactDuplicateRowsCollapsed(t *testing.T) {
	cv := &countingVerifier{}
	r := New(Config{Store: memory.NewJobStore(), Verifier: cv})

	job, err := r.Submit(context.Background(), []Row{
		{Label: "Acme", Email: "a@example.com"},
		{Label: "Acme", Email: "A@Example.com"}, // same pair, different casing
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Total != 1 {
		t.Errorf("total = %d, want 1 (exact duplicates collapse)", job.Total)
	}
}

func TestLabelsArePersistedWithResults(t *testing.T) {
	st := memory.NewJobStore()
	r := New(Config{Store: st, Verifier: okVerifier{}})

	job, _ := r.Submit(context.Background(), []Row{
		{Label: "Acme Ltd", Email: "a@example.com"},
	})
	r.Wait()

	items, _, _ := r.Results(context.Background(), job.ID, 0, 10)
	if len(items) != 1 || items[0].Label != "Acme Ltd" {
		t.Fatalf("label not carried through to results: %+v", items)
	}
}

func TestRowsWithBlankEmailDropped(t *testing.T) {
	r := New(Config{Store: memory.NewJobStore(), Verifier: okVerifier{}})
	if _, err := r.Submit(context.Background(), []Row{{Label: "Acme", Email: "   "}}); !errors.Is(err, ErrNoEmails) {
		t.Errorf("err = %v, want ErrNoEmails", err)
	}
}
