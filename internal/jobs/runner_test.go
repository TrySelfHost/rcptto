package jobs

import (
	"context"
	"errors"
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

	job, err := r.Submit(context.Background(), []string{
		"a@example.com", "A@Example.com", " a@example.com ", // all one address after dedup
		"b@example.com",
	})
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
	if _, err := r.Submit(context.Background(), []string{"  ", ""}); !errors.Is(err, ErrNoEmails) {
		t.Errorf("err = %v, want ErrNoEmails", err)
	}
}

func TestSubmitTooManyIsError(t *testing.T) {
	st := memory.NewJobStore()
	r := New(Config{Store: st, Verifier: okVerifier{}, MaxEmails: 2})
	if _, err := r.Submit(context.Background(), []string{"a@x.com", "b@x.com", "c@x.com"}); !errors.Is(err, ErrTooManyEmails) {
		t.Errorf("err = %v, want ErrTooManyEmails", err)
	}
}

func TestCancel(t *testing.T) {
	r, _ := newRunner(blockingVerifier{})

	job, err := r.Submit(context.Background(), []string{"a@x.com", "b@x.com", "c@x.com"})
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
	job, _ := r.Submit(context.Background(), []string{"a@x.com"})
	r.Wait()
	if err := r.Cancel(context.Background(), job.ID); err != nil {
		t.Errorf("cancel completed: %v", err)
	}
	got, _ := r.Get(context.Background(), job.ID)
	if got.Status != store.JobCompleted {
		t.Errorf("status = %s, want completed (cancel must not override)", got.Status)
	}
}
