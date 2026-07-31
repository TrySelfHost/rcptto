package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

func TestJobStoreLifecycle(t *testing.T) {
	s := NewJobStore()
	s.now = func() time.Time { return time.Unix(100, 0).UTC() }
	ctx := context.Background()

	job := store.Job{ID: "job_1", Status: store.JobRunning, Total: 2, CreatedAt: time.Unix(0, 0)}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatalf("create: %v", err)
	}

	// First result: still running.
	if err := s.AppendResult(ctx, "job_1", verdict.Verdict{Email: "a@x.com", Status: verdict.StatusDeliverable}); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	got, _ := s.GetJob(ctx, "job_1")
	if got.Status != store.JobRunning || got.Done != 1 {
		t.Fatalf("after 1: status=%s done=%d", got.Status, got.Done)
	}

	// Second result reaches Total: completed with timestamp.
	_ = s.AppendResult(ctx, "job_1", verdict.Verdict{Email: "b@x.com", Status: verdict.StatusUndeliverable})
	got, _ = s.GetJob(ctx, "job_1")
	if got.Status != store.JobCompleted || got.Done != 2 {
		t.Fatalf("after 2: status=%s done=%d", got.Status, got.Done)
	}
	if got.CompletedAt == nil {
		t.Errorf("completed_at not set")
	}
}

func TestJobStoreNotFound(t *testing.T) {
	s := NewJobStore()
	ctx := context.Background()
	if _, err := s.GetJob(ctx, "nope"); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("GetJob err = %v, want ErrJobNotFound", err)
	}
	if err := s.AppendResult(ctx, "nope", verdict.Verdict{}); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("AppendResult err = %v, want ErrJobNotFound", err)
	}
	if _, _, err := s.Results(ctx, "nope", 0, 10); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("Results err = %v, want ErrJobNotFound", err)
	}
	if err := s.SetStatus(ctx, "nope", store.JobCanceled); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("SetStatus err = %v, want ErrJobNotFound", err)
	}
}

func TestJobStoreListJobsNewestFirst(t *testing.T) {
	s := NewJobStore()
	ctx := context.Background()
	base := time.Unix(1000, 0)

	_ = s.CreateJob(ctx, store.Job{ID: "old", Total: 1, CreatedAt: base})
	_ = s.CreateJob(ctx, store.Job{ID: "new", Total: 1, CreatedAt: base.Add(time.Hour)})

	jobs, err := s.ListJobs(ctx, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(jobs) != 2 || jobs[0].ID != "new" || jobs[1].ID != "old" {
		t.Fatalf("got %+v, want [new, old]", jobs)
	}
}

func TestJobStoreListJobsRespectsLimit(t *testing.T) {
	s := NewJobStore()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = s.CreateJob(ctx, store.Job{ID: string(rune('a' + i)), Total: 1, CreatedAt: time.Unix(int64(i), 0)})
	}
	jobs, err := s.ListJobs(ctx, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
}

func TestJobStoreResultsPagination(t *testing.T) {
	s := NewJobStore()
	ctx := context.Background()
	_ = s.CreateJob(ctx, store.Job{ID: "j", Status: store.JobRunning, Total: 5})
	for i := 0; i < 5; i++ {
		_ = s.AppendResult(ctx, "j", verdict.Verdict{Email: "x@y.com"})
	}

	page, next, err := s.Results(ctx, "j", 0, 2)
	if err != nil {
		t.Fatalf("results: %v", err)
	}
	if len(page) != 2 || next != 2 {
		t.Fatalf("page1: len=%d next=%d", len(page), next)
	}

	page, next, _ = s.Results(ctx, "j", next, 2)
	if len(page) != 2 || next != 4 {
		t.Fatalf("page2: len=%d next=%d", len(page), next)
	}

	page, next, _ = s.Results(ctx, "j", next, 2)
	if len(page) != 1 || next != 0 {
		t.Fatalf("page3: len=%d next=%d (want 1, 0=end)", len(page), next)
	}
}
