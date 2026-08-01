package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
)

// JobStore is a concurrency-safe, in-memory store.JobStore.
type JobStore struct {
	mu   sync.Mutex
	jobs map[string]*jobEntry
	now  func() time.Time
}

type jobEntry struct {
	job     store.Job
	results []store.Result
}

// NewJobStore returns an empty in-memory JobStore.
func NewJobStore() *JobStore {
	return &JobStore{jobs: make(map[string]*jobEntry), now: time.Now}
}

// CreateJob implements store.JobStore.
func (s *JobStore) CreateJob(_ context.Context, job store.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = &jobEntry{job: job}
	return nil
}

// GetJob implements store.JobStore.
func (s *JobStore) GetJob(_ context.Context, id string) (store.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jobs[id]
	if !ok {
		return store.Job{}, store.ErrJobNotFound
	}
	return e.job, nil
}

// AppendResult implements store.JobStore.
func (s *JobStore) AppendResult(_ context.Context, jobID string, r store.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jobs[jobID]
	if !ok {
		return store.ErrJobNotFound
	}
	e.results = append(e.results, r)
	e.job.Done++
	if e.job.Status != store.JobCanceled && e.job.Done >= e.job.Total {
		e.job.Status = store.JobCompleted
		t := s.now()
		e.job.CompletedAt = &t
	}
	return nil
}

// Results implements store.JobStore.
func (s *JobStore) Results(_ context.Context, jobID string, cursor, limit int) ([]store.Result, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jobs[jobID]
	if !ok {
		return nil, 0, store.ErrJobNotFound
	}
	if cursor < 0 {
		cursor = 0
	}
	if limit <= 0 {
		limit = len(e.results)
	}
	if cursor >= len(e.results) {
		return []store.Result{}, 0, nil
	}
	end := cursor + limit
	if end > len(e.results) {
		end = len(e.results)
	}
	page := make([]store.Result, end-cursor)
	copy(page, e.results[cursor:end])

	next := 0
	if end < len(e.results) {
		next = end
	}
	return page, next, nil
}

// SetStatus implements store.JobStore.
func (s *JobStore) SetStatus(_ context.Context, jobID string, status store.JobStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jobs[jobID]
	if !ok {
		return store.ErrJobNotFound
	}
	e.job.Status = status
	if status == store.JobCompleted || status == store.JobCanceled {
		if e.job.CompletedAt == nil {
			t := s.now()
			e.job.CompletedAt = &t
		}
	}
	return nil
}

// ListJobs implements store.JobStore, returning jobs newest-first.
func (s *JobStore) ListJobs(_ context.Context, limit int) ([]store.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]store.Job, 0, len(s.jobs))
	for _, e := range s.jobs {
		out = append(out, e.job)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })

	if limit <= 0 {
		limit = 200
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
