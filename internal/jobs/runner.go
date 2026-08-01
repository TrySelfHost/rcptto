// Package jobs runs bulk verification asynchronously. A Runner accepts a batch
// of addresses, persists a job, and processes the addresses through a bounded
// worker pool, recording each verdict as it completes. Jobs are cancelable and
// survive the submitting HTTP request (they run on a detached context).
//
// This is the single-process MVP of bulk processing. Splitting the worker pool
// out across processes behind a durable bus (Redis Streams / NATS) is a later,
// scale-oriented milestone; the JobStore and Verifier seams here are what that
// step will build on.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Errors returned by Submit.
var (
	// ErrNoEmails is returned when a submission contains no usable addresses.
	ErrNoEmails = errors.New("no emails to verify")
	// ErrTooManyEmails is returned when a submission exceeds the configured cap.
	ErrTooManyEmails = errors.New("too many emails in one job")
)

const (
	defaultConcurrency = 10
	defaultMaxEmails   = 100_000
)

// Row is one submitted address with the label it arrived under. Addresses
// submitted without a list (a pasted textarea, or the single-verify form) carry
// an empty Label.
type Row struct {
	Label string
	Email string
}

// Verifier verifies a single address. It is satisfied by *verifier.Service.
type Verifier interface {
	Verify(ctx context.Context, email string) (verdict.Verdict, error)
}

// Config configures a Runner. Store and Verifier are required.
type Config struct {
	Store       store.JobStore
	Verifier    Verifier
	Concurrency int              // per-job worker count; defaults to 10
	MaxEmails   int              // per-job cap; defaults to 100k
	Now         func() time.Time // defaults to time.Now
}

// Runner processes bulk jobs through a bounded worker pool.
type Runner struct {
	store       store.JobStore
	verifier    Verifier
	concurrency int
	maxEmails   int
	now         func() time.Time

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	wg      sync.WaitGroup
}

// New builds a Runner, applying defaults. It panics if Store or Verifier is nil.
func New(cfg Config) *Runner {
	if cfg.Store == nil || cfg.Verifier == nil {
		panic("jobs: Store and Verifier are required")
	}
	r := &Runner{
		store:       cfg.Store,
		verifier:    cfg.Verifier,
		concurrency: cfg.Concurrency,
		maxEmails:   cfg.MaxEmails,
		now:         cfg.Now,
		cancels:     make(map[string]context.CancelFunc),
	}
	if r.concurrency <= 0 {
		r.concurrency = defaultConcurrency
	}
	if r.maxEmails <= 0 {
		r.maxEmails = defaultMaxEmails
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r
}

// Submit deduplicates the rows, creates a job, and starts processing it
// asynchronously. The returned Job reflects the initial (running) state.
//
// Deduplication is by (label, email): the same address listed under two
// different client names produces two result rows, because the caller needs a
// result against each name. The address is still probed only once — the verdict
// is fanned out to every row sharing it — so duplicates cost no extra
// reputation.
func (r *Runner) Submit(ctx context.Context, rows []Row) (store.Job, error) {
	unique := dedup(rows)
	if len(unique) == 0 {
		return store.Job{}, ErrNoEmails
	}
	_, maxEmails := r.limits()
	if len(unique) > maxEmails {
		return store.Job{}, ErrTooManyEmails
	}

	job := store.Job{
		ID:        newJobID(),
		Status:    store.JobRunning,
		Total:     len(unique),
		CreatedAt: r.now(),
	}
	if err := r.store.CreateJob(ctx, job); err != nil {
		return store.Job{}, err
	}

	// Detach from the request context so the job outlives the HTTP request.
	jobCtx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancels[job.ID] = cancel
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.process(jobCtx, job.ID, unique)
		r.finish(job.ID)
	}()

	return job, nil
}

// Get returns a job's current state, or store.ErrJobNotFound.
func (r *Runner) Get(ctx context.Context, id string) (store.Job, error) {
	return r.store.GetJob(ctx, id)
}

// Stats aggregates a job's results.
func (r *Runner) Stats(ctx context.Context, id string) (store.JobStats, error) {
	return r.store.Stats(ctx, id)
}

// List returns the most recently created jobs, newest first.
func (r *Runner) List(ctx context.Context, limit int) ([]store.Job, error) {
	return r.store.ListJobs(ctx, limit)
}

// Results returns a page of a job's results.
func (r *Runner) Results(ctx context.Context, id string, cursor, limit int) ([]store.Result, int, error) {
	return r.store.Results(ctx, id, cursor, limit)
}

// Cancel stops a running job. It is idempotent and a no-op for jobs that have
// already completed or been canceled. Returns store.ErrJobNotFound if unknown.
func (r *Runner) Cancel(ctx context.Context, id string) error {
	job, err := r.store.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if job.Status == store.JobCompleted || job.Status == store.JobCanceled {
		return nil
	}
	r.mu.Lock()
	cancel, ok := r.cancels[id]
	r.mu.Unlock()
	if ok {
		cancel()
	}
	return r.store.SetStatus(ctx, id, store.JobCanceled)
}

// Wait blocks until all in-flight jobs finish. Intended for graceful shutdown
// and deterministic tests.
func (r *Runner) Wait() { r.wg.Wait() }

// process verifies the addresses through a bounded worker pool, recording a
// result for every submitted row. Rows sharing an address are grouped so the
// address is probed once and its verdict fanned out, which keeps duplicate
// entries from spending extra egress reputation.
func (r *Runner) process(ctx context.Context, jobID string, rows []Row) {
	// Group row labels by address, preserving first-seen order.
	order := make([]string, 0, len(rows))
	byEmail := make(map[string][]string, len(rows))
	for _, row := range rows {
		key := strings.ToLower(row.Email)
		if _, seen := byEmail[key]; !seen {
			order = append(order, row.Email)
		}
		byEmail[key] = append(byEmail[key], row.Label)
	}

	concurrency, _ := r.limits()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, email := range order {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(email string) {
			defer wg.Done()
			defer func() { <-sem }()

			v, err := r.verifier.Verify(ctx, email)
			if err != nil {
				v = verdict.Verdict{
					Email:     email,
					Status:    verdict.StatusUnknown,
					SubStatus: verdict.SubTemporaryFailure,
					CheckedAt: r.now(),
				}
			}
			for _, label := range byEmail[strings.ToLower(email)] {
				_ = r.store.AppendResult(ctx, jobID, store.Result{Label: label, Verdict: v})
			}
		}(email)
	}
	wg.Wait()
}

// finish releases the job's cancel func and marks a partially-processed job as
// canceled. A fully-processed job is already marked completed by AppendResult.
func (r *Runner) finish(jobID string) {
	r.mu.Lock()
	if cancel, ok := r.cancels[jobID]; ok {
		cancel()
		delete(r.cancels, jobID)
	}
	r.mu.Unlock()

	if job, err := r.store.GetJob(context.Background(), jobID); err == nil && job.Status == store.JobRunning {
		_ = r.store.SetStatus(context.Background(), jobID, store.JobCanceled)
	}
}

// dedup drops rows with a blank address and collapses exact duplicates of the
// same (label, address) pair, comparing case-insensitively while preserving the
// original casing and input order.
func dedup(rows []Row) []Row {
	seen := make(map[string]struct{}, len(rows))
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		email := strings.TrimSpace(row.Email)
		if email == "" {
			continue
		}
		label := strings.TrimSpace(row.Label)
		key := strings.ToLower(label) + "\x00" + strings.ToLower(email)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Row{Label: label, Email: email})
	}
	return out
}

// newJobID returns a random, URL-safe job identifier.
func newJobID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "job_000000000000000000000000"
	}
	return "job_" + hex.EncodeToString(b[:])
}

// limits returns the current sizing under the lock, so a concurrent SetLimits
// cannot race with a job being submitted or started.
func (r *Runner) limits() (concurrency, maxEmails int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.concurrency, r.maxEmails
}

// SetLimits updates job sizing at runtime. Concurrency applies to jobs started
// after the change; a job already running keeps the pool it was created with,
// since resizing a live worker pool mid-flight would risk losing in-flight
// probes for no real benefit.
func (r *Runner) SetLimits(concurrency, maxEmails int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if concurrency > 0 {
		r.concurrency = concurrency
	}
	if maxEmails > 0 {
		r.maxEmails = maxEmails
	}
}
