package store

import (
	"context"
	"errors"
	"time"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// ErrJobNotFound is returned by JobStore methods when a job id is unknown.
var ErrJobNotFound = errors.New("job not found")

// JobStatus is the lifecycle state of a bulk job.
type JobStatus string

const (
	// JobQueued means the job is accepted but not yet processing.
	JobQueued JobStatus = "queued"
	// JobRunning means addresses are being verified.
	JobRunning JobStatus = "running"
	// JobCompleted means every address has a result.
	JobCompleted JobStatus = "completed"
	// JobCanceled means the job was stopped before completion.
	JobCanceled JobStatus = "canceled"
)

// Job is the state and progress of a bulk verification job.
type Job struct {
	ID          string     `json:"id"`
	Status      JobStatus  `json:"status"`
	Total       int        `json:"total"`
	Done        int        `json:"done"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// JobStore persists bulk jobs and their per-address results.
type JobStore interface {
	// CreateJob stores a new job. Total should already reflect the deduplicated
	// address count.
	CreateJob(ctx context.Context, job Job) error
	// GetJob returns the job, or ErrJobNotFound.
	GetJob(ctx context.Context, id string) (Job, error)
	// AppendResult records one address's verdict, increments Done, and marks the
	// job completed once Done reaches Total (unless it was canceled). Returns
	// ErrJobNotFound for an unknown id.
	AppendResult(ctx context.Context, jobID string, v verdict.Verdict) error
	// Results returns a page of verdicts starting at cursor (a zero-based
	// offset), up to limit items. next is the cursor for the following page, or
	// 0 when there are no more. Returns ErrJobNotFound for an unknown id.
	Results(ctx context.Context, jobID string, cursor, limit int) (items []verdict.Verdict, next int, err error)
	// SetStatus updates the job status, setting CompletedAt for terminal states.
	// Returns ErrJobNotFound for an unknown id.
	SetStatus(ctx context.Context, jobID string, status JobStatus) error
}
