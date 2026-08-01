// Package postgres implements the store ports against PostgreSQL.
//
// The adapters use only the standard library's database/sql, so the SQL driver
// is a runtime detail chosen by the binary (main blank-imports the pgx stdlib
// driver). This keeps the package driver-agnostic and buildable without the
// driver present.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Compile-time guarantees that the adapters satisfy the store ports.
var (
	_ store.ResultStore = (*ResultStore)(nil)
	_ store.JobStore    = (*JobStore)(nil)
)

// ResultStore is a PostgreSQL-backed store.ResultStore.
type ResultStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewResultStore returns a ResultStore backed by db.
func NewResultStore(db *sql.DB) *ResultStore {
	return &ResultStore{db: db, now: time.Now}
}

// Get implements store.ResultStore.
func (s *ResultStore) Get(ctx context.Context, key string) (verdict.Verdict, bool, error) {
	var raw []byte
	var expires sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT verdict, expires_at FROM result_cache WHERE key = $1`, key,
	).Scan(&raw, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return verdict.Verdict{}, false, nil
	}
	if err != nil {
		return verdict.Verdict{}, false, err
	}
	if expires.Valid && s.now().After(expires.Time) {
		// Lazily evict the expired row; ignore delete errors.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM result_cache WHERE key = $1`, key)
		return verdict.Verdict{}, false, nil
	}
	var v verdict.Verdict
	if err := json.Unmarshal(raw, &v); err != nil {
		return verdict.Verdict{}, false, err
	}
	return v, true, nil
}

// Put implements store.ResultStore.
func (s *ResultStore) Put(ctx context.Context, key string, v verdict.Verdict, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var expires any
	if ttl > 0 {
		expires = s.now().Add(ttl)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO result_cache (key, verdict, expires_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE
		   SET verdict = EXCLUDED.verdict, expires_at = EXCLUDED.expires_at`,
		key, raw, expires,
	)
	return err
}

// JobStore is a PostgreSQL-backed store.JobStore.
type JobStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewJobStore returns a JobStore backed by db.
func NewJobStore(db *sql.DB) *JobStore {
	return &JobStore{db: db, now: time.Now}
}

// CreateJob implements store.JobStore.
func (s *JobStore) CreateJob(ctx context.Context, job store.Job) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (id, status, total, done, created_at, completed_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		job.ID, string(job.Status), job.Total, job.Done, job.CreatedAt, job.CompletedAt,
	)
	return err
}

// GetJob implements store.JobStore.
func (s *JobStore) GetJob(ctx context.Context, id string) (store.Job, error) {
	return scanJob(s.db.QueryRowContext(ctx,
		`SELECT id, status, total, done, created_at, completed_at FROM jobs WHERE id = $1`, id,
	))
}

// AppendResult implements store.JobStore. It atomically records the verdict,
// increments done, and completes the job when done reaches total.
func (s *JobStore) AppendResult(ctx context.Context, jobID string, r store.Result) error {
	raw, err := json.Marshal(r.Verdict)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var done, total int
	var status string
	err = tx.QueryRowContext(ctx,
		`UPDATE jobs SET done = done + 1 WHERE id = $1 RETURNING done, total, status`, jobID,
	).Scan(&done, &total, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrJobNotFound
	}
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO job_results (job_id, idx, verdict, label) VALUES ($1, $2, $3, $4)`,
		jobID, done-1, raw, r.Label,
	); err != nil {
		return err
	}

	if status != string(store.JobCanceled) && done >= total {
		if _, err := tx.ExecContext(ctx,
			`UPDATE jobs SET status = $2, completed_at = $3 WHERE id = $1`,
			jobID, string(store.JobCompleted), s.now(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Results implements store.JobStore.
func (s *JobStore) Results(ctx context.Context, jobID string, cursor, limit int) ([]store.Result, int, error) {
	if _, err := s.GetJob(ctx, jobID); err != nil {
		return nil, 0, err
	}
	if cursor < 0 {
		cursor = 0
	}
	if limit <= 0 {
		limit = 1000
	}

	// Fetch one extra row to determine whether a further page exists.
	rows, err := s.db.QueryContext(ctx,
		`SELECT verdict, label FROM job_results WHERE job_id = $1 ORDER BY idx OFFSET $2 LIMIT $3`,
		jobID, cursor, limit+1,
	)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]store.Result, 0, limit)
	for rows.Next() {
		var raw []byte
		var label string
		if err := rows.Scan(&raw, &label); err != nil {
			return nil, 0, err
		}
		var v verdict.Verdict
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, 0, err
		}
		items = append(items, store.Result{Label: label, Verdict: v})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	next := 0
	if len(items) > limit {
		items = items[:limit]
		next = cursor + limit
	}
	return items, next, nil
}

// SetStatus implements store.JobStore.
func (s *JobStore) SetStatus(ctx context.Context, jobID string, status store.JobStatus) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs
		    SET status = $2,
		        completed_at = CASE
		            WHEN $2 IN ($4, $5) AND completed_at IS NULL THEN $3
		            ELSE completed_at
		        END
		  WHERE id = $1`,
		jobID, string(status), s.now(), string(store.JobCompleted), string(store.JobCanceled),
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrJobNotFound
	}
	return nil
}

// ListJobs implements store.JobStore, returning jobs newest-first.
func (s *JobStore) ListJobs(ctx context.Context, limit int) ([]store.Job, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, status, total, done, created_at, completed_at
		   FROM jobs ORDER BY created_at DESC LIMIT $1`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]store.Job, 0, limit)
	for rows.Next() {
		var job store.Job
		var status string
		var completed sql.NullTime
		if err := rows.Scan(&job.ID, &status, &job.Total, &job.Done, &job.CreatedAt, &completed); err != nil {
			return nil, err
		}
		job.Status = store.JobStatus(status)
		if completed.Valid {
			job.CompletedAt = &completed.Time
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// scanJob scans a job row, translating no-rows into ErrJobNotFound.
func scanJob(row interface{ Scan(...any) error }) (store.Job, error) {
	var job store.Job
	var status string
	var completed sql.NullTime
	err := row.Scan(&job.ID, &status, &job.Total, &job.Done, &job.CreatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Job{}, store.ErrJobNotFound
	}
	if err != nil {
		return store.Job{}, err
	}
	job.Status = store.JobStatus(status)
	if completed.Valid {
		job.CompletedAt = &completed.Time
	}
	return job, nil
}
