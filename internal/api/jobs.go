package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Jobs is the behavior the API needs from the bulk-verification runner.
type Jobs interface {
	Submit(ctx context.Context, emails []string) (store.Job, error)
	Get(ctx context.Context, id string) (store.Job, error)
	Results(ctx context.Context, id string, cursor, limit int) ([]verdict.Verdict, int, error)
	Cancel(ctx context.Context, id string) error
}

const (
	defaultResultsLimit = 100
	maxResultsLimit     = 1000
	maxBulkBodyBytes    = 8 << 20 // 8 MiB
)

type createJobRequest struct {
	Emails []string `json:"emails"`
}

type resultsResponse struct {
	Results    []verdict.Verdict `json:"results"`
	NextCursor int               `json:"next_cursor"`
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeProblem(w, http.StatusNotImplemented, "jobs_disabled", "bulk jobs are not enabled on this server")
		return
	}

	var req createJobRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBulkBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "request body must be JSON of the form {\"emails\": [\"...\"]}")
		return
	}

	job, err := s.jobs.Submit(r.Context(), req.Emails)
	switch {
	case errors.Is(err, jobs.ErrNoEmails):
		writeProblem(w, http.StatusBadRequest, "no_emails", "at least one email address is required")
		return
	case errors.Is(err, jobs.ErrTooManyEmails):
		writeProblem(w, http.StatusRequestEntityTooLarge, "too_many_emails", "the job exceeds the maximum number of addresses")
		return
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "job_create_failed", "the job could not be created")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeProblem(w, http.StatusNotImplemented, "jobs_disabled", "bulk jobs are not enabled on this server")
		return
	}
	job, err := s.jobs.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrJobNotFound) {
		writeProblem(w, http.StatusNotFound, "job_not_found", "no job with that id")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "job_lookup_failed", "the job could not be retrieved")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleJobResults(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeProblem(w, http.StatusNotImplemented, "jobs_disabled", "bulk jobs are not enabled on this server")
		return
	}
	cursor := queryInt(r, "cursor", 0)
	limit := queryInt(r, "limit", defaultResultsLimit)
	if limit > maxResultsLimit {
		limit = maxResultsLimit
	}
	if limit < 1 {
		limit = defaultResultsLimit
	}

	items, next, err := s.jobs.Results(r.Context(), r.PathValue("id"), cursor, limit)
	if errors.Is(err, store.ErrJobNotFound) {
		writeProblem(w, http.StatusNotFound, "job_not_found", "no job with that id")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "results_failed", "the results could not be retrieved")
		return
	}
	writeJSON(w, http.StatusOK, resultsResponse{Results: items, NextCursor: next})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeProblem(w, http.StatusNotImplemented, "jobs_disabled", "bulk jobs are not enabled on this server")
		return
	}
	id := r.PathValue("id")
	err := s.jobs.Cancel(r.Context(), id)
	if errors.Is(err, store.ErrJobNotFound) {
		writeProblem(w, http.StatusNotFound, "job_not_found", "no job with that id")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cancel_failed", "the job could not be canceled")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": string(store.JobCanceled)})
}

// queryInt reads an integer query parameter, returning def when absent or invalid.
func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
