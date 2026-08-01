package web

import (
	"errors"
	"net/http"
	"sort"

	"github.com/tryselfhost/rcptto/internal/store"
)

// metricRow is one line of a breakdown table, with the percentage precomputed
// because html/template has no arithmetic.
type metricRow struct {
	Key     string
	Count   int
	Percent int
	// Class is the badge class for status/reason rows, empty otherwise.
	Class string
}

// jobMetrics is the view model for a list's report.
type jobMetrics struct {
	Job jobView

	Total int
	// Deliverable is the headline number a client asks for.
	Deliverable        int
	DeliverablePercent int
	// Retryable counts unknown results — greylisted, deferred, or blocked —
	// which are not final answers and are worth re-running later.
	Retryable        int
	RetryablePercent int

	// Probed vs NotProbed is how much egress reputation this list consumed:
	// addresses resolved by the funnel or skipped by provider policy cost
	// nothing, while probed ones each opened an SMTP connection.
	Probed           int
	ProbedPercent    int
	NotProbed        int
	NotProbedPercent int

	Statuses  []metricRow
	Reasons   []metricRow
	Providers []metricRow

	// Buckets drive the per-group download controls.
	Buckets []bucketView
}

func (s *Server) handleJobMetrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Jobs == nil {
		http.Error(w, "bulk jobs are not enabled on this server", http.StatusNotImplemented)
		return
	}
	id := r.PathValue("id")

	job, err := s.cfg.Jobs.Get(r.Context(), id)
	if errors.Is(err, store.ErrJobNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load job: "+err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := s.cfg.Jobs.Stats(r.Context(), id)
	if err != nil {
		http.Error(w, "could not compute statistics: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderPage(w, "rcpttō — Report", "content-metrics", buildJobMetrics(job, stats))
}

func buildJobMetrics(job store.Job, stats store.JobStats) jobMetrics {
	m := jobMetrics{
		Job:       newJobView(job),
		Total:     stats.Total,
		Probed:    stats.Probed,
		NotProbed: stats.NotProbed,
	}
	m.Deliverable = stats.ByStatus["deliverable"]
	m.Retryable = stats.ByStatus["unknown"]

	m.DeliverablePercent = percent(m.Deliverable, stats.Total)
	m.RetryablePercent = percent(m.Retryable, stats.Total)
	m.ProbedPercent = percent(stats.Probed, stats.Total)
	m.NotProbedPercent = percent(stats.NotProbed, stats.Total)

	m.Statuses = breakdown(stats.ByStatus, stats.Total, true)
	m.Reasons = breakdown(stats.BySubStatus, stats.Total, false)
	m.Providers = breakdown(stats.ByProvider, stats.Total, false)
	m.Buckets = bucketViews(stats)
	return m
}

// breakdown turns a count map into rows sorted by count, largest first, so the
// dominant outcome is always at the top.
func breakdown(counts map[string]int, total int, badged bool) []metricRow {
	rows := make([]metricRow, 0, len(counts))
	for k, n := range counts {
		if k == "" {
			k = "unknown"
		}
		row := metricRow{Key: k, Count: n, Percent: percent(n, total)}
		if badged {
			row.Class = k
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

func percent(n, total int) int {
	if total <= 0 {
		return 0
	}
	return int(float64(n)/float64(total)*100 + 0.5)
}
