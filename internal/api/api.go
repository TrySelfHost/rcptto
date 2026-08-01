// Package api exposes the rcpttō HTTP surface. It depends on a Verifier
// interface rather than the concrete service, so handlers are testable in
// isolation. Errors follow RFC 7807 (application/problem+json).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Verifier is the behavior the API needs from the verification service.
type Verifier interface {
	Verify(ctx context.Context, email string) (verdict.Verdict, error)
}

// Config configures the API server.
type Config struct {
	// Verifier performs single-address verification. Required.
	Verifier Verifier
	// Jobs handles bulk verification. Optional; when nil, /v1/jobs returns 501.
	Jobs Jobs
	// Egress exposes the reputation manager for admin inspection/control.
	// Optional; when nil, /v1/admin/egress returns 501.
	Egress Egress
	// Policy exposes the provider-policy engine for admin inspection/control.
	// Optional; when nil, /v1/admin/policies returns 501.
	Policy Policy
	// APIKeys, when non-empty, are the accepted X-API-Key values for /v1/*
	// routes. When empty, /v1 is open (development mode).
	APIKeys []string
}

// Server holds the API dependencies and builds the HTTP handler.
type Server struct {
	verifier Verifier
	jobs     Jobs
	egress   Egress
	policy   Policy
	apiKeys  map[string]struct{}
}

// New builds a Server. It panics if no Verifier is configured.
func New(cfg Config) *Server {
	if cfg.Verifier == nil {
		panic("api: Verifier is required")
	}
	keys := make(map[string]struct{}, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		if k != "" {
			keys[k] = struct{}{}
		}
	}
	return &Server{verifier: cfg.Verifier, jobs: cfg.Jobs, egress: cfg.Egress, policy: cfg.Policy, apiKeys: keys}
}

// Handler returns the composed HTTP handler with routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/verify", s.handleVerify)
	mux.HandleFunc("POST /v1/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /v1/jobs/{id}/results", s.handleJobResults)
	mux.HandleFunc("GET /v1/jobs/{id}/stats", s.handleJobStats)
	mux.HandleFunc("POST /v1/jobs/{id}/cancel", s.handleCancelJob)
	mux.HandleFunc("GET /v1/admin/egress", s.handleListEgress)
	mux.HandleFunc("POST /v1/admin/egress/{id}/quarantine", s.handleQuarantineEgress)
	mux.HandleFunc("POST /v1/admin/egress/{id}/enable", s.handleEnableEgress)
	mux.HandleFunc("POST /v1/admin/egress/{id}/disable", s.handleDisableEgress)
	mux.HandleFunc("GET /v1/admin/policies", s.handleListPolicies)
	mux.HandleFunc("PUT /v1/admin/policies/{provider}", s.handleSetPolicy)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	return s.authMiddleware(mux)
}

type verifyRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "request body must be JSON of the form {\"email\": \"...\"}")
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeProblem(w, http.StatusBadRequest, "missing_email", "the 'email' field is required")
		return
	}

	v, err := s.verifier.Verify(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeProblem(w, http.StatusRequestTimeout, "verification_timeout", "verification did not complete in time")
			return
		}
		writeProblem(w, http.StatusBadGateway, "verification_failed", "the verification could not be completed")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// authMiddleware enforces the X-API-Key header on /v1/ routes when keys are
// configured. Health and readiness endpoints are always open.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.apiKeys) > 0 && strings.HasPrefix(r.URL.Path, "/v1/") {
			if _, ok := s.apiKeys[r.Header.Get("X-API-Key")]; !ok {
				writeProblem(w, http.StatusUnauthorized, "unauthorized", "a valid X-API-Key header is required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// problem is an RFC 7807 problem detail.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Detail: detail,
	})
}
