package api

import (
	"encoding/json"
	"net/http"
)

// EgressIdentity is a read-only snapshot of one egress identity, as exposed by
// the admin API. Mirrors egress.IdentityInfo without importing that package.
type EgressIdentity struct {
	ID     string `json:"id"`
	IP     string `json:"ip,omitempty"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// PolicyEntry is one provider-policy rule, as exposed by the admin API.
// Mirrors policy.Entry without importing that package.
type PolicyEntry struct {
	Key      string `json:"key"`
	Strategy string `json:"strategy"`
	Reason   string `json:"reason,omitempty"`
}

// Egress is the behavior the admin API needs from the egress reputation manager.
type Egress interface {
	Identities() []EgressIdentity
	Quarantine(id, reason string)
	Enable(id string)
	Disable(id, reason string)
}

// Policy is the behavior the admin API needs from the provider-policy engine.
type Policy interface {
	List() []PolicyEntry
	Set(key, strategy, reason string)
}

type policyUpdateRequest struct {
	Strategy string `json:"strategy"`
	Reason   string `json:"reason"`
}

type quarantineRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleListEgress(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the egress admin API is not enabled on this server")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": s.egress.Identities()})
}

func (s *Server) handleQuarantineEgress(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the egress admin API is not enabled on this server")
		return
	}
	var req quarantineRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) // reason is optional
	s.egress.Quarantine(r.PathValue("id"), firstNonEmptyAPI(req.Reason, "manual"))
	writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "state": "quarantined"})
}

func (s *Server) handleEnableEgress(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the egress admin API is not enabled on this server")
		return
	}
	s.egress.Enable(r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "state": "warming"})
}

func (s *Server) handleDisableEgress(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the egress admin API is not enabled on this server")
		return
	}
	var req quarantineRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req)
	s.egress.Disable(r.PathValue("id"), firstNonEmptyAPI(req.Reason, "manual"))
	writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "state": "disabled"})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if s.policy == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the policy admin API is not enabled on this server")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": s.policy.List()})
}

func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	if s.policy == nil {
		writeProblem(w, http.StatusNotImplemented, "admin_disabled", "the policy admin API is not enabled on this server")
		return
	}
	var req policyUpdateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "request body must be JSON of the form {\"strategy\": \"probe|skip|statistical\", \"reason\": \"...\"}")
		return
	}
	switch req.Strategy {
	case "probe", "skip", "statistical":
	default:
		writeProblem(w, http.StatusBadRequest, "invalid_strategy", "strategy must be one of: probe, skip, statistical")
		return
	}
	key := r.PathValue("provider")
	s.policy.Set(key, req.Strategy, req.Reason)
	writeJSON(w, http.StatusOK, PolicyEntry{Key: key, Strategy: req.Strategy, Reason: req.Reason})
}

func firstNonEmptyAPI(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
