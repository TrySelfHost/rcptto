// Package web implements the rcpttō dashboard: server-rendered HTML pages with
// htmx for interactivity (form submission, polling job progress, incremental
// result loading), so the whole product ships as one Go binary with no Node
// build step.
//
// It depends on the same Verifier/Jobs behavior the JSON API uses, plus Egress
// and Policy for the admin views — kept as narrow interfaces so this package
// has no dependency on internal/egress or internal/policy concrete types.
package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

// Verifier performs single-address verification.
type Verifier interface {
	Verify(ctx context.Context, email string) (verdict.Verdict, error)
}

// Jobs handles bulk verification.
type Jobs interface {
	Submit(ctx context.Context, rows []jobs.Row) (store.Job, error)
	Get(ctx context.Context, id string) (store.Job, error)
	List(ctx context.Context, limit int) ([]store.Job, error)
	Results(ctx context.Context, id string, cursor, limit int) ([]store.Result, int, error)
	Cancel(ctx context.Context, id string) error
}

// EgressIdentity mirrors api.EgressIdentity for the dashboard's egress view.
type EgressIdentity struct {
	ID     string
	IP     string
	State  string
	Reason string
	Online bool
}

// Egress exposes the reputation manager for the dashboard.
type Egress interface {
	Identities() []EgressIdentity
	Quarantine(id, reason string)
	Enable(id string)
	Disable(id, reason string)
}

// PolicyEntry mirrors api.PolicyEntry for the dashboard's policy view.
type PolicyEntry struct {
	Key      string
	Strategy string
	Reason   string
}

// AgentInfo is a read-only view of one remote probe agent, mirroring
// worker.AgentInfo so this package keeps no dependency on the worker package.
type AgentInfo struct {
	ID       string
	BaseURL  string
	Online   bool
	IP       string
	HELO     string
	Region   string
	ASN      string
	LastErr  string
	LastSeen string
}

// Servers exposes the remote agent fleet for the dashboard. Optional; when nil
// the Servers page shows only the local control plane.
type Servers interface {
	Agents() []AgentInfo
}

// Policy exposes the provider-policy engine for the dashboard.
type Policy interface {
	List() []PolicyEntry
	Set(key, strategy, reason string)
}

// Config configures the dashboard server.
type Config struct {
	Verifier Verifier // required
	Jobs     Jobs     // optional; job pages return 501 when nil
	Egress   Egress   // optional; egress page returns 501 when nil
	Policy   Policy   // optional; policies page returns 501 when nil
	// Servers exposes the remote agent fleet. Optional; when nil the Servers
	// page shows only the control plane's own egress.
	Servers Servers
	// Auth password-protects the dashboard. When nil the dashboard is
	// unauthenticated, which is only safe on a trusted network or behind an
	// authenticating reverse proxy.
	Auth *AuthConfig
}

// Server serves the dashboard.
type Server struct {
	cfg     Config
	tmpl    *template.Template
	auth    *auth
	uploads *uploadCache
}

// New builds a dashboard Server. It panics on a nil Verifier or an invalid
// AuthConfig — both are programmer errors; callers reading configuration from
// the environment should validate it before constructing the Server.
func New(cfg Config) *Server {
	if cfg.Verifier == nil {
		panic("web: Verifier is required")
	}
	a, err := newAuth(cfg.Auth)
	if err != nil {
		panic(err)
	}
	tmpl := template.Must(template.New("").Funcs(templateFuncs()).ParseFS(templatesFS, "templates/*.html"))
	return &Server{cfg: cfg, tmpl: tmpl, auth: a, uploads: newUploadCache()}
}

// Handler returns the composed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("POST /verify", s.handleVerifySubmit)
	mux.HandleFunc("POST /jobs", s.handleJobSubmit)
	mux.HandleFunc("GET /jobs", s.handleJobsList)
	mux.HandleFunc("GET /jobs/{id}", s.handleJobShow)
	mux.HandleFunc("GET /jobs/{id}/status", s.handleJobStatus)
	mux.HandleFunc("GET /jobs/{id}/results", s.handleJobResultsPage)
	mux.HandleFunc("POST /jobs/{id}/cancel", s.handleJobCancel)
	mux.HandleFunc("GET /jobs/{id}/export/{format}", s.handleJobExport)
	mux.HandleFunc("POST /upload", s.handleUploadPreview)
	mux.HandleFunc("POST /upload/confirm", s.handleUploadConfirm)
	mux.HandleFunc("GET /egress", s.handleEgress)
	mux.HandleFunc("POST /egress/{id}/quarantine", s.handleEgressQuarantine)
	mux.HandleFunc("POST /egress/{id}/enable", s.handleEgressEnable)
	mux.HandleFunc("POST /egress/{id}/disable", s.handleEgressDisable)
	mux.HandleFunc("GET /servers", s.handleServers)
	mux.HandleFunc("GET /policies", s.handlePolicies)
	mux.HandleFunc("POST /policies/{key}", s.handlePolicySet)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.Handle("GET /assets/", http.FileServerFS(assetsFS))
	return s.requireAuth(mux)
}

// ---- view models -----------------------------------------------------------

// verdictView adapts verdict.Verdict for templates, precomputing the
// confidence percentage since html/template cannot do arithmetic.
type verdictView struct {
	verdict.Verdict
	ConfidencePct int
	// Label is the client name the address arrived under, shown in job result
	// tables so a verified list can be read against the original sheet.
	Label string
}

func newVerdictView(v verdict.Verdict) verdictView {
	return verdictView{Verdict: v, ConfidencePct: int(v.Confidence*100 + 0.5)}
}

// newResultView adapts a stored result, keeping its label.
func newResultView(r store.Result) verdictView {
	view := newVerdictView(r.Verdict)
	view.Label = r.Label
	return view
}

// jobView adapts store.Job for templates, precomputing progress and a
// formatted timestamp.
type jobView struct {
	store.Job
	StatusClass  string
	PercentDone  int
	Running      bool
	CreatedAtStr string
}

func newJobView(j store.Job) jobView {
	pct := 0
	if j.Total > 0 {
		pct = j.Done * 100 / j.Total
	}
	return jobView{
		Job:          j,
		StatusClass:  string(j.Status),
		PercentDone:  pct,
		Running:      j.Status == store.JobRunning || j.Status == store.JobQueued,
		CreatedAtStr: j.CreatedAt.Format("2006-01-02 15:04:05"),
	}
}

// jobShowData is the view model for the job detail page and its polling
// status fragment.
type jobShowData struct {
	Job        jobView
	Results    []verdictView
	HasMore    bool
	NextCursor int
}

// ---- rendering helpers -----------------------------------------------------

// renderPage executes the named content template into a buffer, then wraps it
// in the shared layout. The two-pass approach lets every page define its
// content under a uniquely-named template — html/template shares one namespace
// across all files parsed together, so identical block names would collide.
func (s *Server) renderPage(w http.ResponseWriter, title, contentTemplate string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, contentTemplate, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := struct {
		Title       string
		Content     template.HTML
		AuthEnabled bool
	}{
		Title:       title,
		Content:     template.HTML(buf.String()),
		AuthEnabled: s.auth != nil,
	}
	if err := s.tmpl.ExecuteTemplate(w, "layout", page); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderFragment executes a template straight to the response, for htmx
// partial swaps that are not full pages.
func (s *Server) renderFragment(w http.ResponseWriter, tmplName string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, tmplName, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// ---- verify ----------------------------------------------------------------

func (s *Server) handleHome(w http.ResponseWriter, _ *http.Request) {
	s.renderPage(w, "rcpttō — Verify", "content-home", nil)
}

func (s *Server) handleVerifySubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFragment(w, "verdict-error", "invalid form submission")
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		s.renderFragment(w, "verdict-error", "email is required")
		return
	}
	v, err := s.cfg.Verifier.Verify(r.Context(), email)
	if err != nil {
		s.renderFragment(w, "verdict-error", "verification failed")
		return
	}
	s.renderFragment(w, "verdict-result", newVerdictView(v))
}

// ---- jobs ------------------------------------------------------------------

func (s *Server) jobsEnabled(w http.ResponseWriter) bool {
	if s.cfg.Jobs == nil {
		http.Error(w, "bulk jobs are not enabled on this server", http.StatusNotImplemented)
		return false
	}
	return true
}

func (s *Server) handleJobSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFragment(w, "verdict-error", "invalid form submission")
		return
	}
	lines := strings.Split(r.FormValue("emails"), "\n")
	rows := make([]jobs.Row, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			rows = append(rows, jobs.Row{Email: t})
		}
	}
	job, err := s.cfg.Jobs.Submit(r.Context(), rows)
	if err != nil {
		s.renderFragment(w, "verdict-error", "could not submit job: "+err.Error())
		return
	}
	s.renderFragment(w, "job-created", job)
}

func (s *Server) handleJobsList(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	jobs, err := s.cfg.Jobs.List(r.Context(), 100)
	if err != nil {
		http.Error(w, "could not list jobs", http.StatusInternalServerError)
		return
	}
	views := make([]jobView, len(jobs))
	for i, j := range jobs {
		views[i] = newJobView(j)
	}
	s.renderPage(w, "rcpttō — Jobs", "content-jobs", struct{ Jobs []jobView }{views})
}

func (s *Server) loadJobShowData(ctx context.Context, id string) (jobShowData, error) {
	job, err := s.cfg.Jobs.Get(ctx, id)
	if err != nil {
		return jobShowData{}, err
	}
	items, next, err := s.cfg.Jobs.Results(ctx, id, 0, 50)
	if err != nil {
		return jobShowData{}, err
	}
	views := make([]verdictView, len(items))
	for i, v := range items {
		views[i] = newResultView(v)
	}
	return jobShowData{Job: newJobView(job), Results: views, HasMore: next > 0, NextCursor: next}, nil
}

func (s *Server) handleJobShow(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	data, err := s.loadJobShowData(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrJobNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load job", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, fmt.Sprintf("rcpttō — Job %s", data.Job.ID), "content-job", data)
}

// handleJobStatus serves the polling fragment (htmx hx-trigger="every 2s").
func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	data, err := s.loadJobShowData(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrJobNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load job", http.StatusInternalServerError)
		return
	}
	s.renderFragment(w, "job-status-inner", data)
}

func (s *Server) handleJobResultsPage(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	id := r.PathValue("id")
	job, err := s.cfg.Jobs.Get(r.Context(), id)
	if errors.Is(err, store.ErrJobNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load job", http.StatusInternalServerError)
		return
	}
	items, next, err := s.cfg.Jobs.Results(r.Context(), id, queryInt(r, "cursor", 0), 50)
	if err != nil {
		http.Error(w, "could not load results", http.StatusInternalServerError)
		return
	}
	views := make([]verdictView, len(items))
	for i, v := range items {
		views[i] = newResultView(v)
	}
	s.renderFragment(w, "job-result-rows-page", jobShowData{
		Job: newJobView(job), Results: views, HasMore: next > 0, NextCursor: next,
	})
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	if !s.jobsEnabled(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.cfg.Jobs.Cancel(r.Context(), id); err != nil && !errors.Is(err, store.ErrJobNotFound) {
		http.Error(w, "could not cancel job", http.StatusInternalServerError)
		return
	}
	data, err := s.loadJobShowData(r.Context(), id)
	if errors.Is(err, store.ErrJobNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load job", http.StatusInternalServerError)
		return
	}
	s.renderFragment(w, "job-status-inner", data)
}

// ---- egress ----------------------------------------------------------------

func (s *Server) egressEnabled(w http.ResponseWriter) bool {
	if s.cfg.Egress == nil {
		http.Error(w, "the egress dashboard is not enabled on this server", http.StatusNotImplemented)
		return false
	}
	return true
}

func (s *Server) handleEgress(w http.ResponseWriter, _ *http.Request) {
	if !s.egressEnabled(w) {
		return
	}
	s.renderPage(w, "rcpttō — Egress", "content-egress",
		struct{ Identities []EgressIdentity }{s.cfg.Egress.Identities()})
}

func (s *Server) handleEgressQuarantine(w http.ResponseWriter, r *http.Request) {
	if !s.egressEnabled(w) {
		return
	}
	_ = r.ParseForm()
	id := r.PathValue("id")
	s.cfg.Egress.Quarantine(id, firstNonEmpty(r.FormValue("reason"), "manual"))
	s.renderEgressRow(w, r, id)
}

func (s *Server) handleEgressEnable(w http.ResponseWriter, r *http.Request) {
	if !s.egressEnabled(w) {
		return
	}
	id := r.PathValue("id")
	s.cfg.Egress.Enable(id)
	s.renderEgressRow(w, r, id)
}

func (s *Server) handleEgressDisable(w http.ResponseWriter, r *http.Request) {
	if !s.egressEnabled(w) {
		return
	}
	_ = r.ParseForm()
	id := r.PathValue("id")
	s.cfg.Egress.Disable(id, firstNonEmpty(r.FormValue("reason"), "manual"))
	s.renderEgressRow(w, r, id)
}

// renderEgressRow re-reads the identity after a state change and renders just
// its table row, which htmx swaps in place.
func (s *Server) renderEgressRow(w http.ResponseWriter, r *http.Request, id string) {
	for _, info := range s.cfg.Egress.Identities() {
		if info.ID == id {
			s.renderFragment(w, "egress-row", info)
			return
		}
	}
	http.NotFound(w, r)
}

// ---- policies --------------------------------------------------------------

func (s *Server) handlePolicies(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Policy == nil {
		http.Error(w, "the policy dashboard is not enabled on this server", http.StatusNotImplemented)
		return
	}
	s.renderPage(w, "rcpttō — Policies", "content-policies",
		struct{ Policies []PolicyEntry }{s.cfg.Policy.List()})
}

func (s *Server) handlePolicySet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Policy == nil {
		http.Error(w, "the policy dashboard is not enabled on this server", http.StatusNotImplemented)
		return
	}
	_ = r.ParseForm()
	key := r.PathValue("key")
	strategy := r.FormValue("strategy")
	switch strategy {
	case "probe", "skip", "statistical":
	default:
		http.Error(w, "strategy must be one of: probe, skip, statistical", http.StatusBadRequest)
		return
	}
	s.cfg.Policy.Set(key, strategy, "dashboard edit")

	for _, e := range s.cfg.Policy.List() {
		if e.Key == key {
			s.renderFragment(w, "policy-row", e)
			return
		}
	}
	http.NotFound(w, r)
}

// ---- helpers ---------------------------------------------------------------

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// templateFuncs provides the small helpers the upload templates need, so
// column handling stays out of the template markup.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// columnName labels a column by its header when there is one, falling
		// back to a positional name for headerless sheets.
		"columnName": func(header []string, c int) string {
			if c >= 0 && c < len(header) {
				if h := strings.TrimSpace(header[c]); h != "" {
					return h
				}
			}
			return fmt.Sprintf("Column %d", c+1)
		},
		// cell reads a cell, tolerating ragged rows.
		"cell": func(row []string, c int) string {
			if c >= 0 && c < len(row) {
				return row[c]
			}
			return ""
		},
	}
}

// identitiesOrEmpty returns an Egress port's identities, tolerating a nil port
// so the Servers page renders even on a control plane without egress wired up.
func identitiesOrEmpty(e Egress) []EgressIdentity {
	if e == nil {
		return nil
	}
	return e.Identities()
}

// serverRow is one machine in the fleet view: either the control plane itself
// or a remote probe agent.
type serverRow struct {
	Role     string // "control plane" | "probe agent"
	ID       string
	Address  string
	Online   bool
	IP       string
	HELO     string
	Region   string
	LastSeen string
	LastErr  string
	// State is the egress lifecycle state for this machine's identity, when it
	// has one (warming/active/quarantined/disabled).
	State string
}

// handleServers renders fleet health: which machines exist, whether they are
// reachable, and what egress identity each provides. Without this, a remote box
// going down shows up only as a badge flipping on the egress table, with no
// indication of which machine or why.
func (s *Server) handleServers(w http.ResponseWriter, _ *http.Request) {
	// Egress state is keyed by identity id, so agents can be annotated with the
	// lifecycle state of the identity they serve.
	states := map[string]EgressIdentity{}
	if s.cfg.Egress != nil {
		for _, id := range s.cfg.Egress.Identities() {
			states[id.ID] = id
		}
	}

	rows := []serverRow{}
	remote := map[string]bool{}
	if s.cfg.Servers != nil {
		for _, a := range s.cfg.Servers.Agents() {
			remote[a.ID] = true
			row := serverRow{
				Role: "probe agent", ID: a.ID, Address: a.BaseURL, Online: a.Online,
				IP: a.IP, HELO: a.HELO, Region: a.Region,
				LastSeen: a.LastSeen, LastErr: a.LastErr,
			}
			if st, ok := states[a.ID]; ok {
				row.State = st.State
			}
			rows = append(rows, row)
		}
	}

	// Any egress identity not served by an agent belongs to the control plane
	// itself, so the local machine appears in the same view.
	for _, id := range identitiesOrEmpty(s.cfg.Egress) {
		if remote[id.ID] {
			continue
		}
		rows = append(rows, serverRow{
			Role: "control plane", ID: id.ID, Address: "local",
			Online: id.Online, IP: id.IP, State: id.State,
		})
	}

	s.renderPage(w, "rcpttō — Servers", "content-servers", struct {
		Rows          []serverRow
		AgentsEnabled bool
	}{Rows: rows, AgentsEnabled: s.cfg.Servers != nil})
}
