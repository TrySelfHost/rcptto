// Command rcptto-server runs the rcpttō control-plane HTTP API.
//
// This early build serves synchronous single-address verification (POST
// /v1/verify) plus health and readiness endpoints, backed by the in-memory
// result cache and the builtin SMTP engine. Bulk jobs, durable persistence,
// and the reputation-managed egress fleet arrive in later milestones.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tryselfhost/rcptto/internal/api"
	"github.com/tryselfhost/rcptto/internal/egress"
	"github.com/tryselfhost/rcptto/internal/egress/audit"
	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/pipeline"
	"github.com/tryselfhost/rcptto/internal/policy"
	"github.com/tryselfhost/rcptto/internal/ratelimit"
	"github.com/tryselfhost/rcptto/internal/settings"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/internal/store/postgres"
	"github.com/tryselfhost/rcptto/internal/verifier"
	"github.com/tryselfhost/rcptto/internal/web"
	"github.com/tryselfhost/rcptto/internal/worker"
	"github.com/tryselfhost/rcptto/pkg/engine/builtin"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := getenv("RCPTTO_ADDR", ":8080")
	helo := getenv("RCPTTO_HELO", "localhost")
	mailFrom := getenv("RCPTTO_MAIL_FROM", "verify@localhost")
	apiKeys := splitAndTrim(os.Getenv("RCPTTO_API_KEYS"))
	detectCatchAll := getenvBool("RCPTTO_DETECT_CATCHALL", true)
	dashboardEnabled := getenvBool("RCPTTO_DASHBOARD", true)

	var (
		resultCache   store.ResultStore   = memory.NewResultStore()
		jobStore      store.JobStore      = memory.NewJobStore()
		egressStore   store.EgressStore   = memory.NewEgressStore()
		settingsStore store.SettingsStore = memory.NewSettingsStore()
	)
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := postgres.Open(context.Background(), dsn)
		if err != nil {
			return err
		}
		if err := postgres.Migrate(context.Background(), db); err != nil {
			return err
		}
		resultCache = postgres.NewResultStore(db)
		jobStore = postgres.NewJobStore(db)
		egressStore = postgres.NewEgressStore(db)
		settingsStore = postgres.NewSettingsStore(db)
		log.Info("using postgres store")
	} else {
		log.Info("using in-memory store (set DATABASE_URL for persistence)")
	}

	egressMgr := egress.New(egress.Config{
		Store: egressStore,
		Identities: []egress.Spec{{
			ID:        "direct",
			Kind:      egress.KindLocalIP,
			HELO:      helo,
			MailFrom:  mailFrom,
			Transport: egress.DirectTransport{},
		}},
	})

	// Restore previously earned reputation. Without this, every restart would
	// reset a multi-day warm-up to day zero and silently un-quarantine an
	// identity that was withdrawn for a good reason.
	if states, err := egressStore.LoadEgress(context.Background()); err != nil {
		log.Warn("could not restore egress reputation; starting from configured defaults", "err", err)
	} else if len(states) > 0 {
		egressMgr.Restore(states)
		log.Info("restored egress reputation", "identities", len(states))
	}

	policySet := policy.Default()

	// Remote probe agents. Each agent owns one egress IP on its own machine;
	// the control plane keeps all the intelligence and delegates only the SMTP
	// probe. Identities are registered here so they appear in the dashboard
	// even before the first health check reaches them.
	agentCfgs, err := worker.ParseAgents(os.Getenv("RCPTTO_WORKERS"), os.Getenv("RCPTTO_WORKER_TOKEN"))
	if err != nil {
		return err
	}
	registry, err := worker.NewRegistry(agentCfgs, 60*time.Second)
	if err != nil {
		return err
	}
	for _, a := range agentCfgs {
		egressMgr.AddIdentity(egress.Spec{
			ID:        a.ID,
			Kind:      egress.KindLocalIP,
			WarmUp:    true, // a newly introduced remote IP has no reputation yet
			Transport: egress.DirectTransport{},
		})
		// Until a health check succeeds the agent is unreachable, so keep it out
		// of routing rather than letting probes fail against a dead box.
		egressMgr.SetOnline(a.ID, false)
	}
	if registry.Len() > 0 {
		log.Info("remote probe agents configured", "count", registry.Len())
	}

	// Pace probes per destination mail server. Without this, a bulk job
	// concentrated on one domain hammers that domain's MX at full worker
	// concurrency — a reliable way to get an egress IP blocked.
	limiter := ratelimit.New(ratelimit.Config{
		Rate:  getenvFloat("RCPTTO_PROBE_RATE", 1),
		Burst: getenvFloat("RCPTTO_PROBE_BURST", 5),
	})

	probeEngine := builtin.New(builtin.Config{
		HELO:           helo,
		MailFrom:       mailFrom,
		DetectCatchAll: detectCatchAll,
	})

	svc := verifier.New(verifier.Config{
		Pipeline: pipeline.New(pipeline.Config{}),
		Engine:   probeEngine,
		Egress:   egressMgr,
		Sink:     egressMgr,
		Cache:    resultCache,
		Policy:   policySet,
		Limiter:  limiter,
		Engines:  registry,
	})

	runner := jobs.New(jobs.Config{
		Store:    jobStore,
		Verifier: svc,
	})

	// Runtime settings: environment values are the starting point, then any
	// previously saved configuration overrides them, so an operator's tuning
	// survives a restart instead of silently reverting on every deploy.
	settingsMgr := &settingsManager{
		current: settings.Default().WithDefaults(),
		store:   settingsStore, limiter: limiter, runner: runner,
		egress: egressMgr, engine: probeEngine, log: log,
	}
	settingsMgr.current.ProbeRate = getenvFloat("RCPTTO_PROBE_RATE", settingsMgr.current.ProbeRate)
	settingsMgr.current.ProbeBurst = getenvFloat("RCPTTO_PROBE_BURST", settingsMgr.current.ProbeBurst)
	settingsMgr.current.DetectCatchAll = detectCatchAll

	if saved, found, err := settingsStore.LoadSettings(context.Background()); err != nil {
		log.Warn("could not load saved settings; using defaults", "err", err)
	} else if found {
		settingsMgr.current = saved.WithDefaults()
		log.Info("restored saved settings")
	}
	settingsMgr.activate(settingsMgr.current)

	apiHandler := api.New(api.Config{
		Verifier: svc,
		Jobs:     runner,
		Egress:   egressAdapter{egressMgr},
		Policy:   policyAdapter{policySet},
		APIKeys:  apiKeys,
	}).Handler()

	// The JSON API owns /v1/* and the health endpoints; the dashboard owns
	// everything else (/, /jobs, /egress, /policies, /assets). Composing them
	// under one mux keeps a single listener and a single binary.
	root := http.NewServeMux()
	root.Handle("/v1/", apiHandler)
	root.Handle("/healthz", apiHandler)
	root.Handle("/readyz", apiHandler)
	if dashboardEnabled {
		dashUser := os.Getenv("RCPTTO_DASHBOARD_USER")
		dashPass := os.Getenv("RCPTTO_DASHBOARD_PASSWORD")
		if (dashUser == "") != (dashPass == "") {
			return errors.New("RCPTTO_DASHBOARD_USER and RCPTTO_DASHBOARD_PASSWORD must be set together")
		}

		var dashAuth *web.AuthConfig
		if dashUser != "" {
			dashAuth = &web.AuthConfig{
				Username:     dashUser,
				Password:     dashPass,
				Secret:       []byte(os.Getenv("RCPTTO_SESSION_SECRET")),
				SecureCookie: getenvBool("RCPTTO_SECURE_COOKIE", false),
			}
		} else {
			// The dashboard can quarantine egress identities and rewrite
			// provider policy, so an unauthenticated one must never face an
			// untrusted network.
			log.Warn("dashboard has NO authentication; bind it to localhost or set " +
				"RCPTTO_DASHBOARD_USER and RCPTTO_DASHBOARD_PASSWORD before exposing it")
		}

		root.Handle("/", web.New(web.Config{
			Verifier: svc,
			Jobs:     runner,
			Egress:   webEgressAdapter{egressMgr},
			Policy:   webPolicyAdapter{policySet},
			Servers:  webServersAdapter{registry},
			Settings: settingsMgr,
			Auth:     dashAuth,
		}).Handler())
		log.Info("dashboard enabled", "url", "http://localhost"+addr+"/", "auth", dashAuth != nil)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Track agent reachability, so routing skips a box that has gone away and
	// resumes using it — with its earned reputation intact — when it returns.
	if registry.Len() > 0 {
		go registry.HealthLoop(ctx, 30*time.Second, func(info worker.AgentInfo) {
			egressMgr.SetOnline(info.ID, info.Online)
			if info.Online {
				// An agent's IP and HELO are only known once it has been reached.
				egressMgr.AddIdentity(egress.Spec{
					ID:        info.ID,
					Kind:      egress.KindLocalIP,
					IP:        info.IP,
					HELO:      info.HELO,
					Region:    info.Region,
					ASN:       info.ASN,
					Transport: egress.DirectTransport{},
				})
				log.Info("probe agent online", "id", info.ID, "ip", info.IP)
			} else {
				log.Warn("probe agent offline", "id", info.ID, "err", info.LastErr)
			}
		})
	}

	// Persist egress reputation periodically and once more on shutdown.
	persistDone := make(chan struct{})
	go func() {
		defer close(persistDone)
		egressMgr.PersistLoop(ctx, 30*time.Second, func(err error) {
			log.Warn("persisting egress reputation failed", "err", err)
		})
	}()

	// Optional background DNSBL auditing of egress identities, tied to the
	// server lifecycle.
	if zones := splitAndTrim(os.Getenv("RCPTTO_DNSBL_ZONES")); len(zones) > 0 {
		dnsbl := audit.NewDNSBL(audit.DirectResolver{}, zones)
		go runDNSBLAudits(ctx, egressMgr, dnsbl, log)
		log.Info("dnsbl auditing enabled", "zones", zones)
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("rcptto-server listening", "addr", addr, "auth", len(apiKeys) > 0)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	// Wait for the final reputation flush so accumulated warm-up and quarantine
	// state is not lost on exit.
	select {
	case <-persistDone:
	case <-time.After(15 * time.Second):
		log.Warn("timed out waiting for egress reputation to persist")
	}

	log.Info("stopped")
	return nil
}

// egressAdapter satisfies api.Egress by translating egress.Manager's richer
// types into the API's plain-string wire shapes, keeping internal/api free of
// a dependency on internal/egress.
type egressAdapter struct{ mgr *egress.Manager }

func (a egressAdapter) Identities() []api.EgressIdentity {
	infos := a.mgr.Identities()
	out := make([]api.EgressIdentity, len(infos))
	for i, info := range infos {
		out[i] = api.EgressIdentity{
			ID: info.ID, IP: info.IP, State: string(info.State),
			Reason: info.Reason, Online: info.Online,
		}
	}
	return out
}

func (a egressAdapter) Quarantine(id, reason string) { a.mgr.Quarantine(id, reason) }
func (a egressAdapter) Enable(id string)             { a.mgr.Enable(id) }
func (a egressAdapter) Disable(id, reason string)    { a.mgr.Disable(id, reason) }

// settingsManager persists runtime configuration and applies it to the live
// components, so a change takes effect without a restart.
//
// Applying is deliberately narrow: the rate limiter and reputation thresholds
// change immediately, while job concurrency applies to jobs started afterwards.
// Resizing a running job's worker pool would risk losing in-flight probes for
// no real benefit.
type settingsManager struct {
	mu      sync.RWMutex
	current settings.Settings

	store   store.SettingsStore
	limiter *ratelimit.Limiter
	runner  *jobs.Runner
	egress  *egress.Manager
	engine  *builtin.Engine
	log     *slog.Logger
}

// Current implements web.SettingsManager.
func (m *settingsManager) Current() settings.Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Apply validates, persists, then activates. Persisting first means a restart
// cannot resurrect settings that were rejected, and activating only after a
// successful save keeps the running configuration and the stored one in step.
func (m *settingsManager) Apply(ctx context.Context, s settings.Settings) error {
	s = s.WithDefaults()
	if err := s.Validate(); err != nil {
		return err
	}
	if err := m.store.SaveSettings(ctx, s); err != nil {
		return fmt.Errorf("could not save settings: %w", err)
	}
	m.activate(s)
	m.log.Info("settings applied",
		"probe_rate", s.ProbeRate, "probe_burst", s.ProbeBurst,
		"job_concurrency", s.JobConcurrency, "quarantine_threshold", s.QuarantineThreshold)
	return nil
}

// activate pushes settings into the live components.
func (m *settingsManager) activate(s settings.Settings) {
	m.mu.Lock()
	m.current = s
	m.mu.Unlock()

	m.limiter.SetRate(s.ProbeRate, s.ProbeBurst)
	m.runner.SetLimits(s.JobConcurrency, s.MaxEmailsPerJob)
	m.egress.SetThresholds(s.QuarantineThreshold, s.CircuitThreshold)
	m.engine.SetDetectCatchAll(s.DetectCatchAll)
}

// webServersAdapter satisfies web.Servers, translating the registry's agent
// view into the dashboard's wire shape so internal/web keeps no dependency on
// internal/worker.
type webServersAdapter struct{ reg *worker.Registry }

func (a webServersAdapter) Agents() []web.AgentInfo {
	agents := a.reg.Agents()
	out := make([]web.AgentInfo, len(agents))
	for i, ag := range agents {
		lastSeen := ""
		if !ag.LastSeen.IsZero() {
			lastSeen = ag.LastSeen.Format("2006-01-02 15:04:05")
		}
		out[i] = web.AgentInfo{
			ID: ag.ID, BaseURL: ag.BaseURL, Online: ag.Online,
			IP: ag.IP, HELO: ag.HELO, Region: ag.Region, ASN: ag.ASN,
			LastErr: ag.LastErr, LastSeen: lastSeen,
		}
	}
	return out
}

// policyAdapter satisfies api.Policy by translating policy.Set's typed Strategy
// into the API's plain strings, keeping internal/api free of a dependency on
// internal/policy.
type policyAdapter struct{ set *policy.Set }

func (a policyAdapter) List() []api.PolicyEntry {
	entries := a.set.List()
	out := make([]api.PolicyEntry, len(entries))
	for i, e := range entries {
		out[i] = api.PolicyEntry{Key: e.Key, Strategy: string(e.Rule.Strategy), Reason: e.Rule.Reason}
	}
	return out
}

func (a policyAdapter) Set(key, strategy, reason string) {
	a.set.Set(key, policy.Rule{Strategy: policy.Strategy(strategy), Reason: reason})
}

// webEgressAdapter satisfies web.Egress, mirroring egressAdapter for the
// dashboard's own narrow interface (the web package deliberately does not
// import internal/egress).
type webEgressAdapter struct{ mgr *egress.Manager }

func (a webEgressAdapter) Identities() []web.EgressIdentity {
	infos := a.mgr.Identities()
	out := make([]web.EgressIdentity, len(infos))
	for i, info := range infos {
		out[i] = web.EgressIdentity{
			ID: info.ID, IP: info.IP, State: string(info.State),
			Reason: info.Reason, Online: info.Online,
		}
	}
	return out
}

func (a webEgressAdapter) Quarantine(id, reason string) { a.mgr.Quarantine(id, reason) }
func (a webEgressAdapter) Enable(id string)             { a.mgr.Enable(id) }
func (a webEgressAdapter) Disable(id, reason string)    { a.mgr.Disable(id, reason) }

// webPolicyAdapter satisfies web.Policy, mirroring policyAdapter.
type webPolicyAdapter struct{ set *policy.Set }

func (a webPolicyAdapter) List() []web.PolicyEntry {
	entries := a.set.List()
	out := make([]web.PolicyEntry, len(entries))
	for i, e := range entries {
		out[i] = web.PolicyEntry{Key: e.Key, Strategy: string(e.Rule.Strategy), Reason: e.Rule.Reason}
	}
	return out
}

func (a webPolicyAdapter) Set(key, strategy, reason string) {
	a.set.Set(key, policy.Rule{Strategy: policy.Strategy(strategy), Reason: reason})
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getenvFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return def
	}
	return f
}

// runDNSBLAudits periodically checks egress identities against the configured
// DNSBLs, quarantining any that become listed. It runs until ctx is canceled.
func runDNSBLAudits(ctx context.Context, mgr *egress.Manager, dnsbl *audit.DNSBL, log *slog.Logger) {
	const interval = 15 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	mgr.AuditDNSBL(ctx, dnsbl) // once at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mgr.AuditDNSBL(ctx, dnsbl)
			log.Debug("dnsbl audit completed")
		}
	}
}

func splitAndTrim(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
