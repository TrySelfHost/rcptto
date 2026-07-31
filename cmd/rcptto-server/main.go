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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tryselfhost/rcptto/internal/api"
	"github.com/tryselfhost/rcptto/internal/egress"
	"github.com/tryselfhost/rcptto/internal/egress/audit"
	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/pipeline"
	"github.com/tryselfhost/rcptto/internal/policy"
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/internal/store/postgres"
	"github.com/tryselfhost/rcptto/internal/verifier"
	"github.com/tryselfhost/rcptto/internal/web"
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
		resultCache store.ResultStore = memory.NewResultStore()
		jobStore    store.JobStore    = memory.NewJobStore()
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
		log.Info("using postgres store")
	} else {
		log.Info("using in-memory store (set DATABASE_URL for persistence)")
	}

	egressMgr := egress.New(egress.Config{
		Identities: []egress.Spec{{
			ID:        "direct",
			Kind:      egress.KindLocalIP,
			HELO:      helo,
			MailFrom:  mailFrom,
			Transport: egress.DirectTransport{},
		}},
	})

	policySet := policy.Default()

	svc := verifier.New(verifier.Config{
		Pipeline: pipeline.New(pipeline.Config{}),
		Engine: builtin.New(builtin.Config{
			HELO:           helo,
			MailFrom:       mailFrom,
			DetectCatchAll: detectCatchAll,
		}),
		Egress: egressMgr,
		Sink:   egressMgr,
		Cache:  resultCache,
		Policy: policySet,
	})

	runner := jobs.New(jobs.Config{
		Store:    jobStore,
		Verifier: svc,
	})

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
		out[i] = api.EgressIdentity{ID: info.ID, IP: info.IP, State: string(info.State), Reason: info.Reason}
	}
	return out
}

func (a egressAdapter) Quarantine(id, reason string) { a.mgr.Quarantine(id, reason) }
func (a egressAdapter) Enable(id string)             { a.mgr.Enable(id) }
func (a egressAdapter) Disable(id, reason string)    { a.mgr.Disable(id, reason) }

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
		out[i] = web.EgressIdentity{ID: info.ID, IP: info.IP, State: string(info.State), Reason: info.Reason}
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
