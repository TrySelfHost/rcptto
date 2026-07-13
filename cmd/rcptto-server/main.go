// Command rcptto-server runs the rcpttō control-plane HTTP API.
//
// This early build serves synchronous single-address verification (POST
// /v1/verify) plus health and readiness endpoints, backed by the in-memory
// result cache and the builtin SMTP engine. Bulk jobs, durable persistence,
// and the reputation-managed egress fleet arrive in later milestones.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tryselfhost/rcptto/internal/api"
	"github.com/tryselfhost/rcptto/internal/pipeline"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/internal/verifier"
	"github.com/tryselfhost/rcptto/pkg/engine/builtin"
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

	svc := verifier.New(verifier.Config{
		Pipeline: pipeline.New(pipeline.Config{}),
		Engine: builtin.New(builtin.Config{
			HELO:           helo,
			MailFrom:       mailFrom,
			DetectCatchAll: detectCatchAll,
		}),
		Egress: verifier.DirectProvider{HELO: helo, MailFrom: mailFrom},
		Cache:  memory.NewResultStore(),
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(api.Config{Verifier: svc, APIKeys: apiKeys}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
