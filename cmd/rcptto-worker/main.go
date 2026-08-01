// Command rcptto-worker runs a remote probe agent.
//
// An agent is deliberately small: it owns exactly one egress IP, performs SMTP
// probes on request from the control plane, and reports the result. It holds no
// jobs, no reputation state, no database, and no dashboard — all of that stays
// on the control plane. Run one agent per egress IP; a machine with two IPs
// runs two agents on different ports.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tryselfhost/rcptto/internal/worker"
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

	addr := getenv("RCPTTO_WORKER_ADDR", ":9090")
	id := os.Getenv("RCPTTO_WORKER_ID")
	token := os.Getenv("RCPTTO_WORKER_TOKEN")
	egressIP := os.Getenv("RCPTTO_WORKER_IP")
	helo := getenv("RCPTTO_HELO", "localhost")
	mailFrom := getenv("RCPTTO_MAIL_FROM", "verify@localhost")

	if id == "" {
		return errors.New("RCPTTO_WORKER_ID is required; it must match the egress identity id configured on the control plane")
	}
	if token == "" {
		return errors.New("RCPTTO_WORKER_TOKEN is required; an unauthenticated agent would let anyone probe mail servers from your IP")
	}
	if egressIP == "" {
		// Not fatal on a single-homed host, but on a multi-IP box the OS would
		// pick the source address and probes could leave via the wrong identity.
		log.Warn("RCPTTO_WORKER_IP is not set; the OS will choose the source address, " +
			"which is wrong on a host with several public IPs")
	}

	srv, err := worker.NewServer(worker.ServerConfig{
		Identity: worker.Identity{
			ID:       id,
			IP:       egressIP,
			HELO:     helo,
			MailFrom: mailFrom,
			Region:   os.Getenv("RCPTTO_WORKER_REGION"),
			ASN:      os.Getenv("RCPTTO_WORKER_ASN"),
		},
		Engine: builtin.New(builtin.Config{
			HELO:           helo,
			MailFrom:       mailFrom,
			DetectCatchAll: getenvBool("RCPTTO_DETECT_CATCHALL", true),
		}),
		Token: token,
		Log:   log,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		log.Info("rcptto-worker listening", "addr", addr, "id", id, "egress_ip", egressIP, "helo", helo)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
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
