package worker

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/tryselfhost/rcptto/pkg/engine"
)

// Identity describes the single egress identity an agent owns — the IP it
// dials from and the name it presents. One agent serves exactly one identity;
// running two IPs on one machine means running two agents.
type Identity struct {
	// ID must match the identity id configured for this agent on the control
	// plane, so reputation is attributed to the right egress.
	ID string
	// IP is the local source address to bind outbound connections to. Required
	// when the host has several addresses, so probes provably leave via this one.
	IP string
	// HELO is the hostname presented to destination mail servers. Its forward
	// and reverse DNS must both resolve to IP.
	HELO string
	// MailFrom is the envelope sender used in probes.
	MailFrom string
	// Region and ASN are informational, reported to the control plane.
	Region string
	ASN    string
}

// ServerConfig configures a worker agent's HTTP server.
type ServerConfig struct {
	// Identity is the egress this agent provides. Required.
	Identity Identity
	// Engine performs the SMTP probe. Required.
	Engine engine.Engine
	// Token authenticates the control plane. Required; agents accept probe
	// requests from the internet, so an unauthenticated agent would let anyone
	// use your IP to probe mail servers.
	Token string
	// Log receives one record per probe. Optional; defaults to discarding.
	// Agents are unattended remote boxes, so a request log is often the only
	// way to see what an IP was actually asked to do.
	Log *slog.Logger
}

// Server is the agent-side HTTP handler.
type Server struct {
	identity Identity
	engine   engine.Engine
	token    string
	log      *slog.Logger
}

// NewServer validates the config and builds an agent server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Identity.ID == "" {
		return nil, errors.New("worker: identity ID is required")
	}
	if cfg.Engine == nil {
		return nil, errors.New("worker: engine is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("worker: token is required; an unauthenticated agent lets anyone probe from your IP")
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{identity: cfg.Identity, engine: cfg.Engine, token: cfg.Token, log: log}, nil
}

// Handler returns the agent's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathVerify, s.handleVerify)
	mux.HandleFunc("GET "+PathHealth, s.handleHealth)
	return s.authMiddleware(mux)
}

// authMiddleware enforces the shared bearer token in constant time.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Version: ProtocolVersion,
		ID:      s.identity.ID,
		IP:      s.identity.IP,
		HELO:    s.identity.HELO,
		Region:  s.identity.Region,
		ASN:     s.identity.ASN,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Version != ProtocolVersion {
		http.Error(w,
			fmt.Sprintf("unsupported protocol version %d; this agent speaks %d", req.Version, ProtocolVersion),
			http.StatusBadRequest)
		return
	}
	if req.Task.Email == "" {
		http.Error(w, "task.email is required", http.StatusBadRequest)
		return
	}

	v, signals, err := s.engine.Verify(r.Context(), req.Task.ToTask(), s.binding())
	if err != nil {
		http.Error(w, "probe failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	// The agent owns the identity, so it stamps the verdict itself rather than
	// trusting whatever the caller claimed.
	v.EgressID = s.identity.ID

	s.log.Info("probe executed",
		"email", req.Task.Email,
		"domain", req.Task.Domain,
		"status", string(v.Status),
		"sub_status", string(v.SubStatus),
		"egress_id", s.identity.ID)

	writeJSON(w, http.StatusOK, VerifyResponse{
		Version: ProtocolVersion,
		Verdict: v,
		Signals: SignalsToWire(signals),
	})
}

// binding returns the agent's local egress binding.
func (s *Server) binding() engine.EgressBinding {
	return localBinding{identity: s.identity}
}

// localBinding dials from the agent's configured source IP.
type localBinding struct {
	identity Identity
}

func (b localBinding) ID() string       { return b.identity.ID }
func (b localBinding) HELO() string     { return b.identity.HELO }
func (b localBinding) MailFrom() string { return b.identity.MailFrom }

// DialContext binds the connection's source address to the agent's IP, so a
// host with several addresses provably egresses via the intended one.
func (b localBinding) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{}
	if b.identity.IP != "" {
		ip := net.ParseIP(b.identity.IP)
		if ip == nil {
			return nil, fmt.Errorf("worker: invalid egress IP %q", b.identity.IP)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return d.DialContext(ctx, network, addr)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
