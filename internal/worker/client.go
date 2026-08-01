package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// defaultClientTimeout bounds a remote probe. SMTP probes can legitimately take
// tens of seconds (connect + greeting + several commands, possibly retrying MX
// hosts), so this is generous compared to a typical HTTP call.
const defaultClientTimeout = 60 * time.Second

// ClientConfig configures a Client.
type ClientConfig struct {
	// BaseURL is the agent's address, e.g. "https://worker1.example.com:9090".
	BaseURL string
	// Token is the shared secret configured on the agent.
	Token string
	// Timeout bounds each request; defaults to 60s.
	Timeout time.Duration
	// HTTPClient overrides the underlying client, for tests or custom TLS.
	HTTPClient *http.Client
}

// Client talks to one remote worker agent.
//
// It implements engine.Engine, so the verifier can treat a probe executed on a
// remote machine exactly like a local one. The EgressBinding passed to Verify is
// ignored: the agent owns its identity and dials from its own IP, which is the
// entire point of running it remotely.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// compile-time guarantee that Client satisfies the engine contract.
var _ engine.Engine = (*Client)(nil)

// NewClient builds a client for a remote agent.
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		token:   cfg.Token,
		http:    httpClient,
	}
}

// Name implements engine.Engine.
func (c *Client) Name() string { return "remote" }

// Capabilities implements engine.Engine. A remote agent runs the builtin engine
// on a machine with port 25 egress, so it has the same capabilities.
func (c *Client) Capabilities() engine.Caps {
	return engine.Caps{SupportsCatchAll: true, SupportsProxy: true, NeedsPort25: true}
}

// Verify sends the probe to the remote agent and returns its result.
func (c *Client) Verify(ctx context.Context, t engine.Task, _ engine.EgressBinding) (verdict.Verdict, []engine.Signal, error) {
	body, err := json.Marshal(VerifyRequest{
		Version:        ProtocolVersion,
		Task:           TaskToWire(t),
		DetectCatchAll: true,
	})
	if err != nil {
		return verdict.Verdict{}, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathVerify, bytes.NewReader(body))
	if err != nil {
		return verdict.Verdict{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return verdict.Verdict{}, nil, fmt.Errorf("worker: contacting agent: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return verdict.Verdict{}, nil, fmt.Errorf("worker: agent returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var out VerifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return verdict.Verdict{}, nil, fmt.Errorf("worker: decoding agent response: %w", err)
	}
	return out.Verdict, ToSignals(out.Signals), nil
}

// Health queries the agent, confirming it is reachable and reporting the
// identity it serves. The control plane uses this to register agents at startup
// and to detect one going offline.
func (c *Client) Health(ctx context.Context) (HealthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+PathHealth, nil)
	if err != nil {
		return HealthResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return HealthResponse{}, fmt.Errorf("worker: contacting agent: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return HealthResponse{}, fmt.Errorf("worker: agent health returned %d", resp.StatusCode)
	}
	var out HealthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return HealthResponse{}, fmt.Errorf("worker: decoding agent health: %w", err)
	}
	return out, nil
}
