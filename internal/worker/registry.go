package worker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// AgentConfig describes one remote agent the control plane should use.
type AgentConfig struct {
	// ID is the egress identity the agent serves. It must match the agent's
	// own RCPTTO_WORKER_ID, or reputation would be attributed to the wrong IP.
	ID string
	// BaseURL is the agent's address, e.g. "https://worker1.example.com:9090".
	BaseURL string
	// Token is the shared secret configured on that agent.
	Token string
}

// AgentInfo is a read-only view of an agent's current state.
type AgentInfo struct {
	ID       string
	BaseURL  string
	Online   bool
	IP       string
	HELO     string
	Region   string
	ASN      string
	LastErr  string
	LastSeen time.Time
}

// Registry holds the configured agents, tracks their reachability, and hands
// out the client used to dispatch probes to each one.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*agentState
	order  []string
	now    func() time.Time
}

type agentState struct {
	cfg      AgentConfig
	client   *Client
	online   bool
	ip       string
	helo     string
	region   string
	asn      string
	lastErr  string
	lastSeen time.Time
}

// NewRegistry builds a registry from the configured agents. Agents start
// offline and become available once a health check succeeds, so the control
// plane never routes a probe to an agent it has not reached.
func NewRegistry(cfgs []AgentConfig, timeout time.Duration) (*Registry, error) {
	r := &Registry{agents: make(map[string]*agentState), now: time.Now}
	for _, cfg := range cfgs {
		if cfg.ID == "" || cfg.BaseURL == "" {
			return nil, fmt.Errorf("worker: agent needs both an id and a URL (got id=%q url=%q)", cfg.ID, cfg.BaseURL)
		}
		if _, dup := r.agents[cfg.ID]; dup {
			return nil, fmt.Errorf("worker: duplicate agent id %q", cfg.ID)
		}
		r.agents[cfg.ID] = &agentState{
			cfg:    cfg,
			client: NewClient(ClientConfig{BaseURL: cfg.BaseURL, Token: cfg.Token, Timeout: timeout}),
		}
		r.order = append(r.order, cfg.ID)
	}
	return r, nil
}

// Len reports how many agents are configured.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

// ClientFor returns the client for an agent, or nil if the id is unknown.
func (r *Registry) ClientFor(id string) *Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a := r.agents[id]; a != nil {
		return a.client
	}
	return nil
}

// IsRemote reports whether an identity is served by a remote agent rather than
// the control plane's own egress.
func (r *Registry) IsRemote(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.agents[id]
	return ok
}

// Agents returns a snapshot of every agent, sorted by id.
func (r *Registry) Agents() []AgentInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]AgentInfo, 0, len(r.agents))
	for _, id := range r.order {
		a := r.agents[id]
		out = append(out, AgentInfo{
			ID: a.cfg.ID, BaseURL: a.cfg.BaseURL, Online: a.online,
			IP: a.ip, HELO: a.helo, Region: a.region, ASN: a.asn,
			LastErr: a.lastErr, LastSeen: a.lastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CheckAll health-checks every agent, updating reachability. onChange is called
// for each agent whose online state flipped, so the caller can update routing.
// Checks run concurrently: one unreachable agent must not delay the others.
func (r *Registry) CheckAll(ctx context.Context, onChange func(info AgentInfo)) {
	r.mu.RLock()
	ids := append([]string(nil), r.order...)
	r.mu.RUnlock()

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if info, changed := r.check(ctx, id); changed && onChange != nil {
				onChange(info)
			}
		}(id)
	}
	wg.Wait()
}

// check polls one agent and reports its info plus whether its online state
// changed.
func (r *Registry) check(ctx context.Context, id string) (AgentInfo, bool) {
	r.mu.RLock()
	a := r.agents[id]
	r.mu.RUnlock()
	if a == nil {
		return AgentInfo{}, false
	}

	health, err := a.client.Health(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	was := a.online

	switch {
	case err != nil:
		a.online = false
		a.lastErr = err.Error()
	case health.ID != a.cfg.ID:
		// A mismatched id means this agent serves a different egress than the
		// control plane believes. Routing to it would attribute reputation to
		// the wrong IP, so treat it as unusable rather than guess.
		a.online = false
		a.lastErr = fmt.Sprintf("agent reports id %q but is configured as %q", health.ID, a.cfg.ID)
	default:
		a.online = true
		a.lastErr = ""
		a.ip, a.helo, a.region, a.asn = health.IP, health.HELO, health.Region, health.ASN
		a.lastSeen = r.now()
	}

	return AgentInfo{
		ID: a.cfg.ID, BaseURL: a.cfg.BaseURL, Online: a.online,
		IP: a.ip, HELO: a.helo, Region: a.region, ASN: a.asn,
		LastErr: a.lastErr, LastSeen: a.lastSeen,
	}, was != a.online
}

// HealthLoop polls agents until ctx is canceled, invoking onChange whenever an
// agent's reachability flips. It performs one check immediately so the control
// plane learns the fleet's state at startup rather than after the first tick.
func (r *Registry) HealthLoop(ctx context.Context, interval time.Duration, onChange func(info AgentInfo)) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	r.CheckAll(ctx, onChange)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.CheckAll(ctx, onChange)
		}
	}
}

// ParseAgents reads the compact agent list used for configuration:
//
//	id=https://host:port,id2=https://host2:port
//
// Every agent shares the same token, supplied separately.
func ParseAgents(spec, token string) ([]AgentConfig, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []AgentConfig
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, url, ok := strings.Cut(part, "=")
		id, url = strings.TrimSpace(id), strings.TrimSpace(url)
		if !ok || id == "" || url == "" {
			return nil, fmt.Errorf("worker: agent %q must be of the form id=https://host:port", part)
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("worker: agent %q URL must start with http:// or https://", id)
		}
		out = append(out, AgentConfig{ID: id, BaseURL: url, Token: token})
	}
	return out, nil
}
