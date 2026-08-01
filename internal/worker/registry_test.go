package worker

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine/mock"
)

// startAgent runs a real agent server with the given identity id.
func startAgent(t *testing.T, id string) *httptest.Server {
	t.Helper()
	srv, err := NewServer(ServerConfig{
		Identity: Identity{ID: id, IP: "203.0.113.7", HELO: id + ".test"},
		Engine:   mock.New(),
		Token:    testToken,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestRegistryDiscoversAgentOnHealthCheck(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, err := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 5*time.Second)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Agents start offline so the control plane never routes to one it has not
	// actually reached.
	if r.Agents()[0].Online {
		t.Error("agent should start offline before its first successful check")
	}

	var changed []AgentInfo
	r.CheckAll(context.Background(), func(i AgentInfo) { changed = append(changed, i) })

	got := r.Agents()[0]
	if !got.Online {
		t.Fatalf("agent should be online after a successful check: %+v", got)
	}
	if got.IP != "203.0.113.7" || got.HELO != "eg_1.test" {
		t.Errorf("agent metadata not discovered: %+v", got)
	}
	if len(changed) != 1 || changed[0].ID != "eg_1" {
		t.Errorf("onChange = %+v, want one change for eg_1", changed)
	}
}

func TestRegistryMarksUnreachableAgentOffline(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 2*time.Second)

	r.CheckAll(context.Background(), nil)
	if !r.Agents()[0].Online {
		t.Fatal("precondition: agent should be online")
	}

	ts.Close() // simulate the remote VPS going away

	var changed []AgentInfo
	r.CheckAll(context.Background(), func(i AgentInfo) { changed = append(changed, i) })

	got := r.Agents()[0]
	if got.Online {
		t.Error("agent should be offline once unreachable")
	}
	if got.LastErr == "" {
		t.Error("expected the failure reason to be recorded")
	}
	if len(changed) != 1 {
		t.Errorf("expected one change notification, got %d", len(changed))
	}
}

func TestRegistryRejectsMismatchedIdentity(t *testing.T) {
	// The agent reports "eg_other" but is configured here as "eg_1". Routing to
	// it would credit reputation to the wrong IP, so it must be unusable.
	ts := startAgent(t, "eg_other")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 2*time.Second)

	r.CheckAll(context.Background(), nil)

	got := r.Agents()[0]
	if got.Online {
		t.Error("an agent reporting a different identity must not be marked online")
	}
	if !strings.Contains(got.LastErr, "eg_other") {
		t.Errorf("error should name the mismatch, got %q", got.LastErr)
	}
}

func TestRegistryBadTokenKeepsAgentOffline(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: "wrong"}}, 2*time.Second)

	r.CheckAll(context.Background(), nil)
	if r.Agents()[0].Online {
		t.Error("agent should stay offline when the token is wrong")
	}
}

func TestRegistryNoChangeNotificationWhenStable(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 2*time.Second)

	r.CheckAll(context.Background(), nil) // offline -> online (a change)

	var changed int
	r.CheckAll(context.Background(), func(AgentInfo) { changed++ })
	if changed != 0 {
		t.Errorf("a stable agent should not report a change, got %d", changed)
	}
}

func TestRegistryClientForAndIsRemote(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 2*time.Second)

	if r.ClientFor("eg_1") == nil {
		t.Error("ClientFor should return a client for a configured agent")
	}
	if r.ClientFor("unknown") != nil {
		t.Error("ClientFor should return nil for an unknown id")
	}
	if !r.IsRemote("eg_1") || r.IsRemote("local") {
		t.Error("IsRemote misreported")
	}
}

func TestRegistryRejectsBadConfig(t *testing.T) {
	if _, err := NewRegistry([]AgentConfig{{ID: "", BaseURL: "http://x"}}, 0); err == nil {
		t.Error("expected an error for a missing id")
	}
	if _, err := NewRegistry([]AgentConfig{{ID: "a", BaseURL: ""}}, 0); err == nil {
		t.Error("expected an error for a missing URL")
	}
	dup := []AgentConfig{{ID: "a", BaseURL: "http://x"}, {ID: "a", BaseURL: "http://y"}}
	if _, err := NewRegistry(dup, 0); err == nil {
		t.Error("expected an error for duplicate ids")
	}
}

func TestParseAgents(t *testing.T) {
	got, err := ParseAgents("eg_1=https://a.test:9090, eg_2=http://b.test:9090", "tok")
	if err != nil {
		t.Fatalf("ParseAgents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d agents, want 2", len(got))
	}
	if got[0].ID != "eg_1" || got[0].BaseURL != "https://a.test:9090" || got[0].Token != "tok" {
		t.Errorf("agent[0] = %+v", got[0])
	}

	if out, err := ParseAgents("", "tok"); err != nil || out != nil {
		t.Errorf("empty spec should yield no agents, got %+v / %v", out, err)
	}
	for _, bad := range []string{"noequals", "=https://x", "eg_1=", "eg_1=ftp://x"} {
		if _, err := ParseAgents(bad, "tok"); err == nil {
			t.Errorf("ParseAgents(%q) should fail", bad)
		}
	}
}

func TestHealthLoopChecksImmediatelyAndStops(t *testing.T) {
	ts := startAgent(t, "eg_1")
	r, _ := NewRegistry([]AgentConfig{{ID: "eg_1", BaseURL: ts.URL, Token: testToken}}, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.HealthLoop(ctx, time.Hour, nil) // long tick: only the immediate check runs
		close(done)
	}()

	// The immediate check should bring the agent online well before any tick.
	deadline := time.After(3 * time.Second)
	for !r.Agents()[0].Online {
		select {
		case <-deadline:
			t.Fatal("HealthLoop did not perform an immediate check")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HealthLoop did not stop on cancellation")
	}
}
