package worker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/engine/mock"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

const testToken = "shared-secret-token"

// newAgent starts a real HTTP agent backed by the deterministic mock engine and
// returns a client pointed at it, exercising the full wire round-trip.
func newAgent(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	srv, err := NewServer(ServerConfig{
		Identity: Identity{
			ID:       "eg_remote_1",
			IP:       "127.0.0.1",
			HELO:     "worker1.test",
			MailFrom: "probe@worker1.test",
			Region:   "eu",
			ASN:      "AS12345",
		},
		Engine: mock.New(),
		Token:  testToken,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return NewClient(ClientConfig{BaseURL: ts.URL, Token: testToken}), ts
}

func TestVerifyRoundTrip(t *testing.T) {
	c, _ := newAgent(t)

	v, signals, err := c.Verify(context.Background(), engine.Task{
		Email:      "valid@example.com",
		Normalized: "valid@example.com",
		Domain:     "example.com",
		Provider:   "custom",
		MX:         []string{"mx1.example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Status != verdict.StatusDeliverable {
		t.Errorf("status = %s, want deliverable", v.Status)
	}
	// The agent stamps its own identity; the control plane must not have to
	// trust a caller-supplied value.
	if v.EgressID != "eg_remote_1" {
		t.Errorf("egress id = %q, want eg_remote_1", v.EgressID)
	}
	if len(signals) != 1 || signals[0].Kind != engine.SignalAccepted {
		t.Errorf("signals = %+v, want one accepted signal", signals)
	}
}

func TestVerifyPropagatesFailureOutcomes(t *testing.T) {
	c, _ := newAgent(t)

	for _, tc := range []struct {
		email  string
		status verdict.Status
		signal engine.SignalKind
	}{
		{"invalid@example.com", verdict.StatusUndeliverable, engine.SignalMailboxGone},
		{"blocked@example.com", verdict.StatusUnknown, engine.SignalBlocked},
		{"tempfail@example.com", verdict.StatusUnknown, engine.SignalTempFail},
	} {
		v, sigs, err := c.Verify(context.Background(), engine.Task{Email: tc.email, Domain: "example.com"}, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.email, err)
		}
		if v.Status != tc.status {
			t.Errorf("%s: status = %s, want %s", tc.email, v.Status, tc.status)
		}
		if len(sigs) != 1 || sigs[0].Kind != tc.signal {
			t.Errorf("%s: signals = %+v, want %s", tc.email, sigs, tc.signal)
		}
	}
}

func TestHealthReportsIdentity(t *testing.T) {
	c, _ := newAgent(t)

	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.ID != "eg_remote_1" || h.IP != "127.0.0.1" || h.HELO != "worker1.test" {
		t.Errorf("health = %+v", h)
	}
	if h.Version != ProtocolVersion {
		t.Errorf("version = %d, want %d", h.Version, ProtocolVersion)
	}
}

func TestUnauthorizedRejected(t *testing.T) {
	_, ts := newAgent(t)
	bad := NewClient(ClientConfig{BaseURL: ts.URL, Token: "wrong-token"})

	if _, _, err := bad.Verify(context.Background(), engine.Task{Email: "a@b.com"}, nil); err == nil {
		t.Error("Verify with a wrong token should fail")
	}
	if _, err := bad.Health(context.Background()); err == nil {
		t.Error("Health with a wrong token should fail")
	}
}

func TestProtocolVersionMismatchRejected(t *testing.T) {
	_, ts := newAgent(t)

	// Hand-roll a request advertising a future protocol version.
	body := `{"version":999,"task":{"email":"a@b.com"}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+PathVerify,
		stringsReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a version mismatch", resp.StatusCode)
	}
}

func TestServerConfigValidation(t *testing.T) {
	cases := map[string]ServerConfig{
		"missing id":     {Engine: mock.New(), Token: "t"},
		"missing engine": {Identity: Identity{ID: "a"}, Token: "t"},
		"missing token":  {Identity: Identity{ID: "a"}, Engine: mock.New()},
	}
	for name, cfg := range cases {
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestUnreachableAgentSurfacesError(t *testing.T) {
	// Port 1 on loopback has nothing listening.
	c := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:1", Token: testToken})
	if _, _, err := c.Verify(context.Background(), engine.Task{Email: "a@b.com"}, nil); err == nil {
		t.Error("expected an error contacting an unreachable agent")
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

func TestLocalBindingMetadata(t *testing.T) {
	b := localBinding{identity: Identity{ID: "eg_1", HELO: "h.test", MailFrom: "p@h.test"}}
	if b.ID() != "eg_1" || b.HELO() != "h.test" || b.MailFrom() != "p@h.test" {
		t.Errorf("binding metadata = %s/%s/%s", b.ID(), b.HELO(), b.MailFrom())
	}
}

func TestLocalBindingDialsFromConfiguredIP(t *testing.T) {
	// Listen on loopback, then dial it through a binding pinned to 127.0.0.1
	// and confirm the connection's source address is the one we bound.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	b := localBinding{identity: Identity{ID: "eg_1", IP: "127.0.0.1"}}
	conn, err := b.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if host != "127.0.0.1" {
		t.Errorf("source address = %s, want 127.0.0.1 (the configured egress IP)", host)
	}
}

func TestLocalBindingRejectsInvalidIP(t *testing.T) {
	b := localBinding{identity: Identity{ID: "eg_1", IP: "not-an-ip"}}
	if _, err := b.DialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil {
		t.Error("expected an error for a malformed egress IP")
	}
}

func TestLocalBindingWithoutIPUsesDefault(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	b := localBinding{identity: Identity{ID: "eg_1"}} // no IP configured
	conn, err := b.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with no bound IP should still work: %v", err)
	}
	_ = conn.Close()
}
