package egress

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/egress/audit"
	"github.com/tryselfhost/rcptto/pkg/engine"
)

// auditResolver is a programmable audit.Resolver for DNSBL integration tests.
type auditResolver struct {
	hosts map[string][]string
}

func (r auditResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := r.hosts[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r auditResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

// nopTransport satisfies Transport without dialing (selection tests never dial).
type nopTransport struct{}

func (nopTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("nop")
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func spec(id string, warm bool) Spec {
	return Spec{ID: id, Kind: KindLocalIP, HELO: id + ".test", MailFrom: "p@" + id + ".test", Transport: nopTransport{}, WarmUp: warm}
}

func taskTo(dest string) engine.Task {
	// dest is treated as a custom domain (destOf falls back to Domain when
	// provider is empty/custom).
	return engine.Task{Domain: dest, Provider: "custom"}
}

func blocked(id, dest string) engine.Signal {
	return engine.Signal{Kind: engine.SignalBlocked, EgressID: id, Destination: dest}
}
func accepted(id, dest string) engine.Signal {
	return engine.Signal{Kind: engine.SignalAccepted, EgressID: id, Destination: dest}
}

func TestBindingReturnsMetadata(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, Identities: []Spec{spec("a", false)}})

	b, err := m.Binding(context.Background(), taskTo("example.com"))
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if b.ID() != "a" || b.HELO() != "a.test" || b.MailFrom() != "p@a.test" {
		t.Errorf("metadata: id=%s helo=%s from=%s", b.ID(), b.HELO(), b.MailFrom())
	}
}

func TestNoIdentities(t *testing.T) {
	m := New(Config{Identities: nil})
	if _, err := m.Binding(context.Background(), taskTo("example.com")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("err = %v, want ErrNoEgress", err)
	}
}

func TestRoutingPrefersHealthiestPerDestination(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	// High circuit threshold so health (not circuit exclusion) drives the choice.
	m := New(Config{Now: clk.now, CircuitThreshold: 100, Identities: []Spec{spec("a", false), spec("b", false)}})

	// Degrade "a" for gmail only.
	for i := 0; i < 3; i++ {
		m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail")})
	}

	b, _ := m.Binding(context.Background(), taskTo("gmail"))
	if b.ID() != "b" {
		t.Errorf("gmail should route to healthy b, got %s", b.ID())
	}

	// For a different destination, "a" has no history (score 1.0) and ties with
	// "b"; the tie-break by insertion order picks "a".
	b, _ = m.Binding(context.Background(), taskTo("other.com"))
	if b.ID() != "a" {
		t.Errorf("other.com should route to a (per-destination health), got %s", b.ID())
	}
}

func TestCircuitBreakerIsPerDestination(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, CircuitThreshold: 2, QuarantineThreshold: 100, Identities: []Spec{spec("a", false)}})

	// Two blocks open the circuit for gmail.
	m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail"), blocked("a", "gmail")})

	if _, err := m.Binding(context.Background(), taskTo("gmail")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("gmail circuit should be open, got err=%v", err)
	}
	// A different destination is unaffected.
	if _, err := m.Binding(context.Background(), taskTo("other.com")); err != nil {
		t.Errorf("other.com should be available, got %v", err)
	}
}

func TestCircuitHalfOpenRecovers(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, CircuitThreshold: 2, CircuitCooldown: 10 * time.Minute, QuarantineThreshold: 100, Identities: []Spec{spec("a", false)}})
	m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail"), blocked("a", "gmail")})

	clk.advance(11 * time.Minute) // past cooldown -> half-open trial allowed
	if _, err := m.Binding(context.Background(), taskTo("gmail")); err != nil {
		t.Fatalf("half-open trial should be allowed, got %v", err)
	}
	// A success on the trial closes the circuit.
	m.Emit(context.Background(), []engine.Signal{accepted("a", "gmail")})
	if _, err := m.Binding(context.Background(), taskTo("gmail")); err != nil {
		t.Errorf("circuit should be closed after success, got %v", err)
	}
}

func TestQuarantineAndRecovery(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, QuarantineThreshold: 3, QuarantineCooldown: time.Hour, Identities: []Spec{spec("a", false)}})

	for i := 0; i < 3; i++ {
		m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail")})
	}
	if m.records["a"].state != StateQuarantined {
		t.Fatalf("state = %s, want quarantined", m.records["a"].state)
	}
	if _, err := m.Binding(context.Background(), taskTo("other.com")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("quarantined identity should serve nothing, got %v", err)
	}

	clk.advance(61 * time.Minute) // past quarantine cooldown
	// Binding reconciles: identity re-enters warming and becomes available.
	if _, err := m.Binding(context.Background(), taskTo("other.com")); err != nil {
		t.Fatalf("recovered identity should be available, got %v", err)
	}
	if m.records["a"].state != StateWarming {
		t.Errorf("recovered identity should re-warm, state = %s", m.records["a"].state)
	}
}

func TestAcceptedResetsBlockStreak(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, QuarantineThreshold: 3, CircuitThreshold: 100, Identities: []Spec{spec("a", false)}})

	m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail"), blocked("a", "gmail")})
	m.Emit(context.Background(), []engine.Signal{accepted("a", "gmail")}) // resets streak
	m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail"), blocked("a", "gmail")})

	if m.records["a"].state == StateQuarantined {
		t.Errorf("streak should have reset; identity must not be quarantined")
	}
}

func TestWarmupRampAndActivation(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, WarmupStages: []int{1, 2}, Identities: []Spec{spec("a", true)}})

	if m.records["a"].state != StateWarming {
		t.Fatalf("fresh identity should start warming")
	}
	// Stage 0 cap is 1: first probe ok, second exceeds cap.
	if _, err := m.Binding(context.Background(), taskTo("x.com")); err != nil {
		t.Fatalf("first probe: %v", err)
	}
	if _, err := m.Binding(context.Background(), taskTo("x.com")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("stage-0 cap of 1 should be exhausted, got %v", err)
	}

	clk.advance(25 * time.Hour) // daily reset -> stage 1 (cap 2)
	if _, err := m.Binding(context.Background(), taskTo("x.com")); err != nil {
		t.Fatalf("after ramp: %v", err)
	}

	clk.advance(25 * time.Hour) // stage advances past stages -> active
	_, _ = m.Binding(context.Background(), taskTo("x.com"))
	if m.records["a"].state != StateActive {
		t.Errorf("identity should be active after warm-up, state = %s", m.records["a"].state)
	}
}

func TestActiveDailyCapResets(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, ActiveDailyCap: 2, Identities: []Spec{spec("a", false)}})

	for i := 0; i < 2; i++ {
		if _, err := m.Binding(context.Background(), taskTo("x.com")); err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	if _, err := m.Binding(context.Background(), taskTo("x.com")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("daily cap should be exhausted, got %v", err)
	}

	clk.advance(25 * time.Hour)
	if _, err := m.Binding(context.Background(), taskTo("x.com")); err != nil {
		t.Errorf("cap should reset next day, got %v", err)
	}
}

func TestEmitUnknownEgressIgnored(t *testing.T) {
	m := New(Config{Identities: []Spec{spec("a", false)}})
	// Must not panic.
	m.Emit(context.Background(), []engine.Signal{blocked("ghost", "gmail")})
}

func specWithIP(id, ip string) Spec {
	s := spec(id, false)
	s.IP = ip
	return s
}

func TestIdentitiesSnapshot(t *testing.T) {
	m := New(Config{Identities: []Spec{specWithIP("a", "1.2.3.4"), specWithIP("b", "5.6.7.8")}})
	infos := m.Identities()
	if len(infos) != 2 {
		t.Fatalf("got %d identities, want 2", len(infos))
	}
	if infos[0].ID != "a" || infos[0].IP != "1.2.3.4" || infos[0].State != StateActive {
		t.Errorf("info[0] = %+v", infos[0])
	}
}

func TestQuarantineWithReason(t *testing.T) {
	m := New(Config{Identities: []Spec{specWithIP("a", "1.2.3.4")}})
	m.Quarantine("a", "manual")
	if _, err := m.Binding(context.Background(), taskTo("x.com")); !errors.Is(err, ErrNoEgress) {
		t.Errorf("quarantined identity should serve nothing, got %v", err)
	}
	infos := m.Identities()
	if infos[0].State != StateQuarantined || infos[0].Reason != "manual" {
		t.Errorf("info = %+v, want quarantined/manual", infos[0])
	}
}

func TestAuditDNSBLQuarantinesListed(t *testing.T) {
	m := New(Config{Identities: []Spec{specWithIP("clean", "1.1.1.1"), specWithIP("dirty", "9.9.9.9")}})

	// DNSBL lists only 9.9.9.9 (reversed 9.9.9.9.zen -> listing code).
	r := auditResolver{hosts: map[string][]string{
		"9.9.9.9.zen.spamhaus.org": {"127.0.0.2"},
	}}
	dnsbl := audit.NewDNSBL(r, []string{"zen.spamhaus.org"})

	m.AuditDNSBL(context.Background(), dnsbl)

	infos := map[string]IdentityInfo{}
	for _, i := range m.Identities() {
		infos[i.ID] = i
	}
	if infos["dirty"].State != StateQuarantined {
		t.Errorf("listed identity should be quarantined, got %s", infos["dirty"].State)
	}
	if infos["clean"].State != StateActive {
		t.Errorf("clean identity should stay active, got %s", infos["clean"].State)
	}
}
