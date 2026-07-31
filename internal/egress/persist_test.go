package egress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/pkg/engine"
)

func TestSnapshotCapturesReputation(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	m := New(Config{Now: clk.now, CircuitThreshold: 100, Identities: []Spec{specWithIP("a", "1.2.3.4")}})

	m.Emit(context.Background(), []engine.Signal{blocked("a", "gmail")})
	m.Quarantine("a", "test reason")

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	st := snap[0]
	if st.ID != "a" || st.State != string(StateQuarantined) {
		t.Errorf("state = %+v", st)
	}
	if st.QuarantineReason != "test reason" {
		t.Errorf("reason = %q", st.QuarantineReason)
	}
	if score, ok := st.Health["gmail"]; !ok || score >= 1.0 {
		t.Errorf("gmail health should be degraded and captured, got %v (present=%v)", score, ok)
	}
}

// TestQuarantineSurvivesRestart is the reason this subsystem exists: a burned
// identity must not silently return to service because the process restarted.
func TestQuarantineSurvivesRestart(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	st := memory.NewEgressStore()
	ctx := context.Background()

	// First process: identity gets quarantined and state is persisted.
	m1 := New(Config{Now: clk.now, Store: st, Identities: []Spec{specWithIP("a", "1.2.3.4")}})
	m1.Quarantine("a", "dnsbl:zen.spamhaus.org")
	if err := m1.Persist(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Second process: same config, restored from the store.
	m2 := New(Config{Now: clk.now, Store: st, Identities: []Spec{specWithIP("a", "1.2.3.4")}})
	loaded, err := st.LoadEgress(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m2.Restore(loaded)

	if _, err := m2.Binding(ctx, taskTo("x.com")); !errors.Is(err, ErrNoEgress) {
		t.Fatalf("quarantined identity must stay quarantined after restart, got %v", err)
	}
	infos := m2.Identities()
	if infos[0].State != StateQuarantined {
		t.Errorf("state = %s, want quarantined", infos[0].State)
	}
	if infos[0].Reason != "dnsbl:zen.spamhaus.org" {
		t.Errorf("reason = %q, want the original quarantine reason", infos[0].Reason)
	}
}

func TestWarmupProgressSurvivesRestart(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0).UTC()}
	st := memory.NewEgressStore()
	ctx := context.Background()

	m1 := New(Config{Now: clk.now, Store: st, WarmupStages: []int{1, 2, 3}, Identities: []Spec{spec("a", true)}})
	// Advance two days so warm-up progresses past stage 0.
	clk.advance(49 * time.Hour)
	_, _ = m1.Binding(ctx, taskTo("x.com"))
	stage := m1.Snapshot()[0].WarmupStage
	if stage == 0 {
		t.Fatalf("precondition: warm-up should have advanced, stage = %d", stage)
	}
	if err := m1.Persist(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}

	m2 := New(Config{Now: clk.now, Store: st, WarmupStages: []int{1, 2, 3}, Identities: []Spec{spec("a", true)}})
	loaded, _ := st.LoadEgress(ctx)
	m2.Restore(loaded)

	if got := m2.Snapshot()[0].WarmupStage; got != stage {
		t.Errorf("warm-up stage = %d after restart, want %d (progress must not reset)", got, stage)
	}
}

func TestRestoreIgnoresUnknownIdentities(t *testing.T) {
	m := New(Config{Identities: []Spec{spec("a", false)}})
	// State for an identity that is no longer configured must be ignored, not
	// resurrect a removed identity.
	m.Restore([]store.EgressState{
		{ID: "removed", State: string(StateQuarantined)},
		{ID: "a", State: string(StateQuarantined), QuarantineReason: "kept"},
	})

	infos := m.Identities()
	if len(infos) != 1 || infos[0].ID != "a" {
		t.Fatalf("identities = %+v, want only the configured one", infos)
	}
	if infos[0].State != StateQuarantined || infos[0].Reason != "kept" {
		t.Errorf("configured identity state not restored: %+v", infos[0])
	}
}

func TestPersistWithoutStoreIsNoop(t *testing.T) {
	m := New(Config{Identities: []Spec{spec("a", false)}})
	if err := m.Persist(context.Background()); err != nil {
		t.Errorf("Persist without a store should be a no-op, got %v", err)
	}
}

func TestPersistLoopFlushesOnShutdown(t *testing.T) {
	st := memory.NewEgressStore()
	m := New(Config{Store: st, Identities: []Spec{spec("a", false)}})
	m.Quarantine("a", "before shutdown")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.PersistLoop(ctx, time.Hour, nil) // long interval: only the shutdown flush should fire
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PersistLoop did not return after cancellation")
	}

	loaded, err := st.LoadEgress(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].QuarantineReason != "before shutdown" {
		t.Errorf("shutdown flush did not persist state: %+v", loaded)
	}
}
