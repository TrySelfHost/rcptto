//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" driver for these tests

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// testDB opens the database from DATABASE_URL, migrates it, and truncates the
// tables for an isolated run. The suite is skipped when DATABASE_URL is unset.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, `TRUNCATE result_cache, job_results, jobs, egress_state RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestResultStoreRoundTrip(t *testing.T) {
	s := NewResultStore(testDB(t))
	ctx := context.Background()

	v := verdict.Verdict{Email: "a@b.com", Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox}
	if err := s.Put(ctx, "a@b.com", v, time.Hour); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := s.Get(ctx, "a@b.com")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Status != verdict.StatusDeliverable || got.SubStatus != verdict.SubValidMailbox {
		t.Errorf("got %+v", got)
	}

	if _, ok, _ := s.Get(ctx, "absent"); ok {
		t.Errorf("expected miss for absent key")
	}
}

func TestResultStoreExpiry(t *testing.T) {
	s := NewResultStore(testDB(t))
	base := time.Now()
	s.now = func() time.Time { return base }
	ctx := context.Background()

	if err := s.Put(ctx, "k", verdict.Verdict{Email: "a@b.com"}, time.Minute); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, ok, _ := s.Get(ctx, "k"); !ok {
		t.Fatalf("expected hit before expiry")
	}
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Errorf("expected miss after expiry")
	}
}

func TestJobStoreLifecycle(t *testing.T) {
	db := testDB(t)
	js := NewJobStore(db)
	ctx := context.Background()

	job := store.Job{ID: "job_1", Status: store.JobRunning, Total: 2, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := js.CreateJob(ctx, job); err != nil {
		t.Fatalf("create: %v", err)
	}

	_ = js.AppendResult(ctx, "job_1", store.Result{Label: "Acme Ltd", Verdict: verdict.Verdict{Email: "a@x.com", Status: verdict.StatusDeliverable}})
	got, _ := js.GetJob(ctx, "job_1")
	if got.Status != store.JobRunning || got.Done != 1 {
		t.Fatalf("after 1: status=%s done=%d", got.Status, got.Done)
	}

	_ = js.AppendResult(ctx, "job_1", store.Result{Label: "Acme Ltd", Verdict: verdict.Verdict{Email: "b@x.com", Status: verdict.StatusUndeliverable}})
	got, _ = js.GetJob(ctx, "job_1")
	if got.Status != store.JobCompleted || got.Done != 2 || got.CompletedAt == nil {
		t.Fatalf("after 2: status=%s done=%d completed=%v", got.Status, got.Done, got.CompletedAt)
	}

	page, next, _ := js.Results(ctx, "job_1", 0, 1)
	if len(page) != 1 || next != 1 {
		t.Fatalf("page1: len=%d next=%d", len(page), next)
	}
	// The client label must survive the round-trip, or an uploaded list cannot
	// be matched back to its source sheet.
	if page[0].Label != "Acme Ltd" {
		t.Errorf("label = %q, want Acme Ltd", page[0].Label)
	}
	page, next, _ = js.Results(ctx, "job_1", 1, 1)
	if len(page) != 1 || next != 0 {
		t.Fatalf("page2: len=%d next=%d", len(page), next)
	}
}

func TestJobStoreNotFound(t *testing.T) {
	js := NewJobStore(testDB(t))
	ctx := context.Background()

	if _, err := js.GetJob(ctx, "nope"); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("GetJob: %v", err)
	}
	if err := js.AppendResult(ctx, "nope", store.Result{Label: "Acme Ltd", Verdict: verdict.Verdict{}}); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("AppendResult: %v", err)
	}
	if _, _, err := js.Results(ctx, "nope", 0, 10); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("Results: %v", err)
	}
	if err := js.SetStatus(ctx, "nope", store.JobCanceled); !errors.Is(err, store.ErrJobNotFound) {
		t.Errorf("SetStatus: %v", err)
	}
}

func TestEgressStoreRoundTrip(t *testing.T) {
	es := NewEgressStore(testDB(t))
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	in := []store.EgressState{{
		ID:               "eg_1",
		State:            "quarantined",
		WarmupStage:      2,
		UsedToday:        37,
		LastReset:        now,
		BlockStreak:      5,
		QuarantinedUntil: now.Add(time.Hour),
		QuarantineReason: "dnsbl:zen.spamhaus.org",
		Health:           map[string]float64{"gmail": 0.25, "custom": 0.9},
	}}
	if err := es.SaveEgress(ctx, in); err != nil {
		t.Fatalf("save: %v", err)
	}

	out, err := es.LoadEgress(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("loaded %d states, want 1", len(out))
	}
	got := out[0]
	if got.ID != "eg_1" || got.State != "quarantined" || got.WarmupStage != 2 {
		t.Errorf("state mismatch: %+v", got)
	}
	if got.QuarantineReason != "dnsbl:zen.spamhaus.org" {
		t.Errorf("reason = %q", got.QuarantineReason)
	}
	if got.Health["gmail"] != 0.25 {
		t.Errorf("health not preserved: %+v", got.Health)
	}
	if !got.QuarantinedUntil.Equal(now.Add(time.Hour)) {
		t.Errorf("quarantinedUntil = %v, want %v", got.QuarantinedUntil, now.Add(time.Hour))
	}
}

func TestEgressStoreUpsert(t *testing.T) {
	es := NewEgressStore(testDB(t))
	ctx := context.Background()

	_ = es.SaveEgress(ctx, []store.EgressState{{ID: "eg_1", State: "active"}})
	_ = es.SaveEgress(ctx, []store.EgressState{{ID: "eg_1", State: "quarantined"}})

	out, err := es.LoadEgress(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("upsert produced %d rows, want 1", len(out))
	}
	if out[0].State != "quarantined" {
		t.Errorf("state = %q, want the updated value", out[0].State)
	}
}

func TestEgressStoreEmptySaveIsNoop(t *testing.T) {
	es := NewEgressStore(testDB(t))
	if err := es.SaveEgress(context.Background(), nil); err != nil {
		t.Errorf("empty save should be a no-op, got %v", err)
	}
}
