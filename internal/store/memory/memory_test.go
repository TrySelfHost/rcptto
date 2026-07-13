package memory

import (
	"context"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

func TestResultStorePutGet(t *testing.T) {
	s := NewResultStore()
	ctx := context.Background()
	v := verdict.Verdict{Email: "a@b.com", Status: verdict.StatusDeliverable}

	if err := s.Put(ctx, "a@b.com", v, time.Hour); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := s.Get(ctx, "a@b.com")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Status != verdict.StatusDeliverable {
		t.Errorf("status = %s", got.Status)
	}
}

func TestResultStoreMiss(t *testing.T) {
	s := NewResultStore()
	_, ok, err := s.Get(context.Background(), "absent")
	if err != nil || ok {
		t.Fatalf("expected miss, got ok=%v err=%v", ok, err)
	}
}

func TestResultStoreExpiry(t *testing.T) {
	s := NewResultStore()
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	ctx := context.Background()

	_ = s.Put(ctx, "k", verdict.Verdict{Email: "a@b.com", Status: verdict.StatusUnknown}, time.Minute)

	if _, ok, _ := s.Get(ctx, "k"); !ok {
		t.Fatalf("expected hit before expiry")
	}
	now = now.Add(2 * time.Minute) // advance past TTL
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatalf("expected miss after expiry")
	}
	if s.Len() != 0 {
		t.Errorf("expired entry not evicted, len=%d", s.Len())
	}
}

func TestResultStoreNoExpiry(t *testing.T) {
	s := NewResultStore()
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	ctx := context.Background()

	_ = s.Put(ctx, "k", verdict.Verdict{Email: "a@b.com"}, 0) // no TTL
	now = now.Add(1000 * time.Hour)
	if _, ok, _ := s.Get(ctx, "k"); !ok {
		t.Fatalf("entry with no TTL should never expire")
	}
}
