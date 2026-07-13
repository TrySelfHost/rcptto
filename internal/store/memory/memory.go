// Package memory provides in-memory implementations of the store ports. They
// are the zero-dependency default (useful for development, single-node
// deployments, and tests) and the reference against which other adapters are
// checked.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// ResultStore is a concurrency-safe, in-memory ResultStore with TTL expiry.
type ResultStore struct {
	mu    sync.RWMutex
	items map[string]entry
	now   func() time.Time
}

type entry struct {
	verdict   verdict.Verdict
	expiresAt time.Time // zero means no expiry
}

// NewResultStore returns an empty in-memory ResultStore.
func NewResultStore() *ResultStore {
	return &ResultStore{items: make(map[string]entry), now: time.Now}
}

// Get implements store.ResultStore.
func (s *ResultStore) Get(_ context.Context, key string) (verdict.Verdict, bool, error) {
	s.mu.RLock()
	e, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return verdict.Verdict{}, false, nil
	}
	if !e.expiresAt.IsZero() && s.now().After(e.expiresAt) {
		// Lazily evict the expired entry.
		s.mu.Lock()
		if cur, still := s.items[key]; still && cur.expiresAt.Equal(e.expiresAt) {
			delete(s.items, key)
		}
		s.mu.Unlock()
		return verdict.Verdict{}, false, nil
	}
	return e.verdict, true, nil
}

// Put implements store.ResultStore.
func (s *ResultStore) Put(_ context.Context, key string, v verdict.Verdict, ttl time.Duration) error {
	e := entry{verdict: v}
	if ttl > 0 {
		e.expiresAt = s.now().Add(ttl)
	}
	s.mu.Lock()
	s.items[key] = e
	s.mu.Unlock()
	return nil
}

// Len reports the number of stored entries (including not-yet-evicted expired
// ones). Intended for tests and diagnostics.
func (s *ResultStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}
