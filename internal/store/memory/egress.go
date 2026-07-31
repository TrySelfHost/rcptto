package memory

import (
	"context"
	"sync"

	"github.com/tryselfhost/rcptto/internal/store"
)

// EgressStore is a concurrency-safe, in-memory store.EgressStore. It provides
// no durability across process restarts and exists for tests and for
// deployments that have not configured Postgres.
type EgressStore struct {
	mu     sync.Mutex
	states map[string]store.EgressState
}

// NewEgressStore returns an empty in-memory EgressStore.
func NewEgressStore() *EgressStore {
	return &EgressStore{states: make(map[string]store.EgressState)}
}

// LoadEgress implements store.EgressStore.
func (s *EgressStore) LoadEgress(_ context.Context) ([]store.EgressState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.EgressState, 0, len(s.states))
	for _, st := range s.states {
		out = append(out, st)
	}
	return out, nil
}

// SaveEgress implements store.EgressStore.
func (s *EgressStore) SaveEgress(_ context.Context, states []store.EgressState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range states {
		s.states[st.ID] = st
	}
	return nil
}
