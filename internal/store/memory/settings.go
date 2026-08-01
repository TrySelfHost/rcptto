package memory

import (
	"context"
	"sync"

	"github.com/tryselfhost/rcptto/internal/settings"
)

// SettingsStore is an in-memory store.SettingsStore. It provides no durability
// across restarts and exists for tests and deployments without Postgres.
type SettingsStore struct {
	mu    sync.RWMutex
	s     settings.Settings
	saved bool
}

// NewSettingsStore returns an empty in-memory SettingsStore.
func NewSettingsStore() *SettingsStore { return &SettingsStore{} }

// LoadSettings implements store.SettingsStore.
func (st *SettingsStore) LoadSettings(context.Context) (settings.Settings, bool, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.s, st.saved, nil
}

// SaveSettings implements store.SettingsStore.
func (st *SettingsStore) SaveSettings(_ context.Context, s settings.Settings) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.s, st.saved = s, true
	return nil
}
