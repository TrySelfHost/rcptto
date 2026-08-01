package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/tryselfhost/rcptto/internal/settings"
	"github.com/tryselfhost/rcptto/internal/store"
)

// Compile-time guarantee that the adapter satisfies the port.
var _ store.SettingsStore = (*SettingsStore)(nil)

// SettingsStore is a PostgreSQL-backed store.SettingsStore.
type SettingsStore struct {
	db *sql.DB
}

// NewSettingsStore returns a SettingsStore backed by db.
func NewSettingsStore(db *sql.DB) *SettingsStore { return &SettingsStore{db: db} }

// LoadSettings implements store.SettingsStore.
func (s *SettingsStore) LoadSettings(ctx context.Context) (settings.Settings, bool, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM settings WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return settings.Settings{}, false, nil
	}
	if err != nil {
		return settings.Settings{}, false, err
	}
	var out settings.Settings
	if err := json.Unmarshal(raw, &out); err != nil {
		return settings.Settings{}, false, err
	}
	return out, true, nil
}

// SaveSettings implements store.SettingsStore.
func (s *SettingsStore) SaveSettings(ctx context.Context, cfg settings.Settings) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO settings (id, data, updated_at) VALUES (1, $1, now())
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, raw)
	return err
}
