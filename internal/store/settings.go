package store

import (
	"context"

	"github.com/tryselfhost/rcptto/internal/settings"
)

// SettingsStore persists operator-tunable configuration so a change survives a
// restart. Without it, settings revert to environment defaults on every deploy
// and an operator's tuning is silently lost.
type SettingsStore interface {
	// LoadSettings returns the stored configuration. found is false when
	// nothing has been saved yet, in which case the caller uses its defaults.
	LoadSettings(ctx context.Context) (s settings.Settings, found bool, err error)
	// SaveSettings replaces the stored configuration.
	SaveSettings(ctx context.Context, s settings.Settings) error
}
