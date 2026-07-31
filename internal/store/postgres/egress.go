package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/tryselfhost/rcptto/internal/store"
)

// Compile-time guarantee that the adapter satisfies the port.
var _ store.EgressStore = (*EgressStore)(nil)

// EgressStore is a PostgreSQL-backed store.EgressStore.
type EgressStore struct {
	db *sql.DB
}

// NewEgressStore returns an EgressStore backed by db.
func NewEgressStore(db *sql.DB) *EgressStore {
	return &EgressStore{db: db}
}

// LoadEgress implements store.EgressStore.
func (s *EgressStore) LoadEgress(ctx context.Context) ([]store.EgressState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM egress_state`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []store.EgressState
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var st store.EgressState
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveEgress implements store.EgressStore, upserting every identity in one
// transaction so a crash mid-save cannot leave the pool partially updated.
func (s *EgressStore) SaveEgress(ctx context.Context, states []store.EgressState) error {
	if len(states) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO egress_state (id, data, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (id) DO UPDATE
		   SET data = EXCLUDED.data, updated_at = now()`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, st := range states {
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, st.ID, raw); err != nil {
			return err
		}
	}
	return tx.Commit()
}
