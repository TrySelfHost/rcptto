// Package store defines the persistence ports for rcpttō and hosts their
// adapters (in-memory now; Postgres later). Application code depends only on
// these interfaces, so swapping the backing store never touches business logic.
package store

import (
	"context"
	"time"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// ResultStore caches verification verdicts keyed by an address's canonical
// (normalized) form. A cache hit lets the verifier skip the expensive SMTP
// probe — the scarcest operation in terms of egress reputation.
type ResultStore interface {
	// Get returns the cached verdict for key. found is false on a miss or when
	// the entry has expired.
	Get(ctx context.Context, key string) (v verdict.Verdict, found bool, err error)
	// Put stores v under key with the given time-to-live. A non-positive ttl
	// stores the entry without expiry.
	Put(ctx context.Context, key string, v verdict.Verdict, ttl time.Duration) error
}
