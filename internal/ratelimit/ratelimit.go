// Package ratelimit provides per-destination pacing for SMTP probes.
//
// Verification opens connections to other people's mail servers. Without
// pacing, a bulk job containing thousands of addresses at one domain would
// hammer that domain's MX continuously at full worker concurrency — the single
// most reliable way to get an egress IP blocked, regardless of how good the
// downstream reputation management is. This limiter caps the rate at which any
// one destination is probed.
//
// The limiter is a token bucket per destination key, created lazily and evicted
// once idle. It is safe for concurrent use.
package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrWaitTooLong is returned by Wait when the required delay exceeds MaxWait.
// Callers should treat this as "cannot probe right now" and defer the task
// rather than block a worker, so a single busy destination cannot starve the
// pool.
var ErrWaitTooLong = errors.New("ratelimit: required wait exceeds maximum")

// Defaults applied for zero-valued Config fields.
const (
	defaultRate    = 1.0 // probes per second, per destination
	defaultBurst   = 5.0
	defaultMaxWait = 30 * time.Second
	defaultMaxIdle = 10 * time.Minute
)

// Config configures a Limiter.
type Config struct {
	// Rate is the sustained probes per second allowed per destination.
	Rate float64
	// Burst is the maximum number of probes that may be issued back-to-back
	// after an idle period.
	Burst float64
	// MaxWait bounds how long Wait will block; beyond it, Wait returns
	// ErrWaitTooLong immediately.
	MaxWait time.Duration
	// MaxIdle is how long an unused destination bucket is retained before
	// eviction, bounding memory across many destinations.
	MaxIdle time.Duration
	// Now supplies the clock; defaults to time.Now.
	Now func() time.Time
	// sleep is injectable for tests; defaults to a context-aware sleep.
	sleep func(ctx context.Context, d time.Duration) error
}

// Limiter paces probes per destination.
type Limiter struct {
	rate    float64
	burst   float64
	maxWait time.Duration
	maxIdle time.Duration
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens     float64
	last       time.Time // when tokens were last refilled
	lastAccess time.Time // for idle eviction
}

// New builds a Limiter, applying defaults for unset Config fields.
func New(cfg Config) *Limiter {
	l := &Limiter{
		rate:    cfg.Rate,
		burst:   cfg.Burst,
		maxWait: cfg.MaxWait,
		maxIdle: cfg.MaxIdle,
		now:     cfg.Now,
		sleep:   cfg.sleep,
		buckets: make(map[string]*bucket),
	}
	if l.rate <= 0 {
		l.rate = defaultRate
	}
	if l.burst <= 0 {
		l.burst = defaultBurst
	}
	if l.maxWait <= 0 {
		l.maxWait = defaultMaxWait
	}
	if l.maxIdle <= 0 {
		l.maxIdle = defaultMaxIdle
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.sleep == nil {
		l.sleep = sleepCtx
	}
	return l
}

// Wait blocks until a probe to key may proceed, then consumes a token.
//
// It returns ErrWaitTooLong if the required delay exceeds MaxWait (without
// consuming a token), or the context's error if ctx is canceled while waiting.
func (l *Limiter) Wait(ctx context.Context, key string) error {
	delay, ok := l.reserve(key)
	if !ok {
		return ErrWaitTooLong
	}
	if delay <= 0 {
		return nil
	}
	return l.sleep(ctx, delay)
}

// reserve consumes a token for key and reports how long the caller must wait
// before proceeding. ok is false when the required wait exceeds MaxWait, in
// which case no token is consumed.
func (l *Limiter) reserve(key string) (delay time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.evictIdleLocked(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	// Refill based on elapsed time, capped at burst.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	b.lastAccess = now

	// A negative token balance represents probes already promised to earlier
	// callers; the wait is however long it takes to earn the deficit back.
	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}
	deficit := 1 - b.tokens
	delay = time.Duration(deficit / l.rate * float64(time.Second))
	if delay > l.maxWait {
		return 0, false
	}
	b.tokens--
	return delay, true
}

// evictIdleLocked drops buckets unused for longer than maxIdle. Caller must
// hold the lock.
func (l *Limiter) evictIdleLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastAccess) > l.maxIdle {
			delete(l.buckets, k)
		}
	}
}

// Len reports the number of tracked destinations, for tests and diagnostics.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// sleepCtx sleeps for d, returning early with ctx.Err() if ctx is canceled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
