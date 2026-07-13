package egress

import "time"

// health is a per-(identity, destination) rolling reputation score in [0,1],
// updated as an exponential moving average. It starts optimistic so a fresh,
// unproven identity is still eligible for routing.
type health struct {
	score   float64
	samples int
}

func newHealth() *health { return &health{score: 1.0} }

// observe folds one outcome into the score. good outcomes pull it toward 1,
// bad outcomes toward 0; alpha is the smoothing weight (0..1).
func (h *health) observe(good bool, alpha float64) {
	target := 0.0
	if good {
		target = 1.0
	}
	h.score = h.score*(1-alpha) + target*alpha
	h.samples++
}

// cbState is a circuit breaker's position.
type cbState int

const (
	cbClosed cbState = iota
	cbOpen
	cbHalfOpen
)

// circuit is a per-(identity, destination) breaker. It opens after a run of
// failures, stays open for a cool-down, then allows a single half-open trial
// before closing on success or re-opening on failure. This localizes damage:
// one destination blocking one identity does not remove that identity from
// service for every other destination.
type circuit struct {
	state     cbState
	failures  int
	openUntil time.Time
}

// allow reports whether a probe may use this (identity, destination) pair now,
// transitioning an expired open breaker to half-open.
func (c *circuit) allow(now time.Time) bool {
	if c.state == cbOpen {
		if now.After(c.openUntil) {
			c.state = cbHalfOpen
			return true
		}
		return false
	}
	return true
}

// onSuccess closes the breaker and clears the failure count.
func (c *circuit) onSuccess() {
	c.state = cbClosed
	c.failures = 0
}

// onFailure records a failure, opening the breaker once the threshold is reached
// or immediately if a half-open trial fails.
func (c *circuit) onFailure(now time.Time, threshold int, cooldown time.Duration) {
	c.failures++
	if c.state == cbHalfOpen || c.failures >= threshold {
		c.state = cbOpen
		c.openUntil = now.Add(cooldown)
	}
}
