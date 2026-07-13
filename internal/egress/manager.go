package egress

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/pkg/engine"
)

// ErrNoEgress is returned by Binding when no identity is currently eligible to
// probe a destination (all quarantined, capped, or tripped). Callers should
// treat this as "defer / cannot probe now", not as a permanent failure.
var ErrNoEgress = errors.New("no eligible egress identity")

// Default tuning.
const (
	defaultHealthAlpha         = 0.3
	defaultCircuitThreshold    = 3
	defaultCircuitCooldown     = 15 * time.Minute
	defaultQuarantineThreshold = 5
	defaultQuarantineCooldown  = time.Hour
	dailyResetInterval         = 24 * time.Hour
)

// defaultWarmupStages is the per-day send cap at each warm-up stage.
var defaultWarmupStages = []int{50, 200, 1000, 5000}

// Config configures a Manager.
type Config struct {
	// Identities is the initial egress pool.
	Identities []Spec
	// Now supplies the clock; defaults to time.Now.
	Now func() time.Time

	// Tuning (zero values fall back to defaults).
	HealthAlpha         float64
	CircuitThreshold    int
	CircuitCooldown     time.Duration
	QuarantineThreshold int
	QuarantineCooldown  time.Duration
	WarmupStages        []int
	// ActiveDailyCap caps an active identity's daily probes; 0 means unlimited.
	ActiveDailyCap int
}

// Manager owns the egress pool and its reputation state.
type Manager struct {
	now                 func() time.Time
	alpha               float64
	circuitThreshold    int
	circuitCooldown     time.Duration
	quarantineThreshold int
	quarantineCooldown  time.Duration
	warmupStages        []int
	activeDailyCap      int

	mu      sync.Mutex
	records map[string]*record
	order   []string
}

type record struct {
	spec             Spec
	state            State
	warmupStage      int
	usedToday        int
	lastReset        time.Time
	blockStreak      int
	quarantinedUntil time.Time
	health           map[string]*health
	circuits         map[string]*circuit
}

// New builds a Manager from the given config, seeding the pool.
func New(cfg Config) *Manager {
	m := &Manager{
		now:                 cfg.Now,
		alpha:               cfg.HealthAlpha,
		circuitThreshold:    cfg.CircuitThreshold,
		circuitCooldown:     cfg.CircuitCooldown,
		quarantineThreshold: cfg.QuarantineThreshold,
		quarantineCooldown:  cfg.QuarantineCooldown,
		warmupStages:        cfg.WarmupStages,
		activeDailyCap:      cfg.ActiveDailyCap,
		records:             make(map[string]*record),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.alpha <= 0 || m.alpha > 1 {
		m.alpha = defaultHealthAlpha
	}
	if m.circuitThreshold <= 0 {
		m.circuitThreshold = defaultCircuitThreshold
	}
	if m.circuitCooldown <= 0 {
		m.circuitCooldown = defaultCircuitCooldown
	}
	if m.quarantineThreshold <= 0 {
		m.quarantineThreshold = defaultQuarantineThreshold
	}
	if m.quarantineCooldown <= 0 {
		m.quarantineCooldown = defaultQuarantineCooldown
	}
	if len(m.warmupStages) == 0 {
		m.warmupStages = defaultWarmupStages
	}

	start := m.now()
	for _, spec := range cfg.Identities {
		st := StateActive
		if spec.WarmUp {
			st = StateWarming
		}
		m.records[spec.ID] = &record{
			spec:      spec,
			state:     st,
			lastReset: start,
			health:    make(map[string]*health),
			circuits:  make(map[string]*circuit),
		}
		m.order = append(m.order, spec.ID)
	}
	return m
}

// Binding selects the best eligible identity for the task's destination and
// returns a binding to probe with. It returns ErrNoEgress when none is eligible.
func (m *Manager) Binding(_ context.Context, t engine.Task) (engine.EgressBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.reconcileLocked(now)

	dest := destOf(t)
	best := m.selectLocked(dest, now)
	if best == nil {
		return nil, ErrNoEgress
	}
	best.usedToday++
	return binding{
		id:        best.spec.ID,
		helo:      best.spec.HELO,
		mailFrom:  best.spec.MailFrom,
		transport: best.spec.Transport,
	}, nil
}

// Emit consumes probe feedback, updating health, circuit breakers, and
// quarantine state for the identity that produced each signal.
func (m *Manager) Emit(_ context.Context, signals []engine.Signal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()

	for _, sig := range signals {
		rec := m.records[sig.EgressID]
		if rec == nil {
			continue
		}
		dest := sig.Destination
		switch sig.Kind {
		case engine.SignalAccepted, engine.SignalMailboxGone:
			// A clean answer means the egress worked, regardless of the mailbox verdict.
			rec.healthFor(dest).observe(true, m.alpha)
			rec.circuitFor(dest).onSuccess()
			rec.blockStreak = 0
		case engine.SignalTempFail:
			// Greylisting/deferral is mild and does not trip the breaker.
			rec.healthFor(dest).observe(false, m.alpha*0.5)
		case engine.SignalBlocked:
			rec.healthFor(dest).observe(false, m.alpha)
			rec.circuitFor(dest).onFailure(now, m.circuitThreshold, m.circuitCooldown)
			rec.blockStreak++
			if rec.blockStreak >= m.quarantineThreshold {
				rec.state = StateQuarantined
				rec.quarantinedUntil = now.Add(m.quarantineCooldown)
			}
		case engine.SignalConnRefused, engine.SignalTimeout:
			rec.healthFor(dest).observe(false, m.alpha*0.5)
			rec.circuitFor(dest).onFailure(now, m.circuitThreshold, m.circuitCooldown)
		}
	}
}

// selectLocked returns the healthiest eligible identity for dest, spreading load
// via a used-today tie-break. Caller must hold the lock.
func (m *Manager) selectLocked(dest string, now time.Time) *record {
	var best *record
	var bestScore float64
	for _, id := range m.order {
		rec := m.records[id]
		if !m.eligibleLocked(rec, dest, now) {
			continue
		}
		score := rec.score(dest)
		if best == nil || score > bestScore || (score == bestScore && rec.usedToday < best.usedToday) {
			best, bestScore = rec, score
		}
	}
	return best
}

func (m *Manager) eligibleLocked(rec *record, dest string, now time.Time) bool {
	if rec.state == StateDisabled || rec.state == StateQuarantined {
		return false
	}
	if c := rec.circuits[dest]; c != nil && !c.allow(now) {
		return false
	}
	limit := m.capFor(rec)
	if limit > 0 && rec.usedToday >= limit {
		return false
	}
	return true
}

// reconcileLocked advances daily resets, warm-up ramping, and quarantine expiry.
func (m *Manager) reconcileLocked(now time.Time) {
	for _, id := range m.order {
		rec := m.records[id]

		if rec.state == StateQuarantined && now.After(rec.quarantinedUntil) {
			// Recovered identities re-enter warming, never straight to active.
			rec.state = StateWarming
			rec.warmupStage = 0
			rec.blockStreak = 0
		}

		for now.Sub(rec.lastReset) >= dailyResetInterval {
			rec.usedToday = 0
			rec.lastReset = rec.lastReset.Add(dailyResetInterval)
			if rec.state == StateWarming {
				rec.warmupStage++
				if rec.warmupStage >= len(m.warmupStages) {
					rec.state = StateActive
				}
			}
		}
	}
}

func (m *Manager) capFor(rec *record) int {
	if rec.state == StateWarming {
		stage := rec.warmupStage
		if stage >= len(m.warmupStages) {
			stage = len(m.warmupStages) - 1
		}
		return m.warmupStages[stage]
	}
	return m.activeDailyCap // 0 => unlimited
}

// destOf derives the reputation key for a task: the provider class for known
// providers, otherwise the domain.
func destOf(t engine.Task) string {
	if t.Provider != "" && t.Provider != "custom" {
		return t.Provider
	}
	return t.Domain
}

func (r *record) healthFor(dest string) *health {
	h := r.health[dest]
	if h == nil {
		h = newHealth()
		r.health[dest] = h
	}
	return h
}

func (r *record) circuitFor(dest string) *circuit {
	c := r.circuits[dest]
	if c == nil {
		c = &circuit{}
		r.circuits[dest] = c
	}
	return c
}

func (r *record) score(dest string) float64 {
	if h := r.health[dest]; h != nil {
		return h.score
	}
	return 1.0 // unproven identities are optimistically eligible
}
