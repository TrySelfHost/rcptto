package egress

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tryselfhost/rcptto/internal/egress/audit"
	"github.com/tryselfhost/rcptto/internal/store"
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
	// Store persists reputation state across restarts. Optional; without it,
	// warm-up progress and quarantine reset every time the process restarts.
	Store store.EgressStore
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

	store store.EgressStore

	mu      sync.Mutex
	records map[string]*record
	order   []string
	dirty   bool
}

type record struct {
	spec             Spec
	state            State
	warmupStage      int
	usedToday        int
	lastReset        time.Time
	blockStreak      int
	quarantinedUntil time.Time
	quarantineReason string
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
		store:               cfg.Store,
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
	m.dirty = true
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
		m.dirty = true
	}
}

// IdentityInfo is a read-only snapshot of an identity, for audits, admin, and
// metrics.
type IdentityInfo struct {
	ID     string
	IP     string
	State  State
	Reason string // quarantine reason, when applicable
}

// Identities returns a snapshot of the pool's identities.
func (m *Manager) Identities() []IdentityInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IdentityInfo, 0, len(m.order))
	for _, id := range m.order {
		r := m.records[id]
		out = append(out, IdentityInfo{ID: id, IP: r.spec.IP, State: r.state, Reason: r.quarantineReason})
	}
	return out
}

// Enable clears any quarantine/disable on an identity, returning it to warming
// (never straight to active, matching the normal recovery path). Unknown ids
// are ignored. Intended for administrative override.
func (m *Manager) Enable(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[id]
	if rec == nil {
		return
	}
	rec.state = StateWarming
	rec.warmupStage = 0
	rec.blockStreak = 0
	rec.quarantineReason = ""
	m.dirty = true
}

// Disable administratively withdraws an identity indefinitely, until Enable is
// called. Unlike Quarantine, Disable has no automatic recovery. Unknown ids are
// ignored.
func (m *Manager) Disable(id, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[id]
	if rec == nil {
		return
	}
	rec.state = StateDisabled
	rec.quarantineReason = reason
	m.dirty = true
}

// Quarantine withdraws an identity for the configured cool-down, recording a
// reason. Used by audits (DNSBL hits) and operators. Unknown ids are ignored.
func (m *Manager) Quarantine(id, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[id]
	if rec == nil {
		return
	}
	rec.state = StateQuarantined
	rec.quarantinedUntil = m.now().Add(m.quarantineCooldown)
	rec.quarantineReason = reason
	m.dirty = true
}

// AuditDNSBL checks every identity's IP against the given DNSBL and quarantines
// any that are listed. DNS lookups run outside the lock (snapshot, check,
// apply), so audits never block routing.
func (m *Manager) AuditDNSBL(ctx context.Context, dnsbl *audit.DNSBL) {
	type item struct {
		id, ip   string
		disabled bool
	}
	m.mu.Lock()
	items := make([]item, 0, len(m.order))
	for _, id := range m.order {
		r := m.records[id]
		items = append(items, item{id: id, ip: r.spec.IP, disabled: r.state == StateDisabled})
	}
	m.mu.Unlock()

	for _, it := range items {
		if it.ip == "" || it.disabled {
			continue
		}
		listed, err := dnsbl.Check(ctx, it.ip)
		if err != nil || len(listed) == 0 {
			continue
		}
		m.Quarantine(it.id, "dnsbl:"+strings.Join(listed, ","))
	}
}
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

// --- persistence -------------------------------------------------------------

// Snapshot returns the serializable reputation state of every identity, for
// persistence. Circuit breakers are deliberately excluded — they are transient
// and re-trip quickly if the underlying problem persists.
func (m *Manager) Snapshot() []store.EgressState {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]store.EgressState, 0, len(m.order))
	for _, id := range m.order {
		rec := m.records[id]
		health := make(map[string]float64, len(rec.health))
		for dest, h := range rec.health {
			health[dest] = h.score
		}
		out = append(out, store.EgressState{
			ID:               id,
			State:            string(rec.state),
			WarmupStage:      rec.warmupStage,
			UsedToday:        rec.usedToday,
			LastReset:        rec.lastReset,
			BlockStreak:      rec.blockStreak,
			QuarantinedUntil: rec.quarantinedUntil,
			QuarantineReason: rec.quarantineReason,
			Health:           health,
		})
	}
	return out
}

// Restore applies previously persisted state to the configured pool.
//
// Only identities present in the current configuration are restored; persisted
// state for an identity that has since been removed is ignored, and a newly
// added identity keeps its configured starting state. This makes the config the
// source of truth for *which* identities exist, and the store the source of
// truth for *what reputation they have earned*.
func (m *Manager) Restore(states []store.EgressState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, st := range states {
		rec := m.records[st.ID]
		if rec == nil {
			continue
		}
		rec.state = State(st.State)
		rec.warmupStage = st.WarmupStage
		rec.usedToday = st.UsedToday
		rec.blockStreak = st.BlockStreak
		rec.quarantinedUntil = st.QuarantinedUntil
		rec.quarantineReason = st.QuarantineReason
		if !st.LastReset.IsZero() {
			rec.lastReset = st.LastReset
		}
		for dest, score := range st.Health {
			rec.health[dest] = &health{score: score}
		}
	}
	m.dirty = true
}

// Persist writes the current reputation state to the configured store. It is a
// no-op when no store is configured.
func (m *Manager) Persist(ctx context.Context) error {
	if m.store == nil {
		return nil
	}
	states := m.Snapshot()
	if err := m.store.SaveEgress(ctx, states); err != nil {
		return err
	}
	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()
	return nil
}

// PersistLoop periodically writes reputation state to the configured store
// until ctx is canceled, then performs a final write so a graceful shutdown
// does not lose the most recent changes. It is a no-op without a store.
func (m *Manager) PersistLoop(ctx context.Context, interval time.Duration, onErr func(error)) {
	if m.store == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	report := func(err error) {
		if err != nil && onErr != nil {
			onErr(err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Final write on shutdown, with a fresh context since ctx is done.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			report(m.Persist(flushCtx))
			cancel()
			return
		case <-ticker.C:
			m.mu.Lock()
			dirty := m.dirty
			m.mu.Unlock()
			if dirty {
				report(m.Persist(ctx))
			}
		}
	}
}
