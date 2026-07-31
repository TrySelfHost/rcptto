package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// testClock is a manually advanced clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestLimiter returns a limiter with a manual clock and a sleep that records
// requested delays instead of actually sleeping.
func newTestLimiter(t *testing.T, cfg Config) (*Limiter, *testClock, *[]time.Duration) {
	t.Helper()
	clk := &testClock{t: time.Unix(1000, 0)}
	var slept []time.Duration
	var mu sync.Mutex
	cfg.Now = clk.now
	cfg.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
	return New(cfg), clk, &slept
}

func TestBurstAllowedImmediately(t *testing.T) {
	l, _, slept := newTestLimiter(t, Config{Rate: 1, Burst: 3})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("burst probe %d: %v", i, err)
		}
	}
	for _, d := range *slept {
		if d > 0 {
			t.Errorf("burst probes should not sleep, got %v", d)
		}
	}
}

func TestFourthProbeIsPaced(t *testing.T) {
	l, _, slept := newTestLimiter(t, Config{Rate: 1, Burst: 3})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = l.Wait(ctx, "example.com")
	}
	// Burst exhausted: the next probe must wait ~1s at 1/sec.
	if err := l.Wait(ctx, "example.com"); err != nil {
		t.Fatalf("paced probe: %v", err)
	}
	if len(*slept) == 0 {
		t.Fatal("expected a sleep after burst exhausted")
	}
	got := (*slept)[len(*slept)-1]
	if got < 900*time.Millisecond || got > 1100*time.Millisecond {
		t.Errorf("delay = %v, want ~1s", got)
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	l, clk, slept := newTestLimiter(t, Config{Rate: 2, Burst: 2})
	ctx := context.Background()

	_ = l.Wait(ctx, "a.com")
	_ = l.Wait(ctx, "a.com") // burst spent

	clk.advance(time.Second) // at 2/sec that refills the full burst
	before := len(*slept)
	if err := l.Wait(ctx, "a.com"); err != nil {
		t.Fatalf("after refill: %v", err)
	}
	if len(*slept) > before && (*slept)[len(*slept)-1] > 0 {
		t.Errorf("probe after refill should not wait, slept %v", (*slept)[len(*slept)-1])
	}
}

func TestLimitsArePerDestination(t *testing.T) {
	l, _, slept := newTestLimiter(t, Config{Rate: 1, Burst: 1})
	ctx := context.Background()

	// Spending a.com's budget must not affect b.com.
	_ = l.Wait(ctx, "a.com")
	before := len(*slept)
	if err := l.Wait(ctx, "b.com"); err != nil {
		t.Fatalf("b.com: %v", err)
	}
	if len(*slept) > before && (*slept)[len(*slept)-1] > 0 {
		t.Errorf("a separate destination should not be throttled, slept %v", (*slept)[len(*slept)-1])
	}
}

func TestWaitTooLongIsRefused(t *testing.T) {
	// Rate 1/sec, burst 1, MaxWait 2s: the 4th queued probe needs ~3s.
	l, _, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxWait: 2 * time.Second})
	ctx := context.Background()

	var lastErr error
	for i := 0; i < 6; i++ {
		lastErr = l.Wait(ctx, "busy.com")
		if errors.Is(lastErr, ErrWaitTooLong) {
			return // expected before the loop ends
		}
	}
	t.Fatalf("expected ErrWaitTooLong once the queue got long, last err = %v", lastErr)
}

func TestContextCancellationPropagates(t *testing.T) {
	l, _, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1})
	ctx, cancel := context.WithCancel(context.Background())

	_ = l.Wait(ctx, "x.com") // consume the burst
	cancel()
	if err := l.Wait(ctx, "x.com"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestIdleBucketsEvicted(t *testing.T) {
	l, clk, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxIdle: time.Minute})
	ctx := context.Background()

	_ = l.Wait(ctx, "old.com")
	if l.Len() != 1 {
		t.Fatalf("len = %d, want 1", l.Len())
	}

	clk.advance(2 * time.Minute)
	_ = l.Wait(ctx, "new.com") // triggers the sweep
	if l.Len() != 1 {
		t.Errorf("len = %d, want 1 (old.com should have been evicted)", l.Len())
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Config{Rate: 1000, Burst: 1000})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = l.Wait(ctx, "shared.com")
		}(i)
	}
	wg.Wait()
}
