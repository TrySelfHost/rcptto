package verifier

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/internal/pipeline"
	"github.com/tryselfhost/rcptto/internal/policy"
	"github.com/tryselfhost/rcptto/internal/ratelimit"
	"github.com/tryselfhost/rcptto/internal/store/memory"
	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/engine/mock"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// fakeResolver implements pipeline.Resolver for hermetic tests.
type fakeResolver struct{ mx map[string][]*net.MX }

func (f fakeResolver) LookupMX(_ context.Context, domain string) ([]*net.MX, error) {
	if r, ok := f.mx[domain]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// spyEngine counts Verify calls and delegates to an inner engine.
type spyEngine struct {
	inner engine.Engine
	calls int
}

func (s *spyEngine) Verify(ctx context.Context, t engine.Task, eg engine.EgressBinding) (verdict.Verdict, []engine.Signal, error) {
	s.calls++
	return s.inner.Verify(ctx, t, eg)
}
func (s *spyEngine) Name() string              { return s.inner.Name() }
func (s *spyEngine) Capabilities() engine.Caps { return s.inner.Capabilities() }

func testPipeline() *pipeline.Pipeline {
	return pipeline.New(pipeline.Config{
		Resolver: fakeResolver{mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}},
			"gmail.com":   {{Host: "gmail-smtp-in.l.google.com.", Pref: 5}},
		}},
	})
}

func TestVerifyDeliverableMergesChecks(t *testing.T) {
	svc := New(Config{Pipeline: testPipeline(), Engine: mock.New()})

	v, err := svc.Verify(context.Background(), "valid@example.com")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusDeliverable {
		t.Fatalf("status = %s, want deliverable", v.Status)
	}
	// funnel-provided checks
	if !v.Checks.Syntax.Valid || !v.Checks.MX.Found {
		t.Errorf("funnel checks not merged: %+v", v.Checks)
	}
	// engine-provided check
	if !v.Checks.SMTP.Probed {
		t.Errorf("engine SMTP check not present: %+v", v.Checks.SMTP)
	}
}

func TestVerifyTerminalSkipsEngine(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	svc := New(Config{Pipeline: testPipeline(), Engine: spy})

	v, err := svc.Verify(context.Background(), "not-an-email")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusUndeliverable || v.SubStatus != verdict.SubInvalidSyntax {
		t.Fatalf("got (%s,%s), want undeliverable/invalid_syntax", v.Status, v.SubStatus)
	}
	if spy.calls != 0 {
		t.Errorf("engine should not be called for a terminal funnel result, calls=%d", spy.calls)
	}
}

func TestRoleAccountDowngrade(t *testing.T) {
	// mock engine returns deliverable for the "info@" prefix (default), and the
	// funnel flags it as a role account; the merge must downgrade to risky.
	svc := New(Config{Pipeline: testPipeline(), Engine: mock.New()})

	v, err := svc.Verify(context.Background(), "info@example.com")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusRisky || v.SubStatus != verdict.SubRoleAccount {
		t.Fatalf("got (%s,%s), want risky/role_account", v.Status, v.SubStatus)
	}
	if !v.Checks.Role {
		t.Errorf("role check flag missing")
	}
}

func TestPolicySkipAvoidsProbe(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	skipGmail := policy.New(map[string]policy.Rule{
		"gmail": {Strategy: policy.StrategySkip, Reason: "test skip"},
	})
	svc := New(Config{Pipeline: testPipeline(), Engine: spy, Policy: skipGmail})

	v, err := svc.Verify(context.Background(), "someone@gmail.com")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != verdict.StatusRisky || v.SubStatus != verdict.SubProviderSkipped {
		t.Fatalf("got (%s,%s), want risky/provider_skipped", v.Status, v.SubStatus)
	}
	if spy.calls != 0 {
		t.Errorf("engine should not be called when policy skips, calls=%d", spy.calls)
	}
	// Funnel findings (syntax/mx) must still be preserved even though skipped.
	if !v.Checks.Syntax.Valid {
		t.Errorf("syntax check should still be populated: %+v", v.Checks)
	}
}

func TestPolicyDefaultProbesUnlistedProvider(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	svc := New(Config{Pipeline: testPipeline(), Engine: spy}) // uses policy.Default()

	if _, err := svc.Verify(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if spy.calls != 1 {
		t.Errorf("custom domain should be probed under the default policy, calls=%d", spy.calls)
	}
}

func TestDefaultPolicySkipsGmailEndToEnd(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	svc := New(Config{Pipeline: testPipeline(), Engine: spy}) // uses policy.Default()

	v, err := svc.Verify(context.Background(), "someone@gmail.com")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.SubStatus != verdict.SubProviderSkipped {
		t.Fatalf("default policy should skip gmail, got %+v", v)
	}
	if spy.calls != 0 {
		t.Errorf("engine should not be called, calls=%d", spy.calls)
	}
}

func TestCacheHitSkipsSecondProbe(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	svc := New(Config{Pipeline: testPipeline(), Engine: spy, Cache: memory.NewResultStore()})
	ctx := context.Background()

	v1, err := svc.Verify(ctx, "valid@example.com")
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	if v1.Cached {
		t.Errorf("first result should not be cached")
	}

	v2, err := svc.Verify(ctx, "valid@example.com")
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if !v2.Cached {
		t.Errorf("second result should be served from cache")
	}
	if spy.calls != 1 {
		t.Errorf("engine should be probed once, calls=%d", spy.calls)
	}
}

func TestRateLimiterPacesProbes(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	// Burst of 1 at 1/sec: the first probe passes, later ones must wait.
	limiter := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1})
	svc := New(Config{Pipeline: testPipeline(), Engine: spy, Limiter: limiter})
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 3; i++ {
		// Distinct addresses so the result cache never short-circuits the probe.
		email := fmt.Sprintf("user%d@example.com", i)
		if _, err := svc.Verify(ctx, email); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	if spy.calls != 3 {
		t.Fatalf("engine calls = %d, want 3", spy.calls)
	}
	// Three probes at 1/sec with burst 1 means roughly two seconds of pacing.
	if elapsed < 1500*time.Millisecond {
		t.Errorf("probes completed in %v; expected pacing to slow them down", elapsed)
	}
}

func TestRateLimitedBeyondMaxWaitDefers(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	// A limiter that refuses almost immediately: burst 1, and any queued wait
	// exceeds the 1ns maximum.
	limiter := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1, MaxWait: time.Nanosecond})
	svc := New(Config{Pipeline: testPipeline(), Engine: spy, Limiter: limiter})
	ctx := context.Background()

	if _, err := svc.Verify(ctx, "first@example.com"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	v, err := svc.Verify(ctx, "second@example.com")
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if v.Status != verdict.StatusUnknown || v.SubStatus != verdict.SubTemporaryFailure {
		t.Fatalf("got (%s,%s), want unknown/temporary_failure when throttled", v.Status, v.SubStatus)
	}
	if spy.calls != 1 {
		t.Errorf("engine calls = %d, want 1 (second probe must be deferred, not sent)", spy.calls)
	}
	// Funnel findings must survive on the deferred verdict.
	if !v.Checks.Syntax.Valid || !v.Checks.MX.Found {
		t.Errorf("deferred verdict lost funnel findings: %+v", v.Checks)
	}
}

func TestDeferredResultsAreNotCached(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	limiter := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1, MaxWait: time.Nanosecond})
	svc := New(Config{
		Pipeline: testPipeline(), Engine: spy, Limiter: limiter,
		Cache: memory.NewResultStore(),
	})
	ctx := context.Background()

	_, _ = svc.Verify(ctx, "a@example.com") // consumes the burst
	v, _ := svc.Verify(ctx, "b@example.com")
	if v.Status != verdict.StatusUnknown {
		t.Fatalf("expected the second probe to be deferred, got %s", v.Status)
	}
	// A deferred (unknown) result must not be cached, so a later retry can
	// still produce a real verdict.
	v2, _ := svc.Verify(ctx, "b@example.com")
	if v2.Cached {
		t.Error("deferred results must never be cached")
	}
}

func TestNoLimiterMeansNoThrottling(t *testing.T) {
	spy := &spyEngine{inner: mock.New()}
	svc := New(Config{Pipeline: testPipeline(), Engine: spy}) // no Limiter
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := svc.Verify(ctx, fmt.Sprintf("u%d@example.com", i)); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("unlimited verifier took %v; should not be paced", elapsed)
	}
	if spy.calls != 5 {
		t.Errorf("engine calls = %d, want 5", spy.calls)
	}
}
