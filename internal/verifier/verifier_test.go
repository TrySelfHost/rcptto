package verifier

import (
	"context"
	"net"
	"testing"

	"github.com/tryselfhost/rcptto/internal/pipeline"
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
