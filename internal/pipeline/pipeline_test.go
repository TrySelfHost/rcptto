package pipeline

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// fakeResolver is a programmable Resolver for hermetic tests.
type fakeResolver struct {
	mx    map[string][]*net.MX
	hosts map[string][]string
	err   map[string]error
}

func (f fakeResolver) LookupMX(_ context.Context, domain string) ([]*net.MX, error) {
	if e, ok := f.err[domain]; ok {
		return nil, e
	}
	if r, ok := f.mx[domain]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if h, ok := f.hosts[host]; ok {
		return h, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func mx(host string, pref uint16) *net.MX { return &net.MX{Host: host, Pref: pref} }

// testPipeline builds a pipeline wired to a resolver covering the domains used
// across the tests.
func testPipeline() *Pipeline {
	r := fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {mx("mx1.example.com.", 10)},
			"gmail.com":   {mx("gmail-smtp-in.l.google.com.", 5)},
			"startup.io":  {mx("aspmx.l.google.com.", 1)},
			"nomail.test": {mx(".", 0)}, // null MX
		},
		hosts: map[string][]string{
			"implicit.test": {"203.0.113.10"}, // A record, no MX
		},
		err: map[string]error{
			// Domain resolves but has no MX records (distinct from NXDOMAIN).
			"nomx.test": &net.DNSError{Err: "no MX", Name: "nomx.test"},
			// Transient resolver failure that should be surfaced for retry.
			"temp.test": &net.DNSError{Err: "timeout", Name: "temp.test", IsTemporary: true},
		},
	}

	return New(Config{
		Resolver: r,
		Now:      func() time.Time { return time.Unix(0, 0).UTC() },
	})
}

func TestSyntax(t *testing.T) {
	p := testPipeline()

	invalid := []string{
		"", "plainaddress", "@nolocal.com", "nodomain@", "no-at.com",
		"a@@b.com", "a..b@example.com", ".a@example.com", "a.@example.com",
		"a@localhostonly", "a@x.c", "a@-bad.com", "a@bad-.com", "a b@example.com",
		"a@ex..com",
	}
	for _, addr := range invalid {
		t.Run("invalid/"+addr, func(t *testing.T) {
			res, err := p.Run(context.Background(), addr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Terminal || res.Verdict.SubStatus != verdict.SubInvalidSyntax {
				t.Fatalf("expected invalid_syntax terminal, got terminal=%v sub=%q", res.Terminal, res.Verdict.SubStatus)
			}
		})
	}

	valid := []string{"user@example.com", "u.ser+tag@example.com", "USER@Example.com"}
	for _, addr := range valid {
		t.Run("valid/"+addr, func(t *testing.T) {
			res, err := p.Run(context.Background(), addr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Terminal {
				t.Fatalf("expected non-terminal (needs probe), got verdict %+v", res.Verdict)
			}
			if !res.Checks.Syntax.Valid {
				t.Errorf("syntax check should be valid")
			}
		})
	}
}

func TestNormalizeGmail(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "First.Last+news@googlemail.com")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// googlemail.com has no configured MX here, so it terminates at domain lookup;
	// assert the normalization that happened before MX regardless of terminality.
	if res.Provider != providerGmail {
		t.Errorf("provider = %q, want gmail", res.Provider)
	}
	// Normalized is carried on the verdict when terminal.
	wantNorm := "firstlast@gmail.com"
	got := res.Verdict.Normalized
	if !res.Terminal {
		got = res.Task.Normalized
	}
	if got != wantNorm {
		t.Errorf("normalized = %q, want %q", got, wantNorm)
	}
}

func TestNormalizePreservesLocalCaseInProbeTarget(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "User@Example.com")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Task.Email != "User@example.com" {
		t.Errorf("probe email = %q, want User@example.com (local case kept, domain lowered)", res.Task.Email)
	}
	if res.Task.Normalized != "user@example.com" {
		t.Errorf("normalized = %q, want user@example.com", res.Task.Normalized)
	}
}

func TestDisposableTerminal(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "x@mailinator.com")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Terminal || res.Verdict.Status != verdict.StatusRisky || res.Verdict.SubStatus != verdict.SubDisposable {
		t.Fatalf("expected risky/disposable terminal, got %+v", res.Verdict)
	}
	if !res.Checks.Disposable {
		t.Errorf("disposable check flag not set")
	}
}

func TestRoleIsFlagNotTerminal(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "info@example.com")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Terminal {
		t.Fatalf("role account should not be terminal, got %+v", res.Verdict)
	}
	if !res.Checks.Role {
		t.Errorf("role flag not set")
	}
}

func TestFreeFlag(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "someone@gmail.com")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Checks.Free {
		t.Errorf("free flag not set for gmail.com")
	}
	if res.Provider != providerGmail {
		t.Errorf("provider = %q, want gmail", res.Provider)
	}
}

func TestMXVariants(t *testing.T) {
	p := testPipeline()

	t.Run("found -> needs probe", func(t *testing.T) {
		res, err := p.Run(context.Background(), "user@example.com")
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Terminal {
			t.Fatalf("expected needs-probe, got %+v", res.Verdict)
		}
		if !res.Checks.MX.Found || len(res.MX) != 1 || res.MX[0] != "mx1.example.com" {
			t.Errorf("mx not recorded correctly: %+v", res.MX)
		}
	})

	t.Run("nxdomain -> domain_not_found", func(t *testing.T) {
		res, _ := p.Run(context.Background(), "user@does-not-exist.test")
		if !res.Terminal || res.Verdict.SubStatus != verdict.SubDomainNotFound {
			t.Fatalf("expected domain_not_found, got %+v", res.Verdict)
		}
	})

	t.Run("implicit MX (A only) -> needs probe", func(t *testing.T) {
		res, err := p.Run(context.Background(), "user@implicit.test")
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Terminal {
			t.Fatalf("expected needs-probe via implicit MX, got %+v", res.Verdict)
		}
		if len(res.MX) != 1 || res.MX[0] != "implicit.test" {
			t.Errorf("implicit MX not set to domain: %+v", res.MX)
		}
	})

	t.Run("null MX -> undeliverable", func(t *testing.T) {
		res, _ := p.Run(context.Background(), "user@nomail.test")
		if !res.Terminal || res.Verdict.SubStatus != verdict.SubNoMXRecord {
			t.Fatalf("expected no_mx_record for null MX, got %+v", res.Verdict)
		}
	})

	t.Run("no MX error -> no_mx_record", func(t *testing.T) {
		res, _ := p.Run(context.Background(), "user@nomx.test")
		if !res.Terminal || res.Verdict.SubStatus != verdict.SubNoMXRecord {
			t.Fatalf("expected no_mx_record, got %+v", res.Verdict)
		}
	})

	t.Run("transient DNS -> error surfaced", func(t *testing.T) {
		_, err := p.Run(context.Background(), "user@temp.test")
		if err == nil {
			t.Fatalf("expected transient DNS error to surface")
		}
	})
}

func TestProviderRefinedFromMX(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "founder@startup.io")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Provider != providerGoogleWorkspace {
		t.Errorf("provider = %q, want google_workspace", res.Provider)
	}
}

func TestEndToEndNeedsProbe(t *testing.T) {
	p := testPipeline()
	res, err := p.Run(context.Background(), "  jane.doe@example.com  ")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Terminal {
		t.Fatalf("expected needs-probe, got %+v", res.Verdict)
	}
	if res.Task.Email != "jane.doe@example.com" {
		t.Errorf("task email = %q", res.Task.Email)
	}
	if res.Task.Domain != "example.com" || res.Task.Provider != providerCustom {
		t.Errorf("task routing = %+v", res.Task)
	}
	if !res.Checks.Syntax.Valid || !res.Checks.MX.Found {
		t.Errorf("checks incomplete: %+v", res.Checks)
	}
}

func TestStagesOrder(t *testing.T) {
	got := New(Config{Resolver: fakeResolver{}}).Stages()
	want := []string{"syntax", "normalize", "disposable", "role", "free", "mx"}
	if len(got) != len(want) {
		t.Fatalf("stage count = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stage[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
