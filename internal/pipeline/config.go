package pipeline

import (
	"context"
	"net"
	"time"
)

// Resolver abstracts DNS lookups so the mx stage can be tested without real DNS.
type Resolver interface {
	// LookupMX returns the DNS MX records for domain, in the standard library's
	// preference-sorted order.
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	// LookupHost returns the A/AAAA hosts for host, used as an implicit-MX fallback.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DisposableSet reports whether a domain belongs to a disposable/throwaway email
// provider. The default implementation is a small embedded set; a larger vendored
// list can be substituted without changing the stage.
type DisposableSet interface {
	// Contains reports whether domain is a known disposable provider. The domain
	// is expected to be lower-cased.
	Contains(domain string) bool
}

// netResolver adapts *net.Resolver to the Resolver interface.
type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return n.r.LookupMX(ctx, domain)
}

func (n netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.r.LookupHost(ctx, host)
}

// Config configures a Pipeline. All fields are optional; New fills in defaults.
type Config struct {
	// Resolver performs DNS lookups. Defaults to the system resolver.
	Resolver Resolver
	// Disposable is the disposable-domain oracle. Defaults to the embedded set.
	Disposable DisposableSet
	// Now supplies timestamps for verdicts. Defaults to time.Now.
	Now func() time.Time
}

// New builds a Pipeline with the default funnel stage order, applying defaults
// for any unset Config fields.
func New(cfg Config) *Pipeline {
	if cfg.Resolver == nil {
		cfg.Resolver = netResolver{r: net.DefaultResolver}
	}
	if cfg.Disposable == nil {
		cfg.Disposable = defaultDisposableSet()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	p := &Pipeline{now: cfg.Now}
	p.stages = []Stage{
		syntaxStage{},
		normalizeStage{},
		disposableStage{set: cfg.Disposable},
		roleStage{},
		freeStage{},
		mxStage{resolver: cfg.Resolver},
	}
	return p
}
