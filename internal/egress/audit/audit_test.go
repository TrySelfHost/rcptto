package audit

import (
	"context"
	"net"
	"testing"
)

// fakeResolver is a programmable Resolver.
type fakeResolver struct {
	hosts map[string][]string
	addrs map[string][]string
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if n, ok := f.addrs[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func TestDNSBLListed(t *testing.T) {
	// 4.3.2.1.zen.spamhaus.org resolving to a 127.0.0.x code = listed.
	r := fakeResolver{hosts: map[string][]string{
		"4.3.2.1.zen.spamhaus.org": {"127.0.0.2"},
	}}
	d := NewDNSBL(r, []string{"zen.spamhaus.org"})

	listed, err := d.Check(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(listed) != 1 || listed[0] != "zen.spamhaus.org" {
		t.Errorf("listed = %v, want [zen.spamhaus.org]", listed)
	}
}

func TestDNSBLNotListed(t *testing.T) {
	d := NewDNSBL(fakeResolver{}, []string{"zen.spamhaus.org"}) // NXDOMAIN => not listed
	listed, err := d.Check(context.Background(), "1.2.3.4")
	if err != nil || len(listed) != 0 {
		t.Fatalf("expected not listed, got %v err=%v", listed, err)
	}
}

func TestDNSBLErrorCodeIsNotAListing(t *testing.T) {
	// 127.255.255.252 is Spamhaus's "public resolver refused" code, NOT a listing.
	r := fakeResolver{hosts: map[string][]string{
		"4.3.2.1.zen.spamhaus.org": {"127.255.255.252"},
	}}
	d := NewDNSBL(r, []string{"zen.spamhaus.org"})
	listed, _ := d.Check(context.Background(), "1.2.3.4")
	if len(listed) != 0 {
		t.Errorf("error code must not count as a listing, got %v", listed)
	}
}

func TestDNSBLSkipsNonIPv4(t *testing.T) {
	d := NewDNSBL(fakeResolver{}, []string{"zen.spamhaus.org"})
	if listed, _ := d.Check(context.Background(), "2001:db8::1"); len(listed) != 0 {
		t.Errorf("IPv6 should be skipped, got %v", listed)
	}
	if listed, _ := d.Check(context.Background(), "not-an-ip"); len(listed) != 0 {
		t.Errorf("garbage should be skipped, got %v", listed)
	}
}

func TestPTRForwardConfirmed(t *testing.T) {
	r := fakeResolver{
		addrs: map[string][]string{"1.2.3.4": {"mail.example.com."}},
		hosts: map[string][]string{"mail.example.com": {"1.2.3.4"}},
	}
	a := NewPTRAuditor(r)

	res, err := a.Audit(context.Background(), "1.2.3.4", "mail.example.com")
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !res.FCrDNS {
		t.Errorf("expected forward-confirmed rDNS")
	}
	if !res.HELOMatch {
		t.Errorf("expected HELO match")
	}
}

func TestPTRNotForwardConfirmed(t *testing.T) {
	// PTR points to a host that resolves to a different IP.
	r := fakeResolver{
		addrs: map[string][]string{"1.2.3.4": {"other.example.com."}},
		hosts: map[string][]string{"other.example.com": {"9.9.9.9"}},
	}
	a := NewPTRAuditor(r)

	res, err := a.Audit(context.Background(), "1.2.3.4", "mail.example.com")
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if res.FCrDNS {
		t.Errorf("should not be forward-confirmed")
	}
	if res.HELOMatch {
		t.Errorf("HELO should not match")
	}
}

func TestPTRNoRecord(t *testing.T) {
	a := NewPTRAuditor(fakeResolver{}) // no PTR
	if _, err := a.Audit(context.Background(), "1.2.3.4", "mail.example.com"); err == nil {
		t.Errorf("expected error when no PTR record exists")
	}
}
