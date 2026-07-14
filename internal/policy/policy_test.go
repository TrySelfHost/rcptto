package policy

import "testing"

func TestDefaultProviderRules(t *testing.T) {
	s := Default()

	skipped := []string{"gmail", "yahoo", "microsoft", "microsoft365", "GMAIL", "Yahoo"}
	for _, p := range skipped {
		if r := s.Lookup(p); r.Strategy != StrategySkip {
			t.Errorf("Lookup(%q).Strategy = %s, want skip", p, r.Strategy)
		}
	}

	probed := []string{"custom", "example.com", "icloud", "proton", ""}
	for _, p := range probed {
		if r := s.Lookup(p); r.Strategy != StrategyProbe {
			t.Errorf("Lookup(%q).Strategy = %s, want probe (fallback default)", p, r.Strategy)
		}
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	s := New(map[string]Rule{"gmail": {Strategy: StrategySkip, Reason: "x"}})
	if r := s.Lookup("GMAIL"); r.Strategy != StrategySkip {
		t.Errorf("case-insensitive lookup failed: %s", r.Strategy)
	}
}

func TestUnsetStrategyNormalizesToProbe(t *testing.T) {
	s := New(map[string]Rule{"example.com": {Reason: "no strategy set"}})
	if r := s.Lookup("example.com"); r.Strategy != StrategyProbe {
		t.Errorf("empty Strategy should normalize to probe, got %q", r.Strategy)
	}
}

func TestCustomDefaultRule(t *testing.T) {
	s := New(map[string]Rule{
		"default": {Strategy: StrategySkip, Reason: "conservative default"},
	})
	if r := s.Lookup("some-unknown-domain.com"); r.Strategy != StrategySkip {
		t.Errorf("custom default not applied, got %s", r.Strategy)
	}
}

func TestSetHotReload(t *testing.T) {
	s := Default()
	if r := s.Lookup("gmail"); r.Strategy != StrategySkip {
		t.Fatalf("precondition: gmail should default to skip")
	}
	s.Set("gmail", Rule{Strategy: StrategyProbe, Reason: "operator override"})
	if r := s.Lookup("gmail"); r.Strategy != StrategyProbe {
		t.Errorf("Set did not override existing rule, got %s", r.Strategy)
	}

	s.Set("default", Rule{Strategy: StrategySkip, Reason: "new default"})
	if r := s.Lookup("brand-new-domain.com"); r.Strategy != StrategySkip {
		t.Errorf("Set(\"default\", ...) did not override fallback, got %s", r.Strategy)
	}
}
