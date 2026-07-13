package pipeline

import (
	"context"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// disposableStage flags throwaway domains. A disposable address is terminal:
// probing a domain designed to accept anything wastes an SMTP connection and
// egress reputation for no signal, so it is reported as risky without a probe.
type disposableStage struct {
	set DisposableSet
}

func (disposableStage) Name() string { return "disposable" }

func (d disposableStage) Run(_ context.Context, s *State) (bool, error) {
	if d.set.Contains(s.Domain) {
		s.Checks.Disposable = true
		s.Reject(verdict.StatusRisky, verdict.SubDisposable, 0.9)
		return true, nil
	}
	return false, nil
}

// roleStage flags shared role accounts (info@, support@, ...). It is not
// terminal: a role account can be a live mailbox, so the flag rides along and
// downgrades the final verdict while the probe still confirms existence.
type roleStage struct{}

func (roleStage) Name() string { return "role" }

func (roleStage) Run(_ context.Context, s *State) (bool, error) {
	if isRoleAccount(s.LocalPart) {
		s.Checks.Role = true
	}
	return false, nil
}

// freeStage flags free consumer providers. Informational only, never terminal.
type freeStage struct{}

func (freeStage) Name() string { return "free" }

func (freeStage) Run(_ context.Context, s *State) (bool, error) {
	if isFreeDomain(s.Domain) {
		s.Checks.Free = true
	}
	return false, nil
}
