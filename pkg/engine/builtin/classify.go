package builtin

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/tryselfhost/rcptto/pkg/engine"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// rcptOutcome is the classified result of a RCPT TO reply.
type rcptOutcome struct {
	status    verdict.Status
	subStatus verdict.SubStatus
	signal    engine.SignalKind
}

// classifyRCPT maps an SMTP RCPT TO reply (code + message) to a verdict outcome.
//
// The hard part of verification is distinguishing three superficially similar
// 5xx cases: a genuinely missing mailbox (undeliverable), a policy/reputation
// block against our egress (unknown — the address may be fine), and transient
// deferral such as greylisting (unknown — retry later). We use the enhanced
// status code (RFC 3463) and message keywords to separate them.
func classifyRCPT(code int, msg string) rcptOutcome {
	enhanced := enhancedStatus(msg)

	switch {
	case code >= 200 && code < 300:
		return rcptOutcome{verdict.StatusDeliverable, verdict.SubValidMailbox, engine.SignalAccepted}

	case code == 552:
		// Mailbox exists but is over quota.
		return rcptOutcome{verdict.StatusRisky, verdict.SubFullMailbox, engine.SignalAccepted}

	case code >= 400 && code < 500:
		// A 4xx is transient: the action is to retry, whether it is greylisting
		// or a soft policy defer. Only an explicit block keyword promotes it to a
		// reputation signal; the enhanced "x.7.x" subject is NOT treated as a
		// block here because greylisting frequently uses 4.7.1.
		if keywordBlock(msg) {
			return rcptOutcome{verdict.StatusUnknown, verdict.SubBlocked, engine.SignalBlocked}
		}
		return rcptOutcome{verdict.StatusUnknown, verdict.SubGreylisted, engine.SignalTempFail}

	case code >= 500 && code < 600:
		// A hard 5xx is either a real missing mailbox or a policy/reputation
		// block. The enhanced "5.7.x" subject or a block keyword indicates the
		// latter (the address may be fine); anything else means no such mailbox.
		if enhancedIsPolicy(enhanced) || keywordBlock(msg) {
			return rcptOutcome{verdict.StatusUnknown, verdict.SubBlocked, engine.SignalBlocked}
		}
		return rcptOutcome{verdict.StatusUndeliverable, verdict.SubMailboxNotFound, engine.SignalMailboxGone}

	default:
		return rcptOutcome{verdict.StatusUnknown, verdict.SubTemporaryFailure, engine.SignalTempFail}
	}
}

// enhancedIsPolicy reports whether an RFC 3463 enhanced status code has the
// "7" (Security or Policy) subject, e.g. "5.7.1".
func enhancedIsPolicy(enhanced string) bool {
	parts := strings.Split(enhanced, ".")
	return len(parts) == 3 && parts[1] == "7"
}

// keywordBlock reports whether a reply message contains a policy/reputation
// rejection keyword, for servers that do not emit enhanced status codes.
func keywordBlock(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range blockKeywords {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// blockKeywords are substrings that indicate a policy/reputation rejection.
var blockKeywords = []string{
	"spam", "block", "blacklist", "blocklist", "denied", "reputation",
	"not allowed", "banned", "policy", "rejected due", "rbl", "dnsbl",
	"access denied", "unsolicited",
}

// enhancedStatus extracts a leading RFC 3463 enhanced status code (e.g. "5.7.1")
// from a reply message, or "" if none is present.
func enhancedStatus(msg string) string {
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[0]
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, p := range parts {
		if p == "" || !isDigits(p) {
			return ""
		}
	}
	return tok
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// confidenceFor assigns a confidence score to a status.
func confidenceFor(s verdict.Status) float64 {
	switch s {
	case verdict.StatusDeliverable, verdict.StatusUndeliverable:
		return 0.9
	case verdict.StatusRisky:
		return 0.5
	default:
		return 0.1
	}
}

// randomLocalPart returns an unpredictable local-part used to detect catch-all
// domains: if the server accepts a RCPT for this almost-certainly-nonexistent
// address, the domain accepts everything.
func randomLocalPart() string {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read essentially never fails; fall back to a fixed probe.
		return "rcptto-probe-000000000000"
	}
	return "rcptto-probe-" + hex.EncodeToString(b[:])
}

// shortResponse trims a reply message for storage in the verdict, avoiding
// oversized or multi-line values.
func shortResponse(msg string) string {
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.TrimSpace(msg)
	const max = 200
	if len(msg) > max {
		return msg[:max]
	}
	return msg
}
