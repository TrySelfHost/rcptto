package web

import (
	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// Bucket groups results by what the operator should actually *do* with them,
// which is not the same as the four-valued verdict.
//
// The important distinction is between "we checked and it failed" and "we did
// not check". A consumer list is frequently majority Gmail/Yahoo/Microsoft,
// which provider policy skips deliberately — probing them is unreliable and
// costs reputation for no signal. Folding those into a risky or undeliverable
// pile would tell a client to discard most of their list for no reason, so they
// get their own bucket.
type Bucket string

const (
	// BucketAll is every result, unfiltered.
	BucketAll Bucket = "all"
	// BucketSafe is addresses worth sending to. Role accounts (info@, sales@)
	// are included: they are real, deliverable mailboxes, and for outreach they
	// are frequently the intended recipient.
	BucketSafe Bucket = "safe"
	// BucketRisky is real-but-questionable addresses — catch-all domains,
	// disposable providers, full mailboxes — where delivery may succeed but
	// carries a cost.
	BucketRisky Bucket = "risky"
	// BucketUndeliverable is addresses that will not accept mail and should be
	// removed from the source list.
	BucketUndeliverable Bucket = "undeliverable"
	// BucketSkipped is addresses deliberately not probed by provider policy.
	// These are not failures; a client may well want to send to them.
	BucketSkipped Bucket = "skipped"
	// BucketRetry is addresses whose check was inconclusive — greylisting, a
	// temporary failure, or a block against our egress. Worth re-running.
	BucketRetry Bucket = "retry"
)

// bucketLabels are the human names shown on download controls.
var bucketLabels = map[Bucket]string{
	BucketAll:           "All results",
	BucketSafe:          "Safe to send",
	BucketRisky:         "Risky",
	BucketUndeliverable: "Do not send",
	BucketSkipped:       "Not checked",
	BucketRetry:         "Retry later",
}

// bucketOrder is the order buckets are presented, most useful first.
var bucketOrder = []Bucket{BucketSafe, BucketRisky, BucketSkipped, BucketRetry, BucketUndeliverable, BucketAll}

// validBucket reports whether b is a known bucket.
func validBucket(b Bucket) bool {
	_, ok := bucketLabels[b]
	return ok
}

// classify assigns a verdict to a bucket. Sub-status is checked before status
// because the two special cases — role accounts and policy skips — are both
// carried as a sub-status under a broader verdict.
func classify(v verdict.Verdict) Bucket {
	switch v.SubStatus {
	case verdict.SubRoleAccount:
		return BucketSafe
	case verdict.SubProviderSkipped:
		return BucketSkipped
	}
	switch v.Status {
	case verdict.StatusDeliverable:
		return BucketSafe
	case verdict.StatusRisky:
		return BucketRisky
	case verdict.StatusUndeliverable:
		return BucketUndeliverable
	default:
		return BucketRetry
	}
}

// bucketCounts derives per-bucket totals from aggregate stats, so download
// controls can show counts without a second pass over the results.
//
// This mirrors classify and must be kept consistent with it; the two are in the
// same file for exactly that reason, and a test asserts they agree.
func bucketCounts(stats store.JobStats) map[Bucket]int {
	role := stats.BySubStatus[string(verdict.SubRoleAccount)]
	skipped := stats.BySubStatus[string(verdict.SubProviderSkipped)]

	// Both special cases are emitted under the risky status: the verifier
	// downgrades a live role account to risky/role_account, and a policy skip
	// to risky/provider_skipped. So both are subtracted from risky, not from
	// unknown.
	counts := map[Bucket]int{
		BucketAll:           stats.Total,
		BucketSafe:          stats.ByStatus["deliverable"] + role,
		BucketRisky:         stats.ByStatus["risky"] - role - skipped,
		BucketUndeliverable: stats.ByStatus["undeliverable"],
		BucketSkipped:       skipped,
		BucketRetry:         stats.ByStatus["unknown"],
	}
	// Guard against a sub-status appearing under an unexpected status, which
	// would otherwise show a negative count.
	for k, v := range counts {
		if v < 0 {
			counts[k] = 0
		}
	}
	return counts
}

// bucketView is one download control.
type bucketView struct {
	Bucket Bucket
	Label  string
	Count  int
}

// bucketViews builds the download controls in presentation order.
func bucketViews(stats store.JobStats) []bucketView {
	counts := bucketCounts(stats)
	out := make([]bucketView, 0, len(bucketOrder))
	for _, b := range bucketOrder {
		out = append(out, bucketView{Bucket: b, Label: bucketLabels[b], Count: counts[b]})
	}
	return out
}

// filterBucket returns only the results belonging to b.
func filterBucket(results []store.Result, b Bucket) []store.Result {
	if b == BucketAll {
		return results
	}
	out := make([]store.Result, 0, len(results))
	for _, r := range results {
		if classify(r.Verdict) == b {
			out = append(out, r)
		}
	}
	return out
}
