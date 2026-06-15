package ink

import (
	"regexp"
	"time"
)

const (
	maxTimestampAge    = 5 * time.Minute
	maxFutureTimestamp = 30 * time.Second
)

var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// CheckReplay reports whether an INK message should be accepted based on
// timestamp freshness and nonce de-duplication. A message is fresh only within
// [receiverClock - 5m, receiverClock + 30s], its nonce must be 16-256 chars of
// [A-Za-z0-9_-], and a nonce already in previouslySeenNonces is a replay.
func CheckReplay(messageTimestamp, receiverClock, nonce string, previouslySeenNonces []string) bool {
	if n := utf16Len(nonce); n < 16 || n > 256 || !nonceRe.MatchString(nonce) {
		return false
	}
	if len(previouslySeenNonces) > 10000 {
		return false
	}
	// Both timestamps use the strict RFC 3339 / millisecond grammar shared
	// across implementations, so a lenient or oversized value the reference
	// rejects is rejected here too and drift is measured in milliseconds.
	msgMs, ok := ParseInkTimestampMs(messageTimestamp)
	if !ok {
		return false
	}
	recvMs, ok := ParseInkTimestampMs(receiverClock)
	if !ok {
		return false
	}
	driftMs := msgMs - recvMs
	if driftMs > maxFutureTimestamp.Milliseconds() {
		return false
	}
	if -driftMs > maxTimestampAge.Milliseconds() {
		return false
	}
	for _, seen := range previouslySeenNonces {
		if seen == nonce {
			return false
		}
	}
	return true
}
