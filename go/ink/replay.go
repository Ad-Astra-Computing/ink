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
	if n := utf16Len(messageTimestamp); n == 0 || n > 64 {
		return false
	}
	if n := utf16Len(receiverClock); n == 0 || n > 64 {
		return false
	}
	msgTime, err := time.Parse(time.RFC3339Nano, messageTimestamp)
	if err != nil {
		return false
	}
	recvTime, err := time.Parse(time.RFC3339Nano, receiverClock)
	if err != nil {
		return false
	}
	drift := msgTime.Sub(recvTime)
	if drift > maxFutureTimestamp {
		return false
	}
	if -drift > maxTimestampAge {
		return false
	}
	for _, seen := range previouslySeenNonces {
		if seen == nonce {
			return false
		}
	}
	return true
}
