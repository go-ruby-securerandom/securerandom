package securerandom

import "time"

// nowFunc is the clock UuidV7 reads for the millisecond timestamp. It is a
// package var so tests can pin it to a fixed instant and assert the UUID's
// timestamp field deterministically. The per-generator method reads it through
// this indirection rather than calling time.Now directly.
var nowFunc = time.Now

// nowUnixMilli returns the current Unix time in milliseconds from the (possibly
// overridden) clock, truncated to the 48 bits UUIDv7 stores.
func (s *SecureRandom) nowUnixMilli() int64 {
	return nowFunc().UnixMilli() & 0xFFFFFFFFFFFF
}
