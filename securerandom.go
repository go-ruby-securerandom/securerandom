// Package securerandom is a pure-Go (no cgo) reimplementation of Ruby's
// [SecureRandom] module — the formatting layer MRI 4.0.5 layers over a
// cryptographically secure entropy source.
//
// The randomness comes from an injectable [RandSource] (the default is
// crypto/rand); everything else — hex, base64, URL-safe base64, UUIDs, the
// alphanumeric/choose string builder, and the random_number distribution — is
// deterministic, interpreter-independent formatting, so it lives here as pure
// Go. The hex path is accelerated with [github.com/go-simd/hex] and the base64
// paths with [github.com/go-simd/base64]; both are byte-identical drop-ins for
// the standard library, so the output matches MRI exactly.
//
// Because the default source is cryptographically random, callers (and the
// tests) assert on the FORMAT, length, charset, and UUID bit-layout, not on
// exact bytes. Feed a fixed [RandSource] when a deterministic result is needed.
//
// [SecureRandom]: https://docs.ruby-lang.org/en/master/SecureRandom.html
package securerandom

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	"math/big"

	simdbase64 "github.com/go-simd/base64"
	simdhex "github.com/go-simd/hex"
)

// RandSource is the entropy seam SecureRandom draws from. The default is
// crypto/rand (via [DefaultSource]); a fixed implementation makes the formatters
// deterministic for testing. Read fills p with len(p) random bytes and returns
// an error only on a broken environment.
type RandSource interface {
	Read(p []byte) (int, error)
}

// DefaultSource is the package-level entropy source used by the top-level
// functions. It defaults to crypto/rand. Replace it (and restore it) to make the
// formatters deterministic; the per-call API on [SecureRandom] is preferred for
// that, as it is concurrency-safe.
var DefaultSource RandSource = cryptoSource{}

// cryptoSource adapts crypto/rand to RandSource. crypto/rand.Read never returns
// a short read, and only fails on a broken platform.
type cryptoSource struct{}

func (cryptoSource) Read(p []byte) (int, error) { return cryptorand.Read(p) }

// SecureRandom is a SecureRandom generator bound to a specific entropy source.
// The zero value is not usable; build one with [New]. Every method mirrors the
// matching MRI 4.0.5 SecureRandom method.
type SecureRandom struct {
	src RandSource
}

// New returns a [SecureRandom] drawing from src. A nil src uses crypto/rand.
func New(src RandSource) *SecureRandom {
	if src == nil {
		src = cryptoSource{}
	}
	return &SecureRandom{src: src}
}

// pkg is the SecureRandom backing the package-level functions; it reads
// DefaultSource on every call so swapping DefaultSource takes effect.
var pkg = &SecureRandom{src: defaultSourceFunc{}}

// defaultSourceFunc forwards to whatever DefaultSource currently is.
type defaultSourceFunc struct{}

func (defaultSourceFunc) Read(p []byte) (int, error) { return DefaultSource.Read(p) }

// randomBytes returns n cryptographically random bytes. crypto/rand never fails
// on a healthy platform, so a read error is an unrecoverable, broken-environment
// condition and panics, exactly as MRI raises.
func (s *SecureRandom) randomBytes(n int) []byte {
	if n < 0 {
		n = 0
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(s.src, b); err != nil {
		panic(err)
	}
	return b
}

// defaultN returns n when present (the first element of opt), else def. It
// mirrors MRI treating a nil/absent count as the default. A negative count is
// clamped to zero, matching MRI's empty result for n <= 0 on the byte-producing
// methods.
func defaultN(def int, opt []int) int {
	if len(opt) > 0 {
		return opt[0]
	}
	return def
}

// RandomBytes returns n random bytes (default 16) as a []byte. This is MRI's
// SecureRandom.random_bytes; in Ruby the result is an ASCII-8BIT (binary) String
// of bytesize n, which maps to a Go byte slice.
func (s *SecureRandom) RandomBytes(n ...int) []byte {
	return s.randomBytes(defaultN(16, n))
}

// Hex returns 2*n hexadecimal characters built from n random bytes (default 16,
// so 32 chars). This is MRI's SecureRandom.hex; the encoding is the SIMD
// drop-in for encoding/hex.
func (s *SecureRandom) Hex(n ...int) string {
	return simdhex.EncodeToString(s.randomBytes(defaultN(16, n)))
}

// Base64 returns the standard padded base64 of n random bytes (default 16). This
// is MRI's SecureRandom.base64; the encoding is the SIMD drop-in for
// base64.StdEncoding.
func (s *SecureRandom) Base64(n ...int) string {
	return simdbase64.EncodeToString(s.randomBytes(defaultN(16, n)))
}

// UrlsafeBase64 returns the URL- and filename-safe base64 of n random bytes
// (default 16). MRI omits the padding by default; pass padding=true to keep it.
// This is MRI's SecureRandom.urlsafe_base64.
func (s *SecureRandom) UrlsafeBase64(n int, padding bool) string {
	if n < 0 {
		n = 0
	}
	std := simdbase64.EncodeToString(s.randomBytes(n)) // padded StdEncoding
	return urlsafe(std, padding)
}

// urlsafe rewrites standard padded base64 into the URL-safe alphabet (+ -> -,
// / -> _) and, unless padding is requested, strips the trailing '=' padding,
// matching base64.RawURLEncoding / URLEncoding without re-encoding.
func urlsafe(std string, padding bool) string {
	b := []byte(std)
	end := len(b)
	for i := 0; i < end; i++ {
		switch b[i] {
		case '+':
			b[i] = '-'
		case '/':
			b[i] = '_'
		}
	}
	if !padding {
		for end > 0 && b[end-1] == '=' {
			end--
		}
	}
	return string(b[:end])
}

// Uuid returns a random RFC 4122 version-4 UUID, the
// xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx form where the version nibble is 4 and the
// variant nibble y is one of 8, 9, a, b. This is MRI's SecureRandom.uuid.
func (s *SecureRandom) Uuid() string {
	b := s.randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10x
	return formatUUID(b)
}

// UuidV7 returns a random UUID version 7: a 48-bit big-endian Unix-milliseconds
// timestamp followed by random bits, with the version nibble 7 and the 10x
// variant. This is MRI 4.0's SecureRandom.uuid_v7. The timestamp comes from the
// injected clock (default: time.Now) so it is deterministic under test.
func (s *SecureRandom) UuidV7() string {
	b := s.randomBytes(16)
	ms := s.nowUnixMilli()
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10x
	return formatUUID(b)
}

// hexDigits maps a nibble to its lowercase hex character.
const hexDigits = "0123456789abcdef"

// formatUUID renders the 16-byte b as the canonical 8-4-4-4-12 hyphenated,
// lowercase UUID string. It writes directly into a fixed 36-byte buffer rather
// than going through fmt, which keeps the hot path allocation-light.
func formatUUID(b []byte) string {
	var out [36]byte
	pos := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[pos] = '-'
			pos++
		}
		out[pos] = hexDigits[b[i]>>4]
		out[pos+1] = hexDigits[b[i]&0x0f]
		pos += 2
	}
	return string(out[:])
}

// Alphanumeric returns an n-character (default 16) random string. With no chars
// it draws from MRI's default A-Z a-z 0-9 alphabet; pass an explicit chars set to
// draw from it instead. This is MRI's SecureRandom.alphanumeric, and it uses the
// same #choose construction so the character distribution matches.
func (s *SecureRandom) Alphanumeric(n int, chars ...string) string {
	if n < 0 {
		n = 0
	}
	src := chars
	if len(src) == 0 {
		src = alphanumericChars
	}
	return s.choose(src, n)
}

// alphanumericChars is MRI's ALPHANUMERIC source list: A-Z, then a-z, then 0-9.
var alphanumericChars = buildAlphanumeric()

func buildAlphanumeric() []string {
	out := make([]string, 0, 62)
	for c := byte('A'); c <= 'Z'; c++ {
		out = append(out, string(c))
	}
	for c := byte('a'); c <= 'z'; c++ {
		out = append(out, string(c))
	}
	for c := byte('0'); c <= '9'; c++ {
		out = append(out, string(c))
	}
	return out
}

// choose builds an n-character string by drawing base-len(source) digits from
// random_number, exactly like MRI's Random::Formatter#choose: it batches m
// characters per random_number(limit) draw where limit is the largest power of
// size that fits in 0x100000000, then emits a final partial batch. With a source
// of size <= 1 there is no batch large enough and MRI loops forever; we instead
// return the only reachable string (n copies of the single element, or "" for an
// empty source), which is the limit of MRI's intent without the hang.
func (s *SecureRandom) choose(source []string, n int) string {
	size := len(source)
	if n <= 0 || size == 0 {
		return ""
	}
	if size == 1 {
		out := make([]byte, 0, n*len(source[0]))
		for i := 0; i < n; i++ {
			out = append(out, source[0]...)
		}
		return string(out)
	}
	bigSize := int64(size)
	m := 1
	limit := bigSize
	for limit*bigSize <= 0x100000000 {
		limit *= bigSize
		m++
	}
	var result []byte
	for m <= n {
		result = appendDigits(result, source, s.randomNumberInt(limit), bigSize, m)
		n -= m
	}
	if n > 0 {
		result = appendDigits(result, source, s.randomNumberInt(limit), bigSize, n)
	}
	return string(result)
}

// appendDigits appends the count base-size digits of rs (least-significant
// first, exactly like Integer#digits) mapped through source, zero-padding the
// high digits when rs has fewer than count digits — the behaviour of MRI's
// values_at(*is) after the (m-is.length).times { is << 0 } padding.
func appendDigits(dst []byte, source []string, rs, size int64, count int) []byte {
	digits := make([]int64, count)
	v := rs
	for i := 0; i < count; i++ {
		digits[i] = v % size // 0 once v hits 0 -> the trailing zero padding
		v /= size
	}
	for _, d := range digits {
		dst = append(dst, source[d]...)
	}
	return dst
}

// RandomNumber mirrors MRI's SecureRandom.random_number. With no argument, or a
// non-positive one, it returns a Float in [0, 1) (as the second return). With a
// positive integer it returns an Integer in [0, n) (first return, isInt true).
// With a positive float it returns a Float in [0, n). Callers that know the
// argument type may prefer [SecureRandom.RandomFloat] / [SecureRandom.RandomInt].
func (s *SecureRandom) RandomNumber(n ...float64) (i int64, f float64, isInt bool) {
	if len(n) == 0 || n[0] <= 0 {
		return 0, s.RandomFloat(), false
	}
	return 0, n[0] * s.RandomFloat(), false
}

// RandomInt returns a uniform random integer in [0, n) for n > 0, and 0 for
// n <= 0. This is the Integer branch of MRI's SecureRandom.random_number(n).
func (s *SecureRandom) RandomInt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return s.randomNumberInt(n)
}

// RandomFloat returns a uniform random float64 in [0, 1), built from 53 random
// bits exactly as MRI's Random#random_number with no bound. This is the
// zero-argument branch of SecureRandom.random_number.
func (s *SecureRandom) RandomFloat() float64 {
	return float64(binary.BigEndian.Uint64(s.randomBytes(8))>>11) / (1 << 53)
}

// randomNumberInt returns a uniform random integer in [0, n) for n > 0 using
// rejection sampling over whole random bytes, so the distribution is unbiased
// for any n (the same guarantee crypto/rand.Int gives, without depending on it).
func (s *SecureRandom) randomNumberInt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(n)
	// Number of bytes needed to cover n, plus rejection of the biased tail. n > 0
	// here, so bits >= 1 and nbytes >= 1.
	nbytes := (max.BitLen() + 7) / 8
	// The largest multiple of n representable in nbytes*8 bits; values at or
	// above it are rejected to keep the result uniform.
	limit := new(big.Int).Lsh(big.NewInt(1), uint(nbytes*8))
	limit.Sub(limit, new(big.Int).Mod(limit, max))
	v := new(big.Int)
	for {
		v.SetBytes(s.randomBytes(nbytes))
		if v.Cmp(limit) < 0 {
			return new(big.Int).Mod(v, max).Int64()
		}
	}
}

// --- package-level convenience functions (use DefaultSource) ---

// RandomBytes calls [SecureRandom.RandomBytes] on the default source.
func RandomBytes(n ...int) []byte { return pkg.RandomBytes(n...) }

// Hex calls [SecureRandom.Hex] on the default source.
func Hex(n ...int) string { return pkg.Hex(n...) }

// Base64 calls [SecureRandom.Base64] on the default source.
func Base64(n ...int) string { return pkg.Base64(n...) }

// UrlsafeBase64 calls [SecureRandom.UrlsafeBase64] on the default source.
func UrlsafeBase64(n int, padding bool) string { return pkg.UrlsafeBase64(n, padding) }

// Uuid calls [SecureRandom.Uuid] on the default source.
func Uuid() string { return pkg.Uuid() }

// UuidV7 calls [SecureRandom.UuidV7] on the default source.
func UuidV7() string { return pkg.UuidV7() }

// Alphanumeric calls [SecureRandom.Alphanumeric] on the default source.
func Alphanumeric(n int, chars ...string) string { return pkg.Alphanumeric(n, chars...) }

// RandomNumber calls [SecureRandom.RandomNumber] on the default source.
func RandomNumber(n ...float64) (int64, float64, bool) { return pkg.RandomNumber(n...) }

// RandomInt calls [SecureRandom.RandomInt] on the default source.
func RandomInt(n int64) int64 { return pkg.RandomInt(n) }

// RandomFloat calls [SecureRandom.RandomFloat] on the default source.
func RandomFloat() float64 { return pkg.RandomFloat() }
