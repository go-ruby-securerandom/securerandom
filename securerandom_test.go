package securerandom

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixedSource is a deterministic RandSource: it returns the bytes of seq,
// cycling, so tests can assert exact formatted output. A zero-length seq yields
// all-zero bytes.
type fixedSource struct {
	seq []byte
	pos int
}

func (f *fixedSource) Read(p []byte) (int, error) {
	for i := range p {
		if len(f.seq) == 0 {
			p[i] = 0
			continue
		}
		p[i] = f.seq[f.pos%len(f.seq)]
		f.pos++
	}
	return len(p), nil
}

// errSource always fails, to drive the panic-on-broken-environment branches.
type errSource struct{}

var errBoom = errors.New("boom")

func (errSource) Read(p []byte) (int, error) { return 0, errBoom }

// ramp returns 0,1,2,...,n-1 as a byte slice, a handy non-trivial fixed source.
func ramp(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestRandomBytes(t *testing.T) {
	s := New(&fixedSource{seq: ramp(4)}) // 0,1,2,3,0,1,2,3,...
	if got := s.RandomBytes(); len(got) != 16 {
		t.Fatalf("default len = %d, want 16", len(got))
	}
	got := New(&fixedSource{seq: []byte{0xab}}).RandomBytes(3)
	if !bytes.Equal(got, []byte{0xab, 0xab, 0xab}) {
		t.Fatalf("RandomBytes(3) = %x", got)
	}
	// Negative count clamps to empty, matching MRI's empty result.
	if got := s.RandomBytes(-5); len(got) != 0 {
		t.Fatalf("RandomBytes(-5) len = %d, want 0", len(got))
	}
}

func TestHex(t *testing.T) {
	s := New(&fixedSource{seq: []byte{0xde, 0xad, 0xbe, 0xef}})
	if got, want := s.Hex(4), "deadbeef"; got != want {
		t.Fatalf("Hex(4) = %q, want %q", got, want)
	}
	if got := s.Hex(); len(got) != 32 {
		t.Fatalf("Hex() len = %d, want 32", len(got))
	}
	// Matches the standard library byte-for-byte.
	in := ramp(20)
	if New(&fixedSource{seq: in}).Hex(20) != hex.EncodeToString(in) {
		t.Fatal("Hex disagrees with encoding/hex")
	}
}

func TestBase64(t *testing.T) {
	in := ramp(16)
	want := base64.StdEncoding.EncodeToString(in)
	if got := New(&fixedSource{seq: in}).Base64(16); got != want {
		t.Fatalf("Base64 = %q, want %q", got, want)
	}
	if got := New(&fixedSource{}).Base64(); len(got) != 24 {
		t.Fatalf("Base64() len = %d, want 24", len(got))
	}
}

func TestUrlsafeBase64(t *testing.T) {
	// A payload that forces both '+' -> '-' and '/' -> '_' substitutions.
	in := []byte{0xfb, 0xff, 0xbf, 0xfe}
	s := func() *SecureRandom { return New(&fixedSource{seq: in}) }
	noPad := s().UrlsafeBase64(4, false)
	if want := base64.RawURLEncoding.EncodeToString(in); noPad != want {
		t.Fatalf("UrlsafeBase64 no-pad = %q, want %q", noPad, want)
	}
	if strings.ContainsAny(noPad, "+/=") {
		t.Fatalf("UrlsafeBase64 no-pad %q contains +/ or =", noPad)
	}
	pad := s().UrlsafeBase64(4, true)
	if want := base64.URLEncoding.EncodeToString(in); pad != want {
		t.Fatalf("UrlsafeBase64 pad = %q, want %q", pad, want)
	}
	// Default count is 16 -> 22 chars unpadded.
	if got := New(&fixedSource{}).UrlsafeBase64(16, false); len(got) != 22 {
		t.Fatalf("default urlsafe len = %d, want 22", len(got))
	}
	// Negative count -> empty.
	if got := New(&fixedSource{}).UrlsafeBase64(-1, false); got != "" {
		t.Fatalf("UrlsafeBase64(-1) = %q, want empty", got)
	}
}

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var uuidV7Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUuid(t *testing.T) {
	// All-zero entropy isolates the forced version/variant nibbles.
	if got, want := New(&fixedSource{}).Uuid(), "00000000-0000-4000-8000-000000000000"; got != want {
		t.Fatalf("Uuid() = %q, want %q", got, want)
	}
	// All-ones entropy: variant nibble must be masked into 8..b.
	got := New(&fixedSource{seq: []byte{0xff}}).Uuid()
	if !uuidV4Re.MatchString(got) {
		t.Fatalf("Uuid() = %q does not match v4 layout", got)
	}
	if got[14] != '4' {
		t.Fatalf("version nibble = %c, want 4", got[14])
	}
}

func TestUuidV7(t *testing.T) {
	defer func(prev func() time.Time) { nowFunc = prev }(nowFunc)
	// Pin the clock: 0x0102030405 ms since epoch.
	fixedMs := int64(0x0102030405)
	nowFunc = func() time.Time { return time.UnixMilli(fixedMs) }
	got := New(&fixedSource{seq: []byte{0xff}}).UuidV7()
	if !uuidV7Re.MatchString(got) {
		t.Fatalf("UuidV7() = %q does not match v7 layout", got)
	}
	// First 12 hex chars (6 bytes) encode the 48-bit timestamp, big-endian.
	if want := "000102030405"; got[:8]+got[9:13] != want {
		t.Fatalf("timestamp field = %q, want %q", got[:8]+got[9:13], want)
	}
	if got[14] != '7' {
		t.Fatalf("version nibble = %c, want 7", got[14])
	}
}

func TestAlphanumericDefault(t *testing.T) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	got := New(&fixedSource{seq: ramp(8)}).Alphanumeric(40)
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}
	for _, c := range got {
		if !strings.ContainsRune(charset, c) {
			t.Fatalf("char %q outside default alphabet", c)
		}
	}
}

func TestAlphanumericDefaultCount(t *testing.T) {
	if got := New(&fixedSource{seq: ramp(3)}).Alphanumeric(0); got != "" {
		t.Fatalf("Alphanumeric(0) = %q, want empty", got)
	}
	if got := New(&fixedSource{seq: ramp(3)}).Alphanumeric(-4); got != "" {
		t.Fatalf("Alphanumeric(-4) = %q, want empty", got)
	}
	// 16 is the MRI default count; call the convenience helper to assert it.
	if got := len(Alphanumeric(16)); got != 16 {
		t.Fatalf("Alphanumeric(16) len = %d, want 16", got)
	}
}

func TestAlphanumericCustomChars(t *testing.T) {
	// Two-element source exercises the full #choose batching path.
	got := New(&fixedSource{seq: ramp(8)}).Alphanumeric(20, "a", "b")
	if len(got) != 20 {
		t.Fatalf("len = %d, want 20", len(got))
	}
	for _, c := range got {
		if c != 'a' && c != 'b' {
			t.Fatalf("char %q outside {a,b}", c)
		}
	}
	// Multi-character source elements are emitted whole, like MRI values_at.join.
	multi := New(&fixedSource{seq: ramp(8)}).Alphanumeric(4, "ab", "cd")
	for i := 0; i < len(multi); i += 2 {
		if multi[i:i+2] != "ab" && multi[i:i+2] != "cd" {
			t.Fatalf("chunk %q outside {ab,cd}", multi[i:i+2])
		}
	}
}

func TestAlphanumericSingleAndEmptyChars(t *testing.T) {
	// Single-element source: MRI loops forever; we return n copies.
	if got := New(&fixedSource{}).Alphanumeric(5, "x"); got != "xxxxx" {
		t.Fatalf("single-char = %q, want xxxxx", got)
	}
	if got := New(&fixedSource{}).Alphanumeric(3, "ab"); got != "ababab" {
		t.Fatalf("single multi-char = %q, want ababab", got)
	}
	// Empty source -> empty result regardless of n.
	if got := New(&fixedSource{}).choose(nil, 5); got != "" {
		t.Fatalf("empty source = %q, want empty", got)
	}
}

func TestChooseBatchTail(t *testing.T) {
	// A large request with a multi-element source crosses several full m-batches
	// and a partial tail, covering both loops in choose.
	src := make([]string, 7)
	for i := range src {
		src[i] = string(rune('0' + i))
	}
	got := New(&fixedSource{seq: ramp(64)}).Alphanumeric(50, src...)
	if len(got) != 50 {
		t.Fatalf("len = %d, want 50", len(got))
	}
	for _, c := range got {
		if c < '0' || c > '6' {
			t.Fatalf("char %q outside 0..6", c)
		}
	}
}

func TestRandomNumber(t *testing.T) {
	s := New(&fixedSource{seq: ramp(8)})
	// No argument -> Float in [0,1), isInt false.
	_, f, isInt := s.RandomNumber()
	if isInt || f < 0 || f >= 1 {
		t.Fatalf("RandomNumber() = (%v, isInt=%v), want float in [0,1)", f, isInt)
	}
	// Non-positive bound -> Float in [0,1).
	for _, n := range []float64{0, -5, -0.0} {
		if _, f, isInt := s.RandomNumber(n); isInt || f < 0 || f >= 1 {
			t.Fatalf("RandomNumber(%v) = (%v, %v)", n, f, isInt)
		}
	}
	// Positive float -> Float in [0,n).
	_, f, isInt = s.RandomNumber(100.0)
	if isInt || f < 0 || f >= 100 {
		t.Fatalf("RandomNumber(100.0) = (%v, %v)", f, isInt)
	}
}

func TestRandomInt(t *testing.T) {
	s := New(&fixedSource{seq: ramp(8)})
	for i := 0; i < 50; i++ {
		if v := s.RandomInt(7); v < 0 || v >= 7 {
			t.Fatalf("RandomInt(7) = %d, out of [0,7)", v)
		}
	}
	if v := s.RandomInt(0); v != 0 {
		t.Fatalf("RandomInt(0) = %d, want 0", v)
	}
	if v := s.RandomInt(-3); v != 0 {
		t.Fatalf("RandomInt(-3) = %d, want 0", v)
	}
	if v := s.RandomInt(1); v != 0 {
		t.Fatalf("RandomInt(1) = %d, want 0", v)
	}
	// Internal helper guard for n<=0 (unreachable via RandomInt but covered).
	if v := s.randomNumberInt(0); v != 0 {
		t.Fatalf("randomNumberInt(0) = %d, want 0", v)
	}
}

func TestRandomIntRejection(t *testing.T) {
	// A source whose first byte lands in the rejected tail forces the loop to
	// draw again, exercising the rejection branch. n=3 over one byte rejects
	// values >= 255 (256 - 256%3 = 255), so byte 0xff is rejected then 0x01
	// accepted.
	s := New(&fixedSource{seq: []byte{0xff, 0x01}})
	if v := s.RandomInt(3); v != 1 {
		t.Fatalf("RandomInt(3) = %d, want 1 after rejecting 0xff", v)
	}
}

func TestRandomFloat(t *testing.T) {
	if got := New(&fixedSource{}).RandomFloat(); got != 0 {
		t.Fatalf("all-zero RandomFloat = %v, want 0", got)
	}
	if got := New(&fixedSource{seq: []byte{0xff}}).RandomFloat(); got < 0 || got >= 1 {
		t.Fatalf("RandomFloat = %v, out of [0,1)", got)
	}
}

func TestPanicOnBrokenSource(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("%s did not panic on broken source", name)
			} else if !errors.Is(r.(error), errBoom) {
				t.Fatalf("%s panic = %v, want errBoom", name, r)
			}
		}()
		fn()
	}
	s := New(errSource{})
	mustPanic("RandomBytes", func() { s.RandomBytes(4) })
	mustPanic("Hex", func() { s.Hex() })
	mustPanic("RandomFloat", func() { s.RandomFloat() })
	mustPanic("RandomInt", func() { s.RandomInt(10) })
	mustPanic("Uuid", func() { s.Uuid() })
	mustPanic("UuidV7", func() { s.UuidV7() })
	mustPanic("Alphanumeric", func() { s.Alphanumeric(5, "a", "b") })
}

func TestNewNilSource(t *testing.T) {
	// A nil source falls back to crypto/rand; just exercise it.
	if len(New(nil).RandomBytes(4)) != 4 {
		t.Fatal("New(nil) did not produce 4 bytes")
	}
}

func TestPackageLevelDefaultSource(t *testing.T) {
	defer func(prev RandSource) { DefaultSource = prev }(DefaultSource)
	DefaultSource = &fixedSource{seq: []byte{0xde, 0xad, 0xbe, 0xef}}
	if got := Hex(4); got != "deadbeef" {
		t.Fatalf("Hex(4) via DefaultSource = %q", got)
	}
	if len(RandomBytes(8)) != 8 {
		t.Fatal("RandomBytes(8) wrong length")
	}
	if len(Base64()) != 24 {
		t.Fatal("Base64() wrong length")
	}
	if strings.ContainsAny(UrlsafeBase64(16, false), "+/=") {
		t.Fatal("UrlsafeBase64 leaked unsafe chars")
	}
	if !uuidV4Re.MatchString(Uuid()) {
		t.Fatal("package Uuid bad layout")
	}
	if !uuidV7Re.MatchString(UuidV7()) {
		t.Fatal("package UuidV7 bad layout")
	}
	if v := RandomInt(5); v < 0 || v >= 5 {
		t.Fatalf("package RandomInt = %d", v)
	}
	if f := RandomFloat(); f < 0 || f >= 1 {
		t.Fatalf("package RandomFloat = %v", f)
	}
	if _, f, isInt := RandomNumber(); isInt || f < 0 || f >= 1 {
		t.Fatalf("package RandomNumber = (%v, %v)", f, isInt)
	}
}

func TestCryptoSourceDefault(t *testing.T) {
	// Directly exercise the default crypto/rand-backed source.
	if len(New(cryptoSource{}).RandomBytes(16)) != 16 {
		t.Fatal("cryptoSource did not yield 16 bytes")
	}
	var b [4]byte
	if n, err := (cryptoSource{}).Read(b[:]); err != nil || n != 4 {
		t.Fatalf("cryptoSource.Read = (%d, %v)", n, err)
	}
}
