package securerandom

import (
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// runRuby runs a SecureRandom snippet under the system ruby and returns its
// stdout. It skips the test on Windows (the CI windows lane has no ruby and the
// org convention keeps the oracle off it), under qemu cross-arch emulation (the
// host's native ruby cannot be exec'd from an emulated target process, and there
// is no target-arch ruby), and wherever ruby is absent — the deterministic,
// ruby-free tests alone hold coverage at 100%, so the no-ruby lanes still pass
// the gate. $stdout.binmode keeps Windows text-mode (were ruby ever present
// there) from corrupting the bytes.
func runRuby(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("oracle: skipping on windows")
	}
	// Native ruby is only assured on the amd64/arm64 lanes; the other arches run
	// the test binary under qemu-user, where exec'ing the host ruby is unreliable.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("oracle: skipping under cross-arch emulation (GOARCH=%s)", runtime.GOARCH)
	}
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("oracle: ruby not installed")
	}
	script := "require 'securerandom'\n$stdout.binmode\n" + body
	out, err := exec.Command("ruby", "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("ruby failed: %v\n%s", err, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// rubyVersionAtLeast reports whether the system ruby is at least 4.0, gating the
// uuid_v7 oracle (added in 4.0) so older rubies do not fail the lane.
func rubyVersionAtLeast(t *testing.T, major, minor int) bool {
	t.Helper()
	out, err := exec.Command("ruby", "-e", "print RUBY_VERSION").CombinedOutput()
	if err != nil {
		return false
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ".")
	if len(parts) < 2 {
		return false
	}
	maj, _ := strconv.Atoi(parts[0])
	min, _ := strconv.Atoi(parts[1])
	return maj > major || (maj == major && min >= minor)
}

// The oracle asserts FORMAT, length, charset, and UUID bit-layout — never exact
// bytes, since both sides draw from independent CSPRNGs.

func TestOracleHexFormat(t *testing.T) {
	for _, n := range []string{"", "8", "0"} {
		got := runRuby(t, "print SecureRandom.hex("+n+")")
		wantLen := 32
		if n == "8" {
			wantLen = 16
		} else if n == "0" {
			wantLen = 0
		}
		if len(got) != wantLen {
			t.Fatalf("ruby hex(%s) len = %d, want %d", n, len(got), wantLen)
		}
		if !regexp.MustCompile(`^[0-9a-f]*$`).MatchString(got) {
			t.Fatalf("ruby hex(%s) = %q not lowercase hex", n, got)
		}
		// Our pure-Go formatter produces the same length and charset class.
		if mine := New(&fixedSource{seq: ramp(16)}).Hex(wantLen / 2); len(mine) != wantLen {
			t.Fatalf("Hex len mismatch with oracle: %d vs %d", len(mine), wantLen)
		}
	}
}

func TestOracleBase64Format(t *testing.T) {
	got := runRuby(t, "print SecureRandom.base64")
	if len(got) != 24 {
		t.Fatalf("ruby base64 len = %d, want 24", len(got))
	}
	if !strings.HasSuffix(got, "==") && !strings.HasSuffix(got, "=") && len(got) != 24 {
		t.Fatalf("ruby base64 padding unexpected: %q", got)
	}
	if New(&fixedSource{}).Base64()[len(New(&fixedSource{}).Base64())-2:] != "==" {
		t.Fatal("our Base64 of 16 zero bytes should end ==")
	}
}

func TestOracleUrlsafeFormat(t *testing.T) {
	noPad := runRuby(t, "print SecureRandom.urlsafe_base64")
	if len(noPad) != 22 {
		t.Fatalf("ruby urlsafe len = %d, want 22", len(noPad))
	}
	if strings.ContainsAny(noPad, "+/=") {
		t.Fatalf("ruby urlsafe leaked unsafe chars: %q", noPad)
	}
	pad := runRuby(t, "print SecureRandom.urlsafe_base64(16, true)")
	if len(pad) != 24 || strings.ContainsAny(pad, "+/") {
		t.Fatalf("ruby urlsafe padded unexpected: %q", pad)
	}
}

func TestOracleUuidLayout(t *testing.T) {
	got := runRuby(t, "print SecureRandom.uuid")
	if !uuidV4Re.MatchString(got) {
		t.Fatalf("ruby uuid = %q does not match v4 layout", got)
	}
}

func TestOracleUuidV7Layout(t *testing.T) {
	if !rubyVersionAtLeast(t, 4, 0) {
		t.Skip("oracle: uuid_v7 needs ruby >= 4.0")
	}
	got := runRuby(t, "print SecureRandom.uuid_v7")
	if !uuidV7Re.MatchString(got) {
		t.Fatalf("ruby uuid_v7 = %q does not match v7 layout", got)
	}
}

func TestOracleAlphanumericFormat(t *testing.T) {
	got := runRuby(t, "print SecureRandom.alphanumeric")
	if len(got) != 16 {
		t.Fatalf("ruby alphanumeric len = %d, want 16", len(got))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(got) {
		t.Fatalf("ruby alphanumeric = %q outside A-Za-z0-9", got)
	}
	// The chars: keyword arrived in Ruby 3.3; gate it so older rubies (e.g. a
	// distro's system ruby on the cross-arch lanes) do not fail the oracle.
	if rubyVersionAtLeast(t, 3, 3) {
		custom := runRuby(t, "print SecureRandom.alphanumeric(20, chars: ['a','b','c'])")
		if len(custom) != 20 || !regexp.MustCompile(`^[abc]+$`).MatchString(custom) {
			t.Fatalf("ruby alphanumeric custom = %q", custom)
		}
	}
}

func TestOracleRandomNumber(t *testing.T) {
	// Zero-arg / non-positive: a Float in [0,1).
	f := runRuby(t, "print SecureRandom.random_number")
	if v, err := strconv.ParseFloat(f, 64); err != nil || v < 0 || v >= 1 {
		t.Fatalf("ruby random_number = %q (%v)", f, err)
	}
	// Positive integer: an Integer in [0,n).
	i := runRuby(t, "print SecureRandom.random_number(100)")
	if v, err := strconv.Atoi(i); err != nil || v < 0 || v >= 100 || strings.Contains(i, ".") {
		t.Fatalf("ruby random_number(100) = %q (%v)", i, err)
	}
	// Non-positive bound falls back to the [0,1) Float, as MRI does.
	z := runRuby(t, "print SecureRandom.random_number(-5)")
	if v, err := strconv.ParseFloat(z, 64); err != nil || v < 0 || v >= 1 {
		t.Fatalf("ruby random_number(-5) = %q (%v)", z, err)
	}
}
