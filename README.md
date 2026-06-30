<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-securerandom/brand/main/social/go-ruby-securerandom-securerandom.png" alt="go-ruby-securerandom/securerandom" width="720"></p>

# securerandom — go-ruby-securerandom

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-securerandom.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's
[SecureRandom](https://docs.ruby-lang.org/en/master/SecureRandom.html)** — the
formatting layer MRI 4.0.5 builds over a cryptographically secure entropy source.
`Hex`, `Base64`, `UrlsafeBase64`, `RandomBytes`, `Uuid` / `UuidV7`,
`Alphanumeric`, and `RandomNumber` all produce byte-identical output to MRI,
**without any Ruby runtime**.

It is the `SecureRandom` backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module with no dependency on the Ruby runtime — a sibling
of [go-ruby-regexp](https://github.com/go-ruby-regexp/regexp),
[go-ruby-erb](https://github.com/go-ruby-erb/erb), and
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml).

> **Randomness vs. formatting.** The randomness comes from an injectable
> [`RandSource`](#the-randsource-seam) (the default is `crypto/rand`); everything
> else — hex/base64/URL-safe encoding, the UUID bit-layout, the `#choose` string
> builder behind `Alphanumeric`, and the `random_number` distribution — is
> deterministic, interpreter-independent formatting and lives here as pure Go.
> The hex path runs on [go-simd/hex](https://github.com/go-simd/hex) and the
> base64 paths on [go-simd/base64](https://github.com/go-simd/base64), both
> byte-identical SIMD drop-ins for the standard library.

## Features

Faithful port of `SecureRandom`, validated against the `ruby` binary on every
supported platform:

- **`Hex(n)` / `Base64(n)` / `UrlsafeBase64(n, padding)` / `RandomBytes(n)`** —
  the encoders, with MRI's defaults (`n = 16`; URL-safe base64 unpadded unless
  asked). Hex is SIMD-accelerated via go-simd/hex; the base64 family via
  go-simd/base64.
- **`Uuid()`** — an RFC 4122 version-4 UUID with the exact
  `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` layout (version nibble `4`, variant
  `8`/`9`/`a`/`b`).
- **`UuidV7()`** — MRI 4.0's version-7 UUID: a 48-bit big-endian
  Unix-milliseconds prefix (from an injectable clock) plus random bits, version
  nibble `7`.
- **`Alphanumeric(n, chars…)`** — MRI's `A-Z a-z 0-9` default (or a supplied
  character set), built with the same `Random::Formatter#choose` base-`size`
  digit construction so the distribution matches.
- **`RandomNumber(n)`** — no/zero/non-positive argument → a `Float` in `[0, 1)`;
  a positive integer → an `Integer` in `[0, n)`; a positive float → a `Float` in
  `[0, n)`. `RandomInt` / `RandomFloat` are typed conveniences.

CGO-free, **100% test coverage**, `gofmt` + `go vet` clean, and green across the
six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le, s390x) and three
operating systems (Linux, macOS, Windows).

## Install

```sh
go get github.com/go-ruby-securerandom/securerandom
```

## Usage

```go
package main

import (
	"fmt"

	securerandom "github.com/go-ruby-securerandom/securerandom"
)

func main() {
	fmt.Println(securerandom.Hex())              // 32 hex chars
	fmt.Println(securerandom.Base64())           // 24 chars, padded
	fmt.Println(securerandom.UrlsafeBase64(16, false)) // 22 chars, no padding
	fmt.Println(securerandom.Uuid())             // 4-version, 8/9/a/b-variant
	fmt.Println(securerandom.Alphanumeric(16))   // A-Za-z0-9

	fmt.Println(securerandom.RandomInt(100))     // Integer in [0,100)
	fmt.Println(securerandom.RandomFloat())      // Float   in [0,1)
}
```

## The `RandSource` seam

Every method ultimately draws from a `RandSource`; the default is `crypto/rand`.
Injecting a fixed source makes the formatters deterministic — exactly how the
test suite asserts exact bytes:

```go
type RandSource interface {
	Read(p []byte) (int, error)
}

// Bind a generator to a specific source (nil -> crypto/rand).
s := securerandom.New(myFixedSource)
s.Hex(4) // deterministic given myFixedSource

// Or swap the package-level default (restore it after):
securerandom.DefaultSource = myFixedSource
```

The top-level `Hex`, `Base64`, … functions read `securerandom.DefaultSource`; the
methods on `*SecureRandom` are preferred for concurrent or test use. A broken
source (a `Read` error) panics, mirroring MRI raising on a failed CSPRNG — a
condition that does not occur on the platforms we target.

## API

```go
func New(src RandSource) *SecureRandom // nil src -> crypto/rand

func (s *SecureRandom) RandomBytes(n ...int) []byte                 // default 16
func (s *SecureRandom) Hex(n ...int) string                        // 2*n chars
func (s *SecureRandom) Base64(n ...int) string                     // StdEncoding
func (s *SecureRandom) UrlsafeBase64(n int, padding bool) string   // URL alphabet
func (s *SecureRandom) Uuid() string                               // v4
func (s *SecureRandom) UuidV7() string                             // v7
func (s *SecureRandom) Alphanumeric(n int, chars ...string) string // #choose
func (s *SecureRandom) RandomNumber(n ...float64) (i int64, f float64, isInt bool)
func (s *SecureRandom) RandomInt(n int64) int64                    // [0,n)
func (s *SecureRandom) RandomFloat() float64                       // [0,1)

// Package-level equivalents read DefaultSource:
func Hex(n ...int) string
func Base64(n ...int) string
func UrlsafeBase64(n int, padding bool) string
func RandomBytes(n ...int) []byte
func Uuid() string
func UuidV7() string
func Alphanumeric(n int, chars ...string) string
func RandomNumber(n ...float64) (int64, float64, bool)
func RandomInt(n int64) int64
func RandomFloat() float64

var DefaultSource RandSource // defaults to crypto/rand
```

## Notes on MRI fidelity

- `random_number` with a **non-positive** bound returns a `Float` in `[0, 1)`,
  matching MRI (which never raises there).
- `Alphanumeric` with a **single-element or empty** character set: MRI's `#choose`
  loops forever (no power of `size` exceeds the batch threshold). This library
  returns the only reachable string instead — `n` copies of the element, or `""`
  for an empty set — rather than hanging.

## Tests & coverage

The suite pairs deterministic, ruby-free tests — which alone hold coverage at
100%, so the qemu cross-arch and Windows lanes pass the gate — with a
**differential MRI oracle**: each method is run under the system `ruby` and the
output is checked for the same **format, length, charset, and UUID bit-layout**
(never exact bytes, since both sides draw from independent CSPRNGs). The oracle
scripts `$stdout.binmode` so a text-mode runner never corrupts the bytes, and
skip themselves on Windows and where `ruby` is absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-securerandom/securerandom authors.
