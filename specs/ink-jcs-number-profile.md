# INK JCS Number Profile Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

A signed INK body is canonicalized (RFC 8785 JCS) and the canonical bytes are
signed. RFC 8785 defers numeric serialization to ECMAScript's `Number`-to-string
algorithm (the same one `JSON.stringify` uses). That algorithm is exact, but a
second implementation in another language does not get it for free: it must
reproduce ECMAScript's shortest round-tripping output, including the threshold at
which the output switches to exponential notation. If two implementations
serialize the same number to different bytes, they disagree on the signature,
which is a consensus failure.

Rather than require every implementation to port the full ECMAScript number
formatter, INK restricts the numbers a signed body may carry to a **safe-integer
profile**, the range over which a plain base-10 integer rendering is exact and
trivially identical across languages.

## Rule

A number in a signed INK body MUST be a **safe integer**: an integer value `v`
with

- no fractional part (`v == trunc(v)`),
- `-(2^53 - 1) <= v <= 2^53 - 1` (ECMAScript `Number.MIN_SAFE_INTEGER` through
  `Number.MAX_SAFE_INTEGER`), and
- not negative zero.

`NaN` and the infinities are not representable in JSON and are likewise
forbidden. A signer MUST refuse to sign a body containing a number outside this
profile. A receiver MUST reject a signed body containing such a number rather
than canonicalize it.

An accepted number is canonicalized as its plain base-10 integer rendering with
no leading zeros, no decimal point, no exponent, and a `-` sign only for
negative values. This is byte-for-byte ECMAScript `String(v)` for every value in
the profile, so no language-specific number formatter is needed.

## The profile is on the decoded value

The profile constrains the **decoded numeric value**, not the source JSON token.
A JSON number is parsed to an IEEE-754 double first; the profile is then applied
to that double. Two consequences:

- An exponential **source** token whose value is a safe integer is accepted and
  re-rendered without an exponent: `1e2` decodes to `100` and canonicalizes to
  `100`.
- A token whose value has no exact double is judged by the double it decodes to.
  `9007199254740993` (2^53 + 1) has no exact double and is parsed to
  `9007199254740992` (2^53) by every IEEE-754 parser; that value exceeds
  `2^53 - 1`, so it is rejected by both implementations identically.

A magnitude such as `1e20` is an integer value but lies above the safe range, so
it is rejected even though some renderers would print it without an exponent.
Fixing the boundary at `2^53 - 1` keeps the accept set to exactly the values
whose integer rendering is unambiguous and exact.

## Reference and second-implementation behavior

In the TypeScript reference, `isJcsSafeNumber(n)` gates every number reaching
canonicalization; it returns true only for `Number.isSafeInteger(n)` and not
negative zero. `jcsCanonicalize` and the signing and verifying paths reject a
body containing any number that fails the predicate.

In the Go implementation, `encoding/json` decodes every JSON number to `float64`,
so `canonicalizeNumber` is the sole numeric path. It rejects a non-integer, a
magnitude above `2^53 - 1`, a negative zero, and the non-finite values, and
otherwise emits `strconv.FormatInt(int64(v), 10)`, which equals ECMAScript
`String(v)` across the profile.

## Conformance

The `jcs-number` category of the [`ink.conformance.v1`](../conformance/v1) corpus
pins this rule. Each vector is a raw JSON body and, for an accepted body, the
exact expected canonical string. The corpus covers zero, positive and negative
safe integers, the maximum safe integer, an exponential source token whose value
is a safe integer, a fraction, an above-safe magnitude in exponential notation, a
negative zero, and the two integers straddling the safe-integer boundary at
`2^53`.
