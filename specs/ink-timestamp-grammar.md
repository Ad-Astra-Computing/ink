# INK Timestamp Grammar Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

INK timestamps are compared across independent implementations: a receiver
checks a message's freshness, and a verifier checks whether a message falls
inside a key's validity window. If two implementations parse the same timestamp
string differently, they can disagree on whether a message is fresh or a key is
valid, which is a consensus bug. This specification pins one grammar and one
precision for every INK timestamp so the decision is deterministic everywhere.

## Where it applies

The grammar applies to every timestamp instant that is parsed and compared:

- the message `timestamp` (freshness and replay checks);
- a key's `validFrom` and `validUntil` (validity-window checks);
- a `revokedAt` value wherever its instant is read (publication and the Agent
  Card schema). Note that at verification a key with `revokedAt` present is
  unusable regardless of the value, so the verifier does not need to parse the
  instant; that presence rule is specified separately from this grammar.

## Grammar

A timestamp MUST match INK's strict RFC 3339 profile: a full RFC 3339
`date-time` with the additional constraints below. The profile is intentionally
narrower than RFC 3339, so values some RFC 3339 parsers accept (a lowercase `t`
or `z`, a comma fractional separator, a leap second) are rejected.

```
date-time = full-date "T" full-time
full-date = 4DIGIT "-" 2DIGIT "-" 2DIGIT
full-time = 2DIGIT ":" 2DIGIT ":" 2DIGIT [ "." 1*DIGIT ] ( "Z" / ("+" / "-") 2DIGIT ":" 2DIGIT )
```

Concretely, a conforming implementation MUST:

- match the whole string with no leading or trailing whitespace or extra
  characters;
- use a four-digit year, which is the literal year (`0099` is year 99, never
  1999);
- require the uppercase `T` date/time separator;
- require seconds in the range `00..59`; leap seconds (`60`) are rejected;
- accept optional dot-separated fractional seconds (a comma separator is
  rejected);
- require a zone designator: either `Z` or a numeric `±HH:MM` offset whose hours
  are `00..23` and minutes `00..59`. `-00:00` is accepted and equal to `Z`;
- reject the value if any date or time component is out of range.

A conforming implementation MUST reject lenient forms that some date parsers
accept, including but not limited to: a date with no time component; a date-time
with no zone designator; a space instead of the `T` separator; and a lowercase
`t` or `z`.

An implementation MUST cap the accepted length (64 characters is sufficient for
any conforming timestamp) before parsing, so an oversized input cannot consume
work ahead of the rejection.

## Precision

The parsed instant is the **whole-millisecond** Unix time, floored to the
containing millisecond. Fractional seconds beyond millisecond precision are
dropped, so the value is `floor(instant / 1ms)`: a pre-epoch instant of
`1969-12-31T23:59:59.9999Z` is `-1`, not `0`. All freshness and validity-window
comparisons are performed on these millisecond values. Implementations MUST NOT
compare at a finer precision than milliseconds, because a millisecond-native
runtime cannot represent a finer distinction and would otherwise diverge on a
sub-millisecond boundary.

Calendar components are range-validated before the instant is computed: the
month, the day against the month and leap year, the hour, the minute, the
second, and the offset. An out-of-range value such as `2026-02-29` (not a leap
year), `2026-06-31`, or an hour of `24` MUST be rejected, never rolled over to
the next valid instant.

## Fail-closed

A value that is not a well-formed, in-range timestamp under this grammar is
treated as absent of a usable instant and the dependent check fails closed: an
unparseable message timestamp is not fresh, and an unparseable `validFrom` or
`validUntil` makes the key unusable.

## Conformance

The `timestamp-validity` category of the
[`ink.conformance.v1`](../conformance/v1) corpus pins this grammar and precision.
Each vector is a timestamp string with the expected accept or reject decision,
and accepted vectors pin the parsed millisecond value, so an implementation that
applied a lenient grammar or compared at nanoseconds would fail the suite.
