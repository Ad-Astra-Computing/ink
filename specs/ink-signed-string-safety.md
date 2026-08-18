# INK Signed String Safety Specification v0.1

**Status:** Stable base-profile spec; formal 1.0 freeze pending governance sign-off (see [`../GOVERNANCE.md`](../GOVERNANCE.md), [`../governance/releases/1.0-readiness-evidence.md`](../governance/releases/1.0-readiness-evidence.md)).
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

A signed INK body is canonicalized (RFC 8785 JCS) and the canonical bytes are
signed. If two implementations canonicalize the same body to different bytes,
they disagree on the signature, which is a consensus failure. One such hazard is
a **lone UTF-16 surrogate** in a string: a high surrogate (`U+D800`–`U+DBFF`)
not immediately followed by a low surrogate (`U+DC00`–`U+DFFF`), or a lone low.
In JSON a lone surrogate can only appear as a `\uXXXX` escape, because UTF-8
cannot encode a surrogate as raw bytes. Some parsers preserve it (and emit it
back as `\uXXXX`), while others, including Go's `encoding/json`, silently
replace it with `U+FFFD` at parse time, so a body that reached canonicalization
would be signed over different bytes depending on the parser.

INK therefore bans lone surrogates in signed bodies rather than trying to make
every parser agree on how to represent one.

## Rule

A receiver MUST reject any signed JSON body whose raw UTF-8 JSON text contains a
`\uXXXX` escape for an unpaired UTF-16 surrogate in any string member name or
string value, **before** JSON parsing, canonicalization, or signature
verification. A signer MUST refuse to sign a body that contains a lone surrogate
in any string member name or value.

The check operates on the **raw JSON text**, not the parsed value, because a
parser that has already rewritten a lone surrogate to `U+FFFD` cannot recover
the original. A backslash escapes the next character, so a literal `\\uD800`
(an escaped backslash followed by the characters `uD800`) is text, not a Unicode
escape, and is accepted. A valid pair such as `😀` is accepted. Hex
digits are case-insensitive.

## Raw UTF-8 validity

A receiver MUST reject a signed body whose raw bytes are not valid UTF-8, before
JSON parsing. `encoding/json` replaces an invalid UTF-8 byte sequence with
`U+FFFD` at parse time, the same parser-introduced divergence as a lone
surrogate, so a body that reached canonicalization would be signed over
different bytes than an implementation that rejected the invalid bytes. A signer
MUST NOT sign a body whose raw bytes are not valid UTF-8.

This rule is on the **raw bytes**, not a decoded string. A runtime whose string
type cannot hold invalid UTF-8 (a JavaScript string is one) has already crossed
the byte boundary once it holds the body as a string: its decoder substituted
`U+FFFD` for any invalid sequence, and the original bytes are gone. Such a
receiver MUST perform the check on the `Uint8Array` (or equivalent byte buffer)
before decoding, with a fatal UTF-8 decoder that fails rather than substitutes.
The lone-surrogate scan still runs on the decoded text after this check passes,
because a lone surrogate escape is itself valid UTF-8.

A leading UTF-8 byte-order mark (`EF BB BF`) is itself valid UTF-8, so the byte
gate MUST NOT strip it. The mark decodes to `U+FEFF`, which is not legal at the
start of a JSON document, so a body that begins with a BOM passes the byte gate
and then rejects at the JSON parse step. A byte gate that silently strips the BOM
would accept a body whose canonical bytes differ from what the signer signed.

## Numeric literal range

A receiver MUST reject a signed body whose raw JSON text contains a number
literal whose value is outside the IEEE-754 double range, before JSON parsing. A
signer MUST NOT sign such a body.

The hazard is the same shape as the two above, but the parsers do not merely
represent the value differently, they disagree about whether the document exists
at all. ECMAScript `JSON.parse` decodes `1e309` to `Infinity` and returns the
document; Go's `encoding/json` refuses the whole document with a range error. A
literal that underflows (`1e-400`) is not affected: every IEEE-754 parser decodes
it to `0`, so implementations already agree on it and it stays accepted.

This rule lives at the raw gate rather than after parsing because the number
profile of [`ink-jcs-number-profile.md`](ink-jcs-number-profile.md) is a check on
decoded **values**, and a value the parser never produces is a value the profile
never sees. JSON member semantics are last-wins, so a duplicate member shadows
the literal: `{"a":1e309,"a":1}` decodes to `{"a":1}` under a parser that
tolerates the literal, canonicalizes cleanly and gets a signature verified over
those canonical bytes, while a parser that refuses the document rejects the body
outright. The two implementations then admit different byte strings as signed
bodies, which is a consensus failure in the signature path and is reachable by
anyone who can choose the bytes of a signed body. Rejecting the literal at the
raw gate makes the admitted set a property of the protocol instead of a property
of whichever JSON parser an implementation happens to link.

The check is on the raw JSON **text**, so it reads number-like characters only
outside strings: `{"note":"1e309"}` carries no number literal and is accepted. A
run of number characters that is not a well-formed number is left to the JSON
parser, which rejects the document on its own.

## Escaped member names

A receiver MUST reject a signed body whose raw JSON text contains an object
member name written with any escape sequence, before JSON parsing. A signer MUST
NOT sign a body containing an object key that would serialize as an escaped
member name, which under RFC 8785's minimal escaping means a key containing a
quotation mark, a reverse solidus, or any character in `U+0000`–`U+001F`.
`U+007F` is not escaped and stays permitted.

The three rules above address parsers that represent a value differently or
refuse a document. This one addresses a parser that returns a **different member
name than the document contains**. V8 sizes the character span for a member name
from a pointer into the raw source text using the name's decoded length, then
compares that span against an existing hidden-class transition name and, on a
match, adopts the transition's name as the property key without decoding the
escape. So `{"x":{"\\":1},"y":{"\n":2}}` yields a `y` whose sole member is named
`\`, not a newline. The wrong name is a real property, so it survives
serialization and reaches canonicalization.

The precondition is that the member name's raw spelling is longer than its
decoded value, which requires an escape. Banning escaped member names removes
the precondition outright, independent of what any particular runtime holds in
its transition tables, which is why the rule is stated on the raw text rather
than as a check for the corruption itself. Detecting the corruption after the
fact is not a workable substitute: the recovered member names cannot be compared
as a set, because `{"a":1,"\u0061":2}` legitimately collapses to a single member,
and a substituted name can coincide with a name the document already contains.

The rule is on the raw JSON **text** and applies to member names only. An escape
in a string value or an array element is unaffected: `{"note":"line\nbreak"}` is
accepted. A string is a member name exactly when the next non-whitespace
character after its closing quotation mark is a colon.

Implementations whose JSON parser decodes escaped member names correctly, which
includes Go's `encoding/json`, MUST enforce this rule anyway. The purpose is not
to protect that implementation but to keep the set of admitted bodies a property
of the protocol: an implementation that accepted such a body would disagree with
a conforming implementation about which bytes a signature covers.

## Enforcement order

A receiver processes a signed body in this order, rejecting at the first failure:

1. receive the raw body bytes;
2. enforce the size cap;
3. reject any raw bytes that are not valid UTF-8;
4. reject any unpaired surrogate escape in the raw JSON text;
5. reject any number literal outside the IEEE-754 double range in the raw JSON
   text;
6. reject any object member name written with an escape sequence in the raw JSON
   text;
7. parse the JSON;
8. apply schema and complexity bounds;
9. canonicalize and verify the signature.

Steps 3 through 6 must run before step 7: once the JSON is parsed, the raw
provenance, and with it the ability to detect the original invalid bytes, the
surrogate, the out-of-range literal or the original member name, is gone. Step 5
in particular cannot be moved after step 7 in any form, because a parser that
rejects the document outright never reaches step 7 and a parser that does not has
already discarded the shadowed literal. Step 6 likewise cannot be moved after
step 7, because the substituted member name is indistinguishable from a name the
sender chose.

## Conformance

The `jcs-string-safety` category of the
[`ink.conformance.v1`](../conformance/v1) corpus pins the surrogate rule. Each
vector is a raw JSON body with the expected accept or reject decision, covering a
valid pair, a literal `\\uD800`, and lone surrogates in a value, a member name,
and a nested array, in upper and lower case.

The `signed-body-utf8` category pins the raw-UTF-8 rule. A JSON string cannot
hold invalid UTF-8, so each vector carries the raw body as a hex-encoded
`bodyHex` field the runner decodes to bytes before deciding. It covers valid
multibyte UTF-8 accepts, invalid-UTF-8 rejects (a lone continuation byte, a
truncated multibyte sequence, an overlong encoding, the byte `0xFF`, and
UTF-16-encoded bytes), and a valid-UTF-8 body whose text carries a lone
surrogate escape, which rejects because the surrogate scan still runs once the
UTF-8 check passes.

The numeric-literal rule is pinned in both places it acts. `signed-body-utf8`
covers the gate itself: a bare out-of-range literal as the whole body, one in a
member value, one shadowed by a later duplicate member, and an underflowing
exponent that stays accepted. `jcs-number` covers what the gate protects, the
canonicalization step: the shadowed literal rejects rather than canonicalizing to
the surviving member, an in-range duplicate member still canonicalizes last-wins,
and an underflowing exponent canonicalizes to `0`.
