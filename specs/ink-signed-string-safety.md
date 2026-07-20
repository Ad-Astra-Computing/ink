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

## Enforcement order

A receiver processes a signed body in this order, rejecting at the first failure:

1. receive the raw body bytes;
2. enforce the size cap;
3. reject any raw bytes that are not valid UTF-8;
4. reject any unpaired surrogate escape in the raw JSON text;
5. parse the JSON;
6. apply schema and complexity bounds;
7. canonicalize and verify the signature.

Steps 3 and 4 must run before step 5: once the JSON is parsed, the raw
provenance, and with it the ability to detect the original invalid bytes or
surrogate, is gone.

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
