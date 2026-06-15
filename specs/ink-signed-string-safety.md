# INK Signed String Safety Specification v0.1

**Status:** Draft
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

## Enforcement order

A receiver processes a signed body in this order, rejecting at the first failure:

1. receive the raw body bytes;
2. enforce the size cap;
3. reject any unpaired surrogate escape in the raw JSON text;
4. parse the JSON;
5. apply schema and complexity bounds;
6. canonicalize and verify the signature.

Steps 3 must run before step 4: once the JSON is parsed, the raw provenance, and
with it the ability to detect the original surrogate, is gone.

## Related: raw UTF-8 validity

`encoding/json` also replaces invalid UTF-8 byte sequences in a string with
`U+FFFD`, which is the same class of parser-introduced divergence. A receiver
SHOULD require the raw body to be valid UTF-8 before parsing. That guard lives at
the same boundary as the surrogate check; it is noted here and tracked
separately because invalid UTF-8 cannot be expressed in the JSON conformance
corpus.

## Conformance

The `jcs-string-safety` category of the
[`ink.conformance.v1`](../conformance/v1) corpus pins this rule. Each vector is a
raw JSON body with the expected accept or reject decision, covering a valid
pair, a literal `\\uD800`, and lone surrogates in a value, a member name, and a
nested array, in upper and lower case.
