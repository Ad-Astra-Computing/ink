"""RFC 8785 JCS (JSON Canonicalization Scheme) implementation.

INK signs over a canonical form of the message body so that semantically
equivalent JSON (key order, optional whitespace, integer-vs-float
encoding) always produces the same signature input. We reimplement JCS
here rather than depending on a library so this CLI doubles as a
spec-portability proof: anyone reading this file can see exactly what
bytes the spec requires on the wire.

Scope of this implementation:

* Object keys sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3).
* Strings serialized per RFC 8259 §7 with the JCS escape rules
  (RFC 8785 §3.2.2.2) — only required escapes, lowercase ``\\u`` hex.
  Lone surrogates are rejected up front so the canonicalizer cannot
  emit malformed UTF-8 that one impl tolerates and another does not.
* Numbers are restricted to integers in the IEEE-754-safe range
  (``±(2**53 - 1)``). Floats other than integer-valued floats in that
  range are rejected. Rationale: RFC 8785 specifies ECMA-262 §7.1.12.1
  ToString for numbers; Python's float ``repr`` matches the shortest-
  round-trip invariant but DIVERGES from ECMA-262's exponent
  formatting choices (e.g. ``1e-06`` vs ``0.000001``). Rather than
  reimplement §7.1.12.1, we refuse non-integer floats — INK envelopes
  do not put floats on the wire (timestamps are strings, counts are
  ints), so the restriction is invisible in practice but blocks a
  class of cross-implementation signature mismatches.
* Arrays preserve order; nested objects and arrays are canonicalized
  recursively.

What this does NOT do:

* Convert other types (datetime, Decimal, bytes) — callers are
  responsible for emitting JSON-native types only.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["MAX_SAFE_INTEGER", "MIN_SAFE_INTEGER", "canonicalize"]

# Per ECMA-262 / IEEE-754: the largest integer that round-trips through
# a JS Number without precision loss. JCS numbers are interpreted as
# ECMA Numbers, so emitting an integer outside this range would let two
# implementations disagree on the canonical form once a JS parser
# rounds it. RFC 8785 §3.2.2.3 leaves this to the application; we
# require it explicitly so divergence becomes a typed error.
MAX_SAFE_INTEGER = (1 << 53) - 1
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def canonicalize(value: Any) -> bytes:
    """Return the JCS-canonical UTF-8 encoding of ``value``.

    Raises:
        ValueError: If the value contains a non-finite float, a
            non-integer float, an integer outside the IEEE-754 safe
            range, a string containing lone surrogates, a non-string
            object key, or a type outside the supported JSON value set.
    """
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, bool):
        # Unreachable — bool is a subclass of int but handled above.
        return "true" if value else "false"
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return _encode_object(value)
    raise ValueError(f"unsupported JSON type: {type(value).__name__}")


def _encode_int(value: int) -> str:
    if value > MAX_SAFE_INTEGER or value < MIN_SAFE_INTEGER:
        raise ValueError(
            f"integer {value} is outside the IEEE-754 safe range "
            f"(±{MAX_SAFE_INTEGER}); cross-implementation parsers will "
            f"round it inconsistently"
        )
    return str(value)


def _encode_object(obj: dict[str, Any]) -> str:
    parts: list[str] = []
    # Validate key types and unicode validity FIRST. Sorting must not be
    # the failure mode because the UTF-16-BE sort key would raise an
    # opaque UnicodeEncodeError on lone surrogates and an AttributeError
    # on non-strings, both of which obscure the actual contract violation.
    for key in obj:
        if not isinstance(key, str):
            raise ValueError(f"non-string object key: {type(key).__name__}")
        _validate_no_lone_surrogates(key)
    # RFC 8785 §3.2.3: sort by UTF-16 code units.
    keys = sorted(obj.keys(), key=_utf16_sort_key)
    for key in keys:
        parts.append(_encode_string(key) + ":" + _encode(obj[key]))
    return "{" + ",".join(parts) + "}"


def _validate_no_lone_surrogates(value: str) -> None:
    for ch in value:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError(
                f"string contains lone surrogate U+{code:04X}; JCS requires valid Unicode"
            )


def _utf16_sort_key(key: str) -> tuple[int, ...]:
    """UTF-16 code-unit comparison key per RFC 8785 §3.2.3.

    Encoding as UTF-16-BE produces big-endian byte pairs, and comparing
    those byte tuples is equivalent to comparing the underlying 16-bit
    code-unit sequences — so the resulting sort order matches the one
    a JS implementation would produce on the same key set.
    """
    return tuple(key.encode("utf-16-be"))


# RFC 8785 §3.2.2.2 — characters that MUST be escaped. Anything else
# with a code point >= 0x20 passes through as the raw UTF-8 character.
# Characters 0x00-0x1F are escaped as either their short form (\b, \t,
# \n, \f, \r) or a six-character \uXXXX sequence. " and \ get their
# short escapes.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _encode_string(value: str) -> str:
    # Reject lone surrogates explicitly so a hostile or malformed input
    # can't produce a different signature input than a strict UTF-8
    # implementation in another language would. Lone surrogates are
    # invalid UTF-8 and RFC 8785 inherits RFC 8259's "MUST be valid
    # Unicode" requirement.
    _validate_no_lone_surrogates(value)
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise ValueError("JCS forbids NaN and Infinity")
    # Only integer-valued floats inside the IEEE-754 safe integer range
    # are accepted. Everything else is rejected: rendering arbitrary
    # IEEE-754 doubles per ECMA-262 §7.1.12.1 is complex and Python's
    # `repr` diverges in exponent formatting (e.g. ``1e-06`` vs
    # ``0.000001``), which would silently break cross-implementation
    # signatures. INK envelopes only carry integers and strings, so
    # this restriction is invisible to real call sites.
    if not value.is_integer():
        raise ValueError(
            "non-integer float not supported by this canonicalizer; "
            "encode decimals as JSON strings to avoid ECMA-262 ToString "
            "divergence"
        )
    if value > MAX_SAFE_INTEGER or value < MIN_SAFE_INTEGER:
        raise ValueError(
            f"integer-valued float {value} is outside the IEEE-754 safe range (±{MAX_SAFE_INTEGER})"
        )
    return str(int(value))
