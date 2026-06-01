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
  (RFC 8785 §3.2.2.2) — only required escapes, lowercase ``\\u`` hex,
  surrogate pairs preserved.
* Numbers serialized per ECMAScript ``Number.prototype.toString`` semantics
  using Python's float repr, which matches for the small finite-range values
  INK actually puts on the wire (counts, timestamps-as-strings, etc.). The
  spec uses strings for timestamps so the floating-point edge cases that
  diverge between ECMA-262 §7.1.12.1 and other languages do not arise in
  practice. Non-finite numbers raise ValueError (RFC 8785 §3.2.2.3 forbids them).
* Arrays preserve order; nested objects and arrays are canonicalized
  recursively.

What this does NOT do:

* Convert other types (datetime, Decimal, bytes) — callers are responsible
  for using strings, ints, floats, bools, None, list, dict only.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["canonicalize"]

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def canonicalize(value: Any) -> bytes:
    """Return the JCS-canonical UTF-8 encoding of ``value``.

    Raises:
        ValueError: If the value contains a non-finite float, a non-string
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
        return str(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return _encode_object(value)
    raise ValueError(f"unsupported JSON type: {type(value).__name__}")


def _encode_object(obj: dict[str, Any]) -> str:
    parts: list[str] = []
    # Validate key types first — sorting must not be the failure mode
    # because the sort key function can blow up with a confusing
    # AttributeError on non-string keys.
    for key in obj:
        if not isinstance(key, str):
            raise ValueError(f"non-string object key: {type(key).__name__}")
    # RFC 8785 §3.2.3: sort by UTF-16 code units.
    keys = sorted(obj.keys(), key=_utf16_sort_key)
    for key in keys:
        parts.append(_encode_string(key) + ":" + _encode(obj[key]))
    return "{" + ",".join(parts) + "}"


def _utf16_sort_key(key: str) -> tuple[int, ...]:
    """UTF-16 code-unit comparison key per RFC 8785 §3.2.3."""
    return tuple(key.encode("utf-16-be"))


# RFC 8785 §3.2.2.2 — characters that MUST be escaped. Anything else with a
# code point >= 0x20 passes through as the raw UTF-8 character. Characters
# 0x00-0x1F are escaped as either their short form (\b, \t, \n, \f, \r) or
# a six-character \uXXXX sequence. " and \ get their short escapes.
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
    # An integer-valued float must render as the integer form. Python's
    # `repr(1.0)` is `"1.0"`, but JCS (and ECMA-262 ToString) emit `"1"`.
    if value.is_integer() and abs(value) < 1e16:
        return str(int(value))
    # For non-integer floats Python's repr already matches ECMA-262 for the
    # IEEE-754 double values INK actually serializes. The full ECMA Number-to-
    # String algorithm (§7.1.12.1) is complex; we stay within the safe band by
    # contracting that INK payloads do not put exotic doubles on the wire.
    return repr(value)
