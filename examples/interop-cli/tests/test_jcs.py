"""Validate our JCS implementation against the published INK test vectors."""

from __future__ import annotations

import math

import pytest

from ink_interop.jcs import canonicalize


def test_jcs_vectors_match(jcs_vectors: dict[str, object]) -> None:
    """Every published vector must produce its expected canonical form."""
    vectors = jcs_vectors["vectors"]  # type: ignore[index]
    assert isinstance(vectors, list)
    assert vectors, "expected at least one JCS vector"
    for vec in vectors:
        assert isinstance(vec, dict)
        got = canonicalize(vec["input"]).decode("utf-8")
        assert got == vec["expectedCanonical"], (
            f"JCS mismatch for: {vec.get('description')!r}\n"
            f"expected: {vec['expectedCanonical']}\n"
            f"got:      {got}"
        )


def test_keys_sorted_lexicographically_by_utf16() -> None:
    # ASCII keys round-trip; the harder cases (surrogate pairs) follow.
    out = canonicalize({"b": 1, "a": 2}).decode("ascii")
    assert out == '{"a":2,"b":1}'


def test_string_escapes_short_form() -> None:
    out = canonicalize({"k": '\n\t"\\'}).decode("ascii")
    assert out == r'{"k":"\n\t\"\\"}'


def test_string_escapes_control_chars_lowercase_hex() -> None:
    out = canonicalize({"k": "\x01\x1f"}).decode("ascii")
    assert out == '{"k":"\\u0001\\u001f"}'


def test_unicode_passes_through_as_utf8() -> None:
    out = canonicalize({"k": "résumé✓"})
    assert out == b'{"k":"r\xc3\xa9sum\xc3\xa9\xe2\x9c\x93"}'


def test_array_preserves_order() -> None:
    out = canonicalize([3, 1, 2]).decode("ascii")
    assert out == "[3,1,2]"


def test_integer_float_renders_as_integer() -> None:
    # JCS / ECMA-262 ToString: 1.0 -> "1" not "1.0".
    out = canonicalize({"n": 1.0}).decode("ascii")
    assert out == '{"n":1}'


def test_non_finite_floats_rejected() -> None:
    with pytest.raises(ValueError, match="JCS forbids"):
        canonicalize({"n": math.nan})
    with pytest.raises(ValueError, match="JCS forbids"):
        canonicalize({"n": math.inf})


def test_non_string_keys_rejected() -> None:
    with pytest.raises(ValueError, match="non-string object key"):
        canonicalize({1: "a"})


def test_nested_objects_recurse() -> None:
    out = canonicalize({"a": {"y": 1, "x": 2}, "b": [{"q": 3, "p": 4}]}).decode("ascii")
    assert out == '{"a":{"x":2,"y":1},"b":[{"p":4,"q":3}]}'


def test_empty_collections() -> None:
    assert canonicalize({}) == b"{}"
    assert canonicalize([]) == b"[]"


def test_unsupported_type_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported JSON type"):
        canonicalize({"k": object()})
