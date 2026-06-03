"""Conformance: the body-signature vectors verify as declared.

Loads ``test-vectors/body-signature.json`` from the repo root and runs
each vector through ``envelope.verify_body``. This proves the standalone
Python client agrees with the published vectors on the version-keyed
body-signature domain, including the cross-version and tamper cases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ink_interop import envelope

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test-vectors" / "body-signature.json"


def _load_vectors() -> list[dict[str, Any]]:
    if not VECTORS_PATH.exists():
        pytest.skip(f"vector file not found: {VECTORS_PATH}")
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["description"])
def test_body_signature_vector(vector: dict[str, Any]) -> None:
    public_key = bytes.fromhex(vector["input"]["signerPublicKeyHex"])
    result = envelope.verify_body(public_key, vector["input"]["body"])
    assert result is vector["expected"]["signatureVerifies"]


VALID = _load_vectors()[0]  # the ink/0.1 valid vector


def _valid_pubkey() -> bytes:
    return bytes.fromhex(VALID["input"]["signerPublicKeyHex"])


def test_verify_body_never_raises_on_malformed_input() -> None:
    pk = _valid_pubkey()
    # Non-dict body, missing signature, wrong-typed signature, bad shape.
    assert envelope.verify_body(pk, None) is False  # type: ignore[arg-type]
    assert envelope.verify_body(pk, {}) is False
    assert envelope.verify_body(pk, {"signature": 123}) is False
    assert envelope.verify_body(pk, {"signature": "short"}) is False
    assert envelope.verify_body(pk, {"signature": "=" * 86}) is False
    # Wrong-length public key must return False, not raise.
    assert envelope.verify_body(b"\x00" * 5, VALID["input"]["body"]) is False


def test_verify_body_rejects_padded_signature() -> None:
    # A padded base64url signature must be rejected to match the strict
    # 86-char shape the TypeScript verifier enforces.
    pk = _valid_pubkey()
    body = dict(VALID["input"]["body"])
    body["signature"] = str(body["signature"]) + "=="
    assert envelope.verify_body(pk, body) is False


def test_verify_body_rejects_oversized_body() -> None:
    pk = _valid_pubkey()
    sig = "A" * 86  # valid shape so it reaches the bounds check
    deep: dict[str, Any] = {"signature": sig}
    node = deep
    for _ in range(40):  # deeper than the depth cap
        child: dict[str, Any] = {}
        node["n"] = child
        node = child
    assert envelope.verify_body(pk, deep) is False
    huge = {"signature": sig, "big": "x" * 1_200_001}
    assert envelope.verify_body(pk, huge) is False
