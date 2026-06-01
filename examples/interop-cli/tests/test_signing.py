"""Validate Ed25519 signing/verification against the INK test vectors.

Cross-implementation test vector matching is the whole point of this CLI —
if our signature bytes diverge from the spec vectors, tulpa (and every
other receiver) will reject every request.
"""

from __future__ import annotations

import base64

from ink_interop import envelope, jcs
from ink_interop.crypto import (
    Keypair,
    sign_detached,
    verify_detached,
)


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_signing_vector_alice_intent(signing_vectors: dict[str, object]) -> None:
    """First vector: Alice signs an intent to Bob — exact byte match required."""
    vec = next(
        v
        for v in signing_vectors["vectors"]  # type: ignore[index]
        if "valid signature" in v["description"]  # type: ignore[index]
    )
    inp = vec["input"]
    expected = vec["expected"]

    # 1. JCS of body matches.
    canonical = jcs.canonicalize(inp["body"]).decode("utf-8")
    assert canonical == expected["canonicalBody"]

    # 2. Signature base matches.
    sig_base = envelope.build_signature_base(
        method=inp["method"],
        path=inp["path"],
        recipient_did=inp["recipientDid"],
        canonical_body=canonical.encode("utf-8"),
        timestamp=inp["timestamp"],
    )
    assert sig_base.decode("utf-8") == expected["signatureBase"]

    # 3. Loaded keypair signs to the exact published hex.
    seed = bytes.fromhex(inp["signerPrivateKeyHex"])
    kp = Keypair.from_private_bytes(seed)
    assert kp.public_key_hex == inp["signerPublicKeyHex"]
    sig = sign_detached(kp, sig_base)
    assert sig.hex() == expected["signatureHex"]

    # 4. Base64url-encoded signature matches.
    assert _b64url_no_pad(sig) == expected["signatureBase64url"]

    # 5. Authorization header matches.
    auth = envelope.format_authorization_header(sig)
    assert auth == expected["authorizationHeader"]


def test_verify_rejects_wrong_public_key(signing_vectors: dict[str, object]) -> None:
    vec = next(
        v
        for v in signing_vectors["vectors"]  # type: ignore[index]
        if "wrong public key" in v["description"]  # type: ignore[index]
    )
    inp = vec["input"]
    sig = bytes.fromhex(inp["signatureHex"])
    sig_base = inp["signatureBase"].encode("utf-8")
    wrong_pk = bytes.fromhex(inp["verifierPublicKeyHex"])
    assert verify_detached(wrong_pk, sig_base, sig) is False


def test_verify_rejects_tampered_path(signing_vectors: dict[str, object]) -> None:
    vec = next(
        v
        for v in signing_vectors["vectors"]  # type: ignore[index]
        if "tampered path" in v["description"]  # type: ignore[index]
    )
    inp = vec["input"]
    # Reconstruct the signature base with the tampered path; that's the
    # exact attack the spec's signature base design is meant to defeat.
    sig_base = envelope.build_signature_base(
        method="POST",
        path=inp["tamperedPath"],
        recipient_did="did:plc:bob456test",
        canonical_body=b"",  # body irrelevant; the path delta alone breaks verification
        timestamp="2026-03-18T12:00:00Z",
    )
    sig = bytes.fromhex(inp["signatureHex"])
    pk = bytes.fromhex(inp["verifierPublicKeyHex"])
    assert verify_detached(pk, sig_base, sig) is False
