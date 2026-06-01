"""End-to-end envelope construction tests (no network)."""

from __future__ import annotations

import datetime as dt

import pytest

from ink_interop import crypto, envelope, jcs


def test_build_intent_envelope_emits_canonical_message_envelope_shape() -> None:
    """v0.1.2: the CLI MUST emit the canonical MessageEnvelopeSchema
    shape defined by `@adastracomputing/ink/src/models/intent.ts`.
    A v0.1.1-shape body would be rejected by the tulpa receiver with
    `invalid_envelope` — this test pins the bug closed."""
    kp = crypto.Keypair.generate()
    env = envelope.build_intent_envelope(
        keypair=kp,
        from_did="did:plc:sender",
        to_did="did:plc:recipient",
        target="did:plc:target-person",
        reason="Test introduction",
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        nonce="fixed-nonce",
    )
    body = env.body
    # Required canonical fields (provenance is optional in the schema
    # and intentionally omitted here so the envelope parses cleanly —
    # explicit `null` would be rejected by Zod):
    for required in (
        "protocol", "id", "correlationId", "createdAt",
        "from", "to", "intent", "payload", "signature",
    ):
        assert required in body, f"missing canonical field: {required}"
    assert "provenance" not in body, (
        "provenance MUST be omitted when not supplied; an explicit null fails "
        "MessageProvenanceSchema parsing on the receiver"
    )
    assert body["protocol"] == "ink/0.1"
    assert body["intent"] == "intro_request"
    assert isinstance(body["id"], str) and len(body["id"]) == 26
    assert isinstance(body["correlationId"], str) and len(body["correlationId"]) == 26
    assert body["payload"] == {
        "target": "did:plc:target-person",
        "reason": "Test introduction",
        "urgency": "normal",
    }
    assert body["createdAt"] == "2026-06-01T00:00:00Z"
    # The legacy phantom-shape fields MUST NOT be on the wire:
    for forbidden in ("type", "intentType", "purpose"):
        assert forbidden not in body, f"legacy field {forbidden!r} must not appear"
    # HTTP-auth fields (timestamp + nonce) ride alongside canonical
    # fields because verifyInkAuth() reads them from the body.
    assert body["timestamp"] == "2026-06-01T00:00:00Z"
    assert body["nonce"] == "fixed-nonce"
    # Body-level signature MUST be present.
    assert isinstance(body["signature"], str) and len(body["signature"]) > 0


def test_build_intent_envelope_auto_generates_nonce() -> None:
    kp = crypto.Keypair.generate()
    env = envelope.build_intent_envelope(
        keypair=kp,
        from_did="did:plc:sender",
        to_did="did:plc:recipient",
        target="did:plc:target",
        reason="Test",
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
    )
    assert env.body["nonce"]
    assert isinstance(env.body["nonce"], str)


def test_build_intent_envelope_body_signature_round_trips() -> None:
    """The body-level signature uses the canonical `tulpa/sign\\n` domain
    prefix per `src/crypto/sign.ts`. Verify the prefix + JCS-bytes
    integrity by signing locally and re-verifying."""
    kp = crypto.Keypair.generate()
    env = envelope.build_intent_envelope(
        keypair=kp,
        from_did="did:key:" + kp.public_key_multibase,
        to_did="did:plc:recipient",
        target="did:plc:target",
        reason="Test",
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        nonce="fixed-nonce",
    )
    body = env.body
    # Recompute the signed bytes and verify with the public key.
    import base64 as _b64
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    canonical = jcs.canonicalize(unsigned)
    prefixed = b"tulpa/sign\n" + canonical
    sig_bytes = _b64.urlsafe_b64decode(body["signature"] + "===")
    assert crypto.verify_detached(kp.public_key_bytes, prefixed, sig_bytes)


def test_build_connection_envelope_emits_canonical_connection_request_shape() -> None:
    """v0.1.2: the CLI MUST emit a `ConnectionRequestPayloadSchema`-
    conformant payload (method, context, profileSnapshot) under the
    `connection_request` intent. Tulpa receivers only accept this
    intent from a first-contact foreign sender, so getting the shape
    right is the difference between "lands as pending action" and
    "rejected with unknown_sender / invalid_envelope"."""
    kp = crypto.Keypair.generate()
    env = envelope.build_connection_envelope(
        keypair=kp,
        from_did="did:key:" + kp.public_key_multibase,
        to_did="did:plc:recipient",
        context="Saw your profile in the discovery index",
        headline="Researcher exploring agent-to-agent coordination",
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-06-01T01:00:00Z",
        nonce="fixed-conn-nonce",
    )
    body = env.body
    assert body["intent"] == "connection_request"
    payload = body["payload"]
    assert payload["method"] == "discovery"
    assert payload["context"] == "Saw your profile in the discovery index"
    snap = payload["profileSnapshot"]
    assert snap == {
        "headline": "Researcher exploring agent-to-agent coordination",
        "skills": [],
        "interests": [],
        "openTo": [],
    }
    assert "introducedBy" not in payload, (
        "introducedBy is optional and MUST be omitted when not supplied"
    )
    for forbidden in ("type", "intentType", "purpose"):
        assert forbidden not in body
    import base64 as _b64
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    canonical = jcs.canonicalize(unsigned)
    prefixed = b"tulpa/sign\n" + canonical
    sig_bytes = _b64.urlsafe_b64decode(body["signature"] + "===")
    assert crypto.verify_detached(kp.public_key_bytes, prefixed, sig_bytes)


def test_build_connection_envelope_rejects_invalid_method() -> None:
    """method MUST be one of qr|intro|discovery|import per
    ConnectionRequestPayloadSchema."""
    kp = crypto.Keypair.generate()
    with pytest.raises(ValueError, match="qr|intro|discovery|import"):
        envelope.build_connection_envelope(
            keypair=kp,
            from_did="did:key:" + kp.public_key_multibase,
            to_did="did:plc:recipient",
            context="Test",
            headline="Test",
            method="garbage",
            created_at="2026-06-01T00:00:00Z",
            expires_at="2026-06-01T01:00:00Z",
        )


def test_build_signed_request_round_trips() -> None:
    """Sign a request and verify the HTTP §3.3 signature against the
    reconstructed signature base."""
    kp = crypto.Keypair.generate()
    body = envelope.build_intent_envelope(
        keypair=kp,
        from_did="did:key:" + kp.public_key_multibase,
        to_did="did:plc:recipient",
        target="did:plc:target",
        reason="Test",
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        nonce="fixed-nonce",
    ).body
    signed = envelope.build_signed_request(
        keypair=kp,
        target_url="https://example.invalid/ink/v1/recipient/intent",
        path="/ink/v1/recipient/intent",
        recipient_did="did:plc:recipient",
        body=body,
        timestamp="2026-06-01T00:00:00Z",
    )
    # Round-trip: verify the produced signature against the reconstructed base.
    assert crypto.verify_detached(
        kp.public_key_bytes, signed.signature_base, signed.signature_bytes
    )
    # Canonical body bytes are stable.
    assert signed.canonical_body == jcs.canonicalize(body)
    # Header has the expected prefix.
    assert signed.authorization_header.startswith("INK-Ed25519 ")


def test_signed_request_with_key_id() -> None:
    kp = crypto.Keypair.generate()
    signed = envelope.build_signed_request(
        keypair=kp,
        target_url="https://example.invalid/ink/v1/x/intent",
        path="/ink/v1/x/intent",
        recipient_did="did:plc:x",
        body={"protocol": "ink/0.1", "timestamp": "2026-06-01T00:00:00Z"},
        timestamp="2026-06-01T00:00:00Z",
        key_id="sig-2026-06",
    )
    assert "keyId=sig-2026-06" in signed.authorization_header


def test_format_authorization_header_rejects_unsafe_key_id() -> None:
    with pytest.raises(ValueError, match="ASCII letters"):
        envelope.format_authorization_header(b"\x00" * 64, key_id="bad id with space")
    with pytest.raises(ValueError, match="ASCII letters"):
        envelope.format_authorization_header(b"\x00" * 64, key_id='bad"quote')


def test_utc_timestamp_uses_z_suffix_at_second_precision() -> None:
    ts = envelope.utc_timestamp(dt.datetime(2026, 6, 1, 12, 34, 56, 789_000, tzinfo=dt.UTC))
    assert ts == "2026-06-01T12:34:56Z"


def test_utc_timestamp_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        envelope.utc_timestamp(dt.datetime(2026, 6, 1, 12, 0, 0))


def test_signature_base_format_matches_spec() -> None:
    base = envelope.build_signature_base(
        method="post",  # lowercase input → spec wants uppercase
        path="/ink/v1/recipient/intent",
        recipient_did="did:plc:recipient",
        canonical_body=b'{"k":"v"}',
        timestamp="2026-06-01T00:00:00Z",
    ).decode("utf-8")
    assert base == (
        "ink/0.1\n"
        "POST\n"
        "/ink/v1/recipient/intent\n"
        "did:plc:recipient\n"
        '{"k":"v"}\n'
        "2026-06-01T00:00:00Z"
    )


def test_utc_timestamp_converts_non_utc_tz() -> None:
    est = dt.timezone(dt.timedelta(hours=-5))
    ts = envelope.utc_timestamp(dt.datetime(2026, 1, 15, 12, 34, 56, tzinfo=est))
    assert ts == "2026-01-15T17:34:56Z"


def test_signature_base_rejects_embedded_newlines() -> None:
    base_kwargs = {
        "method": "POST",
        "path": "/x",
        "recipient_did": "did:plc:x",
        "canonical_body": b"{}",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    for field in ("method", "path", "recipient_did", "timestamp"):
        kwargs = dict(base_kwargs)
        kwargs[field] = str(kwargs[field]) + "\ninjected"
        with pytest.raises(ValueError, match="CR or LF"):
            envelope.build_signature_base(**kwargs)


def test_format_authorization_header_rejects_delimiter_chars_in_key_id() -> None:
    for bad in ("comma,bad", "eq=bad", "ctrl\x01bad", "non-ascii-é"):
        with pytest.raises(ValueError, match="ASCII letters"):
            envelope.format_authorization_header(b"\x00" * 64, key_id=bad)


def test_format_authorization_header_accepts_safe_key_id() -> None:
    header = envelope.format_authorization_header(b"\x00" * 64, key_id="sig-2026-06.v1_a")
    assert "keyId=sig-2026-06.v1_a" in header


def test_build_intent_envelope_refuses_invalid_urgency() -> None:
    """IntroRequestPayloadSchema constrains urgency to 'low' | 'normal'.
    Catching this client-side gives a clearer error than the receiver's
    Zod rejection."""
    kp = crypto.Keypair.generate()
    with pytest.raises(ValueError, match="urgency"):
        envelope.build_intent_envelope(
            keypair=kp,
            from_did="did:key:sender",
            to_did="did:plc:recipient",
            target="did:plc:target",
            reason="Test",
            urgency="urgent",  # invalid for intro_request
            created_at="2026-06-01T00:00:00Z",
            expires_at="2026-12-31T23:59:59Z",
        )


def test_new_ulid_is_26_chars_crockford_base32() -> None:
    u = envelope.new_ulid()
    assert len(u) == 26
    for ch in u:
        assert ch in "0123456789ABCDEFGHJKMNPQRSTVWXYZ", f"non-Crockford char: {ch!r}"
