"""End-to-end envelope construction tests (no network)."""

from __future__ import annotations

import datetime as dt

import pytest

from ink_interop import crypto, envelope, jcs


def test_build_intent_envelope_includes_required_fields() -> None:
    env = envelope.build_intent_envelope(
        from_did="did:plc:sender",
        to_did="did:plc:recipient",
        intent_type="introduction",
        purpose="Test",
        expires_at="2026-12-31T23:59:59Z",
        timestamp="2026-06-01T00:00:00Z",
        nonce="fixed-nonce",
    )
    body = env.body
    assert body["protocol"] == "ink/0.1"
    assert body["type"] == "network.tulpa.intent"
    assert body["from"] == "did:plc:sender"
    assert body["to"] == "did:plc:recipient"
    assert body["intentType"] == "introduction"
    assert body["purpose"] == "Test"
    assert body["urgency"] == "normal"
    assert body["expiresAt"] == "2026-12-31T23:59:59Z"
    assert body["timestamp"] == "2026-06-01T00:00:00Z"
    assert body["nonce"] == "fixed-nonce"


def test_build_intent_envelope_auto_generates_nonce() -> None:
    env = envelope.build_intent_envelope(
        from_did="did:plc:sender",
        to_did="did:plc:recipient",
        intent_type="introduction",
        purpose="Test",
        expires_at="2026-12-31T23:59:59Z",
        timestamp="2026-06-01T00:00:00Z",
    )
    assert env.body["nonce"]
    assert isinstance(env.body["nonce"], str)


def test_build_signed_request_round_trips() -> None:
    """Sign a request and verify it locally — proves the wire format is internally consistent."""
    kp = crypto.Keypair.generate()
    body = envelope.build_intent_envelope(
        from_did="did:key:" + kp.public_key_multibase,
        to_did="did:plc:recipient",
        intent_type="introduction",
        purpose="Test",
        expires_at="2026-12-31T23:59:59Z",
        timestamp="2026-06-01T00:00:00Z",
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
    with pytest.raises(ValueError, match="keyId must not contain"):
        envelope.format_authorization_header(b"\x00" * 64, key_id="bad id with space")
    with pytest.raises(ValueError, match="keyId must not contain"):
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
