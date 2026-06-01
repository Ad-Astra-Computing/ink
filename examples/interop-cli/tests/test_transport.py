"""Transport layer tests with mocked HTTP."""

from __future__ import annotations

import json

import httpx
import pytest
from pytest_httpx import HTTPXMock

from ink_interop import crypto, envelope, transport


def test_fetch_agent_card_decodes_active_keys(httpx_mock: HTTPXMock) -> None:
    kp = crypto.Keypair.generate()
    httpx_mock.add_response(
        url="https://example.test/ink/v1/agent-id/agent.json",
        json={
            "protocol": "ink/0.1",
            "agentId": "did:plc:agent-id",
            "endpoint": "https://example.test/ink/v1/agent-id/intent",
            "keys": {
                "signing": [
                    {
                        "keyId": "sig-active",
                        "publicKeyMultibase": kp.public_key_multibase,
                        "status": "active",
                    },
                    {
                        "keyId": "sig-retired",
                        "publicKeyMultibase": kp.public_key_multibase,
                        "status": "retired",
                    },
                ]
            },
        },
    )
    card = transport.fetch_agent_card("https://example.test/ink/v1/agent-id/agent.json")
    assert card.agent_id == "did:plc:agent-id"
    assert card.endpoint == "https://example.test/ink/v1/agent-id/intent"
    assert len(card.active_signing_keys) == 1
    assert card.active_signing_keys[0][0] == "sig-active"
    assert card.active_signing_keys[0][1] == kp.public_key_bytes


def test_fetch_agent_card_404_raises_discovery_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url="https://example.test/agent.json", status_code=404)
    with pytest.raises(transport.DiscoveryError, match="no agent card"):
        transport.fetch_agent_card("https://example.test/agent.json")


def test_fetch_agent_card_wrong_protocol_rejected(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://example.test/agent.json",
        json={"protocol": "ink/2.0", "agentId": "x", "endpoint": "y"},
    )
    with pytest.raises(transport.DiscoveryError, match="unsupported protocol"):
        transport.fetch_agent_card("https://example.test/agent.json")


def test_plain_http_rejected_except_localhost(httpx_mock: HTTPXMock) -> None:
    with pytest.raises(transport.TransportError, match="plain HTTP"):
        transport.fetch_agent_card("http://example.test/agent.json")
    # Localhost is allowed for dev.
    httpx_mock.add_response(
        url="http://localhost:8787/agent.json",
        json={
            "protocol": "ink/0.1",
            "agentId": "x",
            "endpoint": "http://localhost:8787/ink/v1/x/intent",
        },
    )
    card = transport.fetch_agent_card("http://localhost:8787/agent.json")
    assert card.agent_id == "x"


def test_fetch_agent_card_oversized_body_rejected(httpx_mock: HTTPXMock) -> None:
    huge = "a" * (transport.MAX_CARD_BYTES + 1)
    httpx_mock.add_response(
        url="https://example.test/agent.json",
        json={
            "protocol": "ink/0.1",
            "agentId": "x",
            "endpoint": "y",
            "padding": huge,
        },
    )
    with pytest.raises(transport.DiscoveryError, match="too large"):
        transport.fetch_agent_card("https://example.test/agent.json")


def test_send_signed_request_posts_canonical_body(httpx_mock: HTTPXMock) -> None:
    kp = crypto.Keypair.generate()
    httpx_mock.add_response(
        method="POST",
        url="https://example.test/ink/v1/x/intent",
        status_code=200,
        json={"accepted": True},
    )
    signed = envelope.build_signed_request(
        keypair=kp,
        target_url="https://example.test/ink/v1/x/intent",
        path="/ink/v1/x/intent",
        recipient_did="did:plc:x",
        body=envelope.build_intent_envelope(
            keypair=kp,
            from_did="did:key:foo",
            to_did="did:plc:x",
            target="did:plc:target",
            reason="test",
            created_at="2026-06-01T00:00:00Z",
            expires_at="2026-12-31T23:59:59Z",
            nonce="abc",
        ).body,
        timestamp="2026-06-01T00:00:00Z",
    )
    response = transport.send_signed_request(signed)
    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    # Verify the actually-sent request matches what we signed.
    sent = httpx_mock.get_requests()[0]
    assert sent.headers["authorization"].startswith("INK-Ed25519 ")
    assert sent.content == signed.canonical_body


def test_send_signed_request_rejects_non_https(httpx_mock: HTTPXMock) -> None:
    kp = crypto.Keypair.generate()
    signed = envelope.build_signed_request(
        keypair=kp,
        target_url="ftp://example.test/intent",
        path="/intent",
        recipient_did="did:plc:x",
        body={"protocol": "ink/0.1", "timestamp": "2026-06-01T00:00:00Z"},
        timestamp="2026-06-01T00:00:00Z",
    )
    with pytest.raises(transport.TransportError, match="http"):
        transport.send_signed_request(signed)
    # httpx_mock should not have been hit.
    assert not httpx_mock.get_requests()


def test_verify_response_signature_round_trip(httpx_mock: HTTPXMock) -> None:
    """A response signed with the recipient's key verifies with that key."""
    kp = crypto.Keypair.generate()
    body = {"protocol": "ink/0.1", "type": "network.tulpa.ack", "ok": True}
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = "2026-06-01T00:00:00Z"
    sig_base = envelope.build_signature_base(
        method="POST",
        path="/ink/v1/x/intent",
        recipient_did="did:plc:x",
        canonical_body=canonical,
        timestamp=timestamp,
    )
    sig = crypto.sign_detached(kp, sig_base)
    import base64

    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    response = httpx.Response(
        status_code=200,
        headers={
            "authorization": f"INK-Ed25519 {sig_b64}",
            "x-ink-timestamp": timestamp,
            "content-type": "application/json",
        },
        content=canonical,
    )
    assert (
        transport.verify_response_signature(
            response,
            method="POST",
            path="/ink/v1/x/intent",
            recipient_did="did:plc:x",
            candidate_keys=[kp.public_key_bytes],
        )
        is True
    )


def test_verify_response_signature_without_auth_returns_false(httpx_mock: HTTPXMock) -> None:
    response = httpx.Response(status_code=200, content=b"{}")
    assert (
        transport.verify_response_signature(
            response,
            method="POST",
            path="/x",
            recipient_did="did:plc:x",
            candidate_keys=[b"\x00" * 32],
        )
        is False
    )


def test_url_validation_rejects_userinfo() -> None:
    with pytest.raises(transport.TransportError, match="userinfo"):
        transport.fetch_agent_card("https://attacker:pw@example.test/agent.json")


def test_url_validation_rejects_private_ip_by_default() -> None:
    with pytest.raises(transport.TransportError, match="private"):
        transport.fetch_agent_card("https://10.0.0.5/agent.json")
    with pytest.raises(transport.TransportError, match="private"):
        transport.fetch_agent_card("https://169.254.169.254/agent.json")
    with pytest.raises(transport.TransportError, match="private"):
        transport.fetch_agent_card("https://192.168.1.10/agent.json")


def test_url_validation_allows_private_ip_with_env_optin(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INK_INTEROP_ALLOW_PRIVATE_HOSTS", "1")
    httpx_mock.add_response(
        url="https://10.0.0.5/agent.json",
        json={
            "protocol": "ink/0.1",
            "agentId": "x",
            "endpoint": "https://10.0.0.5/ink/v1/x/intent",
        },
    )
    card = transport.fetch_agent_card("https://10.0.0.5/agent.json")
    assert card.agent_id == "x"


def test_url_validation_rejects_missing_hostname() -> None:
    with pytest.raises(transport.TransportError, match="hostname"):
        transport.fetch_agent_card("https:///foo")


def test_fetch_agent_card_refuses_redirect(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://example.test/agent.json",
        status_code=302,
        headers={"location": "https://elsewhere/"},
    )
    with pytest.raises(transport.DiscoveryError, match="redirect"):
        transport.fetch_agent_card("https://example.test/agent.json")


def test_fetch_agent_card_streams_with_oversized_response_aborted(
    httpx_mock: HTTPXMock,
) -> None:
    # Mock returns a 200 with Content-Length spoofed but a body exceeding
    # MAX_CARD_BYTES. The streaming reader must abort before buffering it.
    huge = b"a" * (transport.MAX_CARD_BYTES + 100)
    httpx_mock.add_response(
        url="https://example.test/agent.json",
        status_code=200,
        headers={"content-length": "10"},  # lying about size
        content=huge,
    )
    with pytest.raises(transport.DiscoveryError, match="exceeded"):
        transport.fetch_agent_card("https://example.test/agent.json")


def test_send_signed_request_refuses_redirect(httpx_mock: HTTPXMock) -> None:
    kp = crypto.Keypair.generate()
    httpx_mock.add_response(
        method="POST",
        url="https://example.test/ink/v1/x/intent",
        status_code=307,
        headers={"location": "https://elsewhere/"},
    )
    signed = envelope.build_signed_request(
        keypair=kp,
        target_url="https://example.test/ink/v1/x/intent",
        path="/ink/v1/x/intent",
        recipient_did="did:plc:x",
        body=envelope.build_intent_envelope(
            keypair=kp,
            from_did="did:key:foo",
            to_did="did:plc:x",
            target="did:plc:target",
            reason="test",
            created_at="2026-06-01T00:00:00Z",
            expires_at="2026-12-31T23:59:59Z",
            nonce="abc",
        ).body,
        timestamp="2026-06-01T00:00:00Z",
    )
    with pytest.raises(transport.DiscoveryError, match="redirect"):
        transport.send_signed_request(signed)


def test_verify_response_signature_derives_method_and_path_from_request(
    httpx_mock: HTTPXMock,
) -> None:
    """Default method/path come from the actual request, not caller-supplied values."""
    import base64

    kp = crypto.Keypair.generate()
    body = {"ok": True}
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = "2026-06-01T00:00:00Z"
    sig_base = envelope.build_signature_base(
        method="POST",
        path="/ink/v1/x/intent",
        recipient_did="did:plc:x",
        canonical_body=canonical,
        timestamp=timestamp,
    )
    sig = crypto.sign_detached(kp, sig_base)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    request = httpx.Request("POST", "https://example.test/ink/v1/x/intent")
    response = httpx.Response(
        status_code=200,
        headers={
            "authorization": f"INK-Ed25519 {sig_b64}",
            "x-ink-timestamp": timestamp,
            "content-type": "application/json",
        },
        content=canonical,
        request=request,
    )
    # No method/path overrides — they should come from response.request.
    assert (
        transport.verify_response_signature(
            response,
            recipient_did="did:plc:x",
            candidate_keys=[kp.public_key_bytes],
        )
        is True
    )
