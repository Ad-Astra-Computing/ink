"""Network transport for INK: agent card discovery + signed POST + response verify.

We use ``httpx`` (HTTP/2-capable, async-friendly, stricter than legacy
``requests``). Every call has an explicit timeout and follows the
fail-closed semantics the spec mandates: a transient transport failure
during key resolution must NOT regress to bootstrap mode.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from . import crypto, envelope

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_CARD_BYTES",
    "MAX_RESPONSE_BYTES",
    "AgentCard",
    "DiscoveryError",
    "TransportError",
    "fetch_agent_card",
    "send_signed_request",
    "verify_response_signature",
]

DEFAULT_TIMEOUT_SECONDS = 10.0
# The witness reference impl caps card bodies at 64 KB; we mirror that.
MAX_CARD_BYTES = 64 * 1024
# Responses are small JSON objects — 256 KB is plenty and keeps a hostile
# server from streaming us a giant body.
MAX_RESPONSE_BYTES = 256 * 1024


class TransportError(RuntimeError):
    """Raised when the HTTP exchange fails for non-protocol reasons."""


class DiscoveryError(RuntimeError):
    """Raised when an agent card cannot be discovered or is malformed."""


@dataclass(frozen=True, slots=True)
class AgentCard:
    agent_id: str
    endpoint: str
    raw: dict[str, Any]
    active_signing_keys: list[tuple[str, bytes]]
    """List of ``(keyId, public_key_bytes)`` for keys with status="active"."""


def _validate_https(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise TransportError(f"only http(s) URLs supported, got {parsed.scheme!r}")
    if parsed.scheme == "http" and parsed.hostname not in (
        "localhost",
        "127.0.0.1",
        "::1",
    ):
        # Plain HTTP is only acceptable for local development. We refuse
        # it elsewhere so a misconfigured CLI cannot send signed messages
        # in cleartext to an arbitrary host.
        raise TransportError(
            "plain HTTP only allowed for localhost; use https:// for any remote target"
        )


def fetch_agent_card(card_url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> AgentCard:
    """GET an agent.json discovery card and decode its signing keys.

    Raises:
        DiscoveryError: card is missing, oversized, or fails schema checks.
        TransportError: network error or bad URL.
    """
    _validate_https(card_url)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.get(card_url, headers={"accept": "application/json"})
    except httpx.RequestError as exc:
        raise TransportError(f"agent card fetch failed: {exc}") from exc
    if resp.status_code == 404:
        raise DiscoveryError(f"no agent card at {card_url}")
    if resp.status_code != 200:
        raise DiscoveryError(f"agent card returned HTTP {resp.status_code}")
    content_length = int(resp.headers.get("content-length") or 0)
    if content_length and content_length > MAX_CARD_BYTES:
        raise DiscoveryError(f"agent card too large: {content_length} bytes")
    body = resp.content
    if len(body) > MAX_CARD_BYTES:
        raise DiscoveryError(f"agent card too large: {len(body)} bytes")
    try:
        card = resp.json()
    except ValueError as exc:
        raise DiscoveryError(f"agent card is not valid JSON: {exc}") from exc
    if not isinstance(card, dict):
        raise DiscoveryError("agent card root must be a JSON object")
    if card.get("protocol") != envelope.INK_PROTOCOL_VERSION:
        raise DiscoveryError(f"unsupported protocol: {card.get('protocol')!r}")
    agent_id = card.get("agentId")
    if not isinstance(agent_id, str) or not agent_id:
        raise DiscoveryError("card.agentId missing")
    endpoint = card.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        raise DiscoveryError("card.endpoint missing")

    active_keys: list[tuple[str, bytes]] = []
    signing_block = ((card.get("keys") or {}).get("signing")) or []
    if isinstance(signing_block, list):
        for entry in signing_block:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") != "active":
                continue
            key_id = entry.get("keyId")
            mb = entry.get("publicKeyMultibase")
            if not isinstance(key_id, str) or not isinstance(mb, str):
                continue
            try:
                active_keys.append((key_id, crypto.decode_public_key_multibase(mb)))
            except ValueError:
                # Drop malformed entries; one bad key should not collapse
                # the whole set.
                continue
    return AgentCard(
        agent_id=agent_id, endpoint=endpoint, raw=card, active_signing_keys=active_keys
    )


def send_signed_request(
    signed: envelope.SignedRequest,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> httpx.Response:
    """POST a SignedRequest and return the response. Caller handles status."""
    _validate_https(signed.url)
    headers = {
        "authorization": signed.authorization_header,
        "content-type": "application/json",
        "accept": "application/json",
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            return client.post(signed.url, headers=headers, content=signed.canonical_body)
    except httpx.RequestError as exc:
        raise TransportError(f"signed POST failed: {exc}") from exc


def verify_response_signature(
    response: httpx.Response,
    *,
    method: str,
    path: str,
    recipient_did: str,
    candidate_keys: list[bytes],
) -> bool:
    """Verify the response signature in the same shape as a request signature.

    Some INK endpoints (challenge, resolution) sign their responses with
    the recipient's key. This helper reconstructs the signature base over
    the response body and tries each candidate key.

    Returns False if no Authorization header is present — the caller
    decides whether unsigned responses are acceptable for the endpoint.
    """
    auth_header = response.headers.get("authorization", "")
    if not auth_header.startswith("INK-Ed25519 "):
        return False
    sig_b64 = auth_header[len("INK-Ed25519 ") :].split(" ", 1)[0]
    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    except ValueError:
        return False
    if len(sig_bytes) != 64:
        return False

    timestamp = response.headers.get("x-ink-timestamp", "")
    if not timestamp:
        return False

    body = response.content
    if len(body) > MAX_RESPONSE_BYTES:
        return False
    try:
        parsed = response.json()
    except ValueError:
        return False
    from . import jcs  # local import to keep the public API surface small

    canonical = jcs.canonicalize(parsed)
    sig_base = envelope.build_signature_base(
        method=method,
        path=path,
        recipient_did=recipient_did,
        canonical_body=canonical,
        timestamp=timestamp,
    )
    return any(crypto.verify_detached(key, sig_base, sig_bytes) for key in candidate_keys)
