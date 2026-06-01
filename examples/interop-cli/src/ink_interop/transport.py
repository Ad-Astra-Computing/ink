"""Network transport for INK: agent card discovery + signed POST + response verify.

We use ``httpx`` (HTTP/2-capable, async-friendly, stricter than legacy
``requests``). Every call has an explicit timeout, refuses redirects,
streams response bodies with a hard cap before buffering, and fails
closed: a transient transport failure during key resolution must NOT
silently regress to bootstrap mode.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
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

# Environment escape hatch for local development against private-IP
# endpoints (Docker networks, k8s clusters, an INK reference server on
# a LAN host). Defaults to off because the safe behavior for a CLI that
# signs and sends messages is to refuse SSRF-shaped URLs.
_ALLOW_PRIVATE_ENV = "INK_INTEROP_ALLOW_PRIVATE_HOSTS"


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


def _allow_private_hosts() -> bool:
    return os.environ.get(_ALLOW_PRIVATE_ENV, "").lower() in {"1", "true", "yes"}


def _is_loopback_hostname(hostname: str) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _classify_hostname(hostname: str) -> str:
    """Return one of: "loopback", "private", "public".

    Returns "public" for hostnames that are not raw IPs — we cannot resolve
    DNS here without a network call, so we treat hostnames as public and
    let the network layer fail closed on resolution. This is consistent
    with the existing fail-closed posture: an attacker who controls DNS
    can already redirect a hostname; the defense for that is the response
    signature check, not URL validation.
    """
    if _is_loopback_hostname(hostname):
        return "loopback"
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        # Not an IP literal — treat as a public hostname.
        return "public"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "private"
    return "public"


def _validate_request_url(url: str) -> None:
    """Reject URLs we will not send signed requests to.

    Refuses non-http(s) schemes, plain HTTP outside loopback, embedded
    userinfo (which can confuse hostname checks for downstream
    consumers), and private / link-local / reserved IPs unless the
    operator has explicitly set ``INK_INTEROP_ALLOW_PRIVATE_HOSTS=1``
    for local development.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise TransportError(f"only http(s) URLs supported, got {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise TransportError("URLs with embedded userinfo are not supported")
    hostname = parsed.hostname
    if not hostname:
        raise TransportError("URL is missing a hostname")
    classification = _classify_hostname(hostname)
    if parsed.scheme == "http" and classification != "loopback":
        # Plain HTTP only ever allowed for loopback so a misconfigured
        # CLI cannot send signed messages in cleartext to an arbitrary
        # host. Even with the private-hosts opt-in we still require
        # HTTPS for non-loopback addresses.
        raise TransportError(
            "plain HTTP only allowed for localhost; use https:// for any remote target"
        )
    if classification == "private" and not _allow_private_hosts():
        raise TransportError(
            f"refusing to send to private/link-local host {hostname!r}; "
            f"set {_ALLOW_PRIVATE_ENV}=1 to allow this for local dev"
        )


def _read_capped_body(response: httpx.Response, max_bytes: int) -> bytes:
    """Stream the response body, aborting if it exceeds ``max_bytes``.

    httpx buffers the body when ``response.content`` is accessed, so a
    hostile server could otherwise force us to hold an arbitrarily large
    payload in memory before our cap check ran. ``iter_bytes`` returns
    incrementally so we can break early.
    """
    buf = bytearray()
    for chunk in response.iter_bytes():
        if len(buf) + len(chunk) > max_bytes:
            raise DiscoveryError(f"response exceeded {max_bytes} bytes")
        buf.extend(chunk)
    return bytes(buf)


def fetch_agent_card(card_url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> AgentCard:
    """GET an agent.json discovery card and decode its signing keys.

    Raises:
        DiscoveryError: card is missing, oversized, or fails schema checks.
        TransportError: network error or bad URL.
    """
    _validate_request_url(card_url)
    try:
        with (
            httpx.Client(timeout=timeout, follow_redirects=False) as client,
            client.stream("GET", card_url, headers={"accept": "application/json"}) as resp,
        ):
            _enforce_no_redirect(resp)
            if resp.status_code == 404:
                raise DiscoveryError(f"no agent card at {card_url}")
            if resp.status_code != 200:
                raise DiscoveryError(f"agent card returned HTTP {resp.status_code}")
            content_length = int(resp.headers.get("content-length") or 0)
            if content_length and content_length > MAX_CARD_BYTES:
                raise DiscoveryError(f"agent card too large: {content_length} bytes")
            body = _read_capped_body(resp, MAX_CARD_BYTES)
    except httpx.RequestError as exc:
        raise TransportError(f"agent card fetch failed: {exc}") from exc
    try:
        card = json.loads(body)
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


def _enforce_no_redirect(response: httpx.Response) -> None:
    """Refuse 3xx responses explicitly so the failure mode is unambiguous.

    httpx already refuses to follow redirects (``follow_redirects=False``),
    but a 3xx status would otherwise propagate as a generic "non-200" and
    the caller would not know it was a redirect. Raising here makes the
    contract explicit and protects against a future maintainer flipping
    the flag without auditing every call site.
    """
    if 300 <= response.status_code < 400:
        raise DiscoveryError(f"refusing to follow redirect: HTTP {response.status_code}")


def _assert_header_value_clean(name: str, value: str) -> None:
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        raise TransportError(f"refusing header with CR/LF/NUL: {name!r}")


def send_signed_request(
    signed: envelope.SignedRequest,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> httpx.Response:
    """POST a SignedRequest and return the response. Caller handles status."""
    _validate_request_url(signed.url)
    _assert_header_value_clean("authorization", signed.authorization_header)
    headers = {
        "authorization": signed.authorization_header,
        "content-type": "application/json",
        "accept": "application/json",
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.post(signed.url, headers=headers, content=signed.canonical_body)
            _enforce_no_redirect(response)
            return response
    except httpx.RequestError as exc:
        raise TransportError(f"signed POST failed: {exc}") from exc


def verify_response_signature(
    response: httpx.Response,
    *,
    recipient_did: str,
    candidate_keys: list[bytes],
    method: str | None = None,
    path: str | None = None,
) -> bool:
    """Verify the response signature in the same shape as a request signature.

    Some INK endpoints (challenge, resolution) sign their responses with
    the recipient's key. This helper reconstructs the signature base over
    the response body and tries each candidate key.

    ``method`` and ``path`` default to the values httpx actually sent
    (``response.request.method`` and the path component of the request
    URL). Pass explicit overrides only if the verifying value should
    differ from what was sent — e.g. when verifying through a path-
    rewriting proxy. Default behavior is the safe one: caller never has
    to keep its own stale copy of these values.

    Returns False if no Authorization header is present — the caller
    decides whether unsigned responses are acceptable for the endpoint.
    """
    request_method = method if method is not None else (response.request.method or "POST")
    request_path = path if path is not None else (response.request.url.raw_path.decode())
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

    # The response body is already buffered on a non-streamed httpx call,
    # but the size cap is still meaningful: a hostile server can return
    # a 64 KB JSON blob that costs us nothing to ignore, and the cap
    # makes the contract explicit. Real streaming protection lives on
    # the fetch path (fetch_agent_card).
    body = response.content
    if len(body) > MAX_RESPONSE_BYTES:
        return False
    try:
        parsed = json.loads(body)
    except ValueError:
        return False
    from . import jcs  # local import to keep the public API surface small

    canonical = jcs.canonicalize(parsed)
    try:
        sig_base = envelope.build_signature_base(
            method=request_method,
            path=request_path,
            recipient_did=recipient_did,
            canonical_body=canonical,
            timestamp=timestamp,
        )
    except ValueError:
        # Recipient DID or path with CR/LF — refuse rather than accept
        # an unverifiable signature base.
        return False
    return any(crypto.verify_detached(key, sig_base, sig_bytes) for key in candidate_keys)
