"""INK envelope construction and signature-base assembly.

Per INK spec §3.3 the signature base is::

    signatureBase = PROTOCOL + "\\n" + METHOD + "\\n" + PATH + "\\n"
                  + recipientDid + "\\n" + JCS(body) + "\\n" + timestamp

This module deliberately avoids any tulpa- or @adastracomputing/ink-
specific helpers. Everything here is derived from the published spec on
ink.tulpa.network so an external integrator can audit it line-by-line.
"""

from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass
from typing import Any

from . import crypto, jcs

__all__ = [
    "INK_PROTOCOL_VERSION",
    "Envelope",
    "SignedRequest",
    "build_intent_envelope",
    "build_signature_base",
    "build_signed_request",
    "format_authorization_header",
    "utc_timestamp",
]

INK_PROTOCOL_VERSION = "ink/0.1"


@dataclass(frozen=True, slots=True)
class Envelope:
    """An INK message envelope ready to be JCS-encoded and signed.

    The dataclass mirrors the spec's intent envelope (network.tulpa.intent)
    field-for-field. Callers can also construct envelopes directly as dicts
    if they want full control — ``build_intent_envelope`` is a convenience.
    """

    body: dict[str, Any]

    def canonical_body(self) -> bytes:
        return jcs.canonicalize(self.body)


@dataclass(frozen=True, slots=True)
class SignedRequest:
    """A fully assembled, signed INK request ready to send.

    Attributes:
        method: HTTP method (always "POST" for INK in 0.1).
        path: Request path relative to the target host.
        url: Fully-qualified target URL.
        canonical_body: The JCS bytes that were actually signed.
        signature_base: The plaintext signature input (spec §3.3).
        signature_bytes: Raw 64-byte Ed25519 signature.
        authorization_header: The value to send in the Authorization header.
        timestamp: The ISO-8601 UTC timestamp included in the signature base.
        recipient_did: The recipient DID included in the signature base.
        body_obj: The original Python dict (for logging / inspection).
    """

    method: str
    path: str
    url: str
    canonical_body: bytes
    signature_base: bytes
    signature_bytes: bytes
    authorization_header: str
    timestamp: str
    recipient_did: str
    body_obj: dict[str, Any]


def utc_timestamp(now: _dt.datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp at second precision (spec §3.3).

    The spec uses second-precision timestamps; receivers reject finer
    precision because it complicates replay windows. We strip microseconds
    explicitly. A non-UTC tz-aware datetime is converted to UTC before
    formatting — otherwise the output would carry the caller's local
    offset and the receiver would reject the signature.
    """
    moment = now if now is not None else _dt.datetime.now(tz=_dt.UTC)
    if moment.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware (UTC)")
    moment_utc = moment.astimezone(_dt.UTC).replace(microsecond=0)
    return moment_utc.isoformat().replace("+00:00", "Z")


def build_intent_envelope(
    *,
    from_did: str,
    to_did: str,
    intent_type: str,
    purpose: str,
    urgency: str = "normal",
    expires_at: str,
    timestamp: str,
    nonce: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Envelope:
    """Build a network.tulpa.intent envelope.

    Args:
        from_did: Sender DID.
        to_did: Recipient DID.
        intent_type: One of the published intent types (see INK §4.2). For
            interop tests we usually use "introduction" because it has no
            mandatory encrypted-body requirement.
        purpose: One-line free-text purpose.
        urgency: One of "low", "normal", "urgent".
        expires_at: ISO-8601 UTC expiry for the intent.
        timestamp: ISO-8601 UTC timestamp matching the signature base.
        nonce: Base64url-encoded replay-protection nonce. Auto-generated
            with :func:`crypto.generate_nonce` if omitted.
        extra: Optional additional fields to merge into the body. Use this
            to attach context the spec defines but this helper does not
            cover (e.g. "context": {...}).
    """
    body: dict[str, Any] = {
        "protocol": INK_PROTOCOL_VERSION,
        "type": "network.tulpa.intent",
        "from": from_did,
        "to": to_did,
        "intentType": intent_type,
        "purpose": purpose,
        "urgency": urgency,
        "expiresAt": expires_at,
        "nonce": nonce if nonce is not None else crypto.generate_nonce(),
        "timestamp": timestamp,
    }
    if extra:
        # Refuse to overwrite core envelope fields via `extra`. Silent
        # overwrites would let a caller accidentally sign a malformed
        # intent (e.g. an `extra` containing a stale "nonce" or a
        # swapped "to"), and there's no legitimate reason a higher-
        # level helper would do that intentionally.
        clashing = set(extra) & set(body)
        if clashing:
            raise ValueError(f"extra fields collide with core envelope keys: {sorted(clashing)}")
        body.update(extra)
    return Envelope(body=body)


def build_signature_base(
    *,
    method: str,
    path: str,
    recipient_did: str,
    canonical_body: bytes,
    timestamp: str,
) -> bytes:
    """Assemble the INK signature base (spec §3.3).

    The base is plain ASCII/UTF-8 text with explicit "\\n" separators —
    NOT JSON, NOT URL-encoded. The body slot is the JCS bytes verbatim.
    """
    # All non-body parts are restricted to printable ASCII by the spec
    # (HTTP methods, paths after percent-encoding, ISO-8601 timestamps,
    # the protocol literal). Encode as ASCII so a non-ASCII surprise
    # raises here rather than producing a signature base that no
    # receiver can reconstruct. recipientDid is UTF-8 because did:web:
    # technically allows IDN labels.
    parts = [
        INK_PROTOCOL_VERSION.encode("ascii"),
        method.upper().encode("ascii"),
        path.encode("ascii"),
        recipient_did.encode("utf-8"),
        canonical_body,
        timestamp.encode("ascii"),
    ]
    # Reject embedded newlines anywhere except the body — they would
    # alias separator semantics in the signature base and let an
    # attacker craft a payload whose canonical signature base matches
    # a different intended message.
    for component in (
        method.upper(),
        path,
        recipient_did,
        timestamp,
    ):
        if "\n" in component or "\r" in component:
            raise ValueError("signature base components must not contain CR or LF")
    return b"\n".join(parts)


def format_authorization_header(signature_bytes: bytes, key_id: str | None = None) -> str:
    """Format the Authorization header value per spec §3.2.

    ``keyId`` is the rotation hint receivers use to pick the right candidate
    public key without trial-verifying every active key.
    """
    sig_b64 = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    header = f"INK-Ed25519 {sig_b64}"
    if key_id:
        # Enforce a conservative key-id alphabet: ASCII letters, digits,
        # `-`, `_`, `.`. This blocks header-parser confusion via commas,
        # equals, semicolons, control bytes, or non-ASCII characters
        # (any of which a future spec addition could repurpose as a
        # delimiter). The published INK key-id format is keyed-rotation
        # hints like ``sig-2026-06`` which fit this alphabet.
        if not key_id or not all(ch.isascii() and (ch.isalnum() or ch in "-_.") for ch in key_id):
            raise ValueError("keyId must contain only ASCII letters, digits, '-', '_', or '.'")
        header = f"{header} keyId={key_id}"
    return header


def build_signed_request(
    *,
    keypair: crypto.Keypair,
    target_url: str,
    path: str,
    recipient_did: str,
    body: dict[str, Any],
    method: str = "POST",
    timestamp: str | None = None,
    key_id: str | None = None,
) -> SignedRequest:
    """Build a fully signed INK request ready to send.

    The ``target_url`` is the absolute URL the HTTP client will POST to;
    ``path`` is the path component the receiver will use to reconstruct
    the signature base. These are passed separately because a load
    balancer can rewrite the network URL without changing the path the
    receiver verifies against.
    """
    ts = timestamp if timestamp is not None else utc_timestamp()
    canonical = jcs.canonicalize(body)
    sig_base = build_signature_base(
        method=method,
        path=path,
        recipient_did=recipient_did,
        canonical_body=canonical,
        timestamp=ts,
    )
    sig_bytes = crypto.sign_detached(keypair, sig_base)
    auth = format_authorization_header(sig_bytes, key_id=key_id)
    return SignedRequest(
        method=method,
        path=path,
        url=target_url,
        canonical_body=canonical,
        signature_base=sig_base,
        signature_bytes=sig_bytes,
        authorization_header=auth,
        timestamp=ts,
        recipient_did=recipient_did,
        body_obj=body,
    )
