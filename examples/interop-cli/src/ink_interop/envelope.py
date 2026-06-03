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
import re
import secrets
from dataclasses import dataclass
from typing import Any

from . import crypto, jcs

__all__ = [
    "INK_PROTOCOL_VERSION",
    "Envelope",
    "SignedRequest",
    "build_connection_envelope",
    "build_intent_envelope",
    "build_signature_base",
    "build_signed_request",
    "format_authorization_header",
    "new_ulid",
    "sign_body",
    "utc_timestamp",
]


# Crockford base32 alphabet (no I, L, O, U) per ULID spec.
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid(now: _dt.datetime | None = None) -> str:
    """Generate a 26-char Crockford-base32 ULID.

    INK envelopes use ULIDs for `id` and `correlationId`. 48-bit ms
    timestamp + 80 random bits, no external dependency.
    """
    moment = now if now is not None else _dt.datetime.now(tz=_dt.UTC)
    if moment.tzinfo is None:
        raise ValueError("ulid timestamp must be timezone-aware (UTC)")
    ts_ms = int(moment.timestamp() * 1000)
    rand = secrets.token_bytes(10)
    n = (ts_ms << 80) | int.from_bytes(rand, "big")
    out = ""
    for _ in range(26):
        out = _ULID_ALPHABET[n & 0x1F] + out
        n >>= 5
    return out


# An Ed25519 signature is 64 bytes = 86 base64url chars with no padding.
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}")

# Complexity caps mirroring src/crypto/sign.ts so this client agrees with
# the package on which bodies are too large to verify, and so a deep or
# huge body cannot exhaust CPU/memory before the signature check.
_MAX_NODES = 10_000
_MAX_DEPTH = 32
_MAX_CHARS = 1_200_000
# Cap on the canonical length in UTF-16 code units, matching sign.ts.
_MAX_CANONICAL_LENGTH = 1_048_576


def _utf16_len(s: str) -> int:
    """String length in UTF-16 code units, matching JS String.length so the
    char bounds agree with sign.ts even for characters outside the BMP.
    surrogatepass keeps lone surrogates countable (one unit) rather than
    raising, matching how a JS string measures them."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _within_bounds(value: Any) -> bool:
    """Bounded node/depth/char walk, matching isWithinBounds in sign.ts.
    Character counts use UTF-16 code units, as the TS walk does."""
    counters = {"nodes": 0, "chars": 0}

    def walk(v: Any, depth: int) -> bool:
        if depth > _MAX_DEPTH:
            return False
        counters["nodes"] += 1
        if counters["nodes"] > _MAX_NODES:
            return False
        if v is None or not isinstance(v, (dict, list)):
            if isinstance(v, str):
                counters["chars"] += _utf16_len(v)
                if counters["chars"] > _MAX_CHARS:
                    return False
            return True
        if isinstance(v, list):
            return all(walk(item, depth + 1) for item in v)
        for key, val in v.items():
            counters["nodes"] += 1
            if counters["nodes"] > _MAX_NODES:
                return False
            counters["chars"] += _utf16_len(key) if isinstance(key, str) else 0
            if counters["chars"] > _MAX_CHARS:
                return False
            if not walk(val, depth + 1):
                return False
        return True

    return walk(value, 0)


def _body_signature_domain(unsigned: dict[str, Any]) -> bytes:
    """Body-signature domain separator, keyed off the signed protocol field.

    Mirrors ``bodySignatureDomain`` in ``src/crypto/sign.ts``. ink/0.2 uses
    ``ink/sign\\n``; ink/0.1 and any object without an exact ink/0.2
    protocol use the legacy ``tulpa/sign\\n`` domain, kept for backward
    compatibility. Only the exact string ``"ink/0.2"`` switches domains.
    """
    if unsigned.get("protocol") == "ink/0.2":
        return b"ink/sign\n"
    return b"tulpa/sign\n"


def sign_body(keypair: crypto.Keypair, unsigned: dict[str, Any]) -> str:
    """Domain-separated body-level signature per `src/crypto/sign.ts`.

    Prefixes the version-keyed domain (see ``_body_signature_domain``) to
    the JCS-canonical bytes before Ed25519 signing. That domain separator
    prevents cross-protocol and cross-version signature replay. Output is
    base64url, no padding.
    """
    without_sig = {k: v for k, v in unsigned.items() if k != "signature"}
    canonical = jcs.canonicalize(without_sig)
    prefixed = _body_signature_domain(without_sig) + canonical
    sig = crypto.sign_detached(keypair, prefixed)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def verify_body(public_key_bytes: bytes, body: dict[str, Any]) -> bool:
    """Verify a body-level signature using the version-keyed domain.

    Strips the ``signature`` field, JCS-canonicalizes the rest, selects the
    domain from the signed protocol version, and verifies the Ed25519
    signature. The verifier tries exactly one domain, so a signature made
    under one version's domain does not verify under another.

    Never raises: any malformed input returns ``False``. The signature must
    be exactly 86 base64url characters with no padding, matching the strict
    shape the TypeScript ``verifyMessage`` enforces, so the two
    implementations agree on what counts as a well-formed signature.
    """
    if not isinstance(body, dict):
        return False
    signature = body.get("signature")
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        return False
    try:
        without_sig = {k: v for k, v in body.items() if k != "signature"}
        if not _within_bounds(without_sig):
            return False
        canonical = jcs.canonicalize(without_sig)
        # Match sign.ts, which caps canonical.length in UTF-16 code units
        # (JS string length), not UTF-8 bytes, so the two implementations
        # agree on the cap for non-ASCII bodies.
        if len(canonical.decode("utf-8").encode("utf-16-le")) // 2 > _MAX_CANONICAL_LENGTH:
            return False
        prefixed = _body_signature_domain(without_sig) + canonical
        sig = base64.urlsafe_b64decode(signature + "==")
        return crypto.verify_detached(public_key_bytes, prefixed, sig)
    except (ValueError, TypeError, RecursionError):
        return False

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
    keypair: crypto.Keypair,
    from_did: str,
    to_did: str,
    target: str,
    reason: str,
    urgency: str = "normal",
    expires_at: str,
    created_at: str,
    correlation_id: str | None = None,
    signing_key_id: str | None = None,
    nonce: str | None = None,
    timestamp: str | None = None,
) -> Envelope:
    """Build a canonical INK intent envelope (intro_request).

    Emits the shape defined by ``MessageEnvelopeSchema`` in
    ``@adastracomputing/ink/src/models/intent.ts``: ``id``,
    ``correlationId``, ``createdAt``, ``intent`` enum, ``payload``,
    body-level ``signature`` (domain-separated per ``sign.ts``),
    ``provenance``. The receiver also reads top-level ``timestamp``
    and ``nonce`` for the HTTP §3.3 freshness + replay check —
    those are extra fields the envelope schema does not strict-reject,
    so this builder includes them alongside the canonical fields.

    Args:
        keypair: Sender Ed25519 keypair (for the body signature).
        from_did: Sender DID.
        to_did: Recipient DID.
        target: Person the introduction is about (intro_request payload).
        reason: Why the introduction is being asked for.
        urgency: ``"low"`` or ``"normal"`` per IntroRequestPayloadSchema.
        expires_at: ISO-8601 UTC expiry for the intent.
        created_at: ISO-8601 UTC creation timestamp (envelope `createdAt`).
        correlation_id: Optional pre-existing correlationId; ULID if omitted.
        signing_key_id: Optional `keyId` hint to include in the envelope
            and in the Authorization header.
        nonce: Optional pre-generated replay nonce; auto-generated if omitted.
        timestamp: Optional HTTP-auth timestamp; defaults to ``created_at``
            for consistency between the envelope and the signature base.
    """
    if urgency not in {"low", "normal"}:
        raise ValueError("intro_request urgency must be 'low' or 'normal'")
    # NOTE: `provenance` is `.optional()` in MessageProvenanceSchema.
    # Zod accepts an undefined/absent field but rejects an explicit
    # `null`. Omit the key entirely so the envelope passes strict
    # validation; only include it for envelopes that actually carry
    # provenance metadata (extension-originated sends, etc).
    unsigned: dict[str, Any] = {
        "protocol": INK_PROTOCOL_VERSION,
        "id": new_ulid(),
        "correlationId": correlation_id if correlation_id else new_ulid(),
        "createdAt": created_at,
        "expiresAt": expires_at,
        "from": from_did,
        "to": to_did,
        "intent": "intro_request",
        "payload": {
            "target": target,
            "reason": reason,
            "urgency": urgency,
        },
        # `timestamp` and `nonce` are read by the receiver's
        # `verifyInkAuth()` middleware (INK §3.3) for HTTP-level
        # freshness and replay protection. They live alongside the
        # canonical envelope fields rather than as separate headers
        # so the whole signed-body integrity story stays in one
        # place. Default `timestamp` to `created_at` so the envelope
        # is internally consistent.
        "timestamp": timestamp if timestamp is not None else created_at,
        "nonce": nonce if nonce is not None else crypto.generate_nonce(),
    }
    if signing_key_id:
        unsigned["signingKeyId"] = signing_key_id
    signature = sign_body(keypair, unsigned)
    body = {**unsigned, "signature": signature}
    return Envelope(body=body)


def build_connection_envelope(
    *,
    keypair: crypto.Keypair,
    from_did: str,
    to_did: str,
    context: str,
    headline: str,
    method: str = "discovery",
    introduced_by: str | None = None,
    skills: list[str] | None = None,
    interests: list[str] | None = None,
    open_to: list[str] | None = None,
    timezone: str | None = None,
    expires_at: str,
    created_at: str,
    correlation_id: str | None = None,
    signing_key_id: str | None = None,
    nonce: str | None = None,
    timestamp: str | None = None,
) -> Envelope:
    """Build a canonical INK connection_request envelope.

    `connection_request` is the bootstrap intent for first contact between
    strangers. Receivers that have opted in to foreign senders treat it as
    trust-on-first-use: the body signature is verified against the public
    key extracted from the sender's DID (did:key) without prior key
    exchange. Other intent types (intro_request, ask, follow_up) presume
    the sender is already a known contact.

    Payload shape follows `ConnectionRequestPayloadSchema` in
    `@adastracomputing/ink/src/models/intent.ts`.
    """
    if method not in {"qr", "intro", "discovery", "import"}:
        raise ValueError("connection_request method must be qr|intro|discovery|import")
    payload: dict[str, Any] = {
        "method": method,
        "context": context,
        "profileSnapshot": {
            "headline": headline,
            "skills": skills if skills is not None else [],
            "interests": interests if interests is not None else [],
            "openTo": open_to if open_to is not None else [],
        },
    }
    if introduced_by:
        payload["introducedBy"] = introduced_by
    if timezone:
        payload["profileSnapshot"]["availability"] = {"timezone": timezone}
    unsigned: dict[str, Any] = {
        "protocol": INK_PROTOCOL_VERSION,
        "id": new_ulid(),
        "correlationId": correlation_id if correlation_id else new_ulid(),
        "createdAt": created_at,
        "expiresAt": expires_at,
        "from": from_did,
        "to": to_did,
        "intent": "connection_request",
        "payload": payload,
        "timestamp": timestamp if timestamp is not None else created_at,
        "nonce": nonce if nonce is not None else crypto.generate_nonce(),
    }
    if signing_key_id:
        unsigned["signingKeyId"] = signing_key_id
    signature = sign_body(keypair, unsigned)
    body = {**unsigned, "signature": signature}
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
