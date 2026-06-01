"""Ed25519 signing and verification for INK.

INK uses Ed25519 (RFC 8032) for transport-layer authentication. We use
``cryptography`` for the math — it's well-audited, FIPS-friendly, and uses
constant-time native bindings.

Public keys are serialized as ``multibase('z' + base58btc(0xed01 || key))``
per the did:key spec (W3C DID-Core, multikey codec). This module handles
encoding/decoding for both multibase and raw hex (raw hex is the form
the test vectors use).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from secrets import token_bytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "ED25519_MULTICODEC_PREFIX",
    "Keypair",
    "decode_public_key_multibase",
    "encode_public_key_multibase",
    "generate_nonce",
    "sign_detached",
    "verify_detached",
]

# Multicodec prefix for ed25519-pub: 0xed01 (varint).
ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])

# Base58btc alphabet per IPFS multibase ("z" prefix).
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True, slots=True)
class Keypair:
    """A bound Ed25519 keypair.

    ``private_key`` is held only as the ``cryptography`` opaque object —
    we deliberately do not expose raw bytes on the dataclass surface so
    accidental ``print(keypair)`` cannot leak material.
    """

    private_key: Ed25519PrivateKey
    public_key_bytes: bytes

    @classmethod
    def generate(cls) -> Keypair:
        """Generate a fresh keypair using the OS CSPRNG."""
        sk = Ed25519PrivateKey.generate()
        pk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(private_key=sk, public_key_bytes=pk_bytes)

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> Keypair:
        """Load a keypair from its 32-byte private seed (RFC 8032 §5.1.5)."""
        if len(seed) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(private_key=sk, public_key_bytes=pk_bytes)

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @property
    def public_key_multibase(self) -> str:
        return encode_public_key_multibase(self.public_key_bytes)

    def __repr__(self) -> str:
        # Defensive: never let an accidental log expose the private key.
        return f"Keypair(public_key={self.public_key_hex})"


def sign_detached(keypair: Keypair, message: bytes) -> bytes:
    """Sign ``message`` with the keypair. Returns the 64-byte signature."""
    return keypair.private_key.sign(message)


def verify_detached(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature in constant time. Returns True iff valid."""
    if len(public_key_bytes) != 32:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pk.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def encode_public_key_multibase(public_key_bytes: bytes) -> str:
    """Encode an Ed25519 public key as did:key-compatible multibase."""
    if len(public_key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}")
    return "z" + _base58_encode(ED25519_MULTICODEC_PREFIX + public_key_bytes)


def decode_public_key_multibase(multibase: str) -> bytes:
    """Decode a multibase Ed25519 public key back to its 32 raw bytes."""
    if not multibase.startswith("z"):
        raise ValueError("only base58btc multibase ('z' prefix) supported")
    raw = _base58_decode(multibase[1:])
    if not raw.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("multibase value is not an ed25519-pub key")
    key = raw[len(ED25519_MULTICODEC_PREFIX) :]
    if len(key) != 32:
        raise ValueError(f"decoded key has wrong length: {len(key)}")
    return key


MIN_NONCE_BYTES = 16


def generate_nonce(num_bytes: int = 16) -> str:
    """Generate a base64url-encoded random nonce for replay protection.

    Enforces a 16-byte minimum so a caller cannot accidentally request a
    nonce too short to be collision-resistant against an adversary
    replaying intents within the spec's freshness window.
    """
    if num_bytes < MIN_NONCE_BYTES:
        raise ValueError(f"nonce must be at least {MIN_NONCE_BYTES} bytes, got {num_bytes}")
    return base64.urlsafe_b64encode(token_bytes(num_bytes)).rstrip(b"=").decode("ascii")


# --- Base58btc helpers ----------------------------------------------------


def _base58_encode(data: bytes) -> str:
    if not data:
        return ""
    # Count leading zero bytes — each becomes a leading "1".
    leading_zeros = 0
    for byte in data:
        if byte != 0:
            break
        leading_zeros += 1
    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _BASE58_ALPHABET[rem] + encoded
    return ("1" * leading_zeros) + encoded


def _base58_decode(value: str) -> bytes:
    if not value:
        return b""
    leading_ones = 0
    for ch in value:
        if ch != "1":
            break
        leading_ones += 1
    num = 0
    for ch in value:
        try:
            num = num * 58 + _BASE58_ALPHABET.index(ch)
        except ValueError as exc:
            raise ValueError(f"invalid base58 character: {ch!r}") from exc
    # Determine byte length so we round-trip leading zeros.
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return (b"\x00" * leading_ones) + body
