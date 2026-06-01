"""Standalone crypto + multibase round-trip tests."""

from __future__ import annotations

import pytest

from ink_interop import crypto


def test_generate_keypair_round_trips() -> None:
    kp = crypto.Keypair.generate()
    assert len(kp.public_key_bytes) == 32
    msg = b"hello"
    sig = crypto.sign_detached(kp, msg)
    assert len(sig) == 64
    assert crypto.verify_detached(kp.public_key_bytes, msg, sig) is True
    assert crypto.verify_detached(kp.public_key_bytes, b"different", sig) is False


def test_keypair_repr_does_not_leak_private_seed() -> None:
    # Defense against accidental log exposure.
    kp = crypto.Keypair.generate()
    seed_hex = kp.private_key.private_bytes_raw().hex()  # type: ignore[attr-defined]
    repr_str = repr(kp)
    assert seed_hex not in repr_str
    assert kp.public_key_hex in repr_str


def test_multibase_round_trip() -> None:
    kp = crypto.Keypair.generate()
    mb = kp.public_key_multibase
    assert mb.startswith("z")
    decoded = crypto.decode_public_key_multibase(mb)
    assert decoded == kp.public_key_bytes


def test_decode_multibase_rejects_non_z_prefix() -> None:
    with pytest.raises(ValueError, match="base58btc"):
        crypto.decode_public_key_multibase("f1234")


def test_decode_multibase_rejects_wrong_multicodec() -> None:
    # 0x12 0x34 is not the ed25519-pub prefix (0xed 0x01).
    # Encode 0x1234 + 32 zero bytes and try to decode.
    fake = b"\x12\x34" + b"\x00" * 32
    fake_b58 = crypto._base58_encode(fake)
    with pytest.raises(ValueError, match="ed25519-pub"):
        crypto.decode_public_key_multibase("z" + fake_b58)


def test_decode_multibase_rejects_short_key() -> None:
    # ed25519-pub prefix followed by 31 bytes (one short).
    short = crypto.ED25519_MULTICODEC_PREFIX + b"\x00" * 31
    with pytest.raises(ValueError, match="wrong length"):
        crypto.decode_public_key_multibase("z" + crypto._base58_encode(short))


def test_generate_nonce_is_url_safe_and_long_enough() -> None:
    n = crypto.generate_nonce()
    assert "=" not in n
    assert all(c.isalnum() or c in "-_" for c in n)
    # 16 bytes = 24 b64 chars unpadded - 2 strip = 22.
    assert len(n) >= 20


def test_generate_nonce_rejects_under_minimum() -> None:
    with pytest.raises(ValueError, match="at least"):
        crypto.generate_nonce(num_bytes=8)
    with pytest.raises(ValueError, match="at least"):
        crypto.generate_nonce(num_bytes=0)


def test_seed_with_wrong_length_rejected() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.Keypair.from_private_bytes(b"\x00" * 16)


def test_verify_rejects_short_public_key() -> None:
    assert crypto.verify_detached(b"\x00" * 31, b"msg", b"\x00" * 64) is False


def test_verify_rejects_short_signature() -> None:
    kp = crypto.Keypair.generate()
    assert crypto.verify_detached(kp.public_key_bytes, b"msg", b"\x00" * 32) is False
