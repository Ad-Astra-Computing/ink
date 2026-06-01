"""CLI integration tests using Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ink_interop.cli import app


def test_keygen_emits_public_key_payload() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["keygen"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["publicKeyHex"]
    assert payload["publicKeyMultibase"].startswith("z")
    assert payload["did:key"].startswith("did:key:z")


def test_keygen_writes_seed_file_with_0600(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "seed.hex"
    result = runner.invoke(app, ["keygen", "--out-seed", str(out)])
    assert result.exit_code == 0
    seed_hex = out.read_text().strip()
    assert len(seed_hex) == 64
    # On POSIX the seed file should be 0600. Skip on platforms that ignore mode.
    import sys

    if sys.platform != "win32":
        assert (out.stat().st_mode & 0o777) == 0o600


def test_keygen_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    """Atomic O_EXCL: an existing target path must abort the write so we
    never silently clobber an unrelated file or attacker-planted symlink."""
    runner = CliRunner()
    out = tmp_path / "seed.hex"
    out.write_text("existing content")
    result = runner.invoke(app, ["keygen", "--out-seed", str(out)])
    assert result.exit_code != 0
    # Existing content unchanged.
    assert out.read_text() == "existing content"


def test_keygen_refuses_symlink_target(tmp_path: Path) -> None:
    """On POSIX, --out-seed at a symlink must be refused even if the
    symlink target does not exist yet (NOFOLLOW protects against an
    attacker planting a symlink to a sensitive path)."""
    import sys

    if sys.platform == "win32":
        return
    runner = CliRunner()
    target = tmp_path / "target"
    link = tmp_path / "seed.hex"
    link.symlink_to(target)
    result = runner.invoke(app, ["keygen", "--out-seed", str(link)])
    assert result.exit_code != 0
    assert not target.exists()


def test_build_rejects_zero_or_negative_expires_in() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "build",
            "--from-did",
            "did:key:x",
            "--to-did",
            "did:plc:y",
            "--expires-in",
            "0",
        ],
    )
    assert result.exit_code != 0
    result = runner.invoke(
        app,
        [
            "build",
            "--from-did",
            "did:key:x",
            "--to-did",
            "did:plc:y",
            "--expires-in",
            "-5",
        ],
    )
    assert result.exit_code != 0


def test_load_seed_rejects_partial_hex_without_echoing_bytes(tmp_path: Path) -> None:
    """Error message must not echo the partial seed hex."""
    runner = CliRunner()
    seed_file = tmp_path / "bad.hex"
    secret_partial = "deadbeef" * 2  # only 16 hex chars, not 64
    seed_file.write_text(secret_partial)
    result = runner.invoke(
        app,
        [
            "build",
            "--from-did",
            "did:key:x",
            "--to-did",
            "did:plc:y",
            "--seed",
            str(seed_file),
        ],
    )
    assert result.exit_code != 0
    # Partial seed content must not leak into the error path.
    assert secret_partial not in result.output


def test_build_dry_run_produces_valid_signature_base() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "build",
            "--from-did",
            "did:key:senderxyz",
            "--to-did",
            "did:plc:recipient",
            "--purpose",
            "Interop test",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["request"]["headers"]["authorization"].startswith("INK-Ed25519 ")
    sig_base = payload["wireDetails"]["signatureBase"]
    # Sanity: signature base contains the recipient DID and method.
    assert "did:plc:recipient" in sig_base
    assert sig_base.startswith("ink/0.1\nPOST\n")
