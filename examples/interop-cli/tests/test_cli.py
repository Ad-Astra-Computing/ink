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
