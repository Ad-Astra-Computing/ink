"""Command-line interface for the INK interop client.

Subcommands:

* ``keygen`` — print a fresh Ed25519 keypair (hex + did:key multibase).
* ``discover`` — fetch and pretty-print an agent.json.
* ``build`` — build a signed envelope and print it (dry-run, no network).
* ``send`` — build, sign, POST to the target endpoint, print the response.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer

from . import crypto, envelope, transport

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Non-tulpa INK protocol reference client.",
)


def _err(message: str) -> None:
    typer.secho(message, err=True, fg=typer.colors.RED)


def _load_seed(path: Path) -> bytes:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        # Give the operator a controlled CLI error rather than a raw
        # Python traceback. The error message intentionally does NOT
        # echo `path` content — only its filesystem location.
        raise typer.BadParameter(f"could not read seed file {path}: {exc.strerror}") from exc
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        # Generic message — never include the malformed hex string
        # because it might be partial key material.
        raise typer.BadParameter("seed file is not a valid 32-byte hex string") from exc
    if len(seed) != 32:
        raise typer.BadParameter("seed file must contain exactly 32 bytes (64 hex chars)")
    return seed


def _write_seed_atomically(path: Path, seed_hex: str) -> None:
    """Write the seed to ``path`` with 0o600 mode in a single syscall.

    We use ``os.open(O_CREAT | O_EXCL | O_WRONLY)`` so:
      * the file is created with mode 0o600 atomically (no race window
        where umask permissions briefly apply);
      * an existing file or symlink at the target path causes a
        controlled failure rather than silently overwriting it (which
        would be catastrophic if the operator pointed --out-seed at a
        wrong file, or if an attacker created a symlink there).
    On POSIX we also pass ``O_NOFOLLOW`` so a symlink at the target
    location is treated as already-existing and refused.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise typer.BadParameter(
            f"refusing to overwrite existing path {path}; pick a fresh filename for --out-seed"
        ) from exc
    except OSError as exc:
        raise typer.BadParameter(f"could not create seed file {path}: {exc.strerror}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(seed_hex)
    except Exception:
        # If write fails partway, do not leave a half-written seed file
        # at the target.
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _load_keypair(seed_file: Path | None) -> crypto.Keypair:
    if seed_file is None:
        return crypto.Keypair.generate()
    return crypto.Keypair.from_private_bytes(_load_seed(seed_file))


@app.command()
def keygen(
    out_seed: Annotated[
        Path | None,
        typer.Option(
            "--out-seed",
            help="Write the 32-byte private seed (hex) to this file. Permissions are 0600.",
        ),
    ] = None,
) -> None:
    """Generate a fresh Ed25519 keypair and print its public form."""
    kp = crypto.Keypair.generate()
    payload = {
        "publicKeyHex": kp.public_key_hex,
        "publicKeyMultibase": kp.public_key_multibase,
        "did:key": f"did:key:{kp.public_key_multibase}",
    }
    typer.echo(json.dumps(payload, indent=2))
    if out_seed is not None:
        seed_bytes = kp.private_key.private_bytes_raw()
        _write_seed_atomically(out_seed, seed_bytes.hex())
        typer.echo(f"# seed written to {out_seed}", err=True)


@app.command()
def discover(
    card_url: Annotated[str, typer.Argument(help="Full URL to the agent.json.")],
) -> None:
    """Fetch an agent.json and print its decoded signing keys."""
    try:
        card = transport.fetch_agent_card(card_url)
    except (transport.DiscoveryError, transport.TransportError) as exc:
        _err(str(exc))
        raise typer.Exit(code=1) from exc
    payload = {
        "agentId": card.agent_id,
        "endpoint": card.endpoint,
        "activeKeys": [
            {"keyId": kid, "publicKeyHex": pk.hex()} for kid, pk in card.active_signing_keys
        ],
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command()
def build(
    to_did: Annotated[str, typer.Option("--to-did", help="Recipient DID.")],
    from_did: Annotated[str, typer.Option("--from-did", help="Sender DID.")],
    purpose: Annotated[
        str, typer.Option("--purpose", help="One-line free-text purpose.")
    ] = "Interop smoke test",
    intent_type: Annotated[
        str, typer.Option("--intent-type", help="Intent type per INK §4.2.")
    ] = "introduction",
    target_url: Annotated[
        str | None,
        typer.Option(
            "--target-url",
            help="Absolute URL the request will be POSTed to. "
            "If omitted, only the envelope + signature base are emitted.",
        ),
    ] = None,
    path: Annotated[
        str | None,
        typer.Option(
            "--path",
            help="Path used in the signature base. Defaults to /ink/v1/<to_did>/intent.",
        ),
    ] = None,
    seed: Annotated[
        Path | None,
        typer.Option(
            "--seed",
            help="32-byte hex seed file. Generates a one-shot key if omitted.",
        ),
    ] = None,
    key_id: Annotated[
        str | None,
        typer.Option("--key-id", help="Optional keyId hint for the Authorization header."),
    ] = None,
    expires_in_minutes: Annotated[
        int,
        typer.Option("--expires-in", help="Minutes until the intent expires."),
    ] = 60,
) -> None:
    """Build and sign an INK intent envelope. Prints everything needed to send it."""
    if expires_in_minutes <= 0:
        raise typer.BadParameter("--expires-in must be > 0; an already-expired intent is invalid")
    keypair = _load_keypair(seed)
    timestamp = envelope.utc_timestamp()
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=expires_in_minutes)
    expires_str = envelope.utc_timestamp(expires_at)
    request_path = path if path is not None else f"/ink/v1/{to_did}/intent"
    url = target_url if target_url is not None else f"https://example.invalid{request_path}"
    # v0.1.2: the CLI emits the canonical MessageEnvelopeSchema shape
    # (id, correlationId, createdAt, intent enum, payload, body-level
    # signature). The legacy `--intent-type=introduction` value maps
    # to `intent='intro_request'` per IntroRequestPayloadSchema.
    if intent_type in {"introduction", "intro_request"}:
        body = envelope.build_intent_envelope(
            keypair=keypair,
            from_did=from_did,
            to_did=to_did,
            target=to_did,
            reason=purpose,
            created_at=timestamp,
            expires_at=expires_str,
            signing_key_id=key_id,
        ).body
    elif intent_type in {"connection", "connection_request"}:
        body = envelope.build_connection_envelope(
            keypair=keypair,
            from_did=from_did,
            to_did=to_did,
            context=purpose,
            headline=purpose[:500] or "Interop smoke test",
            created_at=timestamp,
            expires_at=expires_str,
            signing_key_id=key_id,
        ).body
    else:
        raise typer.BadParameter(
            f"--intent-type must be one of: introduction, intro_request, "
            f"connection, connection_request (got {intent_type!r}); "
            "other intent types are not yet wired into this CLI"
        )
    signed = envelope.build_signed_request(
        keypair=keypair,
        target_url=url,
        path=request_path,
        recipient_did=to_did,
        body=body,
        timestamp=timestamp,
        key_id=key_id,
    )
    typer.echo(
        json.dumps(
            {
                "senderPublicKey": {
                    "hex": keypair.public_key_hex,
                    "multibase": keypair.public_key_multibase,
                    "did:key": f"did:key:{keypair.public_key_multibase}",
                },
                "request": {
                    "method": signed.method,
                    "url": signed.url,
                    "path": signed.path,
                    "headers": {
                        "authorization": signed.authorization_header,
                        "content-type": "application/json",
                    },
                    "body": signed.body_obj,
                },
                "wireDetails": {
                    "canonicalBody": signed.canonical_body.decode("utf-8"),
                    "signatureBase": signed.signature_base.decode("utf-8"),
                    "signatureHex": signed.signature_bytes.hex(),
                    "timestamp": signed.timestamp,
                },
            },
            indent=2,
        )
    )


@app.command()
def send(
    to_did: Annotated[str, typer.Option("--to-did", help="Recipient DID.")],
    from_did: Annotated[str, typer.Option("--from-did", help="Sender DID.")],
    target_url: Annotated[
        str,
        typer.Option(
            "--target-url",
            help="Absolute URL for the INK intent endpoint, e.g. "
            "https://api.tulpa.network/ink/v1/<agentId>/intent",
        ),
    ],
    seed: Annotated[
        Path,
        typer.Option(
            "--seed",
            help="32-byte hex seed file. Use `keygen --out-seed` to create one.",
        ),
    ],
    purpose: Annotated[
        str, typer.Option("--purpose", help="One-line free-text purpose.")
    ] = "Interop smoke test",
    intent_type: Annotated[
        str, typer.Option("--intent-type", help="Intent type per INK §4.2.")
    ] = "introduction",
    path: Annotated[
        str | None,
        typer.Option(
            "--path",
            help="Path used in the signature base. Defaults to /ink/v1/<to_did>/intent.",
        ),
    ] = None,
    key_id: Annotated[str | None, typer.Option("--key-id", help="Optional keyId hint.")] = None,
    expires_in_minutes: Annotated[
        int, typer.Option("--expires-in", help="Minutes until the intent expires.")
    ] = 60,
) -> None:
    """Build, sign, and POST an INK intent envelope. Prints the response."""
    if expires_in_minutes <= 0:
        raise typer.BadParameter("--expires-in must be > 0; an already-expired intent is invalid")
    keypair = _load_keypair(seed)
    timestamp = envelope.utc_timestamp()
    expires_str = envelope.utc_timestamp(
        datetime.now(tz=UTC) + timedelta(minutes=expires_in_minutes)
    )
    request_path = path if path is not None else f"/ink/v1/{to_did}/intent"
    if intent_type in {"introduction", "intro_request"}:
        body = envelope.build_intent_envelope(
            keypair=keypair,
            from_did=from_did,
            to_did=to_did,
            target=to_did,
            reason=purpose,
            created_at=timestamp,
            expires_at=expires_str,
            signing_key_id=key_id,
        ).body
    elif intent_type in {"connection", "connection_request"}:
        body = envelope.build_connection_envelope(
            keypair=keypair,
            from_did=from_did,
            to_did=to_did,
            context=purpose,
            headline=purpose[:500] or "Interop smoke test",
            created_at=timestamp,
            expires_at=expires_str,
            signing_key_id=key_id,
        ).body
    else:
        raise typer.BadParameter(
            f"--intent-type must be one of: introduction, intro_request, "
            f"connection, connection_request (got {intent_type!r}); "
            "other intent types are not yet wired into this CLI"
        )
    signed = envelope.build_signed_request(
        keypair=keypair,
        target_url=target_url,
        path=request_path,
        recipient_did=to_did,
        body=body,
        timestamp=timestamp,
        key_id=key_id,
    )
    try:
        response = transport.send_signed_request(signed)
    except transport.TransportError as exc:
        _err(str(exc))
        raise typer.Exit(code=2) from exc
    try:
        response_json = response.json()
    except ValueError:
        response_json = None
    out = {
        "request": {
            "method": signed.method,
            "url": signed.url,
            "path": signed.path,
            "timestamp": signed.timestamp,
            "senderPublicKeyMultibase": keypair.public_key_multibase,
        },
        "response": {
            "status": response.status_code,
            "headers": dict(response.headers),
            "json": response_json,
            "text": None if response_json is not None else response.text[:8192],
        },
    }
    typer.echo(json.dumps(out, indent=2))
    if response.status_code >= 400:
        raise typer.Exit(code=3)


def main() -> None:
    # Entry point for ``python -m ink_interop``.
    app()


if __name__ == "__main__":
    main()
    sys.exit(0)
