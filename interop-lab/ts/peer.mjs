/**
 * The TypeScript half of the interop lab's cross-implementation checks.
 *
 * It is a lab fixture, not a product. It exposes over HTTP the two consuming
 * operations the reference receiver deliberately does not offer, so the Go
 * driver can hand real wire bytes to the TypeScript implementation and read
 * back an observable HTTP result:
 *
 *   GET  /peer/info             identity plus the static X25519 key to seal to
 *   POST /peer/open             open an INK encrypted envelope (§3.4)
 *   POST /peer/verify-envelope  validate an envelope and verify its body
 *                               signature against the sender's did:key
 *   GET  /healthz               readiness
 *
 * Every cryptographic decision is made by the reference library; this file only
 * decodes a request, calls the library, and encodes the result. Both keypairs
 * are minted at process start, so the lab holds no committed key material.
 */

import { createServer } from "node:http";
import {
  generateKeypair,
  generateEncryptionKeypair,
  encodePublicKeyMultibase,
  decodePublicKeyMultibase,
  bytesToHex,
  decryptInkPayload,
  validateMessage,
  verifyMessage,
} from "@adastracomputing/ink";

const PORT = Number(process.env.PORT ?? 8790);
const HOST = process.env.HOST ?? "0.0.0.0";
const MAX_BODY_BYTES = 1024 * 1024;

const signing = await generateKeypair();
const encryption = generateEncryptionKeypair();
const agentDid = `did:key:${encodePublicKeyMultibase(signing.publicKey)}`;
const encryptionPrivateKeyHex = bytesToHex(encryption.privateKey);

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(text);
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/**
 * Resolve the signing key a `did:key` sender carries in its own identifier. No
 * fetch, so the peer has no outbound dependency of any kind.
 */
function didKeyPublicKey(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:")) return null;
  const multibase = did.slice("did:key:".length).split("#")[0] ?? "";
  try {
    return decodePublicKeyMultibase(multibase);
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "peer"}`);
  const route = `${req.method} ${url.pathname}`;

  if (route === "GET /healthz") {
    send(res, 200, { ok: true });
    return;
  }

  if (route === "GET /peer/info") {
    send(res, 200, {
      agentDid,
      signingKeyMultibase: encodePublicKeyMultibase(signing.publicKey),
      encryptionPublicKeyHex: bytesToHex(encryption.publicKey),
    });
    return;
  }

  let raw;
  try {
    raw = await readBody(req);
  } catch {
    send(res, 413, { ok: false, error: "body_too_large" });
    return;
  }

  if (route === "POST /peer/open") {
    let envelope;
    try {
      envelope = JSON.parse(raw.toString("utf8")).envelope;
    } catch {
      send(res, 400, { ok: false, error: "invalid_json" });
      return;
    }
    try {
      // The recipient identity is the peer's own DID, never a caller-supplied
      // value: the library binds the opened plaintext's `to` to it.
      const plaintext = await decryptInkPayload(envelope, encryptionPrivateKeyHex, agentDid);
      send(res, 200, { ok: true, plaintext });
    } catch {
      send(res, 400, { ok: false, error: "decrypt_failed" });
    }
    return;
  }

  if (route === "POST /peer/verify-envelope") {
    let envelope;
    try {
      envelope = JSON.parse(raw.toString("utf8"));
    } catch {
      send(res, 400, { ok: false, error: "invalid_json" });
      return;
    }
    try {
      const validated = validateMessage(envelope);
      const publicKey = didKeyPublicKey(validated.from);
      if (!publicKey) {
        send(res, 400, { ok: false, error: "sender_key_unresolved" });
        return;
      }
      const ok = await verifyMessage(envelope, publicKey);
      send(res, ok ? 200 : 400, { ok, error: ok ? undefined : "body_signature_invalid" });
    } catch (err) {
      send(res, 400, { ok: false, error: `schema:${String(err).slice(0, 120)}` });
    }
    return;
  }

  send(res, 404, { ok: false, error: "not_found" });
});

server.listen(PORT, HOST, () => {
  console.log(`lab peer listening on http://${HOST}:${PORT} as ${agentDid}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
