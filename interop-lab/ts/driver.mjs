/**
 * The TypeScript-produces half of the interop lab: it mints a TypeScript
 * identity, produces the artifacts a sender puts on the wire, and hands each one
 * to the Go implementation over HTTP. Every decision is read from an observable
 * HTTP status or the verdict in the response body.
 *
 * Exits 0 when every check passes and 1 when any check fails, so a caller can
 * gate on the process exit code alone.
 */

import {
  generateKeypair,
  generateEncryptionKeypair,
  encodePublicKeyMultibase,
  bytesToHex,
  signInkMessage,
  signAgentCard,
  encryptInkPayload,
  AgentCardSchema,
} from "@adastracomputing/ink";

const GO_VERIFIER_URL = process.env.GO_VERIFIER_URL ?? "http://go-verifier:8080";
const GO_PEER_URL = process.env.GO_PEER_URL ?? "http://go-peer:8090";

let passed = 0;
let failed = 0;

function check(name, ok, detail = "") {
  if (ok) {
    passed += 1;
    console.log(`  PASS  ${name}`);
    return;
  }
  failed += 1;
  console.log(`  FAIL  ${name}\n        ${detail}`);
}

async function waitReady(url) {
  const deadline = Date.now() + 60_000;
  let last = "no attempt";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.status < 500) return;
      last = `status ${res.status}`;
    } catch (err) {
      last = String(err);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${url} never became ready: ${last}`);
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { status: res.status, body: parsed };
}

/** Flip one base64url character so a signature stays well-formed but wrong. */
function flipBase64url(value) {
  const first = value[0];
  const replacement = first === "A" ? "B" : first === "B" ? "A" : first === "z" ? "y" : "z";
  return replacement + value.slice(1);
}

const nowIso = () => new Date().toISOString();
const randomId = () => crypto.randomUUID();

console.log("ts-driver: TypeScript produces, Go verifies");

await waitReady(`${GO_VERIFIER_URL}/healthz`);
await waitReady(`${GO_PEER_URL}/healthz`);

const signing = await generateKeypair();
const senderKeyMultibase = encodePublicKeyMultibase(signing.publicKey);
// The transport identity is a did:key, which carries its own verification key.
const senderDid = `did:key:${senderKeyMultibase}`;
// The card principal is the key-derived form, the only self-rooting principal
// kind the card-signature spec defines alongside did:web.
const cardAgentId = `ink:${senderKeyMultibase}`;

// ── §3.3 transport signature: TypeScript signs, the Go service verifies ──────
{
  const recipientDid = "did:web:go-verifier.example";
  const timestamp = nowIso();
  const body = {
    protocol: "ink/0.1",
    id: randomId(),
    correlationId: randomId(),
    createdAt: timestamp,
    from: senderDid,
    to: recipientDid,
    intent: "ping",
    payload: { note: "signed by the TypeScript implementation" },
    timestamp,
    nonce: randomId(),
  };
  const signInput = { method: "POST", path: "/ink/v1/inbound", recipientDid, body, timestamp };
  const signature = await signInkMessage(signInput, signing.privateKey);

  const good = await postJson(`${GO_VERIFIER_URL}/verify/signature`, {
    publicKeyHex: bytesToHex(signing.publicKey),
    signInput,
    signature,
  });
  check(
    "Go verifies the TypeScript transport signature",
    good.status === 200 && good.body.ok === true,
    JSON.stringify(good),
  );

  const flipped = await postJson(`${GO_VERIFIER_URL}/verify/signature`, {
    publicKeyHex: bytesToHex(signing.publicKey),
    signInput,
    signature: flipBase64url(signature),
  });
  check(
    "Go rejects a tampered transport signature",
    flipped.body.ok === false,
    JSON.stringify(flipped),
  );

  const alteredBody = await postJson(`${GO_VERIFIER_URL}/verify/signature`, {
    publicKeyHex: bytesToHex(signing.publicKey),
    signInput: { ...signInput, body: { ...body, payload: { note: "altered after signing" } } },
    signature,
  });
  check(
    "Go rejects a signature over a body that changed",
    alteredBody.body.ok === false,
    JSON.stringify(alteredBody),
  );
}

// ── Agent Card proof: TypeScript signs, Go authenticates ─────────────────────
{
  const card = AgentCardSchema.parse({
    protocol: "ink/0.1",
    supportedProtocolVersions: ["ink/0.1", "ink/0.2"],
    agentId: cardAgentId,
    handle: "ts-driver.example",
    displayName: "INK interop lab TypeScript driver",
    endpoint: "https://ts-driver.example/ink/v1/inbound",
    inboxEndpoint: "https://ts-driver.example/ink/v1/inbound",
    publicKeyMultibase: encodePublicKeyMultibase(signing.publicKey),
    capabilities: {
      intentsAccepted: ["ping"],
      intentsSent: ["ping"],
      receipts: { send: false, dispositions: [] },
    },
    availability: { timezone: "UTC", responseSla: "best_effort" },
    keySetVersion: 1,
    updatedAt: nowIso(),
  });
  const cardSignature = {
    keyId: "bootstrap",
    signature: await signAgentCard(card, signing.privateKey),
  };
  const signed = { ...card, cardSignature };

  const accepted = await postJson(`${GO_PEER_URL}/peer/verify-card-signature`, {
    card: signed,
    agentId: cardAgentId,
    profile: "pre-1.0",
  });
  check(
    "Go authenticates the TypeScript card signature",
    accepted.body.authenticated === true,
    JSON.stringify(accepted),
  );

  const tampered = await postJson(`${GO_PEER_URL}/peer/verify-card-signature`, {
    card: { ...signed, displayName: "not the signed display name" },
    agentId: cardAgentId,
    profile: "pre-1.0",
  });
  check(
    "Go rejects a tampered card signature",
    tampered.body.authenticated === false && tampered.body.rejected === true,
    JSON.stringify(tampered),
  );

  const impersonated = await postJson(`${GO_PEER_URL}/peer/verify-card-signature`, {
    card: signed,
    agentId: `ink:${encodePublicKeyMultibase((await generateKeypair()).publicKey)}`,
    profile: "pre-1.0",
  });
  check(
    "Go rejects a card served under another identity",
    impersonated.body.authenticated === false,
    JSON.stringify(impersonated),
  );
}

// ── encrypted payload: TypeScript seals, Go opens ────────────────────────────
{
  const infoRes = await fetch(`${GO_PEER_URL}/peer/info`);
  const info = await infoRes.json();
  check("Go peer publishes an encryption key", typeof info.encryptionPublicKeyHex === "string", JSON.stringify(info));

  const note = "sealed by the TypeScript implementation";
  // Both implementations bind the inner envelope to the outer one: the sealed
  // plaintext MUST carry `from` equal to the outer sender and `to` equal to the
  // recipient asserting the identity, or no conformant decrypter opens it.
  const { envelope: sealed } = await encryptInkPayload(
    { from: senderDid, to: info.agentDid, note },
    senderDid,
    info.encryptionPublicKeyHex,
    nowIso(),
    randomId(),
  );
  const opened = await postJson(`${GO_PEER_URL}/peer/open`, { envelope: sealed });
  check(
    "Go opens the TypeScript-sealed payload",
    opened.status === 200 && opened.body.plaintext?.note === note,
    JSON.stringify(opened),
  );

  const corrupted = await postJson(`${GO_PEER_URL}/peer/open`, {
    envelope: { ...sealed, ciphertext: flipBase64url(sealed.ciphertext) },
  });
  check(
    "Go refuses a corrupted ciphertext",
    corrupted.status === 400 && corrupted.body.ok === false,
    JSON.stringify(corrupted),
  );

  // The message type is bound into the AAD, so relabelling the envelope must
  // not decrypt even though both spellings are accepted discriminators.
  const relabelled = await postJson(`${GO_PEER_URL}/peer/open`, {
    envelope: { ...sealed, type: "network.ink.encrypted" },
  });
  check(
    "Go refuses a relabelled wire type",
    relabelled.status === 400 && relabelled.body.ok === false,
    JSON.stringify(relabelled),
  );

  // An encryption keypair the recipient does not hold must not open it either.
  const stranger = generateEncryptionKeypair();
  const { envelope: misaddressed } = await encryptInkPayload(
    { from: senderDid, to: info.agentDid, note },
    senderDid,
    bytesToHex(stranger.publicKey),
    nowIso(),
    randomId(),
  );
  const refused = await postJson(`${GO_PEER_URL}/peer/open`, { envelope: misaddressed });
  check(
    "Go refuses an envelope sealed to another key",
    refused.status === 400 && refused.body.ok === false,
    JSON.stringify(refused),
  );
}

console.log(`\nts-driver: TypeScript produces, Go verifies: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
