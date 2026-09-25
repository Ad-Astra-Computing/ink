/**
 * Agent integration demo: a sender agent talks to the dockerized receiver.
 *
 * This is the smallest end-to-end INK exchange between two agents, using only
 * the `@adastracomputing/ink` public surface:
 *
 *   1. Mint an ephemeral `did:key` sender identity.
 *   2. Discover the receiver: GET its agent card to learn its DID and inbox.
 *   3. Build a `ping` envelope, attach the body signature, validate it.
 *   4. Sign the INK §3.3 Authorization over the request and POST the envelope.
 *   5. Print the receiver's acknowledgement.
 *
 * Point it at a running receiver (the dockerized one, or `npm start`):
 *   RECEIVER_URL=http://localhost:8787 node agent-demo.mjs "hello from the demo"
 */

import {
  generateKeypair,
  encodePublicKeyMultibase,
  signMessage,
  signInkMessage,
  buildAuthHeader,
  validateMessage,
  parseSignedBodyBytes,
  ParseSignedBodyError,
  AgentCardSchema,
} from "@adastracomputing/ink";

const receiverUrl = (process.env.RECEIVER_URL ?? "http://localhost:8787").replace(/\/+$/, "");
const note = process.argv[2] ?? "hello from the INK agent demo";

// 1. Sender identity. The did:key carries its own verification key, so the
//    receiver decodes it inline with no network lookup.
const kp = await generateKeypair();
const senderDid = `did:key:${encodePublicKeyMultibase(kp.publicKey)}`;

// 2. Discover the receiver at its versioned card path. A real sender would
//    resolve this DID first and decide through `evaluateAgentCardFetch`, the
//    way reference-sender does; this demo already knows the DID (the compose
//    file sets INK_RECEIVER_HOST), so it fetches the path and gates by hand.
const receiverHost = process.env.INK_RECEIVER_HOST ?? "ink-receiver.example";
const receiverDid = `did:web:${receiverHost}`;
const cardUrl = `${receiverUrl}/ink/v1/${encodeURIComponent(receiverDid)}/agent.json`;
const cardRes = await fetch(cardUrl);
if (!cardRes.ok) {
  console.error(`could not fetch agent card: ${cardRes.status}`);
  process.exit(1);
}
// Raw bytes, not `.json()`: a lenient decode could accept a card the
// byte-level signed-body gate would refuse.
const bodyRaw = new Uint8Array(await cardRes.arrayBuffer());
let parsedCard;
try {
  parsedCard = parseSignedBodyBytes(bodyRaw);
} catch (err) {
  const reason = err instanceof ParseSignedBodyError ? err.reason : "invalid_json";
  console.error(`agent card failed the signed-body byte gate: ${reason}`);
  process.exit(1);
}
const cardResult = AgentCardSchema.safeParse(parsedCard);
if (!cardResult.success) {
  console.error("agent card did not validate against the agent card schema");
  process.exit(1);
}
const card = cardResult.data;
if (card.agentId !== receiverDid) {
  console.error(`agent card agentId ${card.agentId} does not match ${receiverDid}`);
  process.exit(1);
}
// The card advertises a public did:web inbox URL, but for this local demo the
// receiver is actually reachable at RECEIVER_URL. The §3.3 signature commits
// to the path only (not the host), so sign over the card's inbox path and POST
// to RECEIVER_URL + that path — exactly how a load balancer or local mapping
// would route a request the receiver still verifies.
const advertised = card.inboxEndpoint ?? card.endpoint ?? `${receiverUrl}/ink/v1/inbound`;
const path = new URL(advertised).pathname;
const inbox = `${receiverUrl}${path}`;

// 3. Build and body-sign the envelope.
const now = new Date().toISOString();
const unsigned = {
  protocol: "ink/0.1",
  id: crypto.randomUUID(),
  correlationId: crypto.randomUUID(),
  createdAt: now,
  from: senderDid,
  to: receiverDid,
  intent: "ping",
  payload: { note },
  timestamp: now,
  nonce: crypto.randomUUID(),
};
const envelope = { ...unsigned, signature: await signMessage(unsigned, kp.privateKey) };
validateMessage(envelope); // never send something we would ourselves reject

// 4. Sign the §3.3 transport Authorization over the inbox path, then POST.
const sig = await signInkMessage(
  { method: "POST", path, recipientDid: receiverDid, body: envelope, timestamp: now },
  kp.privateKey,
);
const res = await fetch(inbox, {
  method: "POST",
  headers: { "content-type": "application/json", authorization: buildAuthHeader(sig) },
  body: JSON.stringify(envelope),
});

const text = await res.text();
console.log(`sender:   ${senderDid}`);
console.log(`receiver: ${receiverDid}`);
console.log(`status:   ${res.status}`);
console.log(`ack:      ${text}`);
process.exit(res.ok ? 0 : 1);
