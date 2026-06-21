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
} from "@adastracomputing/ink";

const receiverUrl = (process.env.RECEIVER_URL ?? "http://localhost:8787").replace(/\/+$/, "");
const note = process.argv[2] ?? "hello from the INK agent demo";

// 1. Sender identity. The did:key carries its own verification key, so the
//    receiver decodes it inline with no network lookup.
const kp = await generateKeypair();
const senderDid = `did:key:${encodePublicKeyMultibase(kp.publicKey)}`;

// 2. Discover the receiver from its published agent card.
const cardRes = await fetch(`${receiverUrl}/.well-known/ink/agent.json`);
if (!cardRes.ok) {
  console.error(`could not fetch agent card: ${cardRes.status}`);
  process.exit(1);
}
const card = await cardRes.json();
const receiverDid = card.agentId;
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
