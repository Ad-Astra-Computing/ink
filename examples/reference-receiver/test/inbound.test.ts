import { describe, it, expect } from "vitest";
import {
  processInbound,
  readBoundedBody,
  buildAckResponse,
  resolveSenderKeys,
  MAX_BODY_BYTES,
} from "../src/inbound.js";
import { InMemoryNonceStore } from "../src/nonce-store.js";
import { loadReceiverIdentity } from "../src/keys.js";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
  signInkMessage,
  buildAuthHeader,
  type InkSignInput,
} from "@adastracomputing/ink";

const RECEIVER_HOST = "receiver.example";
const RECEIVER_DID = `did:web:${RECEIVER_HOST}`;
const SENDER_HOST = "sender.example";
const SENDER_DID = `did:web:${SENDER_HOST}`;

async function makeReceiver() {
  const kp = await generateKeypair();
  const id = loadReceiverIdentity({
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
  });
  return { id, did: RECEIVER_DID };
}

async function makeSenderWithCard() {
  const kp = await generateKeypair();
  const endpoint = `https://${SENDER_HOST}/ink/v1/inbound`;
  const card = {
    protocol: "ink/0.1",
    agentId: SENDER_DID,
    handle: SENDER_HOST,
    displayName: "Test Sender",
    endpoint,
    inboxEndpoint: endpoint,
    publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
    capabilities: { intentsAccepted: ["ping"], intentsSent: ["ping"] },
    availability: { timezone: "UTC" },
  };
  return { kp, card };
}

function jsonFetcher(map: Record<string, unknown>): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    const value = map[u];
    if (value === undefined) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(value), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

function buildPingEnvelope(opts: { from: string; to: string; createdAt?: string; timestamp?: string; nonce?: string }) {
  const createdAt = opts.createdAt ?? new Date().toISOString();
  return {
    protocol: "ink/0.1" as const,
    id: `msg-${crypto.randomUUID()}`,
    correlationId: `corr-${crypto.randomUUID()}`,
    createdAt,
    from: opts.from,
    to: opts.to,
    intent: "ping" as const,
    payload: {},
    signature: "A".repeat(86), // placeholder; outer sig verified via Auth header
    timestamp: opts.timestamp ?? createdAt,
    nonce: opts.nonce ?? crypto.randomUUID(),
  };
}

async function signWithSender(
  envelope: ReturnType<typeof buildPingEnvelope>,
  senderKp: { privateKey: Uint8Array; publicKey: Uint8Array },
  path = "/ink/v1/inbound",
): Promise<string> {
  const input: InkSignInput = {
    method: "POST",
    path,
    recipientDid: envelope.to,
    body: envelope as unknown as Record<string, unknown>,
    timestamp: envelope.timestamp!,
  };
  const sig = await signInkMessage(input, senderKp.privateKey);
  return buildAuthHeader(sig);
}

describe("readBoundedBody", () => {
  it("returns body text for a small payload", async () => {
    const req = new Request("https://example.com", { method: "POST", body: "hello" });
    const out = await readBoundedBody(req);
    expect(out.ok && out.text).toBe("hello");
  });

  it("rejects oversize payloads", async () => {
    const big = "x".repeat(MAX_BODY_BYTES + 1);
    const req = new Request("https://example.com", { method: "POST", body: big });
    const out = await readBoundedBody(req);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe("oversize");
  });
});

describe("resolveSenderKeys", () => {
  it("returns [] for non-did:web senders", async () => {
    const out = await resolveSenderKeys("did:key:z6MkXXX");
    expect(out).toEqual([]);
  });

  it("returns candidate keys from a resolvable did:web card", async () => {
    const { card } = await makeSenderWithCard();
    const fetcher = jsonFetcher({
      [`https://${SENDER_HOST}/.well-known/did.json`]: { id: SENDER_DID, service: [] },
      [`https://${SENDER_HOST}/.well-known/ink/agent.json`]: card,
    });
    const out = await resolveSenderKeys(SENDER_DID, { fetcher });
    expect(out.length).toBeGreaterThan(0);
    expect(out[0]!.publicKey.length).toBe(32);
  });
});

describe("buildAckResponse", () => {
  it("returns ack with inReplyTo + receivedIntent", async () => {
    const { id, did } = await makeReceiver();
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: did });
    const nonceStore = new InMemoryNonceStore();
    const ack = buildAckResponse(envelope as unknown as Parameters<typeof buildAckResponse>[0], {
      identity: id, receiverDid: did, nonceStore,
    }) as { ok: boolean; inReplyTo: string; receivedIntent: string; receiverDid: string };
    expect(ack.ok).toBe(true);
    expect(ack.inReplyTo).toBe(envelope.id);
    expect(ack.receivedIntent).toBe("ping");
    expect(ack.receiverDid).toBe(did);
  });
});

describe("processInbound", () => {
  it("rejects malformed json with schema verdict", async () => {
    const { id, did } = await makeReceiver();
    const out = await processInbound("{ not json", undefined, { identity: id, receiverDid: did, nonceStore: new InMemoryNonceStore() });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") {
      expect(out.verdict).toBe("schema");
      expect(out.errorCode).toBe("json_parse_failed");
    }
  });

  it("rejects schema-invalid envelope", async () => {
    const { id, did } = await makeReceiver();
    const out = await processInbound(JSON.stringify({ protocol: "wrong" }), undefined, { identity: id, receiverDid: did, nonceStore: new InMemoryNonceStore() });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.verdict).toBe("schema");
  });

  it("rejects envelope addressed to a different recipient", async () => {
    const { id, did } = await makeReceiver();
    const { kp: senderKp, card } = await makeSenderWithCard();
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: "did:web:not-me.example" });
    const auth = await signWithSender(envelope, senderKp);
    const fetcher = jsonFetcher({
      [`https://${SENDER_HOST}/.well-known/did.json`]: { id: SENDER_DID, service: [] },
      [`https://${SENDER_HOST}/.well-known/ink/agent.json`]: card,
    });
    const out = await processInbound(JSON.stringify(envelope), auth, {
      identity: id, receiverDid: did, fetcher, nonceStore: new InMemoryNonceStore(),
    });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode).toBe("recipient_mismatch");
  });

  it("rejects unsupported intent before fetching the card", async () => {
    const { id, did } = await makeReceiver();
    // Use a fully-schema-valid follow_up envelope. follow_up is not in
    // SUPPORTED_INTENTS so the receiver's allowlist should reject it
    // BEFORE the signature path runs.
    const base = buildPingEnvelope({ from: SENDER_DID, to: did });
    const envelope = {
      ...base,
      intent: "follow_up" as const,
      payload: { referenceId: "m-prev-1", message: "ping?" },
    };
    const out = await processInbound(JSON.stringify(envelope), "ignored", {
      identity: id, receiverDid: did, nonceStore: new InMemoryNonceStore(),
    });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.verdict).toBe("unsupported_intent");
  });

  it("rejects when the sender card cannot be resolved", async () => {
    const { id, did } = await makeReceiver();
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: did });
    const out = await processInbound(JSON.stringify(envelope), "INK-Ed25519 " + "A".repeat(86), {
      identity: id, receiverDid: did, fetcher: jsonFetcher({}), nonceStore: new InMemoryNonceStore(),
    });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode).toBe("sender_key_unresolved");
  });

  it("rejects on tampered body (signature won't verify)", async () => {
    const { id, did } = await makeReceiver();
    const { kp: senderKp, card } = await makeSenderWithCard();
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: did });
    const auth = await signWithSender(envelope, senderKp);
    // Tamper a schema-valid field (correlationId) after signing — the
    // verifier canonicalizes the tampered body and the signature
    // doesn't match.
    const tampered = { ...envelope, correlationId: "corr-tampered" };
    const fetcher = jsonFetcher({
      [`https://${SENDER_HOST}/.well-known/did.json`]: { id: SENDER_DID, service: [] },
      [`https://${SENDER_HOST}/.well-known/ink/agent.json`]: card,
    });
    const out = await processInbound(JSON.stringify(tampered), auth, {
      identity: id, receiverDid: did, fetcher, nonceStore: new InMemoryNonceStore(),
    });
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.verdict).toBe("signature");
  });

  it("accepts a correctly signed ping envelope and returns an ack", async () => {
    const { id, did } = await makeReceiver();
    const { kp: senderKp, card } = await makeSenderWithCard();
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: did });
    const auth = await signWithSender(envelope, senderKp);
    const fetcher = jsonFetcher({
      [`https://${SENDER_HOST}/.well-known/did.json`]: { id: SENDER_DID, service: [] },
      [`https://${SENDER_HOST}/.well-known/ink/agent.json`]: card,
    });
    const out = await processInbound(JSON.stringify(envelope), auth, {
      identity: id, receiverDid: did, fetcher, nonceStore: new InMemoryNonceStore(),
    });
    expect(out.kind).toBe("ok");
    if (out.kind === "ok") {
      expect(out.intent).toBe("ping");
      expect(out.sender).toBe(SENDER_DID);
      const ack = out.response as { ok: boolean; inReplyTo: string };
      expect(ack.ok).toBe(true);
      expect(ack.inReplyTo).toBe(envelope.id);
    }
  });

  it("rejects a replay of the same nonce", async () => {
    const { id, did } = await makeReceiver();
    const { kp: senderKp, card } = await makeSenderWithCard();
    const nonceStore = new InMemoryNonceStore();
    const fetcher = jsonFetcher({
      [`https://${SENDER_HOST}/.well-known/did.json`]: { id: SENDER_DID, service: [] },
      [`https://${SENDER_HOST}/.well-known/ink/agent.json`]: card,
    });
    const envelope = buildPingEnvelope({ from: SENDER_DID, to: did });
    const auth = await signWithSender(envelope, senderKp);
    const first = await processInbound(JSON.stringify(envelope), auth, {
      identity: id, receiverDid: did, fetcher, nonceStore,
    });
    expect(first.kind).toBe("ok");
    const second = await processInbound(JSON.stringify(envelope), auth, {
      identity: id, receiverDid: did, fetcher, nonceStore,
    });
    expect(second.kind).toBe("rejected");
    if (second.kind === "rejected") expect(second.verdict).toBe("signature");
  });
});
