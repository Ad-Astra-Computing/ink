/**
 * Proves the bundled reference receiver runs under Node behind the http
 * adapter and accepts a real signed envelope. Requires `node build.mjs` first
 * (the `test` script runs it); the worker bundle is imported via server.mjs.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
  signMessage,
  signInkMessage,
  buildAuthHeader,
} from "@adastracomputing/ink";
import { startServer } from "../server.mjs";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

const HOST = "ink-receiver.test";
let server: Server;
let base: string;

beforeAll(async () => {
  // A stable receiver identity for the run.
  const kp = await generateKeypair();
  process.env.INK_RECEIVER_SIGNING_SEED = base64urlEncode(kp.privateKey);
  process.env.INK_RECEIVER_PUBLIC_KEY_MULTIBASE = encodePublicKeyMultibase(kp.publicKey);
  process.env.INK_RECEIVER_HOST = HOST;
  server = (await startServer(0)) as Server;
  const addr = server.address() as AddressInfo;
  base = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server?.close();
});

async function buildSignedPing(receiverDid: string, path: string) {
  const kp = await generateKeypair();
  const senderDid = `did:key:${encodePublicKeyMultibase(kp.publicKey)}`;
  const now = new Date().toISOString();
  const unsigned: Record<string, unknown> = {
    protocol: "ink/0.1",
    id: crypto.randomUUID(),
    correlationId: crypto.randomUUID(),
    createdAt: now,
    from: senderDid,
    to: receiverDid,
    intent: "ping",
    payload: { note: "test" },
    timestamp: now,
    nonce: crypto.randomUUID(),
  };
  const envelope = { ...unsigned, signature: await signMessage(unsigned, kp.privateKey) };
  const sig = await signInkMessage(
    { method: "POST", path, recipientDid: receiverDid, body: envelope, timestamp: now },
    kp.privateKey,
  );
  return { envelope, authorization: buildAuthHeader(sig) };
}

describe("dockerized reference receiver under Node", () => {
  it("serves a did:web agent card", async () => {
    const res = await fetch(`${base}/.well-known/ink/agent.json`);
    expect(res.status).toBe(200);
    const card = (await res.json()) as { protocol: string; agentId: string };
    expect(card.protocol).toBe("ink/0.1");
    expect(card.agentId).toBe(`did:web:${HOST}`);
  });

  it("serves the same card on the versioned discovery path", async () => {
    const did = `did:web:${HOST}`;
    const res = await fetch(`${base}/ink/v1/${encodeURIComponent(did)}/agent.json`);
    expect(res.status).toBe(200);
    const versioned = await res.text();
    const wellKnown = await (await fetch(`${base}/.well-known/ink/agent.json`)).text();
    expect(versioned).toBe(wellKnown);
    expect((JSON.parse(versioned) as { agentId: string }).agentId).toBe(did);
  });

  it("does not serve a card for another agentId", async () => {
    const res = await fetch(
      `${base}/ink/v1/${encodeURIComponent("did:web:other.example")}/agent.json`,
    );
    expect(res.status).toBe(404);
  });

  it("serves a did:web document", async () => {
    const res = await fetch(`${base}/.well-known/did.json`);
    expect(res.status).toBe(200);
    const doc = (await res.json()) as { id: string };
    expect(doc.id).toBe(`did:web:${HOST}`);
  });

  it("accepts a signed ping and acknowledges it", async () => {
    const receiverDid = `did:web:${HOST}`;
    const { envelope, authorization } = await buildSignedPing(receiverDid, "/ink/v1/inbound");
    const res = await fetch(`${base}/ink/v1/inbound`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization },
      body: JSON.stringify(envelope),
    });
    expect(res.status).toBe(200);
    const ack = (await res.json()) as { ok: boolean; receivedIntent: string; receiverDid: string };
    expect(ack.ok).toBe(true);
    expect(ack.receivedIntent).toBe("ping");
    expect(ack.receiverDid).toBe(receiverDid);
  });

  it("rejects an unsigned envelope", async () => {
    const receiverDid = `did:web:${HOST}`;
    const { envelope } = await buildSignedPing(receiverDid, "/ink/v1/inbound");
    const res = await fetch(`${base}/ink/v1/inbound`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});
