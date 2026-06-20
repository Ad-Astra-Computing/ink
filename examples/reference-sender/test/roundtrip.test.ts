/**
 * The showcase: an envelope this sender produces is accepted by the exact
 * verification path a package-based receiver runs. The fake fetch below is
 * a receiver in miniature — it runs `validateMessage`, the body-signature
 * check (`verifyMessage`), and the transport check (`verifyInkAuth`) with
 * an inline did:key resolver and a real nonce store. Nothing here is sender
 * code; if these pass, the sender interoperates with any receiver built the
 * same way (including `examples/reference-receiver`).
 */

import { describe, it, expect } from "vitest";
import {
  validateMessage,
  verifyMessage,
  verifyInkAuth,
  decodePublicKeyMultibase,
  type NonceStore,
} from "@adastracomputing/ink";
import { generateSenderIdentity, type SenderIdentity } from "../src/identity.ts";
import { sendIntent } from "../src/index.ts";
import { pingPayload } from "../src/envelope.ts";

function inlineDidKey(agentId: string): Uint8Array | null {
  if (!agentId.startsWith("did:key:")) return null;
  try {
    return decodePublicKeyMultibase(agentId.slice("did:key:".length));
  } catch {
    return null;
  }
}

function memoryNonceStore(): NonceStore {
  const seen = new Set<string>();
  return {
    has: (n) => seen.has(n),
    add: (n) => {
      seen.add(n);
    },
  };
}

/** A receiver that accepts exactly what the OSS verification path accepts. */
function makeReceiverFetch(recipientDid: string, recordSeen: NonceStore): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const authHeader = (init?.headers as Record<string, string>)?.Authorization;
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;

    // 1. Schema validation BEFORE any canonicalization.
    let envelope;
    try {
      envelope = validateMessage(body);
    } catch {
      return new Response(JSON.stringify({ ok: false, error: "schema" }), { status: 400 });
    }

    // 2. Body-level signature against the inline did:key sender.
    const senderPub = inlineDidKey(envelope.from);
    if (!senderPub) {
      return new Response(JSON.stringify({ ok: false, error: "sender" }), { status: 400 });
    }
    if (!(await verifyMessage(body, senderPub))) {
      return new Response(JSON.stringify({ ok: false, error: "body_sig" }), { status: 401 });
    }

    // 3. Transport-layer §3.3 Authorization, freshness and replay.
    const auth = await verifyInkAuth({
      authHeader,
      method: "POST",
      path: url.pathname,
      recipientAgentId: recipientDid,
      body,
      resolvePublicKey: inlineDidKey,
      nonceStore: recordSeen,
    });
    if (!auth.valid) {
      return new Response(JSON.stringify({ ok: false, error: auth.error }), { status: 401 });
    }

    return new Response(
      JSON.stringify({ ok: true, receivedIntent: envelope.intent, sender: auth.principal }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;
}

async function recipientIdentity(): Promise<SenderIdentity> {
  // A did:key recipient: the inbox resolver needs an explicit endpoint, and
  // the receiver decodes the sender key inline. The recipient's own keypair
  // is unused here beyond giving it a stable did:key string.
  return generateSenderIdentity();
}

describe("sender → receiver round trip", () => {
  it("a ping is accepted by the OSS verification path", async () => {
    const sender = await generateSenderIdentity();
    const recipient = await recipientIdentity();
    const nonces = memoryNonceStore();

    const result = await sendIntent({
      identity: sender,
      recipientDid: recipient.did,
      intent: "ping",
      payload: pingPayload("round-trip"),
      endpoint: "https://ink-echo.tulpa.network/ink/v1/inbound",
      fetchImpl: makeReceiverFetch(recipient.did, nonces),
    });

    expect(result.stage).toBe("delivery");
    expect(result.ok).toBe(true);
    if (result.stage === "delivery" && result.ok) {
      expect(result.status).toBe(200);
      const ack = JSON.parse(result.bodyPreview) as { ok: boolean; receivedIntent: string };
      expect(ack.ok).toBe(true);
      expect(ack.receivedIntent).toBe("ping");
    }
  });

  it("the receiver rejects a replayed nonce on a second identical send", async () => {
    const sender = await generateSenderIdentity();
    const recipient = await recipientIdentity();
    const nonces = memoryNonceStore();
    const endpoint = "https://ink-echo.tulpa.network/ink/v1/inbound";

    // Pin a fixed nonce so the second send replays it. Timestamps stay real
    // so both requests fall inside the freshness window; the nonce is what
    // makes the second a replay rather than a stale message.
    const fixed = "00000000-0000-4000-8000-000000000abc";
    const fetchImpl = makeReceiverFetch(recipient.did, nonces);

    const first = await sendIntent({
      identity: sender,
      recipientDid: recipient.did,
      intent: "ping",
      payload: pingPayload(),
      endpoint,
      fetchImpl,
      newId: () => fixed,
    });
    expect(first.stage === "delivery" && first.ok).toBe(true);

    const replay = await sendIntent({
      identity: sender,
      recipientDid: recipient.did,
      intent: "ping",
      payload: pingPayload(),
      endpoint,
      fetchImpl,
      newId: () => fixed,
    });
    expect(replay.stage).toBe("delivery");
    expect(replay.ok).toBe(false);
    if (replay.stage === "delivery" && !replay.ok) {
      expect(replay.reason).toBe("non_2xx");
      expect(replay.status).toBe(401);
    }
  });
});
