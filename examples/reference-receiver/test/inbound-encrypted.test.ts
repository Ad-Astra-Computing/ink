import { describe, it, expect } from "vitest";
import {
  processInbound,
  type InboundConfig,
} from "../src/inbound.js";
import { InMemoryNonceStore } from "../src/nonce-store.js";
import { loadReceiverIdentity, loadEncryptionIdentity } from "../src/keys.js";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
  bytesToHex,
  signMessage,
  signInkMessage,
  buildAuthHeader,
  encryptInkPayload,
  type InkSignInput,
} from "@adastracomputing/ink";

// §3.4 receive side. The soak's `encrypted` synthetic variant seals a signed
// inner envelope to the key the receiver's card advertises and POSTs the outer
// encrypted envelope with a §3.3 transport signature over it. These pin the
// whole chain: transport auth over the outer body, decrypt with the
// recipient-DID binding, then the inner envelope through the same validation
// the plaintext path applies. The card half is pinned in
// agent-card-encryption.test.ts; landing that half without this one turns the
// soak's soft "unsupported" gap into a hard daily failure.

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const RECEIVER_DID = "did:web:receiver.example";
const ENC_SEED = Buffer.from(new Uint8Array(32).fill(21)).toString("hex");

async function makeReceiver(withEncryption = true) {
  const kp = await generateKeypair();
  const env = {
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
    ...(withEncryption ? { INK_RECEIVER_ENCRYPTION_SEED: ENC_SEED } : {}),
  };
  const cfg: InboundConfig = {
    identity: loadReceiverIdentity(env)!,
    encryption: loadEncryptionIdentity(env),
    receiverDid: RECEIVER_DID,
    nonceStore: new InMemoryNonceStore(),
  };
  return cfg;
}

async function makeSender() {
  const kp = await generateKeypair();
  const did = `did:key:${encodePublicKeyMultibase(kp.publicKey)}`;
  return { kp, did };
}

async function sealedPing(opts: {
  sender: { kp: { privateKey: Uint8Array; publicKey: Uint8Array }; did: string };
  recipientKeyHex: string;
  messageType?: "network.tulpa.encrypted" | "network.ink.encrypted";
  to?: string;
  intent?: string;
  payload?: Record<string, unknown>;
  messageNonce?: string;
}) {
  const createdAt = new Date().toISOString();
  const inner = {
    protocol: "ink/0.1" as const,
    id: `msg-${crypto.randomUUID()}`,
    correlationId: `corr-${crypto.randomUUID()}`,
    createdAt,
    from: opts.sender.did,
    to: opts.to ?? RECEIVER_DID,
    intent: opts.intent ?? "ping",
    payload: opts.payload ?? {},
    timestamp: createdAt,
    nonce: crypto.randomUUID(),
  };
  const signed = { ...inner, signature: await signMessage(inner, opts.sender.kp.privateKey) };
  const { envelope } = await encryptInkPayload(
    signed,
    opts.sender.did,
    opts.recipientKeyHex,
    createdAt,
    opts.messageNonce ?? `mn-${crypto.randomUUID()}`,
    { messageType: opts.messageType ?? "network.tulpa.encrypted" },
  );
  return { inner: signed, outer: envelope as unknown as Record<string, unknown> };
}

async function transportAuth(
  outer: Record<string, unknown>,
  senderKp: { privateKey: Uint8Array },
): Promise<string> {
  const input: InkSignInput = {
    method: "POST",
    path: "/ink/v1/inbound",
    recipientDid: RECEIVER_DID,
    body: outer,
    timestamp: outer.timestamp as string,
  };
  return buildAuthHeader(await signInkMessage(input, senderKp.privateKey));
}

async function run(cfg: InboundConfig, outer: Record<string, unknown>, auth: string | undefined) {
  return processInbound(enc(JSON.stringify(outer)), auth, cfg);
}

describe("encrypted inbound (§3.4)", () => {
  it("accepts a sealed network.tulpa.encrypted envelope end-to-end", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { inner, outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(cfg.encryption!.publicKey) });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("ok");
    if (out.kind === "ok") {
      expect(out.intent).toBe("ping");
      expect(out.sender).toBe(sender.did);
      expect((out.response as { inReplyTo?: string }).inReplyTo).toBe(inner.id);
    }
  });

  it("accepts the vendor-neutral network.ink.encrypted spelling", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({
      sender,
      recipientKeyHex: bytesToHex(cfg.encryption!.publicKey),
      messageType: "network.ink.encrypted",
    });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("ok");
  });

  it("rejects encrypted envelopes when no encryption identity is configured", async () => {
    // The pre-fix live behavior: the card advertises no key so a conformant
    // sender never seals to us. A sender that seals anyway gets an explicit
    // refusal, not a schema error that misnames the problem.
    const plainCfg = await makeReceiver(false);
    const sealedTo = await makeReceiver(); // any valid recipient key to seal against
    const sender = await makeSender();
    const { outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(sealedTo.encryption!.publicKey) });
    const out = await run(plainCfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode).toBe("encryption_unsupported");
  });

  it("rejects a bad transport signature before any decryption is attempted", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(cfg.encryption!.publicKey) });
    const out = await run(cfg, outer, "INK-Ed25519 " + "A".repeat(86));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") {
      expect(out.verdict).toBe("signature");
      expect(out.errorCode.startsWith("auth:")).toBe(true);
    }
  });

  it("rejects a replayed outer envelope on the shared nonce store", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(cfg.encryption!.publicKey) });
    const auth = await transportAuth(outer, sender.kp);
    const first = await run(cfg, outer, auth);
    expect(first.kind).toBe("ok");
    const second = await run(cfg, outer, auth);
    expect(second.kind).toBe("rejected");
  });

  it("rejects a reused messageNonce even under a fresh seal", async () => {
    // The §3.5 replay nonce for an encrypted envelope is `messageNonce`; the
    // outer `nonce` is the AES-GCM IV and changes on every seal. Recording the
    // IV instead would let an authenticated sender replay one messageNonce
    // under fresh IVs indefinitely.
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const mn = `mn-${crypto.randomUUID()}`;
    const keyHex = bytesToHex(cfg.encryption!.publicKey);
    const first = await sealedPing({ sender, recipientKeyHex: keyHex, messageNonce: mn });
    const second = await sealedPing({ sender, recipientKeyHex: keyHex, messageNonce: mn });
    expect(first.outer.nonce).not.toBe(second.outer.nonce);
    const ok = await run(cfg, first.outer, await transportAuth(first.outer, sender.kp));
    expect(ok.kind).toBe("ok");
    const replay = await run(cfg, second.outer, await transportAuth(second.outer, sender.kp));
    expect(replay.kind).toBe("rejected");
    if (replay.kind === "rejected") expect(replay.errorCode).toBe("auth:nonce_replay");
  });

  it("rejects a messageNonce outside the replay-nonce grammar before auth", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({
      sender,
      recipientKeyHex: bytesToHex(cfg.encryption!.publicKey),
      messageNonce: "too-short", // valid charset, below the 16-char floor
    });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode).toBe("outer_message_nonce_invalid");
  });

  it("rejects tampered ciphertext", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(cfg.encryption!.publicKey) });
    const ct = outer.ciphertext as string;
    const tampered = { ...outer, ciphertext: (ct[0] === "A" ? "B" : "A") + ct.slice(1) };
    const out = await run(cfg, tampered, await transportAuth(tampered, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode.startsWith("decrypt:")).toBe(true);
  });

  it("rejects an envelope sealed to a different recipient key", async () => {
    const cfg = await makeReceiver();
    const other = await generateKeypair(); // wrong X25519 target: use another receiver's key
    const otherEnv = { INK_RECEIVER_ENCRYPTION_SEED: Buffer.from(new Uint8Array(32).fill(33)).toString("hex") };
    const otherEnc = loadEncryptionIdentity(otherEnv as never)!;
    void other;
    const sender = await makeSender();
    const { outer } = await sealedPing({ sender, recipientKeyHex: bytesToHex(otherEnc.publicKey) });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode.startsWith("decrypt:")).toBe(true);
  });

  it("rejects an inner envelope addressed to someone else", async () => {
    // encryptInkPayload allows any non-empty inner `to` when the caller does
    // not assert recipientDid; the decrypt side must still refuse it.
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const { outer } = await sealedPing({
      sender,
      recipientKeyHex: bytesToHex(cfg.encryption!.publicKey),
      to: "did:web:someone-else.example",
    });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.errorCode.startsWith("decrypt:")).toBe(true);
  });

  it("applies the intent allowlist to the decrypted inner envelope", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    // follow_up is schema-valid but not in SUPPORTED_INTENTS, same probe the
    // plaintext allowlist test uses.
    const { outer } = await sealedPing({
      sender,
      recipientKeyHex: bytesToHex(cfg.encryption!.publicKey),
      intent: "follow_up",
      payload: { referenceId: "m-prev-1", message: "ping?" },
    });
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.verdict).toBe("unsupported_intent");
  });

  it("runs the decrypted inner envelope through schema validation", async () => {
    const cfg = await makeReceiver();
    const sender = await makeSender();
    const createdAt = new Date().toISOString();
    // Sealable (has from/to) but not a valid MessageEnvelope: missing id,
    // nonce, signature and the rest.
    const bogus = { from: sender.did, to: RECEIVER_DID, protocol: "ink/0.1", createdAt };
    const { envelope } = await encryptInkPayload(
      bogus,
      sender.did,
      bytesToHex(cfg.encryption!.publicKey),
      createdAt,
      `mn-${crypto.randomUUID()}`,
    );
    const outer = envelope as unknown as Record<string, unknown>;
    const out = await run(cfg, outer, await transportAuth(outer, sender.kp));
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") expect(out.verdict).toBe("schema");
  });
});
