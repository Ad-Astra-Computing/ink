import { describe, it, expect } from "vitest";
import { validateMessage, verifyMessage, decodePublicKeyMultibase } from "@adastracomputing/ink";
import { generateSenderIdentity } from "../src/identity.ts";
import {
  buildSignedEnvelope,
  pingPayload,
  connectionRequestPayload,
} from "../src/envelope.ts";

const RECIPIENT = "did:key:z6MkrecipientPLACEHOLDERdoesNotNeedToResolveForBodySig";

describe("buildSignedEnvelope", () => {
  it("emits an envelope that validateMessage accepts", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: RECIPIENT,
      intent: "ping",
      payload: pingPayload("hello"),
    });
    // Re-validating must not throw.
    expect(() => validateMessage(env)).not.toThrow();
    expect(env.from).toBe(id.did);
    expect(env.to).toBe(RECIPIENT);
    expect(env.intent).toBe("ping");
    expect(typeof env.signature).toBe("string");
    expect(env.timestamp).toBe(env.createdAt);
  });

  it("produces a body signature that verifies under the sender public key", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: RECIPIENT,
      intent: "ping",
      payload: pingPayload(),
    });
    const pub = decodePublicKeyMultibase(id.publicKeyMultibase);
    const ok = await verifyMessage(env as unknown as Record<string, unknown>, pub);
    expect(ok).toBe(true);
  });

  it("body signature fails to verify after the payload is tampered", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: RECIPIENT,
      intent: "ping",
      payload: pingPayload("original"),
    });
    const tampered = { ...env, payload: { note: "tampered" } } as Record<string, unknown>;
    const pub = decodePublicKeyMultibase(id.publicKeyMultibase);
    expect(await verifyMessage(tampered, pub)).toBe(false);
  });

  it("validates a connection_request payload against the intent schema", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: RECIPIENT,
      intent: "connection_request",
      payload: connectionRequestPayload({ context: "hi", headline: "Reference sender" }),
    });
    expect(env.intent).toBe("connection_request");
  });

  it("rejects a payload that violates the intent schema", async () => {
    const id = await generateSenderIdentity();
    await expect(
      buildSignedEnvelope({
        identity: id,
        to: RECIPIENT,
        intent: "ping",
        // `note` must be a string; a number must be rejected by the schema.
        payload: { note: 123 },
      }),
    ).rejects.toThrow();
  });
});
